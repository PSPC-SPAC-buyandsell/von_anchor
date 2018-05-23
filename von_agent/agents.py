"""
Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import asyncio
import json
import logging
import re

from os import makedirs
from os.path import basename, expanduser, isfile, islink, join
from time import time
from typing import Set, Union

from indy import anoncreds, blob_storage, ledger
from indy.error import IndyError, ErrorCode
from von_agent.cache import CRED_DEF_CACHE, REVO_CACHE, RevoCacheEntry, SCHEMA_CACHE
from von_agent.codec import cred_attr_value
from von_agent.error import (
    AbsentAttribute,
    AbsentCredDef,
    AbsentInterval,
    AbsentLinkSecret,
    AbsentRevRegDef,
    AbsentSchema,
    AbsentTailsFile,
    BadLedgerTxn,
    BadRevocation,
    BadRevStateTime,
    CacheIndex,
    CredentialFocus,
    CorruptTails,
    CorruptWallet)
from von_agent.nodepool import NodePool
from von_agent.tails import Tails
from von_agent.util import (
    cred_def_id,
    ppjson,
    prune_creds_json,
    rev_reg_id,
    rev_reg_id2cred_def_id__tag,
    revoc_info,
    schema_id,
    SchemaKey,
    schema_key)
from von_agent.validate_config import validate_config
from von_agent.wallet import Wallet


class _AgentCore:
    """
    Base class for agent implementing low-level functionality.
    """

    def __init__(self, wallet: Wallet) -> None:
        """
        Initializer for agent. Retain wallet.

        Raise AbsentWallet if wallet is not yet created.

        :param wallet: wallet for agent use
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.__init__: >>> wallet: {}'.format(wallet))

        self._wallet = wallet

        logger.debug('_AgentCore.__init__: <<<')

    @property
    def pool(self) -> NodePool:
        """
        Accessor for node pool.

        :return: node pool
        """

        return self.wallet.pool

    @property
    def wallet(self) -> 'Wallet':
        """
        Accessor for wallet.

        :return: wallet
        """

        return self._wallet

    @property
    def did(self) -> str:
        """
        Accessor for agent DID.

        :return: agent DID
        """

        return self.wallet.did

    @property
    def verkey(self) -> str:
        """
        Accessor for agent verification key.

        :return: agent verification key
        """

        return self.wallet.verkey

    async def __aenter__(self) -> '_AgentCore':
        """
        Context manager entry. Open wallet and store agent DID in it.
        For use in monolithic call opening, using, and closing the agent.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.__aenter__: >>>')

        rv = await self.open()

        logger.debug('_AgentCore.__aenter__: <<<')
        return rv

    async def open(self) -> '_AgentCore':
        """
        Explicit entry. Open wallet and store agent DID in it.
        For use when keeping agent open across multiple calls.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.open: >>>')

        await self.wallet.open()

        logger.debug('_AgentCore.open: <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Close wallet.
        For use in monolithic call opening, using, and closing the agent.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.__aexit__: >>> exc_type: {}, exc: {}, traceback: {}'.format(exc_type, exc, traceback))

        await self.close()
        logger.debug('_AgentCore.__exit__: <<<')

    async def close(self) -> None:
        """
        Explicit exit. Close wallet.
        For use when keeping agent open across multiple calls.
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.close: >>>')

        await self.wallet.close()

        logger.debug('_AgentCore.close: <<<')

    async def _submit(self, req_json: str) -> str:
        """
        Submit (json) request to ledger; return (json) result.

        Raise BadLedgerTxn on failure.

        :param req_json: json of request to sign and submit
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore._submit: >>> json: {}'.format(req_json))

        rv_json = await ledger.submit_request(self.pool.handle, req_json)
        await asyncio.sleep(0)

        resp = json.loads(rv_json)
        if ('op' in resp) and (resp['op'] in ('REQNACK', 'REJECT')):
            logger.debug(
                '_AgentCore._submit: <!< ledger rejected request: {}'.format(resp['reason']))
            raise BadLedgerTxn('Ledger rejected transaction request: {}'.format(resp['reason']))

        if 'reason' in resp and 'result' in resp and resp['result'].get('seqNo', None) is None:
            logger.debug('_AgentCore._submit: <!< response indicates no transaction: {}'.format(resp['reason']))
            raise BadLedgerTxn('Response indicates no transaction'.format(resp['reason']))

        logger.debug('_AgentCore._submit: <<< {}'.format(rv_json))
        return rv_json

    async def _sign_submit(self, req_json: str) -> str:
        """
        Sign and submit (json) request to ledger; return (json) result.

        Raise CorruptWallet if existing wallet's pool is no longer extant,
        or BadLedgerTxn on any other failure.

        :param req_json: json of request to sign and submit
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore._sign_submit: >>> json: {}'.format(req_json))

        try:
            rv_json = await ledger.sign_and_submit_request(self.pool.handle, self.wallet.handle, self.did, req_json)
            await asyncio.sleep(0)
        except IndyError as e:
            if e.error_code == ErrorCode.WalletIncompatiblePoolError:
                logger.debug('_AgentCore._sign_submit: <!< Corrupt wallet {} is not compatible with pool {}'.format(
                    self.wallet.name,
                    self.pool.name))
                raise CorruptWallet(
                    'Corrupt wallet {} is not compatible with pool {}'.format(self.wallet.name, self.pool.name))
            else:
                logger.debug(
                    '_AgentCore._sign_submit: <!<  cannot sign/submit request for ledger: indy error code {}'.format(
                        self.wallet.name))
                raise BadLedgerTxn('Cannot sign/submit request for ledger: indy error code {}'.format(e.error_code))

        resp = json.loads(rv_json)
        if ('op' in resp) and (resp['op'] in ('REQNACK', 'REJECT')):
            logger.debug('_AgentCore._sign_submit: ledger rejected request: {}'.format(resp['reason']))
            raise BadLedgerTxn('Ledger rejected transaction request: {}'.format(resp['reason']))

        if 'reason' in resp and 'result' in resp and resp['result'].get('seqNo', None) is None:
            logger.debug('_AgentCore._sign_submit: <!< response indicates no transaction: {}'.format(
                resp['reason']))
            raise BadLedgerTxn('Response indicates no transaction'.format(resp['reason']))

        logger.debug('_AgentCore._sign_submit: <<< {}'.format(rv_json))
        return rv_json

    async def get_nym(self, did: str) -> str:
        """
        Get json cryptonym (including current verification key) for input (agent) DID from ledger.

        Raise BadLedgerTxn on failure.

        :param did: DID of cryptonym to fetch
        :return: cryptonym json
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.get_nym: >>> did: {}'.format(did))

        rv = json.dumps({})
        get_nym_req = await ledger.build_get_nym_request(self.did, did)
        resp_json = await self._submit(get_nym_req)

        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json:
            rv = data_json

        logger.debug('_AgentCore.get_nym: <<< {}'.format(rv))
        return rv

    async def get_schema(self, index: Union[SchemaKey, int]) -> str:
        """
        Get schema from ledger by sequence number or schema key (origin DID, name, version).
        Raise BadLedgerTxn on failure.

        Retrieve the schema from the agent's schema cache if it has it; cache it
        en passant if it does not (and if there is a corresponding schema on the ledger).

        :param schema_id: schema key (origin DID, name, version) or sequence number
        :return: schema json, parsed from ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.get_schema: >>> index: {}'.format(index))

        rv_json = json.dumps({})
        with SCHEMA_CACHE.lock:
            if SCHEMA_CACHE.contains(index):
                logger.info('_AgentCore.get_schema: got schema {} from schema cache'.format(index))
                rv_json = SCHEMA_CACHE[index]
                logger.debug('_AgentCore.get_schema: <<< {}'.format(rv_json))
                return json.dumps(rv_json)

            if isinstance(index, SchemaKey):
                req_json = await ledger.build_get_schema_request(self.did, schema_id(*index))
                resp_json = await self._submit(req_json)
                resp = json.loads(resp_json)
                try:
                    (s_id, rv_json) = await ledger.parse_get_schema_response(resp_json)
                except IndyError as e:  # ledger replied, but there is no such schema
                    logger.debug('_AgentCore.get_schema: <!< no schema exists on {}'.format(index))
                    raise AbsentSchema('No schema exists on {}'.format(index))
                SCHEMA_CACHE[index] = json.loads(rv_json)  # cache indexes by both txn# and schema key en passant
                logger.info('_AgentCore.get_schema: got schema {} from ledger'.format(index))

            elif isinstance(index, int):
                txn_json = await self.process_get_txn(index)
                txn = json.loads(txn_json)
                if txn.get('type', None) == '101':  # {} for no such txn; 101 marks indy-sdk schema txn type
                    rv_json = await self.get_schema(SchemaKey(
                        txn['identifier'],
                        txn['data']['name'],
                        txn['data']['version']))
                else:
                    logger.info('_AgentCore.get_schema: no schema at seq #{} on ledger'.format(index))

            else:
                logger.debug('_AgentCore.get_schema: <!< bad schema index type')
                raise AbsentSchema('Attempt to get schema on ({}) {} , must use schema key or an int'.format(
                    type(index),
                    index))

        logger.debug('_AgentCore.get_schema: <<< {}'.format(rv_json))
        return rv_json

    def role(self) -> str:
        """
        Return the indy-sdk role for an agent in building its nym for the trust anchor to send to the ledger.

        :param: agent: agent instance
        :return: role string
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.role: >>>')

        rv = None
        if isinstance(self, (AgentRegistrar, Origin, Issuer)):
            rv = 'TRUST_ANCHOR'

        logger.debug('_AgentCore.role: <<< {}'.format(rv))
        return rv

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}({})'.format(self.__class__.__name__, self.wallet)

class _BaseAgent(_AgentCore):
    """
    Class for agent that listens and responds to other agents. Note that a service wrapper will
    listen for requests, parse requests, dispatch to agents, and return content to callers;
    the current design calls not to use indy-sdk for direct agent-to-agent communication.

    The _BaseAgent builds on the _AgentCore in that it stores configuration information (e.g., endpoint data),
    and it receives and responds to (json) VON protocol messages (via a VON connector).
    """

    def __init__(self, wallet: Wallet, cfg: dict = None) -> None:
        """
        Initializer for agent. Retain input parameters; do not open wallet.

        :param wallet: wallet for agent use
        :param cfg: configuration, None for default with no endpoint and proxy-relay=False;
            e.g., {
                'endpoint': 'http://127.0.0.1:8808/api/v0',
                'proxy-relay': True
            }
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.__init__: >>> wallet: {}, cfg: {}'.format(wallet, cfg))

        super().__init__(wallet)

        self._cfg = cfg or {}
        validate_config('agent', self._cfg)

        logger.debug('_BaseAgent.__init__: <<<')

    @property
    def cfg(self):
        """
        Accessor for configuration attribute.

        :return: configuration (dict)
        """
        return self._cfg

    async def _get_rev_reg_def(self, rr_id: str) -> str:
        """
        Get revocation registry definition from ledger by its identifier. Return empty production '{}'
        for no such revocation registry definition, logging any error condition on bad request.

        Retrieve the revocation registry definition from the agent's revocation cache if it has it;
        cache it en passant if it does not (and if there is a revocation registry definition on the ledger).

        :param rr_id: (revocation registry) identifier string
            ('<issuer-did>:4:<issuer-did>:3:CL:<schema-seq-no>:CL_ACCUM:<tag>')
        :return: revocation registry definition json as retrieved from ledger,
            empty production '{}' for no such revocation registry definition
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent._get_rev_reg_def: >>> rr_id: {}'.format(rr_id))

        rv_json = json.dumps({})

        with REVO_CACHE.lock:
            revo_cache_entry = REVO_CACHE.get(rr_id, None)
            rrdef = revo_cache_entry.rev_reg_def if revo_cache_entry else None
            if rrdef:
                logger.info('_BaseAgent._get_rev_reg_def: rev reg def for {} from cache'.format(rr_id))
                rv_json = json.dumps(rrdef)
            else:
                get_rrd_req_json = await ledger.build_get_revoc_reg_def_request(self.did, rr_id)
                resp_json = await self._submit(get_rrd_req_json)
                (_, rv_json) = await ledger.parse_get_revoc_reg_def_response(resp_json)
                rrdef = json.loads(rv_json)

                if revo_cache_entry is None:
                    REVO_CACHE[rr_id] = RevoCacheEntry(rrdef, None)
                else:
                    REVO_CACHE[rr_id]._rev_reg_def = rrdef

        logger.debug('_BaseAgent._get_rev_reg_def: <<< {}'.format(rv_json))
        return rv_json

    async def get_cred_def(self, cd_id: str) -> str:
        """
        Get credential definition from ledger by its identifier. Raise AbsentCredDef
        for no such credential definition, logging any error condition on bad request.

        Retrieve the credential definition from the agent's credential definition cache if it has it; cache it
        en passant if it does not (and if there is a corresponding credential definition on the ledger).

        :param cd_id: (credential definition) identifier string ('<issuer-did>:3:CL:<schema-seq-no>')
        :return: credential definition json as retrieved from ledger,
            empty production {} for no such credential definition
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.get_cred_def: >>> cd_id: {}'.format(cd_id))

        rv_json = json.dumps({})

        with CRED_DEF_CACHE.lock:
            if cd_id in CRED_DEF_CACHE:
                logger.info('_BaseAgent.get_cred_def: got cred def for {} from cache'.format(cd_id))
                rv_json = json.dumps(CRED_DEF_CACHE[cd_id])
                logger.debug('_BaseAgent.get_cred_def: <<< {}'.format(rv_json))
                return rv_json

            req_json = await ledger.build_get_cred_def_request(self.did, cd_id)
            resp_json = await self._submit(req_json)
            resp = json.loads(resp_json)
            try:
                (_, rv_json) = await ledger.parse_get_cred_def_response(resp_json)
            except IndyError:  # ledger replied, but there is no such cred def
                logger.debug('_BaseAgent.get_cred_def: <!< no cred def exists on {}'.format(cd_id))
                raise AbsentCredDef('No cred def exists on {}'.format(cd_id))
            CRED_DEF_CACHE[cd_id] = json.loads(rv_json)
            logger.info('_BaseAgent.get_cred_def: got cred def {} from ledger'.format(cd_id))

        logger.debug('_BaseAgent.get_cred_def: <<< {}'.format(rv_json))
        return rv_json

    async def process_get_txn(self, txn: int) -> str:
        """
        Take a request to find a transaction on the distributed ledger by its sequence number.

        :param txn: transaction number
        :return: json sequence number of transaction, null for no match
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.process_get_txn: >>> txn: {}'.format(txn))

        rv_json = json.dumps({})
        req_json = await ledger.build_get_txn_request(self.did, txn)
        resp = json.loads(await self._submit(req_json))

        rv_json = json.dumps(resp['result'].get('data', {}))
        logger.debug('_BaseAgent.process_get_txn: <<< {}'.format(rv_json))
        return rv_json

    async def process_get_did(self) -> str:
        """
        Take a request to get current agent's DID, return json accordingly.

        :return: json DID
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.process_get_did: >>>')

        rv = json.dumps(self.did or {})
        logger.debug('_BaseAgent.process_get_did: <<< {}'.format(rv))
        return rv

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}({}, {}, {})'.format(self.__class__.__name__, repr(self.pool), self.wallet, self.cfg)

    def __str__(self) -> str:
        """
        Return informal string identifying current object.

        :return: string identifying current object
        """

        return '{}({}, {})'.format(self.__class__.__name__, self.wallet, self.cfg)


class AgentRegistrar(_BaseAgent):
    """
    Mixin for (trust anchor) agent to register agents onto the distributed ledger
    """

    async def send_nym(self, did: str, verkey: str, alias: str = None, role: str = None) -> None:
        """
        Send input agent's cryptonym (including DID and current verification key) to ledger.

        Raise BadLedgerTxn on failure.

        :param did: agent DID to send to ledger
        :param verkey: agent verification key
        :param alias: optional alias
        :param role: agent role on the ledger; specify one of 'TRUSTEE', 'STEWARD', 'TRUST_ANCHOR' or '' to reset role
        """

        logger = logging.getLogger(__name__)
        logger.debug('AgentRegistrar.send_nym: >>> did: {}, verkey: {}, alias: {}, role: {}'.format(
            did,
            verkey,
            alias,
            role))

        req_json = await ledger.build_nym_request(
            self.did,
            did,
            verkey,
            alias,
            role)
        await self._sign_submit(req_json)

        logger.debug('AgentRegistrar.send_nym: <<<')


class Origin(_BaseAgent):
    """
    Mixin for agent to send schemata and credential definitions to the distributed ledger
    """

    async def send_schema(self, schema_data_json: str) -> str:
        """
        Send schema to ledger, then retrieve it as written to the ledger and return it.
        If schema already exists on ledger, log error and return schema.

        :param schema_data_json: schema data json with name, version, attribute names; e.g.,:
            {
                'name': 'my-schema',
                'version': '1.234',
                'attr_names': ['favourite_drink', 'height', 'last_visit_date']
            }
        :return: schema json as written to ledger (or existed a priori)
        """

        logger = logging.getLogger(__name__)
        logger.debug('Origin.send_schema: >>> schema_data_json: {}'.format(schema_data_json))

        schema_data = json.loads(schema_data_json)
        s_key = schema_key(schema_id(self.did, schema_data['name'], schema_data['version']))
        with SCHEMA_CACHE.lock:
            try:
                rv_json = await self.get_schema(s_key)
                logger.error('Schema {} version {} already exists on ledger for origin-did {}: not sending'.format(
                    schema_data['name'],
                    schema_data['version'],
                    self.did))
            except AbsentSchema:  # OK - about to create and send it
                (_, schema_json) = await anoncreds.issuer_create_schema(
                    self.did,
                    schema_data['name'],
                    schema_data['version'],
                    json.dumps(schema_data['attr_names']))
                req_json = await ledger.build_schema_request(self.did, schema_json)
                resp_json = await self._sign_submit(req_json)
                resp = json.loads(resp_json)
                resp_result = resp['result']
                rv_json = await self.get_schema(schema_key(schema_id(
                    resp_result['identifier'],
                    resp_result['data']['name'],
                    resp_result['data']['version'])))  # add to cache en passant

        logger.debug('Origin.send_schema: <<< {}'.format(rv_json))
        return rv_json


class Issuer(Origin):
    """
    Mixin for agent acting in role of Issuer.

    The current design calls for any issuer to be able to originate its own schema.
    """

    def __init__(self, wallet: Wallet, cfg: dict = None) -> None:
        """
        Initializer for Issuer agent. Retain input parameters; do not open wallet nor tails writer.

        :param wallet: wallet for agent use
        :param cfg: configuration, None for default with no endpoint and proxy-relay=False;
            e.g., {
                'endpoint': 'http://127.0.0.1:8808/api/v0',
                'proxy-relay': True
            }
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.__init__: >>> wallet: {}, cfg: {}'.format(wallet, cfg))

        super().__init__(wallet, cfg)
        self._dir_tails = join(expanduser('~'), '.indy_client', 'tails')
        makedirs(self._dir_tails, exist_ok=True)

        logger.debug('Issuer.__init__: <<<')

    async def open(self) -> 'Issuer':
        """
        Explicit entry. Perform ancestor opening operations,
        then synchronize revocation registry to tails directory content.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.open: >>>')

        await super().open()
        for path_rr_id in Tails.links(self._dir_tails):
            await self._sync_revoc(basename(path_rr_id))

        logger.debug('Issuer.open: <<<')
        return self

    async def _create_rev_reg(self, rr_id: str, rr_size: int = None) -> None:
        """
        Create revocation registry and new tails file (and association to
        corresponding revocation registry definition via symbolic link) for input
        revocation registry identifier.

        :param rr_id: revocation registry identifier
        :param rr_size: revocation registry size (defaults to 256)
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer._create_rev_reg: >>> rr_id: {}, rr_size: {}'.format(rr_id, rr_size))

        rr_size = rr_size or 256
        (cd_id, tag) = rev_reg_id2cred_def_id__tag(rr_id)

        logger.info('Creating revocation registry (capacity {}) for rev reg id {}'.format(rr_size, rr_id))
        tails_writer_handle = await blob_storage.open_writer(
            'default',
            json.dumps({
                'base_dir': Tails.dir(self._dir_tails, rr_id),
                'uri_pattern': ''
            }))
        apriori = Tails.unlinked(self._dir_tails)
        (rr_id, rrd_json, rre_json) = await anoncreds.issuer_create_and_store_revoc_reg(
            self.wallet.handle,
            self.did,
            'CL_ACCUM',
            tag,
            cd_id,
            json.dumps({
                'max_cred_num': rr_size,
                'issuance_type': 'ISSUANCE_ON_DEMAND'
            }),
            tails_writer_handle)
        delta = Tails.unlinked(self._dir_tails) - apriori
        if len(delta) != 1:
            logger.debug(
                'Issuer._create_rev_reg: <!< Could not create tails file for rev reg id: {}'.format(
                    rr_id,
                    resp['reason']))
            raise CorruptTailsFile('Could not create tails file for rev reg id {}'.format(rr_id))
        tails_hash = basename(delta.pop())
        Tails.associate(self._dir_tails, rr_id, tails_hash)

        with REVO_CACHE.lock:
            rrd_req_json = await ledger.build_revoc_reg_def_request(self.did, rrd_json)
            resp_json = await self._sign_submit(rrd_req_json)
            await self._get_rev_reg_def(rr_id)  # add to cache en passant

        rre_req_json = await ledger.build_revoc_reg_entry_request(self.did, rr_id, 'CL_ACCUM', rre_json)
        await self._sign_submit(rre_req_json)

        logger.debug('Issuer._create_rev_reg: <<<')

    async def _sync_revoc(self, rr_id: str, rr_size: int = None) -> None:
        """
        Create revoc registry if need be for input revocation registry identifier;
        open and cache tails file reader.

        :param rr_id: revocation registry identifier
        :param rr_size: if new revocation registry necessary, its size (default as per _create_rev_reg())
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer._sync_revoc: >>> rr_id: {}, rr_size: {}'.format(rr_id, rr_size))

        (cd_id, tag) = rev_reg_id2cred_def_id__tag(rr_id)

        if not json.loads(await self.get_cred_def(cd_id)):
            logger.debug(
                'Issuer._sync_revoc: <!< corrupt tails directory {} may pertain to another ledger'.format(
                    self._dir_tails))
            raise AbsentCredDef('Corrupt tails directory {} may pertain to another ledger'.format(self._dir_tails))

        with REVO_CACHE.lock:
            revo_cache_entry = REVO_CACHE.get(rr_id, None)
            t = None if revo_cache_entry is None else revo_cache_entry.tails
            if t is None:  #  it's a new revocation registry, or not yet set in cache
                try:
                    t = await Tails(self._dir_tails, cd_id, tag).open()
                except AbsentTailsFile as e:
                    await self._create_rev_reg(rr_id, rr_size)   # it's a new revocation registry
                    t = await Tails(self._dir_tails, cd_id, tag).open()  # symlink should exist now

                if revo_cache_entry is None:
                    REVO_CACHE[rr_id] = RevoCacheEntry(None, t)
                else:
                    REVO_CACHE[rr_id]._tails = t
            # else: print('\n\n$$ tfile $$ got tails file {} from cache'.format(rr_id))

        logger.debug('Issuer._sync_revoc: <<<')

    def path_tails(self, rr_id: str) -> str:
        """
        Return path to tails file for input revocation registry identifier.

        :param rr_id: revocation registry identifier of interest
        :return: path to tails file for input revocation registry identifier
        """

        return Tails.linked(self._dir_tails, rr_id)

    async def send_cred_def(self, schema_json: str, revocation: bool = True, rr_size: int = None) -> str:
        """
        Create a credential definition as Issuer, store it in its wallet, and send it to the ledger.

        Raise CorruptWallet for wallet not pertaining to current ledger, BadLedgerTxn on failure
        to send credential definition to ledger if need be, or IndyError for any other failure
        to create and store credential definition in wallet.

        :param schema_json: schema as it appears on ledger via get_schema()
        :param revocation: whether to support revocation for cred def
        :param rr_size: size of initial revocation registry (default as per _create_rev_reg()), if revocation supported
        :return: json credential definition as it appears on ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.send_cred_def: >>> schema_json: {}, revocation: {}, rr_size: {}'.format(   
            schema_json,
            revocation,
            rr_size))

        rv_json = json.dumps({})
        schema = json.loads(schema_json)

        s_id = schema_id(self.did, schema['name'], schema['version'])
        cd_id = cred_def_id(self.did, schema['seqNo'])

        with CRED_DEF_CACHE.lock:
            try:
                rv_json = await self.get_cred_def(cd_id)
                logger.info(
                    'Cred def on schema {} version {} already exists on ledger; Issuer {} not sending another'.format(
                        schema['name'],
                        schema['version'],
                        self.wallet.name))
            except AbsentCredDef:
                pass  # OK - about to create, store, and send it

            try:
                (_, cred_def_json) = await anoncreds.issuer_create_and_store_credential_def(
                    self.wallet.handle,
                    self.did,  # issuer DID
                    schema_json,
                    'moot-tag',  # indy-sdk ignores under current indy-sdk revocation model: tags rev regs instead
                    'CL',
                    json.dumps({'support_revocation': revocation}))
            except IndyError as e:
                if e.error_code == ErrorCode.AnoncredsCredDefAlreadyExistsError:
                    if json.loads(rv_json):
                        logger.info('Issuer wallet {} reusing existing cred def on schema {} version {}'.format(
                            self.wallet.name,
                            schema['name'],
                            schema['version']))
                    else:
                        logger.debug('Issuer.send_cred_def: <!< corrupt wallet {}'.format(self.wallet.name))
                        raise CorruptWallet(
                            'Corrupt Issuer wallet {} has cred def on schema {} version {} not on ledger'.format(
                                self.wallet.name,
                                schema['name'],
                                schema['version']))
                else:
                    logger.debug(
                        'Issuer.send_cred_def: <!< cannot store cred def in wallet {}: indy error code {}'.format(
                            self.wallet.name,
                            e.error_code))
                    raise

            if not json.loads(rv_json):  # checking the ledger returned no cred def: send it
                req_json = await ledger.build_cred_def_request(self.did, cred_def_json)
                resp_json = await self._sign_submit(req_json)
                rv_json = await self.get_cred_def(cd_id)  # pick up from ledger and parse; add to cache

                if revocation:
                    await self._sync_revoc(rev_reg_id(cd_id, 0), rr_size)  # create new rev reg, tails file for tag 0

        if revocation:
            for tag in [str(t) for t in range(int(Tails.next_tag(self._dir_tails, cd_id)[0]))]:  # '0' to str(next-1)
                await self._sync_revoc(rev_reg_id(cd_id, tag), rr_size if tag == 0 else None)

        logger.debug('Issuer.send_cred_def: <<< {}'.format(rv_json))
        return rv_json

    async def create_cred_offer(self, schema_seq_no: int) -> str:
        """
        Create credential offer as Issuer for given schema and agent on specified DID.

        Raise CorruptWallet if the wallet has no private key for the corresponding credential definition.

        :param schema_seq_no: schema sequence number
        :return: json credential offer for use in storing credentials at HolderProver.
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.create_cred_offer: >>> schema_seq_no: {}'.format(schema_seq_no))

        rv = None
        cd_id = cred_def_id(self.did, schema_seq_no)
        try:
            rv = await anoncreds.issuer_create_credential_offer(self.wallet.handle, cd_id)
        except IndyError as e:
            if e.error_code == ErrorCode.WalletNotFoundError:
                logger.debug('Issuer.create_cred_offer: <!< did not issue cred definition from wallet {}'.format(
                    self.wallet.name))
                raise CorruptWallet('Cannot create cred offer: did not issue cred definition from wallet {}'.format(
                    self.wallet.name))
            else:
                logger.debug('Issuer.create_cred_offer: <!<  cannot create cred offer, indy error code {}'.format(
                    e.error_code))
                raise

        logger.debug('Issuer.create_cred_offer: <<< {}'.format(rv))
        return rv

    async def create_cred(self, cred_offer_json, cred_req_json: str, cred_attrs: dict) -> (str, str):
        """
        Create credential as Issuer out of credential request and dict of key:value (raw, unencoded) entries
        for attributes; return credential json and credential revocation identifier.

        :param cred_offer_json: credential offer json as created by Issuer
        :param cred_req_json: credential request json as created by HolderProver
        :param cred_attrs: dict mapping each attribute to its raw value (the operation encodes it); e.g.,
            ::
            {
                'favourite_drink': 'martini',
                'height': 180,
                'last_visit_date': '2017-12-31',
                'weaknesses': None
            }
        :return: newly issued credential json, credential revocation identifier (None for cred on
            cred def without revocation support)
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.create_cred: >>> cred_offer_json: {}, cred_req_json: {}, cred_attrs: {}'.format(
            cred_offer_json,
            cred_req_json,
            cred_attrs))

        cd_id = json.loads(cred_offer_json)['cred_def_id']
        cred_def = json.loads(await self.get_cred_def(cd_id))  # ensure cred def is in cache

        if 'revocation' in cred_def['value']:
            with REVO_CACHE.lock:
                rr_id = Tails.current_rev_reg_id(self._dir_tails, cd_id)
                t = REVO_CACHE[rr_id].tails
                assert t  # at (re)start, at cred def, Issuer sync_revoc() sets this index in revocation cache

                try:
                    (cred_json, cred_revoc_id, rev_reg_delta_json) = await anoncreds.issuer_create_credential(
                        self.wallet.handle,
                        cred_offer_json,
                        cred_req_json,
                        json.dumps({k: cred_attr_value(cred_attrs[k]) for k in cred_attrs}),
                        t.rr_id,
                        t.reader_handle)
                    rv = (cred_json, cred_revoc_id)
                except IndyError as e:
                    if e.error_code == ErrorCode.AnoncredsRevocationRegistryFullError:
                        (tag, rr_size) = Tails.next_tag(self._dir_tails, cd_id)
                        rr_id = rev_reg_id(cd_id, tag)
                        await self._create_rev_reg(rr_id, rr_size)
                        REVO_CACHE[rr_id]._tails = await Tails(self._dir_tails, cd_id).open()
                        return await self.create_cred(cred_offer_json, cred_req_json, cred_attrs)  # should be ok now
                    else:
                        logger.debug('Issuer.create_cred: <!<  cannot create cred, indy error code {}'.format(
                            e.error_code))
                        raise
                else:
                    rre_req_json = await ledger.build_revoc_reg_entry_request(
                        self.did,
                        t.rr_id,
                        'CL_ACCUM',
                        rev_reg_delta_json)
                    await self._sign_submit(rre_req_json)
        else:
            try:
                (cred_json, _, _) = await anoncreds.issuer_create_credential(
                    self.wallet.handle,
                    cred_offer_json,
                    cred_req_json,
                    json.dumps({k: cred_attr_value(cred_attrs[k]) for k in cred_attrs}),
                    None,
                    None)
                rv = (cred_json, _)
            except IndyError as e:
                logger.debug('Issuer.create_cred: <!<  cannot create cred, indy error code {}'.format(
                    e.error_code))
                raise

        logger.debug('Issuer.create_cred: <<< {}'.format(rv))
        return rv

    async def revoke_cred(self, rr_id: str, cr_id) -> int:
        """
        Revoke credential that input revocation registry identifier and
        credential revocation identifier specify.

        Return (epoch seconds) time of revocation.

        Raise AbsentTailsFile if no tails file is available for input
        revocation registry identifier. Raise BadRevocation if issuer cannot
        revoke specified credential for any other reason (e.g., did not issue it,
        already revoked it).

        :param rr_id: revocation registry identifier
        :param cr_id: credential revocation identifier
        :return: time of revocation, in epoch seconds
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.revoke_cred: >>> rr_id: {}, cr_id: {}'.format(rr_id, cr_id))

        tails_reader_handle = (await Tails(
            self._dir_tails,
            *rev_reg_id2cred_def_id__tag(rr_id)).open()).reader_handle
        try:
            rrd_json = await anoncreds.issuer_revoke_credential(
                self.wallet.handle,
                tails_reader_handle,
                rr_id,
                cr_id)
        except IndyError as e:
            logger.debug(
                'Issuer.revoke_cred: <!< Could not revoke revoc reg id {}, cred rev id {}: indy error code {}'.format(
                    rr_id,
                    cr_id,
                    e.error_code))
            raise BadRevocation('Could not revoke revoc reg id {}, cred rev id {}: indy error code {}'.format(
                    rr_id,
                    cr_id,
                    e.error_code))

        rre_req_json = await ledger.build_revoc_reg_entry_request(self.did, rr_id, 'CL_ACCUM', rrd_json)
        resp_json = await self._sign_submit(rre_req_json)
        resp = json.loads(resp_json)

        rv = resp['result']['txnTime']
        logger.debug('Issuer.revoke_cred: <<< {}'.format(rv))
        return rv


class HolderProver(_BaseAgent):
    """
    Mixin for agent acting in the role of w3c Holder and indy-sdk Prover.
    A Holder holds credentials; a Prover produces proof for credentials.
    """

    def __init__(self, wallet: Wallet, cfg: dict = None) -> None:
        """
        Initializer for HolderProver agent. Retain input parameters; do not open wallet.

        :param wallet: wallet for agent use
        :param cfg: configuration, None for default with no endpoint and proxy-relay=False; e.g.,
            ::
            {
                'endpoint': 'http://127.0.0.1:8808/api/v0',
                'proxy-relay': True
            }
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.__init__: >>> wallet: {}, cfg: {}'.format(wallet, cfg))

        super().__init__(wallet, cfg)
        self._link_secret = None

        self._dir_tails = join(expanduser('~'), '.indy_client', 'tails')
        makedirs(self._dir_tails, exist_ok=True)

        logger.debug('HolderProver.__init__: <<<')

    async def _sync_revoc(self, rr_id: str) -> None:
        """
        Pick up tails file reader handle for input revocation registry identifier.
        Raise AbsentTailsFile for missing corresponding tails file.

        :param rr_id: revocation registry identifier
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver._sync_revoc: >>> rr_id: {}'.format(rr_id))

        (cd_id, tag) = rev_reg_id2cred_def_id__tag(rr_id)

        if not json.loads(await self.get_cred_def(cd_id)):
            logger.debug(
                'HolderProver._sync_revoc: <!< corrupt tails directory {} may pertain to another ledger'.format(
                    self._dir_tails))
            raise AbsentCredDef('Corrupt tails directory {} may pertain to another ledger'.format(self._dir_tails))

        with REVO_CACHE.lock:
            revo_cache_entry = REVO_CACHE.get(rr_id, None)
            t = revo_cache_entry.tails if revo_cache_entry else None
            if t is None:  #  it's not yet set in cache
                try:
                    t = await Tails(self._dir_tails, cd_id, tag).open()
                except AbsentTailsFile as x:  # get hash from ledger and check for tails file
                    rrdef = json.loads(await self._get_rev_reg_def(rr_id))
                    tails_hash = rrdef['value']['tailsHash']
                    path_tails = join(Tails.dir(self._dir_tails, rr_id), tails_hash)
                    if not isfile(path_tails):
                        logger.debug('HolderProver._sync_revoc: <!< No tails file present at {}'.format(path_tails))
                        raise AbsentTailsFile('No tails file present at {}'.format(path_tails))
                    Tails.associate(self._dir_tails, rr_id, tails_hash)
                    t = await Tails(self._dir_tails, cd_id, tag).open()  # OK now since tails file present

                if revo_cache_entry is None:
                    REVO_CACHE[rr_id] = RevoCacheEntry(None, t)
                else:
                    REVO_CACHE[rr_id]._tails = t

        logger.debug('HolderProver._sync_revoc: <<<')

    def path_tails(self, rr_id: str) -> str:
        """
        Return path to tails file for input revocation registry identifier.

        :param rr_id: revocation registry identifier of interest
        :return: path to tails file for input revocation registry identifier
        """

        return Tails.linked(self._dir_tails, rr_id)

    async def open(self) -> 'HolderProver':
        """
        Explicit entry. Perform ancestor opening operations,
        then synchronize revocation registry to tails directory content.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.open: >>>')

        await super().open()
        for path_rr_id in Tails.links(self._dir_tails):
            await self._sync_revoc(basename(path_rr_id))

        logger.debug('HolderProver.open: <<<')
        return self

    '''
    async def _update_rev_reg_state(self, rr_id: str, cr_id: str, tails: Tails, timestamp: int = None) -> str:
        """
        Get revocation registry state from ledger (or rev reg state cache) by its identifier.
        If input timestamp is an update, update state in cache and return. Otherwise, create
        state and return but do not update cache.

        Log and raise exception on error.

        :param rr_id: (revocation registry) identifier string
            ('<issuer-did>:4:<issuer-did>:3:CL:<schema-seq-no>:CL_ACCUM:<tag>')
        :param cr_id: credential revocation identifier to use in creating initial state if need be
        :param tails: Tails object to use in creating initial state if need be (avoids
            locking revocation cache to get it, obviating deadlock)
        :param timestamp: epoch time of interest
        :return: revocation registry state json as retrieved from ledger,
            empty production '{}' for no such revocation registry state
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver._update_rev_reg_state: >>> rr_id: {}, tails: {}'.format(rr_id, tails))

        timestamp = timestamp or int(time())
        rr_state = None

        rr_def_json = await self._get_rev_reg_def(rr_id)
        if not json.loads(rr_def_json):
            logger.debug('HolderProver._update_rev_reg_state: <!< Rev reg def for {} is not on ledger'.format( 
                rr_id))
            raise AbsentRevRegDef('Rev reg def for {} is not on ledger')

        with REVO_STATE_CACHE.lock:
            if rr_id in REVO_STATE_CACHE:
                logger.info('HolderProver._update_rev_reg_state: rev reg state for {} from cache'.format(rr_id))
                rr_state = REVO_STATE_CACHE[rr_id]
                print('\n\n-- URR -- got rr_state from cache: {}'.format(ppjson(rr_state)))
                rr_state_json = json.dumps(rr_state)

            get_rr_delta_req_json = await ledger.build_get_revoc_reg_delta_request(  # get delta to the present
                self.did,
                rr_id,
                rr_state['timestamp']
                    if rr_state and timestamp > rr_state['timestamp']
                    else None,
                timestamp)
            resp_json = await self._submit(get_rr_delta_req_json)
            resp = json.loads(resp_json)
            if 'result' in resp and 'data' in resp['result'] and 'value' in resp['result']['data']:
                # it's a delta to a moment some time after the rev reg def
                (_, rr_delta_json, ledger_timestamp) = await ledger.parse_get_revoc_reg_delta_response(resp_json)
            else:
                logger.debug(
                    'HolderProver._update_rev_reg_state: <!< Revocation registry {} created in the future'.format(
                        rr_id))
                raise BadRevStateTime(
                    'Revocation registry {} created in the future {}'.format(  
                        rr_id))

            if rr_id in REVO_STATE_CACHE:  # OK since we have the lock
                rv_json = await anoncreds.update_revocation_state(
                    tails.reader_handle,
                    rr_state_json,
                    rr_def_json,
                    rr_delta_json,
                    ledger_timestamp,
                    cr_id)
                print('\n\n-- URR -- updating revo state for rr_id {}, cr_id {}, timestamp {} -> {}: {}'.format(
                    rr_id,
                    cr_id,
                    timestamp,
                    ledger_timestamp,
                    ppjson(rv_json)))
                rr_state = json.loads(rv_json)
                if timestamp > rr_state['timestamp']:
                    REVO_STATE_CACHE[rr_id] = rr_state
            else:
                rv_json = await anoncreds.create_revocation_state(  # create rev reg state to the present
                    tails.reader_handle,
                    rr_def_json,
                    rr_delta_json,
                    ledger_timestamp,
                    cr_id)
                print('\n\n-- URR -- created revo state for rr_id {}, cr_id {}, timestamp {} -> {}: {}'.format(
                    rr_id,
                    cr_id,
                    timestamp,
                    ledger_timestamp,
                    ppjson(rv_json)))
                REVO_STATE_CACHE[rr_id] = json.loads(rv_json)

        logger.debug('HolderProver._update_rev_reg_state: <<< {}'.format(rv_json))
        return rv_json
    '''

    def rev_regs(self) -> list:
        """
        Return list of revocation registry identifiers for which HolderProver has tails files.

        :return: list of revocation registry identifiers for which HolderProver has tails files
        """

        return [basename(f) for f in Tails.links(self._dir_tails)]

    async def create_link_secret(self, link_secret: str) -> None:
        """
        Create link secret used in proofs by HolderProver.

        Raise any IndyError causing failure to set link secret in wallet.

        :param link_secret: label for link secret; indy-sdk uses label to generate link secret
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_link_secret: >>> link_secret: {}'.format(link_secret))

        try:
            await anoncreds.prover_create_master_secret(self.wallet.handle, link_secret)
        except IndyError as e:
            if e.error_code == ErrorCode.AnoncredsMasterSecretDuplicateNameError:
                logger.info('HolderProver did not create link secret - it already exists')
            else:
                logger.debug(
                    'HolderProver.create_link_secret: <!<  cannot create link secret {}, indy error code {}'.format(
                        self.wallet.name,
                        e.error_code))
                raise

        self._link_secret = link_secret
        logger.debug('HolderProver.create_link_secret: <<<')

    async def create_cred_req(self, cred_offer_json: str, cred_def_json: str) -> (str, str):
        """
        Create credential request as HolderProver and store in wallet; return credential json and metadata json.

        Raise AbsentLinkSecret if link secret not set.

        :param cred_offer_json: credential offer json
        :param cred_def_json: credential definition json as retrieved from ledger via get_cred_def()
        :return: cred request json and corresponding metadata json as created and stored in wallet
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_cred_req: >>> cred_offer_json: {}, cred_def_json: {}'.format(
            cred_offer_json,
            cred_def_json))

        if self._link_secret is None:
            logger.debug('HolderProver.create_cred_req: <!< link secret not set')
            raise AbsentLinkSecret('Link secret is not set')

        # Check that ledger has schema on ledger where cred def expects - in case of pool reset with extant wallet
        schema_seq_no = int(json.loads(cred_def_json)['schemaId'])
        schema_json = await self.get_schema(schema_seq_no)  # update schema cache en passant if need be
        schema = json.loads(schema_json)
        if not schema:
            logger.debug(
                'HolderProver.create_cred_req: <!< absent schema@#{}, cred req may pertain to another ledger'.format(
                    schema_seq_no))
            raise AbsentSchema('Absent schema@#{}, cred req may pertain to another ledger'.format(schema_seq_no))
        (cred_req_json, cred_req_metadata_json) = await anoncreds.prover_create_credential_req(
            self.wallet.handle,
            self.did,
            cred_offer_json,
            cred_def_json,
            self._link_secret)
        rv = (cred_req_json, cred_req_metadata_json)

        logger.debug('HolderProver.create_cred_req: <<< {}'.format(rv))
        return rv

    async def store_cred(self, cred_json: str, cred_req_metadata_json) -> str:
        """
        Store cred in wallet as HolderProver, return its credential identifier as created in wallet.

        Raise AbsentTailsFile if tails file not available for revocation registry for input credential.

        :param cred_json: credential json as HolderProver created
        :param cred_req_metadata_json: credential request metadata as HolderProver created via create_cred_req()
        :return: credential identifier within wallet
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.store_cred: >>> cred_json: {}, cred_req_metadata_json: {}'.format(
            cred_json,
            cred_req_metadata_json))

        cred = json.loads(cred_json)
        cred_def_json = await self.get_cred_def(cred['cred_def_id'])
        rr_id = cred['rev_reg_id']
        rrdef_json = None
        if rr_id:
            await self._sync_revoc(rr_id)
            rrdef_json = await self._get_rev_reg_def(rr_id)

        rv = await anoncreds.prover_store_credential(
            self.wallet.handle,
            None,  # cred_id, let indy-sdk generate random uuid
            cred_req_metadata_json,
            cred_json,
            cred_def_json,
            rrdef_json)

        logger.debug('HolderProver.store_cred: <<< {}'.format(rv))
        return rv

    async def get_creds_display_coarse(self, filt: dict = None) -> str:
        """
        Return human-readable credentials from wallet by input filter for
        schema identifier and/or credential definition identifier components;
        return all credentials for no filter.

        :param filt: filter for credentials; i.e.,
            ::
            {
                "schema_id": string,  # optional
                "schema_issuer_did": string,  # optional
                "schema_name": string,  # optional
                "schema_version": string,  # optional
                "issuer_did": string,  # optional
                "cred_def_id": string  # optional
            }
        :return: credentials json list; i.e.,
            ::
            [{
                "referent": string,  # credential identifier in the wallet
                "attrs": {
                    "attr1" : {"raw": "value1", "encoded": "value1_as_int" },
                    "attr2" : {"raw": "value2", "encoded": "value2_as_int" },
                    ...
                }
                "schema_id": string,
                "cred_def_id": string,
                "rev_reg_id": Optional<string>,
                "cred_rev_id": Optional<string>
            }]
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_creds_display_coarse: >>> filt: {}'.format(filt))

        rv_json = await anoncreds.prover_get_credentials(self.wallet.handle, json.dumps(filt or {}))
        logger.debug('HolderProver.get_creds_display_coarse: <<< {}'.format(rv_json))
        return rv_json

    async def get_creds(self, proof_req_json: str, filt: dict = None, filt_dflt_incl: bool = False) -> (Set[str], str):
        """
        Get credentials from HolderProver wallet corresponding to proof request and
        filter criteria; return credential identifiers from wallet and credentials json.
        Return empty set and empty production for no such credentials.

        :param proof_req_json: proof request json as Verifier creates; has entries for proof request's
            nonce, name, and version; plus credential's requested attributes, requested predicates. I.e.,
            ::
            {
                'nonce': string,  # indy-sdk makes no semantic specification on this value
                'name': string,  # indy-sdk makes no semantic specification on this value
                'version': numeric-string,  # indy-sdk makes no semantic specification on this value
                'requested_attributes': {
                    '<attr_uuid>': {  # aka attr_referent, a proof-request local identifier
                        'name': string,  # attribute name (matches case- and space-insensitively)
                        'restrictions' [  # optional
                            {
                                "schema_id": string,  # optional
                                "schema_issuer_did": string,  # optional
                                "schema_name": string,  # optional
                                "schema_version": string,  # optional
                                "issuer_did": string,  # optional
                                "cred_def_id": string  # optional
                            },
                            {
                                ...  # if more than one restriction given, combined disjunctively (i.e., via OR)
                            }
                        ],
                        'non_revoked': {  # optional - indy-sdk ignores when getting creds from wallet
                            'from': int,  # optional, epoch seconds
                            'to': int  # optional, epoch seconds
                        }
                    },
                    ...
                },
                'requested_predicates': {
                    '<pred_uuid>': {  # aka predicate_referent, a proof-request local predicate identifier
                        'name': string,  # attribute name (matches case- and space-insensitively)
                        'p_type': '>=',
                        'p_value': int,  # predicate value
                        'restrictions': [  # optional
                            {
                                "schema_id": string,  # optional
                                "schema_issuer_did": string,  # optional
                                "schema_name": string,  # optional
                                "schema_version": string,  # optional
                                "issuer_did": string,  # optional
                                "cred_def_id": string  # optional
                            },
                            {
                                ...  # if more than one restriction given, combined disjunctively (i.e., via OR)
                            }
                        ],
                        'non_revoked': {  # optional - indy-sdk ignores when getting creds from wallet
                            'from': int,  # optional, epoch seconds
                            'to': int  # optional, epoch seconds
                        }
                    },
                    ...
                },
                'non_revoked': {  # optional - indy-sdk ignores when getting creds from wallet
                    'from': Optional<int>,
                    'to': Optional<int>
                }
            }
        :param filt: filter for matching attribute-value pairs and predicates;
            dict mapping each schema identifier to dict (specify empty dict for no filter)
            mapping attributes to values to match or compare. E.g.,
            ::
            {
                'Vx4E82R17q...:2:friendlies:1.0': {
                    'attr-match': {
                        'name': 'Alex',
                        'sex': 'M',
                        'favouriteDrink': None
                    },
                    'pred-match': [  # if both attr-match and pred-match present, combined conjunctively (i.e., via AND)
                        {
                            'attr' : 'favouriteNumber',
                            'pred-type': '>=',
                            'value': 10
                        },
                        {  # if more than one predicate present, combined conjunctively (i.e., via AND)
                            'attr' : 'score',
                            'pred-type': '>=',
                            'value': 100
                        },
                    ]
                },
                'R17v42T4pk...:2:tombstone:2.1': {
                    'attr-match': {
                        'height': 175,
                        'birthdate': '1975-11-15'  # combined conjunctively (i.e., via AND)
                    }
                },
                ...
            }
        :param: filt_dflt_incl: whether to include (True) all attributes for schema that filter does not identify
            or to exclude (False) all such attributes
        :return: tuple with (set of referents, creds json for input proof request);
            empty set and empty production for no such credential
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_creds: >>> proof_req_json: {}, filt: {}'.format(proof_req_json, filt))

        if filt is None:
            filt = {}
        rv = None
        creds_json = await anoncreds.prover_get_credentials_for_proof_req(self.wallet.handle, proof_req_json)
        creds = json.loads(creds_json)
        cred_ids = set()

        if filt:
            for s_id in filt:
                schema = json.loads(await self.get_schema(schema_key(s_id)))
                if not schema:
                    logger.warning('HolderProver.get_creds: ignoring filter criterion, no schema on {}'.format(s_id))
                    filt.pop(s_id)

        for attr_uuid in creds['attrs']:
            for candidate in creds['attrs'][attr_uuid]:  # candidate is a dict in a list of dicts
                cred_info = candidate['cred_info']
                if filt:
                    cred_s_id = cred_info['schema_id']
                    if filt_dflt_incl and cred_s_id not in filt:
                        cred_ids.add(cred_info['referent'])
                        continue
                    if cred_s_id in filt and 'attr-match' in filt[cred_s_id]:
                        if not {k: str(filt[cred_s_id]['attr-match'][k])
                                for k in filt[cred_s_id]['attr-match']}.items() <= cred_info['attrs'].items():
                            continue
                    if cred_s_id in filt and 'pred-match' in filt[cred_s_id]:
                        try:
                            if any((pred_match['attr'] not in cred_info['attrs']) or
                                (int(cred_info['attrs'][pred_match['attr']]) < pred_match['value'])
                                    for pred_match in filt[cred_s_id]['pred-match']):
                                continue
                        except ValueError:
                            # int conversion failed - reject candidate
                            continue
                    cred_ids.add(cred_info['referent'])
                else:
                    cred_ids.add(cred_info['referent'])

        if filt:
            creds = json.loads(prune_creds_json(creds, cred_ids))

        rv = (cred_ids, json.dumps(creds))
        logger.debug('HolderProver.get_creds: <<< {}'.format(rv))
        return rv

    async def get_creds_by_id(self, proof_req_json: str, cred_ids: set) -> str:
        """
        Get creds structure from HolderProver wallet by credential identifiers.

        :param proof_req_json: proof request as per get_creds() above
        :param cred_ids: set of credential identifiers of interest
        :return: json with cred(s) for input credential identifier(s)
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_creds_by_id: >>> proof_req_json: {}, cred_ids: {}'.format(
            proof_req_json,
            cred_ids))

        creds_json = await anoncreds.prover_get_credentials_for_proof_req(self.wallet.handle, proof_req_json)

        # retain only creds of interest: find corresponding referents
        rv_json = prune_creds_json(json.loads(creds_json), cred_ids)
        logger.debug('HolderProver.get_cred_by_referent: <<< {}'.format(rv_json))
        return rv_json

    async def create_proof(self, proof_req: dict, creds: dict, requested_creds: dict) -> str:
        """
        Create proof as HolderProver.

        Raise:
            * AbsentLinkSecret if link secret not set
            * CredentialFocus on attempt to create proof on no creds or multiple creds for a credential definition
            * AbsentTailsFile if missing required tails file
            * BadRevStateTime if a timestamp for a revocation registry state in the proof request
              occurs before revocation registry creation
            * IndyError for any other indy-sdk error.

        :param proof_req: proof request as per get_creds() above
        :param creds: credentials to prove
        :param requested_creds: data structure with self-attested attribute info, requested attribute info
            and requested predicate info, assembled from get_creds() and filtered for content of interest. I.e.,
            ::
            {
                'self_attested_attributes': {},
                'requested_attributes': {
                    'attr0_uuid': {
                        'cred_id': string,
                        'timestamp': integer,  # for revocation state
                        'revealed': bool
                    },
                    ...
                },
                'requested_predicates': {
                    'predicate0_uuid': {
                        'cred_id': string,
                        'timestamp': integer  # for revocation state
                    }
                }
            }
        :return: proof json
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_proof: >>> proof_req: {}, creds: {}, requested_creds: {}'.format(
                proof_req,
                creds,
                requested_creds))

        if self._link_secret is None:
            logger.debug('HolderProver.create_proof: <!< link secret not set')
            raise AbsentLinkSecret('Link secret is not set')

        x_uuids = [attr_uuid for attr_uuid in creds['attrs'] if len(creds['attrs'][attr_uuid]) != 1]
        if x_uuids:
            logger.debug('HolderProver.create_proof: <!< creds specification out of focus (non-uniqueness)')
            raise CredentialFocus('Proof request requires unique cred per attribute; violators: {}'.format(x_uuids))

        '''
        to_default = proof_req.get('non_revoked', {}).get('to', 0)
        c_id2to = {}  # credential identifier to max timestamp of interest
        if requested_creds:
            for cred in {**requested_cred['requested_attributes'], **requested_creds['requested_predicates']}.values():
                if 'timestamp' in cred:
                    (c_id, timestamp) = (cred['cred_id'], cred['timestamp'])
                    c_id2to[c_id]] = max(timestamp, c_id2to.get(c_id, to_default))
        '''

        s_id2schema = {}  # schema identifier to schema
        cd_id2cred_def = {}  # credential definition identifier to credential definition
        rr_id2interval = {}  # revocation registry of interest to non-revocation interval of interest (or None)
        rr_id2cr_id = {}  # revocation registry of interest to credential revocation identifier
        for referents in {**creds['attrs'], **creds['predicates']}.values():
            interval = referents[0].get('interval', None)
            cred_info = referents[0]['cred_info']
            s_id = cred_info['schema_id']
            if s_id not in s_id2schema:
                s_key = schema_key(s_id)
                schema = json.loads(await self.get_schema(s_key))  # add to cache en passant
                if not schema:
                    logger.debug(
                        'HolderProver.create_proof: <!< absent schema {}, proof req may pertain to another ledger'
                            .format(s_id))
                    raise AbsentSchema(
                        'Absent schema {}, proof req may pertain to another ledger'.format(s_id))
                s_id2schema[s_id] = schema

            cd_id = cred_info['cred_def_id']
            if cd_id not in cd_id2cred_def:
                cred_def = json.loads(await self.get_cred_def(cd_id))  # add to cache en passant
                if not cred_def:
                    logger.debug('HolderProver.create_proof: <!< absent cred def for id {}'.format(cd_id))
                    raise AbsentCredDef('Absent cred def for id {}'.format(cd_id))
                cd_id2cred_def[cd_id] = cred_def

            rr_id = cred_info['rev_reg_id']
            if rr_id:
                await self._sync_revoc(rr_id)  # link tails file to its rr_id if it's new
                if interval:
                    if rr_id in rr_id2interval:
                        rr_id2interval[rr_id]['from'] = min(
                            rr_id2interval[rr_id]['from'] or 0,
                            interval['from'] or 0) or None
                        rr_id2interval[rr_id]['to'] = max(rr_id2interval[rr_id]['to'], interval['to'])
                        if rr_id2interval[rr_id]['to'] > int(time()):
                            logger.debug(
                                'HolderProver.create_proof: <!< interval to {} for rev reg {} is in the future'.format(
                                    rr_id2interval[rr_id]['to'],
                                    rr_id))
                            raise BadRevStateTime(
                                'Revocation registry {} created after requested interval {}'.format(  
                                    rr_id,
                                    rr_id2interval[rr_id]))
                    else:
                        rr_id2interval[rr_id] = interval
                elif 'revocation' in cd_id2cred_def[cd_id]['value']:
                    logger.debug(
                        'HolderProver.create_proof: <!< creds on cred def id {} missing non-revocation interval'.format(
                            cd_id))
                    raise AbsentInterval('Creds on cred def id {} missing non-revocation interval'.format(cd_id))
                if rr_id in rr_id2cr_id:
                    continue
                rr_id2cr_id[rr_id] = cred_info['cred_rev_id']

        rr_id2rev_state = {}  # revocation registry identifier to its state
        for rr_id in rr_id2interval:
            revo_cache_entry = REVO_CACHE.get(rr_id, None)
            tails = revo_cache_entry.tails if revo_cache_entry else None
            if tails is None:  # missing tails file
                logger.debug(
                    'HolderProver.create_proof: <!< missing tails file for rev reg id {}'.format(resp['reason']))
                raise AbsentTailsFile('Missing tails file for rev reg id {}'.format(rr_id))
            rr_def_json = await self._get_rev_reg_def(rr_id)
            '''
            # cache doesn't work well: future request could backdate current one, and updating to backdate doesn't work
            rr_state_json = await self._update_rev_reg_state(rr_id, rr_id2cr_id[rr_id], t, rr_id2interval[rr_id]['to'])
            '''
            get_rr_delta_req_json = await ledger.build_get_revoc_reg_delta_request(
                self.did,
                rr_id,
                None, # rr_id2rev_state[rr_id]['timestamp']
                    # if rr_state and timestamp > rr_id2rev_state[rr_id]['timestamp']
                    # else None,
                rr_id2interval[rr_id]['to'])
            resp_json = await self._submit(get_rr_delta_req_json)
            resp = json.loads(resp_json)
            if 'result' in resp and 'data' in resp['result'] and 'value' in resp['result']['data']:
                # it's a delta to a moment some time after the rev reg def
                (_, rr_delta_json, ledger_timestamp) = await ledger.parse_get_revoc_reg_delta_response(resp_json)
            else:
                logger.debug(
                    'HolderProver._update_rev_reg_state: <!< Revocation registry {} created in the future'.format(
                        rr_id))
                raise BadRevStateTime(
                    'Revocation registry {} created in the future'.format(  
                        rr_id))
            rr_state_json = await anoncreds.create_revocation_state(
                tails.reader_handle,
                rr_def_json,
                rr_delta_json,
                ledger_timestamp,
                rr_id2cr_id[rr_id])
            '''
            rr_state_json = await anoncreds.update_revocation_state(
                tails.reader_handle,
                rr_state_json,
                rr_def_json,
                rr_delta_json,
                ledger_timestamp,
                rr_id2cr_id[rr_id])
            '''

            '''
                ledger_timestamp: json.loads(rr_state_json)
            '''
            rr_id2rev_state[rr_id] = {
                rr_id2interval[rr_id]['to']: json.loads(rr_state_json)
            }
        print('\n\n!! HP.CP !! create_proof: rr_id2revstate {}'.format(ppjson(rr_id2rev_state)))
        rv = await anoncreds.prover_create_proof(
            self.wallet.handle,
            json.dumps(proof_req),
            json.dumps(requested_creds),
            self._link_secret,
            json.dumps(s_id2schema),
            json.dumps(cd_id2cred_def),
            json.dumps(rr_id2rev_state))
        logger.debug('HolderProver.create_proof: <<< {}'.format(rv))
        return rv

    async def reset_wallet(self) -> str:
        """
        Close and delete HolderProver wallet, then create and open a replacement.
        Precursor to revocation, and issuer/filter-specifiable cred deletion.

        Raise AbsentLinkSecret if link secret not set.

        :return: wallet name
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.reset_wallet: >>>')

        if self._link_secret is None:
            logger.debug('HolderProver.reset_wallet: <!< link secret not set')
            raise AbsentLinkSecret('Link secret is not set')

        seed = self.wallet._seed
        wallet_name = self.wallet.name
        wallet_cfg = self.wallet.cfg
        wallet_xtype = self.wallet.xtype
        wallet_creds = self.wallet.creds

        await self.wallet.close()
        await self.wallet.remove()
        self._wallet = await Wallet(self.pool, seed, wallet_name, wallet_xtype, wallet_cfg, wallet_creds).create()
        await self.wallet.open()

        await self.create_link_secret(self._link_secret)  # carry over link secret to new wallet

        rv = self.wallet.name
        logger.debug('HolderProver.reset_wallet: <<< {}'.format(rv))
        return rv


class Verifier(_BaseAgent):
    """
    Mixin for agent acting in the role of Verifier.
    """

    async def verify_proof(self, proof_req: dict, proof: dict) -> str:
        """
        Verify proof as Verifier.

        :param proof_req: proof request as Verifier creates, as per proof_req_json above
        :param proof: proof as HolderProver creates
        :return: json encoded True if proof is valid; False if not
        """

        logger = logging.getLogger(__name__)
        logger.debug('Verifier.verify_proof: >>> proof_req: {}, proof: {}'.format(proof_req, proof))

        s_id2schema = {}
        cd_id2cred_def = {}
        rr_id2rr_def = {}
        rr_id2rr = {}
        proof_ids = proof['identifiers']
        for proof_id in proof_ids:
            # schema
            s_id = proof_id['schema_id']
            if s_id not in s_id2schema:
                s_key = schema_key(s_id)
                schema = json.loads(await self.get_schema(s_key))  # add to cache en passant
                if not schema:
                    logger.debug(
                        'Verifier.verify_proof: <!< absent schema {}, proof req may pertain to another ledger'.format(
                            s_id))
                    raise AbsentSchema(
                        'Absent schema {}, proof req may pertain to another ledger'.format(s_id))
                s_id2schema[s_id] = schema

            # cred def
            cd_id = proof_id['cred_def_id']
            if cd_id not in cd_id2cred_def:
                cred_def = json.loads(await self.get_cred_def(cd_id))  # add to cache en passant
                if not cred_def:
                    logger.debug('Verifier.verify_proof: <!< absent cred def for id {}'.format(cd_id))
                    raise AbsentCredDef('Absent cred def for id {}'.format(cd_id))
                cd_id2cred_def[cd_id] = cred_def

            # rev reg def
            rr_id = proof_id['rev_reg_id']
            if not rr_id:
                continue

            rr_def_json = await self._get_rev_reg_def(rr_id)
            rr_id2rr_def[rr_id] = json.loads(rr_def_json)

            # timestamp
            timestamp = proof_id['timestamp']
            get_rr_req_json = await ledger.build_get_revoc_reg_request(self.did, rr_id, timestamp)
            resp_json = await self._submit(get_rr_req_json)
            (_, rr_json, _) = await ledger.parse_get_revoc_reg_response(resp_json)

            if rr_id not in rr_id2rr:
                rr_id2rr[rr_id] = {}
            rr_id2rr[rr_id][timestamp] = json.loads(rr_json)

        # print('\n\n-- VV -- Verify: rr_id2rr: {}'.format(ppjson(rr_id2rr)))
        rv = json.dumps(await anoncreds.verifier_verify_proof(
            json.dumps(proof_req),
            json.dumps(proof),
            json.dumps(s_id2schema),
            json.dumps(cd_id2cred_def),
            json.dumps(rr_id2rr_def),
            json.dumps(rr_id2rr)))

        logger.debug('Verifier.verify_proof: <<< {}'.format(rv))
        return rv
