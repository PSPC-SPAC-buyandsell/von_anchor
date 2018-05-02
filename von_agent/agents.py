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

from time import time
from typing import Set, Union
from indy import anoncreds, ledger
from indy.error import IndyError, ErrorCode
from von_agent.cache import CRED_DEF_CACHE, SCHEMA_CACHE
from von_agent.codec import cred_attr_value
from von_agent.error import (
    AbsentAttribute,
    AbsentCredDef,
    AbsentMasterSecret,
    AbsentSchema,
    CredentialFocus,
    CorruptWallet)
from von_agent.nodepool import NodePool
from von_agent.util import cred_def_id, ppjson, prune_creds_json, schema_id, SchemaKey, schema_key
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

    async def _sign_submit(self, req_json: str) -> str:
        """
        Sign and submit (json) request to ledger; return (json) result.

        Raise CorruptWallet if existing wallet's pool is no longer extant,
        or any other responsible indy-sdk exception on failure.

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
                    '_AgentCore._sign_submit: <!<  cannot sign request for ledger, indy error code {}'.format(
                        self.wallet.name))
                raise e

        logger.debug('_AgentCore._sign_submit: <<< {}'.format(rv_json))
        return rv_json

    async def get_nym(self, did: str) -> str:
        """
        Get json cryptonym (including current verification key) for input (agent) DID from ledger.

        :param did: DID of cryptonym to fetch
        :return: cryptonym json
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.get_nym: >>> did: {}'.format(did))

        rv = json.dumps({})
        get_nym_req = await ledger.build_get_nym_request(
            self.did,
            did)
        resp_json = await ledger.submit_request(self.pool.handle, get_nym_req)
        await asyncio.sleep(0)

        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json:
            rv = data_json

        logger.debug('_AgentCore.get_nym: <<< {}'.format(rv))
        return rv

    async def get_schema(self, index: Union[SchemaKey, int]) -> str:
        """
        Get schema from ledger by sequence number or schema key (origin DID, name, version).
        Return empty production {} for no such schema.

        Retrieve the schema from the agent's schema cache if it has it; cache it
        en passant if it does not (and if there is a corresponding schema on the ledger).

        :param schema_id: schema key (origin DID, name, version) or sequence number
        :return: schema json, parsed from ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.get_schema: >>> index: {}'.format(index))
        # print('\n\n.. get-schema 0 .. on ({}) {}'.format(type(index), index))

        rv = json.dumps({})
        with SCHEMA_CACHE.lock:
            if SCHEMA_CACHE.contains(index):
                # print('\n\n.. get-schema 1 .. cache has {}'.format(index))
                logger.info('_AgentCore.get_schema: got schema {} from schema cache'.format(index))
                rv = SCHEMA_CACHE[index]
                logger.debug('_AgentCore.get_schema: <<< {}'.format(rv))
                return json.dumps(rv)

            if isinstance(index, SchemaKey):
                req_json = await ledger.build_get_schema_request(self.did, schema_id(*index))
                resp_json = await ledger.submit_request(self.pool.handle, req_json)
                await asyncio.sleep(0)

                resp = json.loads(resp_json)
                if ('op' in resp) and (resp['op'] in ('REQNACK', 'REJECT')):
                    logger.error('_AgentCore.get_schema: {}'.format(resp['reason']))
                    # print('\n\n.. get-schema X .. rejected: {}'.format(resp['reason']))
                elif 'result' in resp and resp['result'].get('seqNo', None) is None:
                    logger.info('_AgentCore.get_schema: no schema for {} on ledger'.format(index))
                    # print('\n\n.. get-schema 3 .. no schema for {} on ledger'.format(index))
                else:
                    (s_id, rv) = await ledger.parse_get_schema_response(resp_json)
                    SCHEMA_CACHE[index] = json.loads(rv)  # schema cache indexes by both txn# and schema key en passant
                    logger.info('_AgentCore.get_schema: got schema {} from ledger'.format(index))
                    # print('\n\n.. get-schema 4 .. got schema for {} from ledger'.format(index))

            elif isinstance(index, int):
                txn_json = await self.process_get_txn(index)
                txn = json.loads(txn_json)
                # print('\n\n.. get-schema 5 .. int {}, txn {}'.format(index, ppjson(txn)))
                if txn.get('type', None) == '101':  # {} for no such txn; 101 marks indy-sdk schema txn type
                    # print('\n\n.. get-schema 6 .. prepare for inception')
                    rv = await self.get_schema(SchemaKey(
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

        logger.debug('_AgentCore.get_schema: <<< {}'.format(rv))
        return rv

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

    async def get_cred_def(self, cred_def_id: str) -> str:
        """
        Get credential definition from ledger by its identifier. Return empty production {} for no
        such credential definition, logging any IndyError condition on bad request.

        Retrieve the credential definition from the agent's credential definition cache if it has it; cache it
        en passant if it does not (and if there is a corresponding credential definition on the ledger).

        :param cred_def_id: (credential definition) identifier string ('<issuer-did>:3:CL:<schema-seq-no>')
        :return: credential definition json as retrieved from ledger,
            empty production {} for no such credential definition
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.get_cred_def: >>> cred_def_id: {}'.format(cred_def_id))
        # print('\n\n// get-cred-def 0 // {}'.format(cred_def_id))

        rv = json.dumps({})

        with CRED_DEF_CACHE.lock:
            if cred_def_id in CRED_DEF_CACHE:
                logger.info('_BaseAgent.get_cred_def: got cred def for {} from cache'.format(cred_def_id))
                rv = json.dumps(CRED_DEF_CACHE[cred_def_id])
                logger.debug('_BaseAgent.get_cred_def: <<< {}'.format(rv))
                return rv

            try:
                req_json = await ledger.build_get_cred_def_request(self.did, cred_def_id)
            except IndyError as e:
                if e.error_code == ErrorCode.CommonInvalidStructure:
                    logger.debug('_BaseAgent.get_cred_def: <!< bogus credential definition {}'.format(cred_def_id))
                    return rv
                else:
                    logger.debug(
                        '_BaseAgent.get_cred_def: <!< could not build cred def request; indy error code {}'.format(
                            e.error_code))
                    raise

            resp_json = await ledger.submit_request(self.pool.handle, req_json)
            await asyncio.sleep(0)

            resp = json.loads(resp_json)
            # print('\n\n// get-cred-def 2 // {} -> {}'.format(cred_def_id, ppjson(resp)))
            if ('op' in resp) and (resp['op'] in ('REQNACK', 'REJECT')):
                # print('\n\n// get-cred-def X //')
                logger.error('_BaseAgent.get_cred_def: {}'.format(resp['reason']))
            elif 'result' in resp and 'data' in resp['result'] and resp['result']['data']:
                (cd_id, rv) = await ledger.parse_get_cred_def_response(resp_json)
                CRED_DEF_CACHE[cred_def_id] = json.loads(rv)
                # print('\n\n@@ GET-CRED-DEF @@ GOT CRED_DEF {} -> {}, {}'.format(cred_def_id, cd_id, ppjson(rv)))
                logger.info('_BaseAgent.get_cred_def: got cred def {} from ledger'.format(cred_def_id))
            else:
                logger.info('_BaseAgent.get_cred_def: ledger has no cred def for cred-def-id {}'.format(cred_def_id))

        logger.debug('_BaseAgent.get_cred_def: <<< {}'.format(rv))
        return rv

    async def process_get_txn(self, txn: int) -> str:
        """
        Take a request to find a transaction on the distributed ledger by its sequence number.

        :param txn: transaction number
        :return: json sequence number of transaction, null for no match
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.process_get_txn: >>> txn: {}'.format(txn))

        rv = json.dumps({})
        req_json = await ledger.build_get_txn_request(self.did, txn)
        resp = json.loads(await ledger.submit_request(self.pool.handle, req_json))
        await asyncio.sleep(0)

        if ('op' in resp) and (resp['op'] in ('REQNACK', 'REJECT')):
            logger.error('_BaseAgent.process_get_txn: {}'.format(resp['reason']))
        else:
            rv = json.dumps(resp['result']['data'] or {})

        logger.debug('_BaseAgent.process_get_txn: <<< {}'.format(rv))
        return rv

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
        Method for trust anchor to send input agent's cryptonym (including DID and current verification key) to ledger.

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

        :param schema_data_json: schema data json with name, version, attribute names; e.g.,:
            {
                'name': 'my-schema',
                'version': '1.234',
                'attr_names': ['favourite_drink', 'height', 'last_visit_date']
            }
        :return: schema json as written to ledger, empty production for None
        """

        logger = logging.getLogger(__name__)
        logger.debug('Origin.send_schema: >>> schema_data_json: {}'.format(schema_data_json))

        rv = json.dumps({})
        schema_data = json.loads(schema_data_json)
        s_key = schema_key(schema_id(self.did, schema_data['name'], schema_data['version']))
        if json.loads(await self.get_schema(s_key)):
            logger.error('Schema {} version {} already exists on ledger for origin-did {}: not sending'.format(
                schema_data['name'],
                schema_data['version'],
                self.did))
        else:
            (_, schema_json) = await anoncreds.issuer_create_schema(
                self.did,
                schema_data['name'],
                schema_data['version'],
                json.dumps(schema_data['attr_names']))
            req_json = await ledger.build_schema_request(self.did, schema_json)
            resp_json = await self._sign_submit(req_json)
            resp = json.loads(resp_json)
            if ('op' in resp) and (resp['op'] in ('REQNACK', 'REJECT')):
                logger.error('_BaseAgent.send_schema: {}'.format(resp['reason']))
            else:
                resp_result = (json.loads(resp_json))['result']
                rv = await self.get_schema(schema_key(schema_id(
                    resp_result['identifier'],
                    resp_result['data']['name'],
                    resp_result['data']['version'])))  # adds to cache en passant

        logger.debug('Origin.send_schema: <<< {}'.format(rv))
        return rv

class Issuer(Origin):
    """
    Mixin for agent acting in role of Issuer.

    The current design calls for any issuer to be able to originate its own schema.
    """

    async def send_cred_def(self, schema_json: str) -> str:
        """
        Create a credential definition as Issuer, store it in its wallet, and send it to the ledger.

        Raise any IndyError causing failure to store credential definition.

        :param schema_json: schema as it appears on ledger via get_schema()
        :return: json credential definition as it appears on ledger, empty production for None
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.send_cred_def: >>> schema_json: {}'.format(schema_json))

        schema = json.loads(schema_json)
        # print('\n\n-- SEND-CRED-DEF.0 -- send cred def on schema json {}'.format(ppjson(schema_json)))

        s_id = schema_id(self.did, schema['name'], schema['version'])
        cd_id = cred_def_id(self.did, schema['seqNo'])
        rv = await self.get_cred_def(cd_id)
        # print('\n\n-- SEND-CRED-DEF.1 -- cd_id {}, cred-def-get() -> {}'.format(cd_id, ppjson(rv)))
        if json.loads(rv):
            # TODO: revocation support will definitely change this check
            logger.info(
                'Cred def on schema {} version {} already exists on ledger; Issuer {} not sending another'.format(
                    schema['name'],
                    schema['version'],
                    self.wallet.name))

        # print('\n\n-- SEND-CRED-DEF.2 -- schema_json: {}'.format(ppjson(schema_json)))
        try:
            (_, cred_def_json) = await anoncreds.issuer_create_and_store_credential_def(
                self.wallet.handle,
                self.did,  # issuer DID
                schema_json,
                'tag-0',  # revocation will change this?
                'CL',
                json.dumps({'support_revocation': False}))
            # print('\n\n-- SEND-CRED-DEF.3 -- cred_def_json {}'.format(ppjson(cred_def_json)))
        except IndyError as e:
            # TODO: revocation support may change this check
            if e.error_code == ErrorCode.AnoncredsCredDefAlreadyExistsError:
                if json.loads(rv):
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

        if not json.loads(rv):  # checking the ledger returned no cred def: send it
            req_json = await ledger.build_cred_def_request(self.did, cred_def_json)
            # print('\n\n-- SEND-CRED-DEF.4 -- req_json {}'.format(ppjson(req_json)))
            resp_json = await ledger.sign_and_submit_request(
                self.pool.handle,
                self.wallet.handle,
                self.did,
                req_json)
            await asyncio.sleep(0)

            resp = json.loads(resp_json)
            # print('\n\n-- SEND-CRED-DEF.5 -- {} response {}'.format(s_id, ppjson(resp)))
            if ('op' in resp) and (resp['op'] in ('REQNACK', 'REJECT')):
                # print('  .. 5.0x')
                logger.error('Issuer.send_cred_def: {}'.format(resp['reason']))
            else:
                rv = await self.get_cred_def(cd_id)  # pick up from ledger and parse
                # print('  .. 5.1 get-cred-def picked up rv {}'.format(ppjson(rv)))

        # print('\n\n-- SEND-CRED-DEF.6 -- rv {}'.format(ppjson(rv)))
        logger.debug('Issuer.send_cred_def: <<< {}'.format(rv))
        return rv

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
        # print('  .. {} create-cred-offer cd_id {}'.format(self.wallet.name, cd_id))
        try:
            rv = await anoncreds.issuer_create_credential_offer(self.wallet.handle, cd_id)
        except IndyError as e:
            # print('  .. X indy-sdk-create-offer raised {}'.format(e))
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

    async def create_cred(self, cred_offer_json, cred_req_json: str, cred_attrs: dict) -> (str, str, str):
        """
        Create credential as Issuer out of credential request and dict of key:value (raw, unencoded) entries
        for attributes; return credential, credential revocation identifier, and revocation registry delta.

        :param cred_offer_json: credential offer json as created by Issuer
        :param cred_req_json: credential request json as created by HolderProver
        :param cred_attrs: dict mapping each attribute to its raw value (the operation encodes it); e.g.,
            {
                'favourite_drink': 'martini',
                'height': 180,
                'last_visit_date': '2017-12-31',
                'weaknesses': None
            }
        :return: newly issued credential json, credential revocation identifier, revocation registry delta json
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.create_cred: >>> cred_req_json: {}, cred_attrs: {}'.format(cred_req_json, cred_attrs))

        (cred_json, cred_revoc_id, rev_reg_delta_json) = await anoncreds.issuer_create_credential(
            self.wallet.handle,
            cred_offer_json,
            cred_req_json,
            json.dumps({k: cred_attr_value(cred_attrs[k]) for k in cred_attrs}),
            None,
            None) # TODO revocation will change None values
        rv = (cred_json, cred_revoc_id, rev_reg_delta_json)
        logger.debug('Issuer.create_cred: <<< {}'.format(rv))
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
        :param cfg: configuration, None for default with no endpoint and proxy-relay=False;
            e.g., {
                'endpoint': 'http://127.0.0.1:8808/api/v0',
                'proxy-relay': True
            }
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.__init__: >>> wallet: {}, cfg: {}'.format(wallet, cfg))

        super().__init__(wallet, cfg)
        self._master_secret = None

        logger.debug('HolderProver.__init__: <<<')

    async def create_master_secret(self, master_secret: str) -> None:
        """
        Create master secret used in proofs by HolderProver.

        Raise any IndyError causing failure to set master secret in wallet.

        :param master_secret: label for master secret; indy-sdk uses label to generate master secret
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_master_secret: >>> master_secret: {}'.format(master_secret))

        try:
            await anoncreds.prover_create_master_secret(self.wallet.handle, master_secret)
        except IndyError as e:
            if e.error_code == ErrorCode.AnoncredsMasterSecretDuplicateNameError:
                logger.info('HolderProver did not create master secret - it already exists')
            else:
                logger.debug(
                    'HolderProver.create_master_secret: <!<  cannot create master secret {}, indy error code {}'.format(
                        self.wallet.name,
                        e.error_code))
                raise

        self._master_secret = master_secret
        logger.debug('HolderProver.create_master_secret: <<<')

    async def create_cred_req(self, cred_offer_json: str, cred_def_json: str) -> (str, str):
        """
        Create credential request as HolderProver and store in wallet; return credential json and metadata json.

        Raise AbsentMasterSecret if master secret not set.

        :param cred_offer_json: credential offer json
        :param cred_def_json: credential definition json as retrieved from ledger via get_cred_def()
        :return: cred request json and corresponding metadata json as created and stored in wallet
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_cred_req: >>> cred_offer_json: {}, cred_def_json: {}'.format(
            cred_offer_json,
            cred_def_json))

        if self._master_secret is None:
            logger.debug('HolderProver.create_cred_req: <!< master secret not set')
            raise AbsentMasterSecret('Master secret is not set')

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
            self._master_secret)
        rv = (cred_req_json, cred_req_metadata_json)

        logger.debug('HolderProver.create_cred_req: <<< {}'.format(rv))
        return rv

    async def store_cred(self, cred_def_json: str, cred_json: str, cred_req_metadata_json) -> str:
        """
        Store cred in wallet as HolderProver, return its credential identifier as created in wallet.

        :param cred_def_json: credential definition json
        :param cred_json: credential json as HolderProver created
        :param cred_req_metadata_json: credential request metadata as HolderProver created via create_cred_req()
        :return: credential identifier within wallet
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.store_cred: >>> cred_def_json: {}, cred_json: {}, cred_req_metadata_json: {}'.format(
            cred_def_json,
            cred_json,
            cred_req_metadata_json))

        rv = await anoncreds.prover_store_credential(
            self.wallet.handle,
            None,  # cred_id
            cred_req_metadata_json,
            cred_json,
            cred_def_json,
            None)  # rev_reg_json - TODO: revocation
        logger.debug('HolderProver.store_cred: <<< {}'.format(rv))
        return rv

    async def get_creds_display_coarse(self, filt: dict = None) -> str:
        """
        Return human-readable credentials from wallet by input filter for
        schema identifier and/or credential definition identifier components;
        return all credentials for no filter.

        :param filt: filter for credentials; i.e.,
            {
                "schema_id": string,  # optional
                "schema_issuer_did": string,  # optional
                "schema_name": string,  # optional
                "schema_version": string,  # optional
                "issuer_did": string,  # optional
                "cred_def_id": string  # optional
            }

        :return: credentials json list; i.e.,
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
        logger.debug('HolderProver.get_creds_precis: >>> filt: {}'.format(filt))

        rv = await anoncreds.prover_get_credentials(self.wallet.handle, json.dumps(filt or {}))
        logger.debug('HolderProver.get_creds_precis: <<< {}'.format(rv))
        return rv

    async def get_creds(self, proof_req_json: str, filt: dict = None) -> (Set[str], str):
        """
        Get credentials from HolderProver wallet corresponding to proof request and
        filter criteria; return credential identifiers from wallet and credentials json.
        Return empty set and empty production for no such credentials.

        :param proof_req_json: proof request json as Verifier creates; has entries for proof request's
            nonce, name, and version; plus credential's requested attributes, requested predicates. I.e.,
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
                        'non-revoked': {  # optional
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
                        'non-revoked': {  # optional
                            'from': int,  # optional, epoch seconds
                            'to': int  # optional, epoch seconds
                        }
                    },
                    ...
                },
                'non-revoked': {  # optional; implies that prover must prove non-revocation for each attr
                    'from': Optional<int>,
                    'to': Optional<int>
                }
            }
        :param filt: filter for matching attribute-value pairs and predicates;
            dict mapping each schema identifier to dict (specify empty dict for no filter)
            mapping attributes to values to match or compare. E.g.,
            {
                'Vx4E82R17q...:3:friendlies:1.0': {
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
                'R17v42T4pk...:3:tombstone:2.1': {
                    'attr-match': {
                        'height': 175,
                        'birthdate': '1975-11-15'  # combined conjunctively (i.e., via AND)
                    }
                },
                ...
            }
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

        # print('\n\n-- X.1 -- get-creds got creds {}'.format(ppjson(creds)))
        # retain only creds of interest: find corresponding credential identifiers 

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

    async def get_creds_by_id(self, cred_ids: set, requested_attributes: dict) -> str:
        """
        Get creds structure from HolderProver wallet by credential identifiers.

        :param cred_ids: set of credential identifiers of interest
        :param requested_attributes: requested attrs dict mapping (cred-local) attr-uuids to
            name, restrictions, non-revoked specs for each requested attribute as per get_creds(); e.g.,
            {
                'attr1_uuid': {
                    'name': 'favourite_drink',
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
                        },
                    ],
                    'non-revoked': {  # optional
                        'from': int,  # optional, epoch seconds
                        'to': int  # optional, epoch seconds
                    }
                },
                ...
            }
        :return: json with cred(s) for input credential identifier(s)
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_creds_by_id: >>> cred_ids: {}, requested_attributes: {}'.format(
            cred_ids,
            requested_attributes))

        cred_req_json = json.dumps({
                'nonce': str(int(time() * 1000)),
                'name': 'cred-request',
                'version': '1.0',
                'requested_attributes': requested_attributes,
                'requested_predicates': {}
            })

        creds_json = await anoncreds.prover_get_credentials_for_proof_req(self.wallet.handle, cred_req_json)

        # retain only creds of interest: find corresponding referents
        rv = prune_creds_json(json.loads(creds_json), cred_ids)
        logger.debug('HolderProver.get_cred_by_referent: <<< {}'.format(rv))
        return rv

    async def create_proof(self, proof_req: dict, creds: dict, requested_creds: dict = None) -> str:
        """
        Create proof as HolderProver.

        Raise:
            * AbsentMasterSecret if master secret not set
            * CredentialFocus on attempt to create proof on no creds or multiple creds for a credential definition.

        :param proof_req: proof request as per get_creds() above
        :param creds: credentials to prove
        :param requested_creds: data structure with self-attested attribute info, requested attribute info
            and requested predicate info, assembled from get_creds() and filtered for content of interest. I.e.,
            {
                'self_attested_attributes': {},
                'requested_attributes': {
                    'attr0_uuid': {
                        'cred_id': string,
                        'timestamp': integer,  # optional
                        'revealed': bool
                    },
                    ...
                },
                'requested_predicates': {
                    'predicate0_uuid': {
                        'cred_id': string,
                        'timestamp': integer  # optional
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

        if self._master_secret is None:
            logger.debug('HolderProver.create_proof: <!< master secret not set')
            raise AbsentMasterSecret('Master secret is not set')

        x_uuids = [attr_uuid for attr_uuid in creds['attrs'] if len(creds['attrs'][attr_uuid]) != 1]
        if x_uuids:
            logger.debug('HolderProver.create_proof: <!< creds specification out of focus (non-uniqueness)')
            raise CredentialFocus('Proof request requires unique cred per attribute; violators: {}'.format(x_uuids))

        s_id2schema = {}
        cd_id2cred_def = {}
        for attr_uuid in creds['attrs']:
            cred_info = creds['attrs'][attr_uuid][0]['cred_info']
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

        rv = await anoncreds.prover_create_proof(
            self.wallet.handle,
            json.dumps(proof_req),
            json.dumps(requested_creds),
            self._master_secret,
            json.dumps(s_id2schema),
            json.dumps(cd_id2cred_def),
            json.dumps({}))  # rev_states_json
        logger.debug('HolderProver.create_proof: <<< {}'.format(rv))
        return rv

    async def reset_wallet(self) -> str:
        """
        Close and delete HolderProver wallet, then create and open a replacement.
        Precursor to revocation, and issuer/filter-specifiable cred deletion.

        Raise AbsentMasterSecret if master secret not set.

        :return: wallet name
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.reset_wallet: >>>')

        if self._master_secret is None:
            logger.debug('HolderProver.reset_wallet: <!< master secret not set')
            raise AbsentMasterSecret('Master secret is not set')

        seed = self.wallet._seed
        wallet_name = self.wallet.name
        wallet_cfg = self.wallet.cfg
        wallet_xtype = self.wallet.xtype
        wallet_creds = self.wallet.creds

        await self.wallet.close()
        await self.wallet.remove()
        self._wallet = await Wallet(self.pool, seed, wallet_name, wallet_xtype, wallet_cfg, wallet_creds).create()
        await self.wallet.open()

        await self.create_master_secret(self._master_secret)  # carry over master secret to new wallet

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

        :param proof_req: proof request as Verifier creates - has entries for proof request's
            nonce, name, and version; plus cred's requested attributes and requested predicates; e.g.,
            {
                'nonce': '12345',  # for Verifier info, not HolderProver matching
                'name': 'proof-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attributes': {
                    'attr1_uuid': {
                        'name': 'favourite_drink',
                        'restrictions' [{
                            'schema_id': 'Vx4E82R17q...:friendlies:1.0'
                        }]
                    },
                    'attr2_uuid': {
                        'name': 'height',
                        'restrictions' [{
                            'schema_id': 'R17v42T4pk...:patient-records:2.1'
                        }]
                    },
                    'attr3_uuid': {
                        'name': 'last_visit_date',
                        'restrictions' [{
                            'schema_id': 'R17v42T4pk...:patient-records:2.1'
                        }]
                    }
                },
                'requested_predicates': {
                    'predicate0_uuid': {
                        'name': 'age',
                        'p_type': '>=',
                        'p_value': 18,
                        'restrictions': [{
                            'schema_id': 'R17v42T4pk...:patient-records:2.1'
                        }],
                        'non-revoked': {  # optional
                            'from': 1500000000,  # optional
                            'to': 1600000000  # optional
                        }
                    }
                }
            }
        :param proof: proof as HolderProver creates
        :return: json encoded True if proof is valid; False if not
        """

        logger = logging.getLogger(__name__)
        logger.debug('Verifier.verify_proof: >>> proof_req: {}, proof: {}'.format(proof_req, proof))

        s_id2schema = {}
        cd_id2cred_def = {}
        proof_ids = proof['identifiers']
        for proof_id in proof_ids:
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

            cd_id = proof_id['cred_def_id']
            if cd_id not in cd_id2cred_def:
                cred_def = json.loads(await self.get_cred_def(cd_id))  # add to cache en passant
                if not cred_def:
                    logger.debug('Verifier.verify_proof: <!< absent cred def for id {}'.format(cd_id))
                    raise AbsentCredDef('Absent cred def for id {}'.format(cd_id))
                cd_id2cred_def[cd_id] = cred_def

            # rev_reg_id ...
            # timestamp ...

        # print('\n\n.. s_id2schema {}'.format(ppjson(s_id2schema)))
        # print('\n.. cd_id2cred_def {}'.format(ppjson(cd_id2cred_def)))
        rv = json.dumps(await anoncreds.verifier_verify_proof(
            json.dumps(proof_req),
            json.dumps(proof),
            json.dumps(s_id2schema),
            json.dumps(cd_id2cred_def),
            json.dumps({}),  # rev_reg_defs_json
            json.dumps({})))  # rev_regs_json

        logger.debug('Verifier.verify_proof: <<< {}'.format(rv))
        return rv
