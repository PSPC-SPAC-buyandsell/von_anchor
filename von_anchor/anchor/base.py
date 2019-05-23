"""
Copyright 2017-2019 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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

from typing import Union

from indy import did, ledger
from indy.error import IndyError, ErrorCode

from von_anchor.cache import RevoCacheEntry, CRED_DEF_CACHE, ENDPOINT_CACHE, REVO_CACHE, SCHEMA_CACHE
from von_anchor.error import (
    AbsentCredDef,
    AbsentPool,
    AbsentRecord,
    AbsentRevReg,
    AbsentNym,
    AbsentSchema,
    BadIdentifier,
    BadLedgerTxn,
    ClosedPool,
    CorruptWallet,
    WalletState)
from von_anchor.indytween import Role, SchemaKey
from von_anchor.nodepool import NodePool
from von_anchor.util import ok_cred_def_id, ok_did, ok_rev_reg_id, ok_schema_id, schema_id, schema_key
from von_anchor.wallet import EndpointInfo, Wallet


LOGGER = logging.getLogger(__name__)


class BaseAnchor:
    """
    Base class for common anchor functionality. A VON anchor has a wallet and a
    node pool.  It has a cryptonym and can interact via indy-sdk
    with the distributed ledger that its node pool operates.
    """

    def __init__(self, wallet: Wallet, pool: NodePool = None, **kwargs) -> None:
        """
        Initializer for anchor. Retain wallet and node pool.

        :param wallet: wallet for anchor use
        :param pool: optional node pool for anchor use
        :param kwargs: place holders for super(); implementation ignores
        """

        LOGGER.debug('BaseAnchor.__init__ >>> wallet: %s, pool: %s, kwargs: %s', wallet, pool, kwargs)

        self._wallet = wallet
        self._pool = pool

        LOGGER.debug('BaseAnchor.__init__ <<<')

    @property
    def pool(self) -> NodePool:
        """
        Accessor for node pool.

        :return: node pool
        """

        return self._pool

    @pool.setter
    def pool(self, value: NodePool) -> None:
        """
        Set pool.

        :param value: pool
        """

        self._pool = value

    @property
    def wallet(self) -> Wallet:
        """
        Accessor for wallet.

        :return: wallet
        """

        return self._wallet

    @wallet.setter
    def wallet(self, value: Wallet) -> None:
        """
        Set wallet.

        :param value: wallet
        """

        self._wallet = value

    @property
    def name(self) -> str:
        """
        Accessor for anchor name, from wallet.

        :return: anchor (wallet) name
        """

        return self.wallet.name

    @property
    def did(self) -> str:
        """
        Accessor for anchor DID.

        :return: anchor DID
        """

        return self.wallet.did

    @property
    def verkey(self) -> str:
        """
        Accessor for anchor verification key.

        :return: anchor verification key
        """

        return self.wallet.verkey

    async def __aenter__(self) -> 'BaseAnchor':
        """
        Context manager entry.
        For use in monolithic call opening, using, and closing the anchor.

        :return: current object
        """

        LOGGER.debug('BaseAnchor.__aenter__ >>>')

        rv = await self.open()

        LOGGER.debug('BaseAnchor.__aenter__ <<<')
        return rv

    async def open(self) -> 'BaseAnchor':
        """
        Context manager entry.
        For use when keeping anchor open across multiple calls.

        :return: current object
        """

        LOGGER.debug('BaseAnchor.open >>>')

        # Do not open pool independently: let relying party decide when to go on-line and off-line
        # Do not open wallet independently: allow for sharing open wallet over many anchor lifetimes

        LOGGER.debug('BaseAnchor.open <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit.
        For use in monolithic call opening, using, and closing the anchor.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        LOGGER.debug('BaseAnchor.__aexit__ >>> exc_type: %s, exc: %s, traceback: %s', exc_type, exc, traceback)

        await self.close()

        LOGGER.debug('BaseAnchor.__exit__ <<<')

    async def close(self) -> None:
        """
        Explicit exit.
        For use when keeping anchor open across multiple calls.
        """

        LOGGER.debug('BaseAnchor.close >>>')

        # Do not close wallet independently: allow for sharing open wallet over many anchor lifetimes
        # Do not close pool independently: let relying party decide when to go on-line and off-line

        LOGGER.debug('BaseAnchor.close <<<')

    async def reseed(self, seed: str = None) -> None:
        """
        Rotate key for VON anchor: generate new key, submit to ledger, update wallet.
        Raise WalletState if wallet is currently closed.

        :param seed: new seed for ed25519 key pair (default random)
        """

        LOGGER.debug('BaseAnchor.reseed >>> seed: [SEED]')

        verkey = await self.wallet.reseed_init(seed)
        req_json = await ledger.build_nym_request(
            self.did,
            self.did,
            verkey,
            self.name,
            (await self.get_nym_role()).token())
        await self._sign_submit(req_json)
        await self.wallet.reseed_apply()

        LOGGER.debug('BaseAnchor.reseed <<<')

    async def get_nym(self, target_did: str = None) -> str:
        """
        Get json cryptonym (including current verification key) for input (anchor) DID from ledger.
        Return empty production {} if the ledger has no such cryptonym.

        Raise BadLedgerTxn on failure. Raise WalletState if target DID is default (own DID) value but
        wallet does not have it (neither created nor opened since initialization).

        :param target_did: DID of cryptonym to fetch (default own DID)
        :return: cryptonym json
        """

        LOGGER.debug('BaseAnchor.get_nym >>> target_did: %s', target_did)

        if target_did and not ok_did(target_did):
            LOGGER.debug('BaseAnchor.get_nym <!< Bad DID %s', target_did)
            raise BadIdentifier('Bad DID {}'.format(target_did))

        if not (target_did or self.did):
            LOGGER.debug('BaseAnchor.get_nym <!< Bad wallet state: DID for %s unavailable', self.name)
            raise WalletState('Bad wallet state: DID for {} unavailable'.format(self.name))

        rv = json.dumps({})
        get_nym_req = await ledger.build_get_nym_request(self.did, target_did or self.did)
        resp_json = await self._submit(get_nym_req)

        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json:
            rv = data_json

        LOGGER.debug('BaseAnchor.get_nym <<< %s', rv)
        return rv

    async def get_nym_role(self, target_did: str = None) -> Role:
        """
        Return the cryptonym role for input did from the ledger - note that this may exceed
        the role of least privilege for the class.

        Raise AbsentNym if current anchor has no cryptonym on the ledger, or WalletState if current DID unavailable.

        :param target_did: DID of cryptonym role to fetch (default own DID)
        :return: identifier for current cryptonym role on ledger
        """

        LOGGER.debug('BaseAnchor.get_nym_role >>> target_did: %s', target_did)

        nym = json.loads(await self.get_nym(target_did))
        if not nym:
            LOGGER.debug('BaseAnchor.get_nym_role <!< Ledger has no cryptonym for anchor %s', self.name)
            raise AbsentNym('Ledger has no cryptonym for anchor {}'.format(self.name))

        rv = Role.get(nym['role'])

        LOGGER.debug('BaseAnchor.get_nym_role <<< %s', rv)
        return rv

    @staticmethod
    def least_role() -> Role:
        """
        Return the indy-sdk role of least privilege for an anchor (class) in building
        its cryptonym for the trust anchor to send to the ledger.

        :return: role of least privilege by anchor class
        """

        LOGGER.debug('BaseAnchor.least_role >>>')

        rv = Role.TRUST_ANCHOR

        LOGGER.debug('BaseAnchor.least_role <<< %s', rv)
        return rv

    async def set_did_endpoint(self, remote_did: str, did_endpoint: str) ->  EndpointInfo:
        """
        Set endpoint as metadata for pairwise remote DID in wallet. Pick up (transport)
        verification key from pairwise relation and return with endpoint in EndpointInfo.


        Raise BadIdentifier on bad DID. Raise WalletState if wallet is closed.
        Raise AbsentRecord if pairwise relation not present in wallet.

        :param remote_did: pairwise remote DID
        :param endpoint: value to set as endpoint in wallet and cache
        :return: endpoint and (transport) verification key
        """

        LOGGER.debug('BaseAnchor.set_did_endpoint >>> remote_did: %s, did_endpoint: %s', remote_did, did_endpoint)

        if not ok_did(remote_did):
            LOGGER.debug('BaseAnchor.set_did_endpoint <!< Bad DID %s', remote_did)
            raise BadIdentifier('Bad DID {}'.format(remote_did))

        pairwise_info = (await self.wallet.get_pairwise(remote_did)).get(remote_did, None)
        if not pairwise_info:
            LOGGER.debug(
                'BaseAnchor.set_did_endpoint <!< Anchor %s has no pairwise relation for remote DID %s',
                self.name,
                remote_did)
            raise AbsentRecord('Anchor {} has no pairwise relation for remote DID {}'.format(
                self.name,
                remote_did))

        await self.wallet.write_pairwise(
            pairwise_info.their_did,
            pairwise_info.their_verkey,
            pairwise_info.my_did,
            {'did_endpoint': did_endpoint})

        rv = EndpointInfo(did_endpoint, pairwise_info.their_verkey)

        LOGGER.debug('BaseAnchor.set_did_endpoint <<< %s', rv)
        return rv

    async def get_did_endpoint(self, remote_did: str) -> EndpointInfo:
        """
        Return endpoint info for remote DID.
        Raise BadIdentifier for bad remote DID. Raise WalletState if bypassing cache but wallet is closed.
        Raise AbsentRecord for no such endpoint.

        :param remote_did: pairwise remote DID
        :return: endpoint and (transport) verification key as EndpointInfo
        """

        LOGGER.debug('BaseAnchor.get_did_endpoint >>> remote_did: %s', remote_did)

        if not ok_did(remote_did):
            LOGGER.debug('BaseAnchor.get_did_endpoint <!< Bad DID %s', remote_did)
            raise BadIdentifier('Bad DID {}'.format(remote_did))

        pairwise_info = (await self.wallet.get_pairwise(remote_did)).get(remote_did, None)
        if not (pairwise_info and 'did_endpoint' in pairwise_info.metadata):
            LOGGER.debug('BaseAnchor.get_did_endpoint <!< No endpoint for remote DID %s', remote_did)
            raise AbsentRecord('No endpoint for remote DID {}'.format(remote_did))
        rv = EndpointInfo(pairwise_info.metadata['did_endpoint'], pairwise_info.their_verkey)

        LOGGER.debug('BaseAnchor.get_did_endpoint <<< %s', rv)
        return rv

    async def send_endpoint(self, endpoint: str) -> None:
        """
        Send anchor's own endpoint attribute to ledger (and endpoint cache),
        if ledger does not yet have input value. Specify None to clear.

        Raise BadIdentifier on endpoint not formatted as '<ip-address>:<port>',
        BadLedgerTxn on failure, WalletState if wallet is closed.

        :param endpoint: value to set as endpoint attribute on ledger and cache:
            specify URL or None to clear.
        """

        LOGGER.debug('BaseAnchor.send_endpoint >>> endpoint: %s', endpoint)

        ledger_endpoint = await self.get_endpoint()
        if ledger_endpoint == endpoint:
            LOGGER.info('%s endpoint already set as %s', self.name, endpoint)
            LOGGER.debug('BaseAnchor.send_endpoint <<< (%s already set for %s )')
            return

        attr_json = json.dumps({
            'endpoint': {
                'endpoint': endpoint  # indy-sdk likes 'ha' here but won't map 'ha' to a URL, only ip:port
            }
        })
        req_json = await ledger.build_attrib_request(self.did, self.did, None, attr_json, None)
        await self._sign_submit(req_json)

        for _ in range(16):  # reasonable timeout
            if await self.get_endpoint(None, False) == endpoint:
                break
            await asyncio.sleep(1)
            LOGGER.info('Sent endpoint %s to ledger, waiting 1s for its confirmation', endpoint)
        else:
            LOGGER.debug('BaseAnchor.send_endpoint <!< timed out waiting on send endpoint %s', endpoint)
            raise BadLedgerTxn('Timed out waiting on sent endpoint {}'.format(endpoint))

        LOGGER.debug('BaseAnchor.send_endpoint <<<')

    async def get_endpoint(self, target_did: str = None, from_cache: bool = True) -> str:
        """
        Get endpoint attribute for anchor having input DID (default own DID).
        Raise WalletState if target DID is default (own DID) value but wallet does not have it
        (neither created nor opened since initialization).

        :param target_did: DID of anchor for which to find endpoint attribute on ledger
        :param from_cache: check endpoint cache first before visiting ledger; always update cache with ledger value
        :return: endpoint attribute value, or None for no such value
        """

        LOGGER.debug('BaseAnchor.get_endpoint >>> target_did: %s, from_cache: %s', target_did, from_cache)

        rv = None

        if not (target_did or self.did):
            LOGGER.debug('BaseAnchor.get_endpoint <!< Bad wallet state: DID for %s unavailable', self.name)
            raise WalletState('Bad wallet state: DID for {} unavailable'.format(self.name))

        target_did = target_did or self.did
        if not ok_did(target_did):
            LOGGER.debug('BaseAnchor.get_endpoint <!< Bad DID %s', target_did)
            raise BadIdentifier('Bad DID {}'.format(target_did))

        if from_cache:
            with ENDPOINT_CACHE.lock:
                if target_did in ENDPOINT_CACHE:
                    LOGGER.info('BaseAnchor.get_endpoint: got endpoint for %s from cache', target_did)
                    rv = ENDPOINT_CACHE[target_did]
                    LOGGER.debug('BaseAnchor.get_endpoint <<< %s', rv)
                    return rv

        req_json = await ledger.build_get_attrib_request(
            self.did,
            target_did,
            'endpoint',
            None,
            None)
        resp_json = await self._submit(req_json)

        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json:
            rv = json.loads(data_json)['endpoint'].get('endpoint', None)
        else:
            LOGGER.info('_AgentCore.get_endpoint: ledger query returned response with no data')

        with ENDPOINT_CACHE.lock:
            if rv:
                ENDPOINT_CACHE[target_did] = rv
            else:
                ENDPOINT_CACHE.pop(target_did, None)
                assert target_did not in ENDPOINT_CACHE

        LOGGER.debug('BaseAnchor.get_endpoint <<< %s', rv)
        return rv

    async def _submit(self, req_json: str) -> str:
        """
        Submit (json) request to ledger; return (json) result.

        Raise AbsentPool for no pool, ClosedPool if pool is not yet open, or BadLedgerTxn on failure.

        :param req_json: json of request to sign and submit
        :return: json response
        """

        LOGGER.debug('BaseAnchor._submit >>> req_json: %s', req_json)

        if not self.pool:
            LOGGER.debug('BaseAnchor._submit <!< absent pool')
            raise AbsentPool('Cannot submit request: absent pool')

        if not self.pool.handle:
            LOGGER.debug('BaseAnchor._submit <!< closed pool %s', self.pool.name)
            raise ClosedPool('Cannot submit request to closed pool {}'.format(self.pool.name))

        rv_json = await ledger.submit_request(self.pool.handle, req_json)
        await asyncio.sleep(0)

        resp = json.loads(rv_json)
        if resp.get('op', '') in ('REQNACK', 'REJECT'):
            LOGGER.debug('BaseAnchor._submit <!< ledger rejected request: %s', resp['reason'])
            raise BadLedgerTxn('Ledger rejected transaction request: {}'.format(resp['reason']))

        LOGGER.debug('BaseAnchor._submit <<< %s', rv_json)
        return rv_json

    async def _sign_submit(self, req_json: str) -> str:
        """
        Sign and submit (json) request to ledger; return (json) result.

        Raise:
        * AbsentPool for no pool
        * ClosedPool if pool is not yet open
        * CorruptWallet if existing wallet appears not to pertain to the anchor's pool
        * WalletState if wallet is closed
        * BadLedgerTxn on ledger rejection of transaction.

        :param req_json: json of request to sign and submit
        :return: json response
        """

        LOGGER.debug('BaseAnchor._sign_submit >>> req_json: %s', req_json)

        if not self.pool:
            LOGGER.debug('BaseAnchor._sign_submit <!< absent pool')
            raise AbsentPool('Cannot sign and submit request: absent pool')

        if not self.pool.handle:
            LOGGER.debug('BaseAnchor._submit <!< closed pool %s', self.pool.name)
            raise ClosedPool('Cannot sign and submit request to closed pool {}'.format(self.pool.name))

        if not self.wallet.handle:
            LOGGER.debug('BaseAnchor._sign_submit <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        try:
            rv_json = await ledger.sign_and_submit_request(self.pool.handle, self.wallet.handle, self.did, req_json)
            await asyncio.sleep(0)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletIncompatiblePoolError:
                LOGGER.debug(
                    'BaseAnchor._sign_submit <!< Corrupt wallet %s is not compatible with pool %s',
                    self.name,
                    self.pool.name)
                raise CorruptWallet('Corrupt wallet {} is not compatible with pool {}'.format(
                    self.name,
                    self.pool.name))
            LOGGER.debug(
                'BaseAnchor._sign_submit <!< cannot sign/submit request for ledger: indy error code %s',
                x_indy.error_code)
            raise BadLedgerTxn('Cannot sign/submit request for ledger: indy error code {}'.format(
                x_indy.error_code))

        resp = json.loads(rv_json)
        if resp.get('op', '') in ('REQNACK', 'REJECT'):
            LOGGER.debug('BaseAnchor._sign_submit: ledger rejected request: %s', resp['reason'])
            raise BadLedgerTxn('Ledger rejected transaction request: {}'.format(resp['reason']))

        LOGGER.debug('BaseAnchor._sign_submit <<< %s', rv_json)
        return rv_json

    async def _verkey_for(self, target: str) -> str:
        """
        Given a DID, retrieve its verification key, looking in wallet, then pool.
        Given a verification key or None, return input.

        Raise WalletState if the wallet is closed. Given a recipient DID not in the wallet,
        raise AbsentPool if the instance has no pool or ClosedPool if its pool is closed.
        If no such verification key is on the ledger, raise AbsentNym.

        :param target: verification key, or DID to resolve to such
        :return: verification key
        """

        LOGGER.debug('BaseAnchor._verkey_for >>> target: %s', target)

        rv = target
        if rv is None or not ok_did(rv):  # it's None or already a verification key
            LOGGER.debug('BaseAnchor._verkey_for <<< %s', rv)
            return rv

        if self.wallet.handle:
            try:
                rv = await did.key_for_local_did(self.wallet.handle, target)
                LOGGER.info('Anchor %s got verkey for DID %s from wallet', self.name, target)
                LOGGER.debug('BaseAnchor._verkey_for <<< %s', rv)
                return rv
            except IndyError as x_indy:
                if x_indy.error_code != ErrorCode.WalletItemNotFound:  # on not found, try the pool
                    LOGGER.debug(
                        'BaseAnchor._verkey_for <!< key lookup for local DID %s raised indy error code %s',
                        target,
                        x_indy.error_code)
                    raise

        nym = json.loads(await self.get_nym(target))
        if not nym:
            LOGGER.debug(
                'BaseAnchor._verkey_for <!< Anchor %s cannot get cryptonym (hence verkey) for DID %s',
                self.name,
                target)
            raise AbsentNym('Anchor {} cannot get cryptonym (hence verkey) for DID {}'.format(self.name, target))

        rv = json.loads(await self.get_nym(target))['verkey']
        LOGGER.info('Anchor %s got verkey for DID %s from pool %s', self.name, target, self.pool.name)

        LOGGER.debug('BaseAnchor._verkey_for <<< %s', rv)
        return rv

    async def get_rev_reg_def(self, rr_id: str) -> str:
        """
        Get revocation registry definition from ledger by its identifier. Raise AbsentRevReg
        for no such revocation registry, logging any error condition and raising BadLedgerTxn
        on bad request.

        Retrieve the revocation registry definition from the anchor's revocation cache if it has it;
        cache it en passant if it does not (and such a revocation registry definition exists on the ledger).

        :param rr_id: (revocation registry) identifier string, of the format
            '<issuer-did>:4:<issuer-did>:3:CL:<schema-seq-no>:<tag>:CL_ACCUM:<tag>'
        :return: revocation registry definition json as retrieved from ledger
        """

        LOGGER.debug('BaseAnchor.get_rev_reg_def >>> rr_id: %s', rr_id)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('BaseAnchor.get_rev_reg_def <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        rv_json = json.dumps({})

        with REVO_CACHE.lock:
            revo_cache_entry = REVO_CACHE.get(rr_id, None)
            rr_def = revo_cache_entry.rev_reg_def if revo_cache_entry else None
            if rr_def:
                LOGGER.info('BaseAnchor.get_rev_reg_def: rev reg def for %s from cache', rr_id)
                rv_json = json.dumps(rr_def)
            else:
                get_rr_def_req_json = await ledger.build_get_revoc_reg_def_request(self.did, rr_id)
                resp_json = await self._submit(get_rr_def_req_json)
                try:
                    (_, rv_json) = await ledger.parse_get_revoc_reg_def_response(resp_json)
                    rr_def = json.loads(rv_json)
                except IndyError:  # ledger replied, but there is no such rev reg
                    LOGGER.debug('BaseAnchor.get_rev_reg_def <!< no rev reg exists on %s', rr_id)
                    raise AbsentRevReg('No rev reg exists on {}'.format(rr_id))

                if revo_cache_entry is None:
                    REVO_CACHE[rr_id] = RevoCacheEntry(rr_def, None)
                else:
                    REVO_CACHE[rr_id].rev_reg_def = rr_def

        LOGGER.debug('BaseAnchor.get_rev_reg_def <<< %s', rv_json)
        return rv_json

    async def get_cred_def(self, cd_id: str) -> str:
        """
        Get credential definition from ledger by its identifier.

        Raise AbsentCredDef for no such credential definition, logging any error condition and raising
        BadLedgerTxn on bad request. Raise ClosedPool if cred def not in cache and pool is closed.

        Retrieve the credential definition from the anchor's credential definition cache if it has it; cache it
        en passant if it does not (and if there is a corresponding credential definition on the ledger).

        :param cd_id: (credential definition) identifier string ('<issuer-did>:3:CL:<schema-seq-no>:<tag>')
        :return: credential definition json as retrieved from ledger, empty production for no such cred def
        """

        LOGGER.debug('BaseAnchor.get_cred_def >>> cd_id: %s', cd_id)

        if not ok_cred_def_id(cd_id):
            LOGGER.debug('BaseAnchor.get_cred_def <!< Bad cred def id %s', cd_id)
            raise BadIdentifier('Bad cred def id {}'.format(cd_id))

        rv_json = json.dumps({})

        with CRED_DEF_CACHE.lock:
            if cd_id in CRED_DEF_CACHE:
                LOGGER.info('BaseAnchor.get_cred_def: got cred def for %s from cache', cd_id)
                rv_json = json.dumps(CRED_DEF_CACHE[cd_id])
                LOGGER.debug('BaseAnchor.get_cred_def <<< %s', rv_json)
                return rv_json

            req_json = await ledger.build_get_cred_def_request(self.did, cd_id)
            resp_json = await self._submit(req_json)
            resp = json.loads(resp_json)
            if not ('result' in resp and resp['result'].get('data', None)):
                LOGGER.debug('BaseAnchor.get_cred_def <!< no cred def exists on %s', cd_id)
                raise AbsentCredDef('No cred def exists on {}'.format(cd_id))
            try:
                (_, rv_json) = await ledger.parse_get_cred_def_response(resp_json)
            except IndyError:  # ledger replied, but there is no such cred def
                LOGGER.debug('BaseAnchor.get_cred_def <!< no cred def exists on %s', cd_id)
                raise AbsentCredDef('No cred def exists on {}'.format(cd_id))
            CRED_DEF_CACHE[cd_id] = json.loads(rv_json)
            LOGGER.info('BaseAnchor.get_cred_def: got cred def %s from ledger', cd_id)

        LOGGER.debug('BaseAnchor.get_cred_def <<< %s', rv_json)
        return rv_json

    async def get_schema(self, index: Union[SchemaKey, int, str]) -> str:
        """
        Get schema from ledger by SchemaKey namedtuple (origin DID, name, version),
        sequence number, or schema identifier.

        Raise AbsentSchema for no such schema, logging any error condition and raising
        BadLedgerTxn on bad request.

        Retrieve the schema from the anchor's schema cache if it has it; cache it
        en passant if it does not (and there is a corresponding schema on the ledger).

        :param index: schema key (origin DID, name, version), sequence number, or schema identifier
        :return: schema json, parsed from ledger
        """

        LOGGER.debug('BaseAnchor.get_schema >>> index: %s', index)

        rv_json = json.dumps({})
        with SCHEMA_CACHE.lock:
            if SCHEMA_CACHE.contains(index):
                LOGGER.info('BaseAnchor.get_schema: got schema %s from cache', index)
                rv_json = SCHEMA_CACHE[index]
                LOGGER.debug('BaseAnchor.get_schema <<< %s', rv_json)
                return json.dumps(rv_json)

            if isinstance(index, SchemaKey) or (isinstance(index, str) and ok_schema_id(index)):
                s_id = schema_id(*index) if isinstance(index, SchemaKey) else index
                s_key = schema_key(s_id)
                req_json = await ledger.build_get_schema_request(self.did, s_id)
                resp_json = await self._submit(req_json)
                resp = json.loads(resp_json)

                if not ('result' in resp and resp['result'].get('data', {}).get('attr_names', None)):
                    LOGGER.debug('BaseAnchor.get_schema <!< no schema exists on %s', index)
                    raise AbsentSchema('No schema exists on {}'.format(index))
                try:
                    (_, rv_json) = await ledger.parse_get_schema_response(resp_json)
                except IndyError:  # ledger replied, but there is no such schema
                    LOGGER.debug('BaseAnchor.get_schema <!< no schema exists on %s', index)
                    raise AbsentSchema('No schema exists on {}'.format(index))
                SCHEMA_CACHE[s_key] = json.loads(rv_json)  # cache indexes by both txn# and schema key en passant
                LOGGER.info('BaseAnchor.get_schema: got schema %s from ledger', index)

            elif isinstance(index, (int, str)):  # index is not a schema id: it's a stringified int txn# if it's a str
                txn_json = await self.get_txn(int(index))  # raises AbsentPool if anchor has no pool
                txn = json.loads(txn_json)
                if txn.get('type', None) == '101':  # {} for no such txn; 101 marks indy-sdk schema txn type
                    rv_json = await self.get_schema(self.pool.protocol.txn_data2schema_key(txn))
                else:
                    LOGGER.debug('BaseAnchor.get_schema <!< no schema at seq #%s on ledger', index)
                    raise AbsentSchema('No schema at seq #{} on ledger'.format(index))

            else:
                LOGGER.debug('BaseAnchor.get_schema <!< bad schema index type')
                raise AbsentSchema('Attempt to get schema on ({}) {} , must use schema key or an int'.format(
                    type(index),
                    index))

        LOGGER.debug('BaseAnchor.get_schema <<< %s', rv_json)
        return rv_json

    async def encrypt(self, message: bytes, authn: bool = False, recip: str = None) -> bytes:
        """
        Encrypt plaintext for owner of DID or verification key, anonymously or via
        authenticated encryption scheme. If given DID, first check wallet and then pool
        for corresponding verification key.

        Raise WalletState if the wallet is closed. Given a recipient DID not in the wallet,
        raise AbsentPool if the instance has no pool or ClosedPool if its pool is closed.

        :param message: plaintext, as bytes
        :param authn: whether to use authenticated encryption scheme
        :param recip: DID or verification key of recipient, None for anchor's own
        :return: ciphertext, as bytes
        """

        LOGGER.debug('BaseAnchor.encrypt >>> message: %s, authn: %s, recip: %s', message, authn, recip)

        if not self.wallet.handle:  # don't risk fetching verkey from ledger only to fail encryption on closed wallet
            LOGGER.debug('BaseAnchor.encrypt <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = await self.wallet.encrypt(message, authn, await self._verkey_for(recip))

        LOGGER.debug('BaseAnchor.auth_encrypt <<< %s', rv)
        return rv

    async def decrypt(self, ciphertext: bytes, sender: str = None) -> (bytes, str):
        """
        Decrypt ciphertext and optionally authenticate sender.

        Raise BadKey if authentication operation reveals sender key distinct from current
        verification key of owner of input DID.  Raise WalletState if wallet is closed.

        :param ciphertext: ciphertext, as bytes
        :param sender: DID or verification key of sender, None for anonymously encrypted ciphertext
        :return: decrypted bytes and sender verification key (None for anonymous decryption)
        """

        LOGGER.debug('BaseAnchor.decrypt >>> ciphertext: %s, sender: %s', ciphertext, sender)

        if not self.wallet.handle:  # don't risk fetching verkey from ledger only to fail encryption on closed wallet
            LOGGER.debug('BaseAnchor.decrypt <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        from_verkey = None
        if sender:
            from_verkey = await self._verkey_for(sender)
        rv = await self.wallet.decrypt(
            ciphertext,
            True if from_verkey else None,
            to_verkey=None,
            from_verkey=from_verkey)

        LOGGER.debug('BaseAnchor.decrypt <<< %s', rv)
        return rv

    async def sign(self, message: bytes) -> bytes:
        """
        Sign message; return signature. Raise WalletState if wallet is closed.

        :param message: Content to sign, as bytes
        :return: signature, as bytes
        """

        LOGGER.debug('BaseAnchor.sign >>> message: %s', message)

        if not self.wallet.handle:
            LOGGER.debug('BaseAnchor.sign <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = await self.wallet.sign(message)

        LOGGER.debug('BaseAnchor.sign <<< %s', rv)
        return rv

    async def verify(self, message: bytes, signature: bytes, signer: str = None) -> bool:
        """
        Verify signature with input signer verification key (via lookup by DID first if need be).
        Raise WalletState if wallet is closed.

        :param message: Content to sign, as bytes
        :param signature: signature, as bytes
        :param signer: signer DID or verification key; omit for anchor's own
        :return: whether signature is valid
        """

        LOGGER.debug('BaseAnchor.verify >>> signer: %s, message: %s, signature: %s', signer, message, signature)

        if not self.wallet.handle:
            LOGGER.debug('BaseAnchor.verify <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        verkey = None
        if signer:
            verkey = await self._verkey_for(signer)
        rv = await self.wallet.verify(message, signature, verkey)

        LOGGER.debug('BaseAnchor.verify <<< %s', rv)
        return rv

    async def get_txn(self, seq_no: int) -> str:
        """
        Find a transaction on the distributed ledger by its sequence number.

        :param seq_no: transaction number
        :return: json sequence number of transaction, null for no match
        """

        LOGGER.debug('BaseAnchor.get_txn >>> seq_no: %s', seq_no)

        rv_json = json.dumps({})
        req_json = await ledger.build_get_txn_request(self.did, None, seq_no)
        resp = json.loads(await self._submit(req_json))

        rv_json = self.pool.protocol.txn2data(resp)

        LOGGER.debug('BaseAnchor.get_txn <<< %s', rv_json)
        return rv_json

    def __str__(self) -> str:
        """
        Return string representation for current object.

        :return: string representation for current object
        """

        return '{}({})'.format(self.__class__.__name__, self.name)
