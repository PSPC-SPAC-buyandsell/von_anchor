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


import json
import logging

from ctypes import CDLL
from time import time
from typing import Callable, List, Sequence, Union

from indy import crypto, did, non_secrets, wallet
from indy.error import IndyError, ErrorCode

from von_anchor.canon import canon_non_secret_wql, canon_pairwise_wql
from von_anchor.error import (
    AbsentRecord,
    AbsentMessage,
    AbsentWallet,
    BadKey,
    BadIdentifier,
    BadRecord,
    ExtantWallet,
    ExtantRecord,
    WalletState)
from von_anchor.util import ok_did
from von_anchor.validcfg import validate_config
from von_anchor.wallet import (
    DIDInfo,
    NonSecret,
    non_secret2pairwise_info,
    PairwiseInfo,
    pairwise_info2tags,
    TYPE_PAIRWISE)


LOGGER = logging.getLogger(__name__)


class Wallet:
    """
    Class encapsulating indy-sdk wallet.
    """

    DEFAULT_ACCESS_CREDS = {'key': 'key'}
    DEFAULT_CHUNK = 256  # chunk size in searching credentials

    def __init__(
            self,
            name: str,
            storage_type: str = None,
            config: dict = None,
            access_creds: dict = None) -> None:
        """
        Initializer for wallet. Store input parameters, packing name and storage_type into config.
        Do not create wallet until call to create(). Do not open until call to open() or __aenter__().

        :param name: name of the wallet
        :param storage_type: storage type (default None)
        :param config: configuration dict (default None); i.e.,
            ::
            {
                'auto-remove': bool (default False) - whether to remove serialized indy configuration data on close,
                ... (more keys) : ... (more types) - any other configuration data to pass through to indy-sdk
            }
        :param access_creds: wallet access credentials dict, None for default
        """

        LOGGER.debug(
            'Wallet.__init__ >>> name %s, storage_type %s, config %s, access_creds %s',
            name,
            storage_type,
            config,
            access_creds)

        self._next_seed = None
        self._handle = None

        self._config = {**config} if config else {}
        self._config['id'] = name
        self._config['storage_type'] = storage_type
        if 'freshness_time' not in self._config:
            self._config['freshness_time'] = 0

        validate_config('wallet', self._config)

        # pop and retain configuration specific to von_anchor.Wallet, extrinsic to indy-sdk
        self._auto_remove = self._config.pop('auto-remove') if self._config and 'auto-remove' in self._config else False

        self._access_creds = access_creds
        self._did = None
        self._verkey = None

        LOGGER.debug('Wallet.__init__ <<<')

    @property
    def name(self) -> str:
        """
        Accessor for wallet name, as configuration retains at key 'id'.

        :return: wallet name
        """

        return self.config['id']

    @property
    def handle(self) -> int:
        """
        Accessor for indy-sdk wallet handle.

        :return: indy-sdk wallet handle
        """

        return self._handle

    @property
    def config(self) -> dict:
        """
        Accessor for wallet config.

        :return: wallet config
        """

        return self._config

    @property
    def auto_remove(self) -> bool:
        """
        Accessor for auto-remove wallet config setting.

        :return: auto-remove wallet config setting
        """

        return self._auto_remove

    @property
    def access_creds(self) -> dict:
        """
        Accessor for wallet access credentials.

        :return: wallet access credentials
        """

        return self._access_creds

    @property
    def storage_type(self) -> str:
        """
        Accessor for wallet type, as configuration retains at key 'storage_type'.

        :return: wallet type
        """

        return self.config['storage_type']

    @property
    def did(self) -> str:
        """
        Accessor for anchor DID in wallet.

        :return: anchor DID in wallet
        """

        return self._did

    @property
    def verkey(self) -> str:
        """
        Accessor for wallet verification key.

        :return: wallet verification key
        """

        return self._verkey

    @verkey.setter
    def verkey(self, value: str) -> None:
        """
        Set verification key.

        :param value: verification key
        """

        self._verkey = value

    async def create_local_did(self, seed: str = None, loc_did: str = None, metadata: dict = None) -> DIDInfo:
        """
        Create and store a new local DID for use in pairwise DID relations.

        :param seed: seed from which to create (default random)
        :param loc_did: local DID value (default None to let indy-sdk generate)
        :param metadata: metadata to associate with the local DID (operation always sets 'since' epoch timestamp)
        :return: DIDInfo for new local DID
        """

        LOGGER.debug('Wallet.create_local_did >>> seed: [SEED] loc_did: %s metadata: %s', loc_did, metadata)

        cfg = {}
        if seed:
            cfg['seed'] = seed
        if loc_did:
            cfg['did'] = loc_did

        if not self.handle:
            LOGGER.debug('Wallet.create_local_did <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        try:
            (created_did, verkey) = await did.create_and_store_my_did(self.handle, json.dumps(cfg))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.DidAlreadyExistsError:
                LOGGER.debug('Wallet.create_local_did <!< DID %s already present in wallet %s', loc_did, self.name)
                raise ExtantRecord('Local DID {} already present in wallet {}'.format(loc_did, self.name))
            else:
                LOGGER.debug('Wallet.create_local_did <!< indy-sdk raised error %s', x_indy.error_code)
                raise

        loc_did_metadata = {**(metadata or {}), 'since': int(time())}
        await did.set_did_metadata(self.handle, created_did, json.dumps(loc_did_metadata))

        rv = DIDInfo(created_did, verkey, loc_did_metadata)

        LOGGER.debug('Wallet.create_local_did <<< %s', rv)
        return rv

    async def get_local_did_infos(self) -> List[DIDInfo]:
        """
        Get list of DIDInfos for local DIDs.

        :return: list of local DIDInfos
        """

        LOGGER.debug('Wallet.get_local_did_infos >>>')

        dids_with_meta = json.loads(did.list_my_dids_with_meta(self.handle))  # list

        rv = []
        for did_with_meta in dids_with_meta:
            meta = json.loads(did_with_meta['metadata']) if did_with_meta['metadata'] else {}
            if meta.get('anchor', False):
                continue  # exclude anchor DIDs past and present
            rv.append(DIDInfo(did_with_meta['did'], did_with_meta['verkey'], meta))

        LOGGER.debug('Wallet.get_local_did_infos <<< %s', rv)
        return rv

    async def get_local_did_info(self, loc: str) -> DIDInfo:
        """
        Get local DID info by local DID or verification key.
        Raise AbsentRecord for no such local DID.

        :param loc: DID or verification key of interest
        :return: DIDInfo for local DID
        """

        LOGGER.debug('Wallet.get_local_did_info >>> loc: %s', loc)

        if not self.handle:
            LOGGER.debug('Wallet.get_local_did_info <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        if ok_did(loc):  # it's a DID
            try:
                did_with_meta = json.loads(await did.get_my_did_with_meta(self.handle, loc))
                rv = DIDInfo(
                    did_with_meta['did'],
                    did_with_meta['verkey'],
                    json.loads(did_with_meta['metadata']) if did_with_meta['metadata'] else {})  # nudge None to empty
            except IndyError as x_indy:
                if x_indy.error_code == ErrorCode.WalletItemNotFound:
                    LOGGER.debug('Wallet.get_local_did_info <!< DID %s not present in wallet %s', loc, self.name)
                    raise AbsentRecord('Local DID {} not present in wallet {}'.format(loc, self.name))
                else:
                    LOGGER.debug('Wallet.get_local_did_info <!< indy-sdk raised error %s', x_indy.error_code)
                    raise
        else:  # it's a verkey
            dids_with_meta = json.loads(await did.list_my_dids_with_meta(self.handle))  # list
            for did_with_meta in dids_with_meta:
                if did_with_meta['verkey'] == loc:
                    rv = DIDInfo(
                        did_with_meta['did'],
                        did_with_meta['verkey'],
                        json.loads(did_with_meta['metadata']) if did_with_meta['metadata'] else {})
                    break
            else:
                LOGGER.debug('Wallet.get_local_did_info <!< Wallet %s has no local DID for verkey %s', self.name, loc)
                raise AbsentRecord('Wallet {} has no local DID for verkey {}'.format(self.name, loc))

        LOGGER.debug('Wallet.get_local_did_info <<< %s', rv)
        return rv

    async def get_anchor_did(self) -> str:
        """
        Get current anchor DID by metadata. Raise AbsentRecord for no match.

        :return: DID
        """

        LOGGER.debug('Wallet.get_anchor_did >>>')

        if not self.handle:
            LOGGER.debug('Wallet.get_anchor_did <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = None
        dids_with_meta = json.loads(await did.list_my_dids_with_meta(self.handle))  # list

        latest = 0
        for did_with_meta in dids_with_meta:
            try:
                meta = json.loads(did_with_meta['metadata']) if did_with_meta['metadata'] else {}
                if not meta.get('anchor', False):
                    continue
                if isinstance(meta, dict) and meta.get('since', -1) > latest:
                    rv = did_with_meta.get('did')
            except json.decoder.JSONDecodeError:
                continue  # it's not an anchor DID, carry on

        if not rv:  # no match in metadata
            LOGGER.debug('Wallet.get_anchor_did <!< no anchor DID in wallet %s by metadata', self.name)
            raise AbsentRecord('No anchor DID in wallet {} by metadata'.format(self.name))

        LOGGER.debug('Wallet.get_anchor_did <<< %s', rv)
        return rv

    async def create(self, seed: str) -> 'Wallet':
        """
        Create wallet as configured and store DID.

        Raise ExtantWallet if wallet already exists on current name.

        :param seed: seed
        :return: current object
        """

        LOGGER.debug('Wallet.create >>> seed: [SEED]')

        try:
            await wallet.create_wallet(
                config=json.dumps(self.config),
                credentials=json.dumps(self.access_creds or Wallet.DEFAULT_ACCESS_CREDS))
            LOGGER.info('Created wallet %s', self.name)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletAlreadyExistsError:
                LOGGER.info('Wallet %s already exists', self.name)
                raise ExtantWallet('Wallet {} already exists'.format(self.name))
            else:
                LOGGER.debug(
                    'Wallet.create <!< indy error code %s on creation of wallet %s',
                    x_indy.error_code,
                    self.name)
                raise

        self._handle = await wallet.open_wallet(
            json.dumps(self.config),
            json.dumps(self.access_creds or Wallet.DEFAULT_ACCESS_CREDS))
        LOGGER.info('Opened wallet %s on handle %s', self.name, self.handle)

        try:
            (self._did, self.verkey) = await did.create_and_store_my_did(
                self.handle,
                json.dumps({'seed': seed}))
            LOGGER.debug('Wallet %s stored new DID %s, verkey %s from seed', self.name, self.did, self.verkey)
            await did.set_did_metadata(
                self.handle,
                self.did,
                json.dumps({
                    'anchor': True,
                    'since': int(time())
                }))
            LOGGER.info('Wallet %s set seed hash metadata for DID %s', self.name, self.did)
        finally:
            await wallet.close_wallet(self.handle)  # bypass self.close() in case auto-remove set
            self._handle = None

        LOGGER.debug('Wallet.create <<<')
        return self

    async def __aenter__(self) -> 'Wallet':
        """
        Context manager entry. Open (created) wallet as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing wallet.

        Raise any IndyError causing failure to open wallet, or AbsentWallet on attempt to enter wallet
        not yet created.

        :return: current object
        """

        LOGGER.debug('Wallet.__aenter__ >>>')

        rv = await self.open()
        LOGGER.debug('Wallet.__aenter__ <<<')
        return rv

    async def open(self) -> 'Wallet':
        """
        Explicit entry. Open wallet as configured, for later closure via close().
        For use when keeping wallet open across multiple calls.

        Raise any IndyError causing failure to open wallet, WalletState if wallet already open,
        or AbsentWallet on attempt to enter wallet not yet created.

        :return: current object
        """

        LOGGER.debug('Wallet.open >>>')

        try:
            self._handle = await wallet.open_wallet(
                json.dumps(self.config),
                json.dumps(self.access_creds or Wallet.DEFAULT_ACCESS_CREDS))
            LOGGER.info('Opened wallet %s on handle %s', self.name, self.handle)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletNotFoundError:
                LOGGER.info('Wallet %s does not exist', self.name)
                raise AbsentWallet('Wallet {} does not exist'.format(self.name))
            elif x_indy.error_code == ErrorCode.WalletAlreadyOpenedError:
                LOGGER.info('Wallet %s is already open', self.name)
                raise WalletState('Wallet {} is already open'.format(self.name))
            else:
                raise

        self._did = await self.get_anchor_did()
        self.verkey = await did.key_for_local_did(self.handle, self.did)
        LOGGER.info('Wallet %s got verkey %s for existing DID %s', self.name, self.verkey, self.did)

        LOGGER.debug('Wallet.open <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Close wallet (and delete if so configured).
        For use in monolithic call opening, using, and closing the wallet.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        LOGGER.debug('Wallet.__aexit__ >>>')

        await self.close()

        LOGGER.debug('Wallet.__aexit__ <<<')

    async def close(self) -> None:
        """
        Explicit exit. Close wallet (and delete if so configured).
        For use when keeping wallet open across multiple calls.
        """

        LOGGER.debug('Wallet.close >>>')

        if not self.handle:
            LOGGER.warning('Abstaining from closing wallet %s: already closed', self.name)
        else:
            LOGGER.debug('Closing wallet %s', self.name)
            await wallet.close_wallet(self.handle)
            self._handle = None
            if self.auto_remove:
                LOGGER.info('Auto-removing wallet %s', self.name)
                await self.remove()
        self._handle = None

        LOGGER.debug('Wallet.close <<<')

    async def write_pairwise(
            self,
            their_did: str,
            their_verkey: str,
            my_did: str = None,
            metadata: dict = None,
            replace_meta: bool = False) -> PairwiseInfo:
        """
        Store a pairwise DID for a secure connection. Use verification key for local DID in wallet if
        supplied; otherwise, create one first. If local DID specified but not present, raise AbsentRecord.

        With supplied metadata, replace or augment and overwrite any existing metadata for the pairwise
        relation if one already exists in the wallet. Always include local and remote DIDs and keys in
        metadata to allow for WQL search.

        :param their_did: remote DID
        :param their_verkey: remote verification key
        :param my_did: local DID
        :param metadata: metadata for pairwise connection
        :param replace_meta: whether to (True) replace or (False) augment and overwrite existing metadata
        :return: resulting PairwiseInfo
        """

        LOGGER.debug(
            'Wallet.write_pairwise >>> their_did: %s, their_verkey: %s, my_did: %s, metadata: %s, replace_meta: %s',
            their_did,
            their_verkey,
            my_did,
            metadata,
            replace_meta)

        try:
            await did.store_their_did(self.handle, json.dumps({'did': their_did, 'verkey': their_verkey}))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemAlreadyExists:
                pass  # exists already, carry on
            else:
                LOGGER.debug(
                    'Wallet.write_pairwise <!< Wallet %s write of their_did %s raised indy error code %s',
                    self.name,
                    their_did,
                    x_indy.error_code)
                raise

        if my_did:
            my_did_info = await self.get_local_did_info(my_did)  # raises AbsentRecord if no such local did
        else:
            my_did_info = await self.create_local_did(None, None, {'pairwise_for': their_did})

        pairwise = PairwiseInfo(their_did, their_verkey, my_did_info.did, my_did_info.verkey, metadata)
        non_sec = await self.write_non_secret(
            NonSecret(TYPE_PAIRWISE, their_did, their_verkey, pairwise_info2tags(pairwise)),
            replace_meta)

        rv = non_secret2pairwise_info(non_sec)
        LOGGER.debug('Wallet.write_pairwise <<< %s', rv)
        return rv

    async def delete_pairwise(self, their_did: str) -> None:
        """
        Remove a pairwise DID record by its remote DID. Silently return if no such record is present.
        Raise WalletState for closed wallet, or BadIdentifier for invalid pairwise DID.

        :param their_did: remote DID marking pairwise DID to remove
        """

        LOGGER.debug('Wallet.delete_pairwise >>> their_did: %s', their_did)

        if not ok_did(their_did):
            LOGGER.debug('Wallet.delete_pairwise <!< Bad DID %s', their_did)
            raise BadIdentifier('Bad DID {}'.format(their_did))

        await self.delete_non_secret(TYPE_PAIRWISE, their_did)

        LOGGER.debug('Wallet.delete_pairwise <<<')

    async def get_pairwise(self, pairwise_filt: str = None) -> dict:
        """
        Return dict mapping each pairwise DID of interest in wallet to its pairwise info, or,
        for no filter specified, mapping them all. If wallet has no such item, return empty dict.

        :param pairwise_filt: remote DID of interest, or WQL json (default all)
        :return: dict mapping remote DIDs to PairwiseInfo
        """

        LOGGER.debug('Wallet.get_pairwise >>> pairwise_filt: %s', pairwise_filt)

        if not self.handle:
            LOGGER.debug('Wallet.get_pairwise <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        non_secs = await self.get_non_secret(
            TYPE_PAIRWISE,
            pairwise_filt if ok_did(pairwise_filt) or not pairwise_filt else json.loads(pairwise_filt),
            canon_pairwise_wql)
        rv = {k: non_secret2pairwise_info(non_secs[k]) for k in non_secs}  # touch up tags, mute leading ~

        LOGGER.debug('Wallet.get_pairwise <<< %s', rv)
        return rv

    async def write_non_secret(self, non_secret: NonSecret, replace_meta: bool = False) -> NonSecret:
        """
        Add or update non-secret record to the wallet; return resulting wallet non-secret record.

        :param non_secret: non-secret record
        :return: non-secret record as it appears in the wallet after write
        """

        LOGGER.debug('Wallet.write_non_secret >>> non_secret: %s, replace_meta: %s', non_secret, replace_meta)

        if not NonSecret.ok_tags(non_secret.tags):
            LOGGER.debug('Wallet.write_non_secret <!< bad non_secret tags %s; use flat {str: str} dict', non_secret)
            raise BadRecord('Bad non_secret tags {}; use flat {{str:str}} dict'.format(non_secret))

        try:
            record = json.loads(await non_secrets.get_wallet_record(
                self.handle,
                non_secret.type,
                non_secret.id,
                json.dumps({
                    'retrieveType': False,
                    'retrieveValue': True,
                    'retrieveTags': True
                })))
            if record['value'] != non_secret.value:
                await non_secrets.update_wallet_record_value(
                    self.handle,
                    non_secret.type,
                    non_secret.id,
                    non_secret.value)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                await non_secrets.add_wallet_record(
                    self.handle,
                    non_secret.type,
                    non_secret.id,
                    non_secret.value,
                    json.dumps(non_secret.tags) if non_secret.tags else None)
            else:
                LOGGER.debug(
                    'Wallet.write_non_secret <!< Wallet lookup raised indy error code %s',
                    x_indy.error_code)
                raise
        else:
            if (record['tags'] or None) != non_secret.tags:  # record maps no tags to {}, not None
                tags = (non_secret.tags or {}) if replace_meta else {**record['tags'], **(non_secret.tags or {})}

                await non_secrets.update_wallet_record_tags(
                    self.handle,
                    non_secret.type,
                    non_secret.id,
                    json.dumps(tags))  # indy-sdk takes '{}' instead of None for null tags

        record = json.loads(await non_secrets.get_wallet_record(
            self.handle,
            non_secret.type,
            non_secret.id,
            json.dumps({
                'retrieveType': False,
                'retrieveValue': True,
                'retrieveTags': True
            })))

        rv = NonSecret(non_secret.type, record['id'], record['value'], record.get('tags', None))
        LOGGER.debug('Wallet.write_non_secret <<< %s', rv)
        return rv

    async def delete_non_secret(self, typ: str, ident: str) -> None:
        """
        Remove a pairwise DID record by its type and identifier. Silently return if no such record is present.
        Raise WalletState for closed wallet.

        :param typ: non-secret record type
        :param ident: non-secret record identifier
        """

        LOGGER.debug('Wallet.delete_non_secret >>> typ: %s, ident: %s', typ, ident)

        if not self.handle:
            LOGGER.debug('Wallet.delete_non_secret <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        try:
            await non_secrets.delete_wallet_record(self.handle, typ, ident)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                LOGGER.info('Wallet.delete_non_secret <!< no record for type %s on identifier %s', typ, ident)
            else:
                LOGGER.debug(
                    'Wallet.delete_non_secret <!< deletion of %s record on identifier %s raised indy error code %s',
                    typ,
                    ident,
                    x_indy.error_code)
                raise

        LOGGER.debug('Wallet.delete_non_secret <<<')

    async def get_non_secret(
            self,
            typ: str,
            filt: Union[dict, str] = None,
            canon_wql: Callable[[dict], dict] = None) -> dict:
        """
        Return dict mapping each non-secret record of interest by identifier or,
        for no filter specified, mapping them all. If wallet has no such item, return empty dict.

        :param typ: non-secret record type
        :param filt: non-secret record identifier or WQL json (default all)
        :param canon_wql: WQL canonicalization function (default wallet.nonsecret.canon_non_secret_wql())
        :return: dict mapping identifiers to non-secret records
        """

        LOGGER.debug('Wallet.get_non_secret >>> typ: %s, filt: %s, canon_wql: %s', typ, filt, canon_wql)

        if not self.handle:
            LOGGER.debug('Wallet.get_non_secret <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        records = []
        if isinstance(filt, str):  # ordinary lookup by value
            try:
                records = [json.loads(await non_secrets.get_wallet_record(
                    self.handle,
                    typ,
                    filt,
                    json.dumps({
                        'retrieveType': False,
                        'retrieveValue': True,
                        'retrieveTags': True
                    })))]
            except IndyError as x_indy:
                if x_indy.error_code == ErrorCode.WalletItemNotFound:
                    pass
                else:
                    LOGGER.debug(
                        'Wallet.get_non_secret <!< Wallet %s lookup raised indy exception %s',
                        self.name,
                        x_indy.error_code)
                    raise
        else:
            canon = canon_wql or canon_non_secret_wql
            s_handle = await non_secrets.open_wallet_search(
                self.handle,
                typ,
                json.dumps(canon(filt or {})),
                json.dumps({
                    'retrieveRecords': True,
                    'retrieveTotalCount': True,
                    'retrieveType': False,
                    'retrieveValue': True,
                    'retrieveTags': True
                }))

            # TODO: paginate?  Take approach from cred search WQL in holder-prover
            count = int(json.loads(
                await non_secrets.fetch_wallet_search_next_records(self.handle, s_handle, 0))['totalCount'])
            if count > 0:
                records = json.loads(
                    await non_secrets.fetch_wallet_search_next_records(self.handle, s_handle, count))['records']

        rv = {record['id']: NonSecret(typ, record['id'], record['value'], record['tags']) for record in records}
        LOGGER.debug('Wallet.get_non_secret <<< %s', rv)
        return rv

    async def encrypt(self, message: bytes, authn: bool = False, verkey: str = None) -> bytes:
        """
        Encrypt plaintext for owner of DID, anonymously or via authenticated encryption scheme.
        Raise AbsentMessage for missing message, or WalletState if wallet is closed.

        :param message: plaintext, as bytes
        :param authn: whether to use authenticated encryption scheme
        :param verkey: verification key of recipient, None for anchor's own
        :return: ciphertext, as bytes
        """

        LOGGER.debug('Wallet.encrypt >>> message: %s, authn: %s, verkey: %s', message, authn, verkey)

        if not message:
            LOGGER.debug('Wallet.encrypt <!< No message to encrypt')
            raise AbsentMessage('No message to encrypt')

        if not self.handle:
            LOGGER.debug('Wallet.encrypt <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        if authn:
            rv = await crypto.auth_crypt(self.handle, self.verkey, verkey or self.verkey, message)
        else:
            rv = await crypto.anon_crypt(verkey or self.verkey, message)

        LOGGER.debug('Wallet.auth_encrypt <<< %s', rv)
        return rv

    async def decrypt(self, ciphertext: bytes, verkey: str = None) -> bytes:
        """
        Decrypt ciphertext and optionally authenticate sender.

        Raise BadKey if authentication operation reveals sender key distinct from input
        verification key.  Raise AbsentMessage for missing ciphertext, or WalletState if
        wallet is closed.

        :param ciphertext: ciphertext, as bytes
        :param verkey: sender's verification, or None for anonymously encrypted ciphertext
        :return: decrypted bytes
        """

        LOGGER.debug('Wallet.decrypt >>> ciphertext: %s, verkey: %s', ciphertext, verkey)

        if not ciphertext:
            LOGGER.debug('Wallet.decrypt <!< No ciphertext to decrypt')
            raise AbsentMessage('No ciphertext to decrypt')

        if not self.handle:
            LOGGER.debug('Wallet.decrypt <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        if verkey:
            (sender_verkey, rv) = await crypto.auth_decrypt(self.handle, self.verkey, ciphertext)
            if sender_verkey != verkey:
                LOGGER.debug('Wallet.decrypt <!< Authentication revealed unexpected sender key on decryption')
                raise BadKey('Authentication revealed unexpected sender key on decryption')
        else:
            rv = await crypto.anon_decrypt(self.handle, self.verkey, ciphertext)

        LOGGER.debug('Wallet.decrypt <<< %s', rv)
        return rv

    async def sign(self, message: bytes, verkey: str = None) -> bytes:
        """
        Derive signing key and Sign message; return signature. Raise WalletState if wallet is closed.
        Raise AbsentMessage for missing message, or WalletState if wallet is closed.

        :param message: Content to sign, as bytes
        :param verkey: verification key corresponding to private signing key (default anchor's own)
        :return: signature, as bytes
        """

        LOGGER.debug('Wallet.sign >>> message: %s, verkey: %s', message, verkey)

        if not message:
            LOGGER.debug('Wallet.sign <!< No message to sign')
            raise AbsentMessage('No message to sign')

        if not self.handle:
            LOGGER.debug('Wallet.sign <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = await crypto.crypto_sign(self.handle, verkey or self.verkey, message)

        LOGGER.debug('Wallet.sign <<< %s', rv)
        return rv

    async def verify(self, message: bytes, signature: bytes, verkey: str = None) -> bool:
        """
        Verify signature against input signer verification key (default anchor's own).
        Raise AbsentMessage for missing message, or WalletState if wallet is closed.

        :param message: Content to sign, as bytes
        :param signature: signature, as bytes
        :param verkey: signer verification key (default for anchor's own)
        :return: whether signature is valid
        """

        LOGGER.debug('Wallet.verify >>> message: %s, signature: %s, verkey: %s', message, signature, verkey)

        if not message:
            LOGGER.debug('Wallet.verify <!< No message to verify')
            raise AbsentMessage('No message to verify')

        if not self.handle:
            LOGGER.debug('Wallet.verify <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = await crypto.crypto_verify(verkey or self.verkey, message, signature)

        LOGGER.debug('Wallet.verify <<< %s', rv)
        return rv

    async def pack(self, message: str, recip_verkeys: Sequence[str] = None, sender_verkey: str = None) -> bytes:
        """
        Pack a message for one or more recipients (default anchor only).
        Raise AbsentMessage for missing message, or WalletState if wallet is closed.

        :param message: message to pack
        :param recip_verkeys: verification keys of recipients (default anchor's own, only)
        :param sender_verkey: sender verification key (default anonymous encryption)
        :return: packed message
        """

        LOGGER.debug(
            'Wallet.pack >>> message: %s, recip_verkeys: %s, sender_verkey: %s',
            message,
            recip_verkeys,
            sender_verkey)

        if not message:
            LOGGER.debug('Wallet.pack <!< No message to pack')
            raise AbsentMessage('No message to pack')

        rv = await crypto.pack_message(
            self.handle,
            message,
            [recip_verkeys] if isinstance(recip_verkeys, str) else list(recip_verkeys or [self.verkey]),
            sender_verkey)

        LOGGER.debug('Wallet.pack <<< %s', rv)
        return rv

    async def unpack(self, ciphertext: bytes) -> (str, str, str):
        """
        Unpack a message. Return triple with cleartext, sender verification key, and recipient verification key.
        Raise AbsentMessage for missing ciphertext, or WalletState if wallet is closed. Raise AbsentRecord
        if wallet has no key to unpack ciphertext.

        :param ciphertext: JWE-like formatted message as pack() produces
        :return: cleartext, sender verification key, recipient verification key
        """

        LOGGER.debug('Wallet.unpack >>> ciphertext: %s', ciphertext)

        if not ciphertext:
            LOGGER.debug('Wallet.pack <!< No ciphertext to unpack')
            raise AbsentMessage('No ciphertext to unpack')

        try:
            unpacked = json.loads(await crypto.unpack_message(self.handle, ciphertext))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                LOGGER.debug('Wallet.unpack <!< Wallet %s has no local key to unpack ciphertext', self.name)
                raise AbsentRecord('Wallet {} has no local key to unpack ciphertext'.format(self.name))
            else:
                LOGGER.debug('Wallet.unpack <!< Wallet %s unpack() raised indy error code {}', x_indy.error_code)
                raise
        rv = (unpacked['message'], unpacked.get('recipient_verkey', None), unpacked.get('sender_verkey', None))

        LOGGER.debug('Wallet.unpack <<< %s', rv)
        return rv

    async def reseed_init(self, next_seed) -> str:
        """
        Begin reseed operation: generate new key. Raise WalletState if wallet is closed.

        :param seed: incoming replacement seed
        :return: new verification key
        """

        LOGGER.debug('Wallet.reseed_init >>> next_seed: [SEED]')

        if not self.handle:
            LOGGER.debug('Wallet.reseed_init <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        self._next_seed = next_seed
        rv = await did.replace_keys_start(self.handle, self.did, json.dumps({'seed': next_seed}))
        LOGGER.debug('Wallet.reseed_init <<< %s', rv)
        return rv

    async def reseed_apply(self) -> None:
        """
        Replace verification key with new verification key from reseed operation.
        Raise WalletState if wallet is closed.
        """

        LOGGER.debug('Wallet.reseed_apply >>>')

        if not self.handle:
            LOGGER.debug('Wallet.reseed_init <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        await did.replace_keys_apply(self.handle, self.did)
        self.verkey = await did.key_for_local_did(self.handle, self.did)

        await did.set_did_metadata(
            self.handle,
            self.did,
            json.dumps({
                'anchor': True,
                'since': int(time())
            }))

        LOGGER.info('Wallet %s set seed hash metadata for DID %s', self.name, self.did)
        self._next_seed = None

        LOGGER.debug('Wallet.reseed_apply <<<')

    async def remove(self) -> None:
        """
        Remove serialized wallet if it exists. Raise WalletState if wallet is open.
        """

        LOGGER.debug('Wallet.remove >>>')

        if self.handle:
            LOGGER.debug('Wallet.reseed_init <!< Wallet %s is open', self.name)
            raise WalletState('Wallet {} is open'.format(self.name))

        try:
            LOGGER.info('Removing wallet: %s', self.name)
            await wallet.delete_wallet(
                json.dumps(self.config),
                json.dumps(self.access_creds or Wallet.DEFAULT_ACCESS_CREDS))
        except IndyError as x_indy:
            LOGGER.info('Abstaining from wallet removal; indy-sdk error code %s', x_indy.error_code)

        LOGGER.debug('Wallet.remove <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}({}, {}, {}, [ACCESS_CREDS])'.format(
            self.__class__.__name__,
            self.name,
            self.storage_type,
            self.config)


async def register_wallet_storage_library(storage_type: str, c_library: str, entry_point: str) -> None:
    """
    Load a wallet storage plug-in.

    An indy-sdk wallet storage plug-in is a shared library; relying parties must explicitly
    load it before creating or opening a wallet with the plug-in.

    The implementation loads a dynamic library and calls an entry point; internally,
    the plug-in calls the indy-sdk wallet
    async def register_wallet_storage_library(storage_type: str, c_library: str, fn_pfx: str).

    :param storage_type: wallet storage type
    :param c_library: plug-in library
    :param entry_point: function to initialize the library
    """

    LOGGER.debug(
        'register_wallet_storage_library >>> storage_type %s, c_library %s, entry_point %s',
        storage_type,
        c_library,
        entry_point)

    try:
        stg_lib = CDLL(c_library)
        result = stg_lib[entry_point]()
        if result:
            raise IndyError(result)

        LOGGER.info('Loaded wallet library type %s (%s)', storage_type, c_library)
    except IndyError as x_indy:
        LOGGER.debug(
            'Wallet.register <!< indy error code %s on load of wallet storage %s %s',
            x_indy.error_code,
            storage_type,
            c_library)
        raise

    LOGGER.debug('register_wallet_storage_library <<<')
