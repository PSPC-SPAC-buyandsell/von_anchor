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

from time import time
from typing import Callable, Sequence, Union

from indy import anoncreds, crypto, did, non_secrets, wallet
from indy.error import IndyError, ErrorCode

from von_anchor.canon import canon_non_secret_wql, canon_pairwise_wql
from von_anchor.error import (
    AbsentRecord,
    AbsentMessage,
    AbsentWallet,
    BadAccess,
    BadKey,
    BadIdentifier,
    BadRecord,
    ExtantRecord,
    ExtantWallet,
    WalletState)
from von_anchor.util import ok_did
from von_anchor.wallet import DIDInfo, KeyInfo, storage_record2pairwise_info, PairwiseInfo, pairwise_info2tags
from von_anchor.wallet.record import StorageRecord, TYPE_PAIRWISE, TYPE_LINK_SECRET_LABEL


LOGGER = logging.getLogger(__name__)


class Wallet:
    """
    Class encapsulating indy-sdk wallet.
    """

    DEFAULT_CHUNK = 256  # chunk size in searching credentials, non-secret storage records

    def __init__(self, indy_config: dict, von_config: dict) -> None:
        """
        Initializer for wallet that WalletManager created. Store configuration and access credentials value.

        Actuators should prefer WalletManager.get() to calling this initializer directly - the wallet manager
        filters wallet configuration through preset defaults.

        :param indy_config: configuration for indy-sdk wallet
        :param von_config: VON wallet configuration particulars:

            - 'seed': (optional) seed to use on creation
            - 'did': (optional) anchor DID to use on creation
            - 'link_secret_label': (optional) label to use to create link secret
            - 'auto_create': whether to create wallet automatically on first open
            - 'auto_remove': whether to remove wallet automatically on next close
            - 'access': wallet access credentials value

        """

        LOGGER.debug('Wallet.__init__ >>> indy_config %s, von_config %s', indy_config, von_config)

        self._handle = None
        self._indy_config = {**indy_config}  # make a copy
        self._von_config = {**von_config}
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
    def opened(self) -> bool:
        """
        Accessor for indy-sdk wallet state: True for open, False for closed.

        :return: indy-sdk wallet state
        """

        return bool(self._handle)

    @property
    def config(self) -> dict:
        """
        Accessor for wallet config.

        :return: wallet config
        """

        return self._indy_config

    @property
    def auto_create(self) -> bool:
        """
        Accessor for auto_create wallet config setting.

        :return: auto_create wallet config setting
        """

        return self._von_config['auto_create']

    @auto_create.setter
    def auto_create(self, value: bool) -> None:
        """
        Set auto_create wallet config behaviour.

        :param value: auto_create
        """

        self._von_config['auto_create'] = value

    @property
    def auto_remove(self) -> bool:
        """
        Accessor for auto_remove wallet config setting.

        :return: auto_remove wallet config setting
        """

        return self._von_config['auto_remove']

    @auto_remove.setter
    def auto_remove(self, value: bool) -> None:
        """
        Set auto_remove wallet config behaviour.

        :param value: auto_remove
        """

        self._von_config['auto_remove'] = value

    @property
    def access_creds(self) -> dict:
        """
        Accessor for wallet access credentials.

        :return: wallet access credentials
        """

        return {'key': self._von_config['access']}

    @property
    def access(self) -> str:
        """
        Accessor for wallet access credentials value.

        :return: wallet access credentials value
        """

        return self._von_config['access']

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

    @did.setter
    def did(self, value: str) -> None:
        """
        Set anchor DID in wallet.

        :param value: anchor DID
        """

        self._did = value

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

    async def create_signing_key(self, seed: str = None, metadata: dict = None) -> KeyInfo:
        """
        Create a new signing key pair.

        Raise WalletState if wallet is closed, ExtantRecord if verification key already exists.

        :param seed: optional seed allowing deterministic key creation
        :param metadata: optional metadata to store with key pair
        :return: KeyInfo for new key pair
        """

        LOGGER.debug('Wallet.create_signing_key >>> seed: [SEED], metadata: %s', metadata)

        if not self.handle:
            LOGGER.debug('Wallet.create_signing_key <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        try:
            verkey = await crypto.create_key(self.handle, json.dumps({'seed': seed} if seed else {}))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemAlreadyExists:
                LOGGER.debug('Wallet.create_signing_key <!< Verification key already present in wallet %s', self.name)
                raise ExtantRecord('Verification key already present in wallet {}'.format(self.name))
            LOGGER.debug('Wallet.create_signing_key <!< indy-sdk raised error %s', x_indy.error_code)
            raise

        await crypto.set_key_metadata(self.handle, verkey, json.dumps(metadata or {}))  # coerce None to empty

        rv = KeyInfo(verkey, metadata or {})
        LOGGER.debug('Wallet.create_signing_key <<< %s', rv)
        return rv

    async def get_signing_key(self, verkey: str) -> KeyInfo:
        """
        Get signing key pair for input verification key.

        Raise WalletState if wallet is closed, AbsentRecord for no such key pair.

        :param verkey: verification key of key pair
        :return: KeyInfo for key pair
        """

        LOGGER.debug('Wallet.get_signing_key >>> seed: [SEED], verkey: %s', verkey)

        if not self.handle:
            LOGGER.debug('Wallet.get_signing_key <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        try:
            metadata = await crypto.get_key_metadata(self.handle, verkey)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                LOGGER.debug('Wallet.get_signing_key <!< Verification key %s not in wallet %s', verkey, self.name)
                raise AbsentRecord('Verification key not in wallet {}'.format(self.name))
            LOGGER.debug('Wallet.get_signing_key <!< indy-sdk raised error %s', x_indy.error_code)
            raise

        rv = KeyInfo(verkey, json.loads(metadata) if metadata else {})
        LOGGER.debug('Wallet.get_signing_key <<< %s', rv)
        return rv

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict) -> KeyInfo:
        """
        Replace the metadata associated with a signing key pair.

        Raise WalletState if wallet is closed, AbsentRecord for no such key pair.

        :param verkey: verification key of key pair
        :param metadata: new metadata to store
        :return: resulting KeyInfo for key pair
        """

        LOGGER.debug('Wallet.replace_signing_key_metadata >>> verkey: %s, metadata: %s', verkey, metadata)

        if not self.handle:
            LOGGER.debug('Wallet.replace_signing_key_metadata <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        try:
            await crypto.get_key_metadata(self.handle, verkey)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                LOGGER.debug(
                    'Wallet.replace_signing_key_metadata <!< Verification key %s not in wallet %s',
                    verkey,
                    self.name)
                raise AbsentRecord('Verification key not in wallet {}'.format(self.name))
            LOGGER.debug('Wallet.replace_signing_key_metadata <!< indy-sdk raised error %s', x_indy.error_code)
            raise

        await crypto.set_key_metadata(self.handle, verkey, json.dumps(metadata or {}))

        rv = await self.get_signing_key(verkey)
        LOGGER.debug('Wallet.replace_signing_key_metadata <<< %s', rv)
        return rv

    async def create_local_did(self, seed: str = None, loc_did: str = None, metadata: dict = None) -> DIDInfo:
        """
        Create and store a new local DID for use in pairwise DID relations.

        :param seed: seed from which to create (default random)
        :param loc_did: local DID value (default None to let indy-sdk generate)
        :param metadata: metadata to associate with the local DID
            (operation always sets 'since', 'modified' epoch timestamps)
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
            LOGGER.debug('Wallet.create_local_did <!< indy-sdk raised error %s', x_indy.error_code)
            raise

        now = int(time())
        loc_did_metadata = {**(metadata or {}), 'since': now, 'modified': now}
        await did.set_did_metadata(self.handle, created_did, json.dumps(loc_did_metadata))

        rv = DIDInfo(created_did, verkey, loc_did_metadata)

        LOGGER.debug('Wallet.create_local_did <<< %s', rv)
        return rv

    async def replace_local_did_metadata(self, loc_did: str, metadata: dict) -> DIDInfo:
        """
        Replace the metadata associated with a local DID.

        Raise WalletState if wallet is closed, AbsentRecord for no such local DID.

        :param loc_did: local DID of interest
        :param metadata: new metadata to store
        :return: DIDInfo for local DID after write
        """

        LOGGER.debug('Wallet.replace_local_did_metadata >>> loc_did: %s, metadata: %s', loc_did, metadata)

        old = await self.get_local_did(loc_did)  # raises exceptions if applicable
        now = int(time())
        loc_did_metadata = {**(metadata or {}), 'since': (old.metadata or {}).get('since', now), 'modified': now}
        try:
            await did.set_did_metadata(self.handle, loc_did, json.dumps(loc_did_metadata))
        except IndyError as x_indy:
            LOGGER.debug('Wallet.replace_local_did_metadata <!< indy-sdk raised error %s', x_indy.error_code)
            raise

        rv = await self.get_local_did(loc_did)
        LOGGER.debug('Wallet.replace_local_did_metadata <<< %s', rv)
        return rv

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """
        Get list of DIDInfos for local DIDs.

        :return: list of local DIDInfos
        """

        LOGGER.debug('Wallet.get_local_dids >>>')

        dids_with_meta = json.loads(did.list_my_dids_with_meta(self.handle))  # list

        rv = []
        for did_with_meta in dids_with_meta:
            meta = json.loads(did_with_meta['metadata']) if did_with_meta['metadata'] else {}
            if meta.get('anchor', False):
                continue  # exclude anchor DIDs past and present
            rv.append(DIDInfo(did_with_meta['did'], did_with_meta['verkey'], meta))

        LOGGER.debug('Wallet.get_local_dids <<< %s', rv)
        return rv

    async def get_local_did(self, loc: str) -> DIDInfo:
        """
        Get local DID info by local DID or verification key.
        Raise AbsentRecord for no such local DID.

        :param loc: DID or verification key of interest
        :return: DIDInfo for local DID
        """

        LOGGER.debug('Wallet.get_local_did >>> loc: %s', loc)

        if not self.handle:
            LOGGER.debug('Wallet.get_local_did <!< Wallet %s is closed', self.name)
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
                    LOGGER.debug('Wallet.get_local_did <!< DID %s not present in wallet %s', loc, self.name)
                    raise AbsentRecord('Local DID {} not present in wallet {}'.format(loc, self.name))
                LOGGER.debug('Wallet.get_local_did <!< indy-sdk raised error %s', x_indy.error_code)
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
                LOGGER.debug('Wallet.get_local_did <!< Wallet %s has no local DID for verkey %s', self.name, loc)
                raise AbsentRecord('Wallet {} has no local DID for verkey {}'.format(self.name, loc))

        LOGGER.debug('Wallet.get_local_did <<< %s', rv)
        return rv

    async def get_anchor_did(self) -> str:
        """
        Get current anchor DID by metadata, None for not yet set.

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

        LOGGER.debug('Wallet.get_anchor_did <<< %s', rv)
        return rv

    async def create_link_secret(self, label: str) -> None:
        """
        Create link secret (a.k.a. master secret) used in proofs by HolderProver, if the
        current link secret does not already correspond to the input link secret label.

        Raise WalletState if wallet is closed, or any other IndyError causing failure
        to set link secret in wallet.

        :param label: label for link secret; indy-sdk uses label to generate link secret
        """

        LOGGER.debug('Wallet.create_link_secret >>> label: %s', label)

        if not self.handle:
            LOGGER.debug('Wallet.create_link_secret <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        try:
            await anoncreds.prover_create_master_secret(self.handle, label)
            await self._write_link_secret_label(label)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.AnoncredsMasterSecretDuplicateNameError:
                LOGGER.warning(
                    'Wallet %s link secret already current: abstaining from updating label record', self.name)
                await self._write_link_secret_label(label)
            else:
                LOGGER.debug(
                    'Wallet.create_link_secret <!< cannot create link secret for wallet %s, indy error code %s',
                    self.name,
                    x_indy.error_code)
                raise

        LOGGER.debug('Wallet.create_link_secret <<<')

    async def _write_link_secret_label(self, label) -> None:
        """
        Update non-secret storage record with link secret label.

        :param label: link secret label
        """

        LOGGER.debug('Wallet._write_link_secret_label <<< %s', label)

        if await self.get_link_secret_label() == label:
            LOGGER.info('Wallet._write_link_secret_label abstaining - already current')
        else:
            await self.write_non_secret(StorageRecord(
                TYPE_LINK_SECRET_LABEL,
                label,
                tags=None,
                ident=str(int(time()))))  # indy requires str

        LOGGER.debug('Wallet._write_link_secret_label <<<')

    async def get_link_secret_label(self) -> str:
        """
        Get current link secret label from non-secret storage records; return None for no match.

        :return: latest non-secret storage record for link secret label
        """

        LOGGER.debug('Wallet.get_link_secret_label >>>')

        if not self.handle:
            LOGGER.debug('Wallet.get_link_secret <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = None
        records = await self.get_non_secret(TYPE_LINK_SECRET_LABEL)
        if records:
            rv = records[str(max(int(k) for k in records))].value  # str to int, max, and back again

        LOGGER.debug('Wallet.get_link_secret_label <<< %s', rv)
        return rv

    async def __aenter__(self) -> 'Wallet':
        """
        Context manager entry. Open wallet as configured, for closure on context manager exit.
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

        created = False
        while True:
            try:
                self._handle = await wallet.open_wallet(
                    json.dumps(self.config),
                    json.dumps(self.access_creds))
                LOGGER.info('Opened wallet %s on handle %s', self.name, self.handle)
                break
            except IndyError as x_indy:
                if x_indy.error_code == ErrorCode.WalletNotFoundError:
                    if created:
                        LOGGER.debug('Wallet.open() <!< Wallet %s not found after creation', self.name)
                        raise AbsentWallet('Wallet {} not found after creation'.format(self.name))
                    if self.auto_create:
                        await self.create()
                        continue
                    else:
                        LOGGER.debug('Wallet.open() <!< Wallet %s not found', self.name)
                        raise AbsentWallet('Wallet {} not found'.format(self.name))
                elif x_indy.error_code == ErrorCode.WalletAlreadyOpenedError:
                    LOGGER.debug('Wallet.open() <!< Wallet %s is already open', self.name)
                    raise WalletState('Wallet {} is already open'.format(self.name))
                elif x_indy.error_code == ErrorCode.WalletAccessFailed:
                    LOGGER.debug('Wallet.open() <!< Bad access credentials value for wallet %s', self.name)
                    raise BadAccess('Bad access credentials value for wallet {}'.format(self.name))

                LOGGER.debug('Wallet %s open raised indy error %s', self.name, x_indy.error_code)
                raise

        self.did = await self.get_anchor_did()
        self.verkey = await did.key_for_local_did(self.handle, self.did) if self.did else None
        LOGGER.info('Wallet %s got verkey %s for existing DID %s', self.name, self.verkey, self.did)

        LOGGER.debug('Wallet.open <<<')
        return self

    async def create(self) -> None:
        """
        Persist the wallet. Raise ExtantWallet if it already exists.

        Actuators should prefer WalletManager.create() to calling this method directly - the wallet manager
        filters wallet configuration through preset defaults.
        """

        LOGGER.debug('Wallet.create >>>')

        try:
            await wallet.create_wallet(
                config=json.dumps(self.config),
                credentials=json.dumps(self.access_creds))
            LOGGER.info('Created wallet %s', self.name)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletAlreadyExistsError:
                LOGGER.debug('Wallet.create <!< Wallet %s already exists', self.name)
                raise ExtantWallet('Wallet {} already exists'.format(self.name))
            LOGGER.debug(
                'Wallet.create <!< indy error code %s on creation of wallet %s',
                x_indy.error_code,
                self.name)
            raise

        auto_remove = self.auto_remove
        self.auto_remove = False  # defer past this creation process
        async with self:
            did_info = await self.create_local_did(
                self._von_config.get('seed', None),
                self._von_config.get('did', None),
                {'anchor': True})
            self.did = did_info.did
            self.verkey = did_info.verkey
            if 'link_secret_label' in self._von_config:
                await self.create_link_secret(self._von_config['link_secret_label'])
        self.auto_remove = auto_remove

        LOGGER.debug('Wallet.create <<<')

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
        """

        LOGGER.debug('Wallet.close >>>')

        if not self.handle:
            LOGGER.warning('Abstaining from closing wallet %s: already closed', self.name)
        else:
            LOGGER.debug('Closing wallet %s', self.name)
            await wallet.close_wallet(self.handle)
            self._handle = None
            if self.auto_remove:
                LOGGER.info('Automatically removing wallet %s', self.name)
                await self.remove()
        self._handle = None

        LOGGER.debug('Wallet.close <<<')

    async def remove(self) -> bool:
        """
        Remove serialized wallet, best effort, if it exists. Return whether wallet absent after operation
        (removal successful or else not present a priori).

        Raise WalletState if wallet is open.

        :return: whether wallet gone from persistent storage
        """

        LOGGER.debug('Wallet.remove >>>')

        if self.handle:
            LOGGER.debug('Wallet.remove <!< Wallet %s is open', self.name)
            raise WalletState('Wallet {} is open'.format(self.name))

        rv = True
        try:
            LOGGER.info('Attempting to remove wallet: %s', self.name)
            await wallet.delete_wallet(
                json.dumps(self.config),
                json.dumps(self.access_creds))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletNotFoundError:
                LOGGER.info('Wallet %s not present; abstaining from removal', self.name)
            else:
                LOGGER.info('Failed wallet %s removal; indy-sdk error code %s', self.name, x_indy.error_code)
                rv = False

        LOGGER.debug('Wallet.remove <<< %s', rv)
        return rv

    async def write_pairwise(
            self,
            their_did: str,
            their_verkey: str = None,
            my_did: str = None,
            metadata: dict = None,
            replace_meta: bool = False) -> PairwiseInfo:
        """
        Store a pairwise DID for a secure connection. Use verification key for local DID in wallet if
        supplied; otherwise, create one first. If local DID specified but not present, raise AbsentRecord.

        With supplied metadata, replace or augment and overwrite any existing metadata for the pairwise
        relation if one already exists in the wallet. Always include local and remote DIDs and keys in
        metadata to allow for WQL search.

        Raise AbsentRecord on call to update a non-existent record. Raise BadRecord if metadata does not
        coerce into non-secrets API tags specification {str:str}.

        :param their_did: remote DID
        :param their_verkey: remote verification key (default None is OK if updating an existing pairwise DID)
        :param my_did: local DID (default None prompts operation to generate one at random)
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

        if their_verkey is None:
            match = await self.get_pairwise(their_did)
            if not match:
                LOGGER.debug(
                    'Wallet.write_pairwise <!< Wallet %s has no pairwise DID on %s to update',
                    self.name,
                    their_did)
                raise AbsentRecord('Wallet {} has no pairwise DID on {} to update'.format(self.name, their_did))
            their_verkey = [pwise for pwise in match.values()][0].their_verkey

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
            my_did_info = await self.get_local_did(my_did)  # raises AbsentRecord if no such local did
        else:
            my_did_info = await self.create_local_did(None, None, {'pairwise_for': their_did})

        pairwise = PairwiseInfo(their_did, their_verkey, my_did_info.did, my_did_info.verkey, metadata)
        try:
            storec = await self.write_non_secret(
                StorageRecord(TYPE_PAIRWISE, their_verkey, tags=pairwise_info2tags(pairwise), ident=their_did),
                replace_meta)
        except BadRecord:
            LOGGER.debug(
                'Wallet.write_pairwise <!< Pairwise metadata %s does not coerce into flat {str:str} tags dict',
                pairwise.metadata)
            raise

        rv = storage_record2pairwise_info(storec)
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

        storecs = await self.get_non_secret(
            TYPE_PAIRWISE,
            pairwise_filt if not pairwise_filt or ok_did(pairwise_filt) else json.loads(pairwise_filt),
            canon_pairwise_wql)
        rv = {k: storage_record2pairwise_info(storecs[k]) for k in storecs}  # touch up tags, mute leading ~

        LOGGER.debug('Wallet.get_pairwise <<< %s', rv)
        return rv

    async def write_non_secret(self, storec: StorageRecord, replace_meta: bool = False) -> StorageRecord:
        """
        Add or update non-secret storage record to the wallet; return resulting wallet non-secret record.

        :param storec: non-secret storage record
        :param replace_meta: whether to replace any existing metadata on matching record or to augment it
        :return: non-secret storage record as it appears in the wallet after write
        """

        LOGGER.debug('Wallet.write_non_secret >>> storec: %s, replace_meta: %s', storec, replace_meta)

        if not self.handle:
            LOGGER.debug('Wallet.write_non_secret <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        if not StorageRecord.ok_tags(storec.tags):
            LOGGER.debug('Wallet.write_non_secret <!< bad storage record tags %s; use flat {str: str} dict', storec)
            raise BadRecord('Bad storage record tags {}; use flat {{str:str}} dict'.format(storec))

        try:
            record = json.loads(await non_secrets.get_wallet_record(
                self.handle,
                storec.type,
                storec.id,
                json.dumps({
                    'retrieveType': False,
                    'retrieveValue': True,
                    'retrieveTags': True
                })))
            if record['value'] != storec.value:
                await non_secrets.update_wallet_record_value(
                    self.handle,
                    storec.type,
                    storec.id,
                    storec.value)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                await non_secrets.add_wallet_record(
                    self.handle,
                    storec.type,
                    storec.id,
                    storec.value,
                    json.dumps(storec.tags) if storec.tags else None)
            else:
                LOGGER.debug(
                    'Wallet.write_non_secret <!< Wallet lookup raised indy error code %s',
                    x_indy.error_code)
                raise
        else:
            if (record['tags'] or None) != storec.tags:  # record maps no tags to {}, not None
                tags = (storec.tags or {}) if replace_meta else {**record['tags'], **(storec.tags or {})}

                await non_secrets.update_wallet_record_tags(
                    self.handle,
                    storec.type,
                    storec.id,
                    json.dumps(tags))  # indy-sdk takes '{}' instead of None for null tags

        record = json.loads(await non_secrets.get_wallet_record(
            self.handle,
            storec.type,
            storec.id,
            json.dumps({
                'retrieveType': False,
                'retrieveValue': True,
                'retrieveTags': True
            })))

        rv = StorageRecord(storec.type, record['value'], tags=record.get('tags', None), ident=record['id'])
        LOGGER.debug('Wallet.write_non_secret <<< %s', rv)
        return rv

    async def delete_non_secret(self, typ: str, ident: str) -> None:
        """
        Remove a non-secret record by its type and identifier. Silently return if no such record is present.
        Raise WalletState for closed wallet.

        :param typ: non-secret storage record type
        :param ident: non-secret storage record identifier
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
            canon_wql: Callable[[dict], dict] = None,
            limit: int = None) -> dict:
        """
        Return dict mapping each non-secret storage record of interest by identifier or,
        for no filter specified, mapping them all. If wallet has no such item, return empty dict.

        :param typ: non-secret storage record type
        :param filt: non-secret storage record identifier or WQL json (default all)
        :param canon_wql: WQL canonicalization function (default von_anchor.canon.canon_non_secret_wql())
        :param limit: maximum number of results to return (default no limit)
        :return: dict mapping identifiers to non-secret storage records
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

            records = []
            cardinality = int(json.loads(
                await non_secrets.fetch_wallet_search_next_records(self.handle, s_handle, 0))['totalCount'])
            chunk = min(cardinality, limit or cardinality, Wallet.DEFAULT_CHUNK)
            if limit:
                cardinality = min(limit, cardinality)
            try:
                while len(records) != cardinality:
                    batch = json.loads(
                        await non_secrets.fetch_wallet_search_next_records(self.handle, s_handle, chunk))['records']
                    records.extend(batch)
                    if len(batch) < chunk:
                        break
                if len(records) != cardinality:
                    LOGGER.warning(
                        'Non-secret search/limit indicated %s results but fetched %s',
                        cardinality,
                        len(records))
            finally:
                await non_secrets.close_wallet_search(s_handle)

        rv = {record['id']: StorageRecord(typ, record['value'], record['tags'], record['id']) for record in records}
        LOGGER.debug('Wallet.get_non_secret <<< %s', rv)
        return rv

    async def encrypt(
            self,
            message: bytes,
            authn: bool = False,
            to_verkey: str = None,
            from_verkey: str = None) -> bytes:
        """
        Encrypt plaintext for owner of DID, anonymously or via authenticated encryption scheme.
        Raise AbsentMessage for missing message, or WalletState if wallet is closed.

        :param message: plaintext, as bytes
        :param authn: whether to use authenticated encryption scheme
        :param to_verkey: verification key of recipient, None for anchor's own
        :param from_verkey: verification key of sender for authenticated encryption, None for anchor's own
        :return: ciphertext, as bytes
        """

        LOGGER.debug(
            'Wallet.encrypt >>> message: %s, authn: %s, to_verkey: %s, from_verkey: %s',
            message,
            authn,
            to_verkey,
            from_verkey)

        if not message:
            LOGGER.debug('Wallet.encrypt <!< No message to encrypt')
            raise AbsentMessage('No message to encrypt')

        if not self.handle:
            LOGGER.debug('Wallet.encrypt <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        if authn:
            rv = await crypto.auth_crypt(self.handle, from_verkey or self.verkey, to_verkey or self.verkey, message)
        else:
            rv = await crypto.anon_crypt(to_verkey or self.verkey, message)

        LOGGER.debug('Wallet.auth_encrypt <<< %s', rv)
        return rv

    async def decrypt(
            self,
            ciphertext: bytes,
            authn_check: bool = None,
            to_verkey: str = None,
            from_verkey: str = None) -> (bytes, str):
        """
        Decrypt ciphertext and optionally authenticate sender.

        Raise BadKey if authentication operation checks and reveals sender key distinct from input
        sender verification key.  Raise AbsentMessage for missing ciphertext, or WalletState if
        wallet is closed.

        :param ciphertext: ciphertext, as bytes
        :param authn_check: True to authenticate and check sender verification key,
            False to authenticate and return sender verification key for client to decide fitness, or
            None to use anonymous decryption
        :param to_verkey: recipient verification key, default anchor's own
        :param from_verkey: sender verification key, ignored for anonymous decryption,
            default anchor's own for authenticated decryption
        :return: decrypted bytes and sender verification key (None for anonymous decryption)
        """

        LOGGER.debug(
            'Wallet.decrypt >>> ciphertext: %s, authn_check: %s, to_verkey: %s, from_verkey: %s',
            ciphertext,
            authn_check,
            to_verkey,
            from_verkey)

        if not ciphertext:
            LOGGER.debug('Wallet.decrypt <!< No ciphertext to decrypt')
            raise AbsentMessage('No ciphertext to decrypt')

        if not self.handle:
            LOGGER.debug('Wallet.decrypt <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        sender_verkey = None
        if authn_check is None:
            plaintext = await crypto.anon_decrypt(self.handle, to_verkey or self.verkey, ciphertext)
        else:
            (sender_verkey, plaintext) = await crypto.auth_decrypt(self.handle, to_verkey or self.verkey, ciphertext)
            if authn_check and sender_verkey != (from_verkey or self.verkey):
                LOGGER.debug('Wallet.decrypt <!< Authentication revealed unexpected sender key on decryption')
                raise BadKey('Authentication revealed unexpected sender key on decryption')

        rv = (plaintext, sender_verkey)
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
        Raise AbsentMessage for missing message or signature, or WalletState if wallet is closed.

        :param message: Content to sign, as bytes
        :param signature: signature, as bytes
        :param verkey: signer verification key (default for anchor's own)
        :return: whether signature is valid
        """

        LOGGER.debug('Wallet.verify >>> message: %s, signature: %s, verkey: %s', message, signature, verkey)

        if not message:
            LOGGER.debug('Wallet.verify <!< No message to verify')
            raise AbsentMessage('No message to verify')

        if not signature:
            LOGGER.debug('Wallet.verify <!< No signature to verify')
            raise AbsentMessage('No signature to verify')

        if not self.handle:
            LOGGER.debug('Wallet.verify <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = await crypto.crypto_verify(verkey or self.verkey, message, signature)

        LOGGER.debug('Wallet.verify <<< %s', rv)
        return rv

    async def pack(
            self,
            message: str,
            recip_verkeys: Union[str, Sequence[str]] = None,
            sender_verkey: str = None) -> bytes:
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

        if message is None:
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
            LOGGER.debug('Wallet.unpack <!< Wallet %s unpack() raised indy error code {}', x_indy.error_code)
            raise

        rv = (unpacked['message'], unpacked.get('sender_verkey', None), unpacked.get('recipient_verkey', None))
        LOGGER.debug('Wallet.unpack <<< %s', rv)
        return rv

    async def reseed_init(self, next_seed: str = None) -> str:
        """
        Begin reseed operation: generate new key. Raise WalletState if wallet is closed.

        :param next_seed: incoming replacement seed (default random)
        :return: new verification key
        """

        LOGGER.debug('Wallet.reseed_init >>> next_seed: [SEED]')

        if not self.handle:
            LOGGER.debug('Wallet.reseed_init <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        rv = await did.replace_keys_start(self.handle, self.did, json.dumps({'seed': next_seed} if next_seed else {}))
        LOGGER.debug('Wallet.reseed_init <<< %s', rv)
        return rv

    async def reseed_apply(self) -> DIDInfo:
        """
        Replace verification key with new verification key from reseed operation.
        Raise WalletState if wallet is closed.

        :return: DIDInfo with new verification key and metadata for DID
        """

        LOGGER.debug('Wallet.reseed_apply >>>')

        if not self.handle:
            LOGGER.debug('Wallet.reseed_init <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        await did.replace_keys_apply(self.handle, self.did)
        self.verkey = await did.key_for_local_did(self.handle, self.did)
        now = int(time())
        rv = DIDInfo(self.did, self.verkey, {'anchor': True, 'since': now, 'modified': now})
        await did.set_did_metadata(self.handle, self.did, json.dumps(rv.metadata))

        LOGGER.info('Wallet %s set seed hash metadata for DID %s', self.name, self.did)

        LOGGER.debug('Wallet.reseed_apply <<< %s', rv)
        return rv

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'Wallet({}, [ACCESS], {})'.format(self.config, self.auto_remove)
