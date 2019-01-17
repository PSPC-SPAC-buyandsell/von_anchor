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
from hashlib import sha256
from time import time

from indy import did, wallet
from indy.error import IndyError, ErrorCode

from von_anchor.error import AbsentMetadata, AbsentWallet, ExtantWallet
from von_anchor.validcfg import validate_config


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

        self._config = config or {}
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
        Accessor for wallet DID.

        :return: wallet DID
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

    async def find_did(self, seed: str = None) -> str:
        """
        Derive DID from metadata (default most recent). Raise AbsentMetadata for no match.

        :param seed: seed to resolve (default most recent)
        :return: DID
        """

        LOGGER.debug('Wallet.find_did >>> seed [SEED]')

        rv = None
        dids_with_meta = json.loads(await did.list_my_dids_with_meta(self.handle))  # list

        if dids_with_meta:
            if seed:
                seed_hash = sha256(seed.encode()).hexdigest()
                for did_with_meta in dids_with_meta:  # dict
                    try:
                        meta = json.loads(did_with_meta['metadata'])
                        if isinstance(meta, dict) and meta.get('seed_hash', None) == seed_hash:
                            rv = did_with_meta.get('did')
                            break
                    except json.decoder.JSONDecodeError:
                        continue  # it's not one of ours, carry on

            else:
                latest = 0
                for did_with_meta in dids_with_meta:
                    try:
                        meta = json.loads(did_with_meta['metadata'])
                        if isinstance(meta, dict) and meta.get('since', -1) > latest:
                            rv = did_with_meta.get('did')
                    except json.decoder.JSONDecodeError:
                        continue  # it's not one of ours, carry on

        if not rv:  # no match in metadata
            LOGGER.debug('Wallet._seed2did <!< no did match in wallet %s by metadata', self.name)
            raise AbsentMetadata('No did match in wallet {} by metadata'.format(self.name))

        LOGGER.debug('Wallet.find_did <<< %s', rv)
        return rv

    async def create(self, seed: str) -> 'Wallet':
        """
        Create wallet as configured and store DID.

        Raise ExtantWallet if wallet already exists on current name.

        :param seed: seed
        :return: current object
        """

        LOGGER.debug('Wallet.create >>> seed [SEED]')

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

        LOGGER.debug('Attempting to open wallet %s', self.name)
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
                    'seed_hash': sha256(seed.encode()).hexdigest(),
                    'since': int(time())
                }))
            LOGGER.info('Wallet %s set seed hash metadata for DID %s', self.name, self.did)
        finally:
            await wallet.close_wallet(self.handle)

        LOGGER.debug('Wallet.create <<<')
        return self

    async def __aenter__(self) -> 'Wallet':
        """
        Context manager entry. Open (created) wallet as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing wallet.

        Raise any IndyError causing failure to open wallet, or AbsentWallet on attempt to enter wallet
        not yet created. Raise AbsentMetadata on attempt to open wallet without DID having metadata
        identifying any current seed.

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

        Raise any IndyError causing failure to open wallet, or AbsentWallet on attempt to enter wallet
        not yet created. Raise AbsentMetadata on attempt to open wallet without DID having metadata
        identifying any current seed.

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
            else:
                raise

        self._did = await self.find_did()
        self.verkey = await did.key_for_local_did(self.handle, self.did)
        LOGGER.info('Wallet %s got verkey %s for existing DID %s', self.name, self.verkey, self.did)

        LOGGER.debug('Wallet.open <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Close wallet and delete if so configured.
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
        Explicit exit. Close and delete wallet.
        For use when keeping wallet open across multiple calls.
        """

        LOGGER.debug('Wallet.close >>>')

        if not self.handle:
            LOGGER.warning('Abstaining from closing wallet %s: already closed', self.name)
        else:
            LOGGER.debug('Closing wallet %s', self.name)
            await wallet.close_wallet(self.handle)
            if self.auto_remove:
                LOGGER.info('Auto-removing wallet %s', self.name)
                await self.remove()
        self._handle = None

        LOGGER.debug('Wallet.close <<<')

    async def reseed_init(self, next_seed) -> str:
        """
        Begin reseed operation: generate new key.

        :param seed: incoming replacement seed
        :return: new verification key
        """

        LOGGER.debug('Wallet.reseed_init >>> next_seed [SEED]')

        self._next_seed = next_seed
        rv = await did.replace_keys_start(self.handle, self.did, json.dumps({'seed': next_seed}))
        LOGGER.debug('Wallet.reseed_init <<< %s', rv)
        return rv

    async def reseed_apply(self) -> None:
        """
        Replace verification key with new verification key from reseed operation.
        """

        LOGGER.debug('Wallet.reseed_apply >>>')

        await did.replace_keys_apply(self.handle, self.did)
        self.verkey = await did.key_for_local_did(self.handle, self.did)

        await did.set_did_metadata(
            self.handle,
            self.did,
            json.dumps({
                'seed_hash': sha256(self._next_seed.encode()).hexdigest(),
                'since': int(time())
            }))
        LOGGER.info('Wallet %s set seed hash metadata for DID %s', self.name, self.did)
        self._next_seed = None

        LOGGER.debug('Wallet.reseed_apply <<<')

    async def remove(self) -> None:
        """
        Remove serialized wallet if it exists.
        """

        LOGGER.debug('Wallet.remove >>>')

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
