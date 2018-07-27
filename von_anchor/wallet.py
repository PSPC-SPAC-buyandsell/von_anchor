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


import json
import logging

from indy import did, wallet
from indy.error import IndyError, ErrorCode
from von_anchor.error import AbsentWallet, CorruptWallet, JSONValidation


LOGGER = logging.getLogger(__name__)

class Wallet:
    """
    Class encapsulating indy-sdk wallet.
    """

    DEFAULT_ACCESS_CREDS = {'key': 'key'}
    DEFAULT_CHUNK = 256  # chunk size in searching credentials

    def __init__(
            self,
            seed: str,
            name: str,
            wallet_type: str = None,
            cfg: dict = None,
            access_creds: dict = None) -> None:
        """
        Initializer for wallet. Store input parameters, packing name and wallet_type into cfg (the
        signature retains them independently as a convenience and to retain compatibility with prior releases).
        Do not create wallet until call to create(). Do not open until call to open() or __aenter__().

        :param seed: seed for wallet user
        :param name: name of the wallet
        :param wallet_type: wallet type str, None for default
        :param cfg: configuration dict, None for default; i.e.,
            ::
            {
                'auto-remove': bool (default False) - whether to remove serialized indy configuration data on close,
                ... (more keys) : ... (more types) - any other configuration data to pass through to indy-sdk
            }
        :param access_creds: wallet access credentials dict, None for default
        """

        LOGGER.debug(
            'Wallet.__init__ >>> seed [SEED], name %s, wallet_type %s, cfg %s, access_creds %s',
            name,
            wallet_type,
            cfg,
            access_creds)

        self._seed = seed
        self._handle = None

        self._cfg = cfg or {}
        if not isinstance(self.cfg.get('auto-remove', False), bool):
            # enterprise wallet development was having trouble with validate_config.validate_config() - check manually
            LOGGER.debug('Wallet.__init__ <!< Error on wallet configuration: auto-remove value must be boolean')
            raise JSONValidation('Error on wallet configuration: auto-remove value must be boolean')
        self._cfg['id'] = name
        self._cfg['storage_type'] = wallet_type or 'default'

        # pop and retain configuration specific to von_anchor.Wallet, extrinsic to indy-sdk
        self._auto_remove = self._cfg.pop('auto-remove') if self._cfg and 'auto-remove' in self._cfg else False
        if 'freshness_time' not in self._cfg:
            self._cfg['freshness_time'] = 0

        self._access_creds = access_creds or Wallet.DEFAULT_ACCESS_CREDS
        self._did = None
        self._verkey = None
        self._created = False

        LOGGER.debug('Wallet.__init__ <<<')

    @property
    def name(self) -> str:
        """
        Accessor for wallet name, as configuration retains at key 'id'.

        :return: wallet name
        """

        return self.cfg['id']

    @property
    def handle(self) -> int:
        """
        Accessor for indy-sdk wallet handle.

        :return: indy-sdk wallet handle
        """

        return self._handle

    @property
    def cfg(self) -> dict:
        """
        Accessor for wallet config.

        :return: wallet config
        """

        return self._cfg

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
    def xtype(self) -> str:
        """
        Accessor for wallet type, as configuration retains at key 'storage_type'.

        :return: wallet type
        """

        return self.cfg['storage_type']

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

    @property
    def created(self) -> str:
        """
        Accessor for wallet creation state.

        :return: wallet creation state
        """

        return self._created

    # on purpose: don't expose seed via a property

    async def _seed2did(self) -> str:
        """
        Derive DID, as per indy-sdk, from seed.

        :return: DID
        """

        rv = None
        dids_with_meta = json.loads(await did.list_my_dids_with_meta(self.handle))  # list

        if dids_with_meta:
            for did_with_meta in dids_with_meta:  # dict
                if 'metadata' in did_with_meta:
                    try:
                        meta = json.loads(did_with_meta['metadata'])
                        if isinstance(meta, dict) and meta.get('seed', None) == self._seed:
                            rv = did_with_meta.get('did')
                    except json.decoder.JSONDecodeError:
                        continue  # it's not one of ours, carry on

        if not rv:  # seed not in metadata, generate did again on temp wallet
            temp_wallet = await Wallet(
                self._seed,
                '{}.seed2did'.format(self.name),
                None,
                {'auto-remove': True}).create()

            rv = temp_wallet.did
            await temp_wallet.remove()

        return rv

    async def create(self) -> 'Wallet':
        """
        Create wallet as configured and store DID, or else re-use any existing configuration.
        Operation sequence create/store-DID/close does not auto-remove the wallet on close,
        even if so configured.

        :return: current object
        """

        LOGGER.debug('Wallet.create >>>')

        try:
            await wallet.create_wallet(
                config=json.dumps(self.cfg),
                credentials=json.dumps(self.access_creds))
            self._created = True
            LOGGER.info('Created wallet %s', self.name)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletAlreadyExistsError:
                LOGGER.info('Wallet already exists: %s', self.name)
            else:
                LOGGER.debug(
                    'Wallet.create: <!< indy error code %s on creation of wallet %s',
                    x_indy.error_code,
                    self.name)
                raise

        LOGGER.debug('Attempting to open wallet %s', self.name)
        self._handle = await wallet.open_wallet(
            json.dumps(self.cfg),
            json.dumps(self.access_creds))
        LOGGER.info('Opened wallet %s on handle %s', self.name, self.handle)

        if self._created:
            (self._did, self._verkey) = await did.create_and_store_my_did(
                self.handle,
                json.dumps({'seed': self._seed}))
            LOGGER.debug('Wallet %s stored new DID %s, verkey %s from seed', self.name, self.did, self.verkey)
            await did.set_did_metadata(self.handle, self.did, json.dumps({'seed': self._seed}))
        else:
            self._created = True
            LOGGER.debug('Attempting to derive seed to did for wallet %s', self.name)
            self._did = await self._seed2did()
            try:
                self._verkey = await did.key_for_local_did(self.handle, self.did)
            except IndyError:
                LOGGER.debug(
                    'Wallet.create: <!< no verkey for DID %s on ledger, wallet %s may pertain to another',
                    self.did,
                    self.name)
                raise CorruptWallet(
                    'No verkey for DID {} on ledger, wallet {} may pertain to another'.format(
                        self.did,
                        self.name))
            LOGGER.info('Wallet %s got verkey %s for existing DID %s', self.name, self.verkey, self.did)

        await wallet.close_wallet(self.handle)

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

        :return: current object
        """

        LOGGER.debug('Wallet.open >>>')

        if not self.created:
            LOGGER.debug('Wallet.open: <!< absent wallet %s', self.name)
            raise AbsentWallet('Cannot open wallet {}: not created'.format(self.name))

        self._handle = await wallet.open_wallet(
            json.dumps(self.cfg),
            json.dumps(self.access_creds))
        LOGGER.info('Opened wallet %s on handle %s', self.name, self.handle)

        self._did = await self._seed2did()
        self._verkey = await did.key_for_local_did(self.handle, self.did)
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

    async def remove(self) -> None:
        """
        Remove serialized wallet if it exists.
        """

        LOGGER.debug('Wallet.remove >>>')

        try:
            LOGGER.info('Removing wallet: %s', self.name)
            await wallet.delete_wallet(json.dumps(self.cfg), json.dumps(self.access_creds))
        except IndyError as x_indy:
            LOGGER.info('Abstaining from wallet removal; indy-sdk error code %s', x_indy.error_code)

        LOGGER.debug('Wallet.remove <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}([SEED], {}, {}, {}, [ACCESS_CREDS])'.format(
            self.__class__.__name__,
            self.name,
            self.xtype,
            self.cfg)
