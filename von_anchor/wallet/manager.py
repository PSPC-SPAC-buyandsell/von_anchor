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

from indy import wallet
from indy.error import IndyError, ErrorCode

from von_anchor.error import BadAccess, ExtantWallet, WalletState
from von_anchor.wallet import DIDInfo, Wallet


LOGGER = logging.getLogger(__name__)


class WalletManager:
    """
    Class encapsulating management functionality for indy-sdk wallets.
    """

    def __init__(self, defaults: dict = None) -> None:
        """
        Initializer for wallet manager. Store default values by dict key:

            - 'storage_type': storage type (default None)
            - 'freshness_time': freshness time (default indefinite)
            - 'auto_create': auto_create behaviour (default False)
            - 'auto_remove': auto_remove behaviour (default False)
            - 'key': access credentials value (default 'key', for indy wallet access credentials {'key': 'key'}).

        :param defaults: default values to use as above
        """

        LOGGER.debug('WalletManager.__init__ >>> defaults %s', defaults)

        self._defaults = {
            'storage_type': (defaults or {}).get('storage_type', None),
            'freshness_time': int((defaults or {}).get('freshness_time', 0)),
            'auto_create': bool((defaults or {}).get('auto_create', False)),
            'auto_remove': bool((defaults or {}).get('auto_remove', False)),
            'access_creds': {'key': (defaults or {}).get('key', 'key')}
        }

        LOGGER.debug('WalletManager.__init__ <<<')

    @property
    def default_storage_type(self) -> str:
        """
        Accessor for default wallet storage type.

        :return: default storage type
        """

        return self._defaults['storage_type']

    @property
    def default_freshness_time(self) -> int:
        """
        Accessor for default freshness time.

        :return: default freshness time (0 for indefinite)
        """

        return self._defaults['freshness_time']

    @property
    def default_auto_create(self) -> bool:
        """
        Accessor for default auto_create behaviour.

        :return: default auto_create behaviour
        """

        return self._defaults['auto_create']

    @property
    def default_auto_remove(self) -> bool:
        """
        Accessor for default auto_remove behaviour.

        :return: default auto_remove behaviour
        """

        return self._defaults['auto_remove']

    @property
    def default_access(self) -> dict:
        """
        Accessor for default access credential value.

        :return: default access credential value.
        """

        return self._defaults['access_creds']['key']

    def _config2indy(self, config: dict) -> dict:
        """
        Given a configuration dict with indy and possibly more configuration values, return the
        corresponding indy wallet configuration dict from current default and input values.

        :param config: input configuration
        :return: configuration dict for indy wallet
        """

        assert {'name', 'id'} & {k for k in config}
        return {
            'id': config.get('name', config.get('id')),
            'storage_type': config.get('storage_type', self.default_storage_type),
            'freshness_time': config.get('freshness_time', self.default_freshness_time)
        }

    def _config2von(self, config: dict, access: str = None) -> dict:
        """
        Given a configuration dict with indy and possibly more configuration values, return the
        corresponding VON wallet configuration dict from current default and input values.

        :param config: input configuration
        :param access: access credentials value
        :return: configuration dict for VON wallet with VON-specific entries
        """

        rv = {k: config.get(k, self._defaults[k]) for k in ('auto_create', 'auto_remove')}
        rv['access'] = access or self.default_access
        for key in ('seed', 'did', 'link_secret_label'):
            if key in config:
                rv[key] = config[key]
        return rv

    async def create(self, config: dict = None, access: str = None, replace: bool = False) -> Wallet:
        """
        Create wallet on input name with given configuration and access credential value.

        Raise ExtantWallet if wallet on input name exists already and replace parameter is False.
        Raise BadAccess on replacement for bad access credentials value.

        FAIR WARNING: specifying replace=True attempts to remove any matching wallet before proceeding; to
        succeed, the existing wallet must use the same access credentials that the input configuration has.

        :param config: configuration data for both indy-sdk and VON anchor wallet:

            - 'name' or 'id': wallet name
            - 'storage_type': storage type
            - 'freshness_time': freshness time
            - 'did': (optional) DID to use
            - 'seed': (optional) seed to use
            - 'auto_create': whether to create the wallet on first open (persists past close, can work with auto_remove)
            - 'auto_remove': whether to remove the wallet on next close
            - 'link_secret_label': (optional) link secret label to use to create link secret

        :param access: indy wallet access credential ('key') value, if different than default
        :param replace: whether to replace old wallet if it exists
        :return: wallet created
        """

        LOGGER.debug('WalletManager.create >>> config %s, access %s, replace %s', config, access, replace)

        assert {'name', 'id'} & {k for k in config}
        wallet_name = config.get('name', config.get('id'))
        if replace:
            von_wallet = self.get(config, access)
            if not await von_wallet.remove():
                LOGGER.debug('WalletManager.create <!< Failed to remove wallet %s for replacement', wallet_name)
                raise ExtantWallet('Failed to remove wallet {} for replacement'.format(wallet_name))

        indy_config = self._config2indy(config)
        von_config = self._config2von(config, access)
        rv = Wallet(indy_config, von_config)
        await rv.create()
        LOGGER.debug('WalletManager.create <<< %s', rv)
        return rv

    def get(self, config: dict, access: str = None) -> Wallet:
        """
        Instantiate and return VON anchor wallet object on given configuration, respecting wallet manager
        default configuration values.

        :param config: configuration data for both indy-sdk and VON anchor wallet:

            - 'name' or 'id': wallet name
            - 'storage_type': storage type
            - 'freshness_time': freshness time
            - 'did': (optional) DID to use
            - 'seed': (optional) seed to use
            - 'auto_create': whether to create the wallet on first open (persists past close, can work with auto_remove)
            - 'auto_remove': whether to remove the wallet on next close
            - 'link_secret_label': (optional) link secret label to use to create link secret

        :param access: indy access credentials value
        :return: VON anchor wallet
        """

        LOGGER.debug('WalletManager.get >>> config %s, access %s', config, access)

        rv = Wallet(
            self._config2indy(config),
            self._config2von(config, access))

        LOGGER.debug('WalletManager.get <<< %s', rv)
        return rv

    async def reseed_local(self, local_wallet: Wallet, next_seed: str = None) -> DIDInfo:
        """
        Generate and apply new key, in wallet only, for local DID based on input seed (default random).
        Raise WalletState if wallet is closed.

        Note that this operation does not update the corresponding NYM on the ledger: for VON anchors
        anchored to the ledger, use von_anchor.BaseAnchor.reseed().

        :param local_wallet: VON anchor wallet without NYM on ledger
        :param next_seed: incoming replacement seed (default random)
        :return: DIDInfo with new verification key and metadata for DID
        """

        LOGGER.debug('WalletManager.reseed_local >>> local_wallet %s', local_wallet)

        await local_wallet.reseed_init(next_seed)

        rv = await local_wallet.reseed_apply()
        LOGGER.debug('WalletManager.reseed_local <<< %s', rv)
        return rv

    async def export_wallet(self, von_wallet: Wallet, path: str) -> None:
        """
        Export an existing VON anchor wallet. Raise WalletState if wallet is closed.

        :param von_wallet: open wallet
        :param path: path to which to export wallet
        """

        LOGGER.debug('WalletManager.export_wallet >>> von_wallet %s, path %s', von_wallet, path)

        if not von_wallet.handle:
            LOGGER.debug('WalletManager.export_wallet <!< Wallet %s is closed', von_wallet.name)
            raise WalletState('Wallet {} is closed'.format(von_wallet.name))

        await wallet.export_wallet(
            von_wallet.handle,
            json.dumps({
                'path': path,
                **von_wallet.access_creds
            }))

        LOGGER.debug('WalletManager.export_wallet <<<')

    async def import_wallet(self, indy_config: dict, path: str, access: str = None) -> None:
        """
        Import a VON anchor wallet. Raise BadAccess on bad access credential value.

        :param indy_config: indy wallet configuration to use, with:

            - 'id'
            - 'storage_type' (optional)
            - 'storage_config' (optional)

        :param path: path from which to import wallet file
        :param access: indy access credentials value (default value from wallet manager)
        """

        LOGGER.debug('WalletManager.import_wallet >>> indy_config %s, path: %s', indy_config, path)

        try:
            await wallet.import_wallet(
                json.dumps(indy_config),
                json.dumps({'key': access or self.default_access}),
                json.dumps({'path': path, 'key': access or self.default_access}))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.CommonInvalidStructure:  # indy-sdk raises on bad access
                LOGGER.debug(
                    'WalletManager.import_wallet <!< bad access credential value for wallet %s',
                    indy_config.get('id', '(no id)'))
                raise BadAccess('Bad access credential value for wallet {}'.format(indy_config.get('id', '(no id)')))
            LOGGER.debug(
                'WalletManager.import_wallet <!< indy error code %s on wallet %s import',
                x_indy.error_code,
                indy_config.get('id', '(no id)'))
            raise

        LOGGER.debug('WalletManager.import_wallet <<<')

    async def reset(self, von_wallet: Wallet, seed: str = None) -> Wallet:
        """
        Close and delete (open) VON anchor wallet and then create, open, and return
        replacement on current link secret.

        Note that this operation effectively destroys private keys for keyed data
        structures such as credential offers or credential definitions.

        Raise WalletState if the wallet is closed.

        :param von_wallet: open wallet
        :param seed: seed to use for new wallet (default random)
        :return: replacement wallet
        """

        LOGGER.debug('WalletManager.reset >>> von_wallet %s', von_wallet)

        if not von_wallet.handle:
            LOGGER.debug('WalletManager.reset <!< Wallet %s is closed', von_wallet.name)
            raise WalletState('Wallet {} is closed'.format(von_wallet.name))

        w_config = von_wallet.config  # wallet under reset, no need to make copy
        w_config['did'] = von_wallet.did
        w_config['seed'] = seed
        w_config['auto_create'] = von_wallet.auto_create  # in case both auto_remove+auto_create set (create every open)
        w_config['auto_remove'] = von_wallet.auto_remove

        label = await von_wallet.get_link_secret_label()
        if label:
            w_config['link_secret_label'] = label

        await von_wallet.close()
        if not von_wallet.auto_remove:
            await self.remove(von_wallet)

        rv = await self.create(w_config, von_wallet.access)
        await rv.open()

        LOGGER.debug('WalletManager.reset <<< %s', rv)
        return rv

    async def remove(self, von_wallet: Wallet) -> None:
        """
        Remove serialized wallet if it exists. Raise WalletState if wallet is open.

        :param von_wallet: (closed) wallet to remove
        """

        LOGGER.debug('WalletManager.remove >>> wallet %s', von_wallet)

        await von_wallet.remove()

        LOGGER.debug('WalletManager.remove <<<')

    @staticmethod
    async def register_storage_library(storage_type: str, c_library: str, entry_point: str) -> None:
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
            'WalletManager.register_storage_library >>> storage_type %s, c_library %s, entry_point %s',
            storage_type,
            c_library,
            entry_point)

        try:
            stg_lib = CDLL(c_library)
            result = stg_lib[entry_point]()
            if result:
                LOGGER.debug(
                    'WalletManager.register_storage_library <!< indy error code %s on storage library entry at %s',
                    result,
                    entry_point)
                raise IndyError(result)
            LOGGER.info('Loaded storage library type %s (%s)', storage_type, c_library)
        except IndyError as x_indy:
            LOGGER.debug(
                'WalletManager.register_storage_library <!< indy error code %s on load of storage library %s %s',
                x_indy.error_code,
                storage_type,
                c_library)
            raise

        LOGGER.debug('WalletManager.register_storage_library <<<')
