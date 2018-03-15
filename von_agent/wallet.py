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

from indy import did, wallet
from indy.error import IndyError, ErrorCode
from von_agent.error import AbsentWallet
from von_agent.nodepool import NodePool

import json
import logging
import sys


class Wallet:
    """
    Class encapsulating indy-sdk wallet.
    """

    def __init__(
            self,
            pool: NodePool,
            seed: str,
            name: str,
            wallet_type: str = None,
            cfg: dict = None,
            creds: dict = None) -> None:
        """
        Initializer for wallet. Store input parameters and create wallet.
        Does not open until open() or __aenter__().

        :param pool: node pool on which wallet operates
        :param seed: seed for wallet user
        :param name: name of the wallet
        :param wallet_type: wallet type str, None for default
        :param cfg: configuration dict, None for default
            i.e., {
                'auto-remove': bool (default False) - whether to remove serialized indy configuration data on close,
                ... (more keys) : ... (more types) - any other configuration data to pass through to indy-sdk
            }
        :param creds: wallet credentials dict, None for default
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.__init__: >>> pool {}, seed [SEED], name {}, wallet_type {}, cfg {}, creds {}'.format(
            pool,
            name,
            wallet_type,
            cfg,
            creds))

        self._pool = pool
        self._seed = seed
        self._name = name
        self._handle = None
        self._xtype = wallet_type
        self._cfg = cfg or {}

        # indy-sdk refuses extra config settings: pop and retain configuration specific to von_agent.Wallet
        self._auto_remove = self._cfg.pop('auto-remove') if self._cfg and 'auto-remove' in self._cfg else False

        self._creds = creds or None
        self._did = None
        self._verkey = None
        self._created = False

        logger.warn('.. Wallet {} init complete on pool {}={}'.format(self.name, self.pool.handle, self.pool.name))
        logger.debug('Wallet.__init__: <<<')

    @property
    def pool(self) -> NodePool:
        """
        Accessor for pool.

        :return: pool
        """

        return self._pool

    @property
    def name(self) -> str:
        """
        Accessor for wallet name.

        :return: wallet name
        """

        return self._name

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
    def auto_remove(self) -> dict:
        """
        Accessor for auto-remove wallet config setting.

        :return: auto-remove wallet config setting
        """

        return self._auto_remove

    @property
    def creds(self) -> dict:
        """
        Accessor for wallet credentials.

        :return: wallet credentials
        """

        return self._creds

    @property
    def xtype(self) -> dict:
        """
        Accessor for wallet type.

        :return: wallet type
        """

        return self._xtype

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

        temp_wallet = await Wallet(
            self.pool,
            self._seed,
            '{}.seed2did'.format(self.name),
            None,
            {'auto-remove': True}).create()

        rv = temp_wallet.did
        await temp_wallet.remove()
        return rv

    async def __aenter__(self) -> 'Wallet':
        """
        Context manager entry. Open (created) wallet as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing wallet.

        Raise any IndyError causing failure to open wallet, or AbsentWallet on attempt to enter wallet
        not yet created.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.__aenter__: >>>')

        rv = await self.open()
        logger.debug('Wallet.__aenter__: <<<')
        return rv

    async def create(self) -> 'Wallet':
        """
        Create wallet as configured and store DID, or else re-use any existing configuration.
        Operation sequence create/store-DID/close does not auto-remove the wallet on close,
        even if so configured.

        Raise any IndyError causing failure to operate on wallet (create, open, store DID, close).

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.create: >>>')

        try:
            logger.warn('.. Wallet {} create() trying indy-sdk create_wallet on pool {}={}'.format(
                self.name,
                self.pool.handle,
                self.pool.name))
            await wallet.create_wallet(
                pool_name=self.pool.name,
                name=self.name,
                xtype=self.xtype,
                config=json.dumps(self.cfg) if self.cfg else None,
                credentials=json.dumps(self.creds) if self.creds else None)
            self._created = True
            logger.info('Created wallet {}'.format(self.name))
        except IndyError as e:
            if e.error_code == ErrorCode.WalletAlreadyExistsError:
                logger.info('Wallet already exists: {}'.format(self.name))
                logger.warn('.. Wallet already exists: {}'.format(self.name))
            else:
                logger.debug('Wallet.create: <!< indy error code {}'.format(self.e.error_code))
                raise

        self._handle = await wallet.open_wallet(
            self.name,
            json.dumps(self.cfg) if self.cfg else None,
            json.dumps(self.creds) if self.creds else None)
        logger.info('Opened wallet {} on handle {}'.format(self.name, self.handle))
        logger.warn('.. Wallet {} create() done indy-sdk open_wallet now pool {}={}, wallet-handle={}'.format(
            self.name,
            self.pool.handle,
            self.pool.name,
            self.handle))

        if self._created:
            (self._did, self._verkey) = await did.create_and_store_my_did(
                self.handle,
                json.dumps({'seed': self._seed}))
            logger.debug('Wallet.open: derived and stored stored {}, {} from seed'.format(self._did, self._verkey))
            # print('\n\n-- W.0: {} created did, {}, key {}'.format(self.name, self._did, self._verkey))
            logger.warn('.. Wallet {} create() just created+opened new wallet, now pool {}={}, wallet-handle={}'.format(
                self.name,
                self.pool.handle,
                self.pool.name,
                self.handle))
        else:
            self._created = True
            logger.warn('.. Wallet {} create() re-using existing wallet, now pool {}={}, wallet-handle={}'.format(
                self.name,
                self.pool.handle,
                self.pool.name,
                self.handle))
            self._did = await self._seed2did()
            logger.warn('.. Wallet {} create() used seed2did: {} -> {}, have pool {}={}, wallet-handle={}'.format(
                self.name,
                self._seed,
                self.did,
                self.pool.handle,
                self.pool.name,
                self.handle))
            self._verkey = await did.key_for_did(self.pool.handle, self.handle, self.did)
            logger.warn('.. Wallet {} create() got verkey {}'.format(self.name, self.verkey))

        await wallet.close_wallet(self.handle)

        logger.debug('Wallet.create: <<<')
        return self

    async def open(self) -> 'Wallet':
        """
        Explicit entry. Open wallet as configured, for later closure via close().
        For use when keeping wallet open across multiple calls.

        Raise any IndyError causing failure to open wallet.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.open: >>>')

        if not self.created:
            logger.debug('Wallet.open: <!< absent wallet {}'.format(self.name))
            raise AbsentWallet('Cannot open wallet {}: not created'.format(self.name))

        self._handle = await wallet.open_wallet(
            self.name,
            json.dumps(self.cfg) if self.cfg else None,
            json.dumps(self.creds) if self.creds else None)
        logger.info('Opened wallet {} on handle {}'.format(self.name, self.handle))

        logger.warn('.. Wallet {} open() called indy-sdk open_wallet, now pool {}={}, wallet-handle={}'.format(
            self.name,
            self.pool.handle,
            self.pool.name,
            self.handle))
        self._did = await self._seed2did()
        logger.warn('.. Wallet {} open() used seed2did: {} -> {}, have pool {}={}'.format(
            self.name,
            self._seed,
            self.did,
            self.pool.name,
            self.handle))
        self._verkey = await did.key_for_did(self.pool.handle, self.handle, self.did)
        # print('\n\n-- W.1: {} assigned from prior did, {}, key {}'.format(self.name, self._did, self._verkey))

        logger.debug('Wallet.open: <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None: 
        """
        Context manager exit. Close wallet and delete if so configured.
        For use in monolithic call opening, using, and closing the wallet.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.__aexit__: >>>')

        await self.close()

        logger.debug('Wallet.__aexit__: <<<')

    async def close(self) -> None:
        """
        Explicit exit. Close and delete wallet.
        For use when keeping wallet open across multiple calls.
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.close: >>>')

        await wallet.close_wallet(self.handle)

        if self.auto_remove:
            await self.remove()
        self._handle = None

        logger.debug('Wallet.close: <<<')

    async def remove(self) -> None:
        """
        Remove serialized wallet if it exists.
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.remove: >>>')

        try:
            await wallet.delete_wallet(self.name, None)
        except Exception:
            logger.info('Abstaining from wallet removal: {}'.format(sys.exc_info()[0]))

        logger.debug('Wallet.remove: <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """
        
        return '{}({}, [SEED], {}, {})'.format(
            self.__class__.__name__,
            self.pool,
            self.name,
            self.cfg)
