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
from von_agent.validate_config import validate_config

import json
import logging


class Wallet:
    """
    Class encapsulating indy-sdk wallet.
    """

    def __init__(self, pool_name: str, seed: str, name: str, cfg: dict = None) -> None:
        """
        Initializer for wallet. Store input parameters and create wallet.
        Does not open until open() or __enter__().

        :param pool_name: name of pool on which wallet operates
        :param seed: seed for wallet user
        :param name: name of the wallet
        :param cfg: configuration, None for default;
            i.e., {
                'auto-remove': bool (default False), whether to remove serialized indy configuration data on close,
                ... (any other indy configuration data)
            }
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.__init__: >>> pool_name {}, seed [SEED], name {}, cfg {}'.format(pool_name, name, cfg))

        self._pool_name = pool_name
        self._seed = seed
        self._name = name
        self._handle = None

        self._cfg = cfg or {}
        validate_config('wallet', self._cfg)

        self._did = None
        self._verkey = None

        logger.debug('Wallet.__init__: <<<')

    @property
    def pool_name(self) -> str:
        """
        Accessor for pool name.

        :return: pool name
        """

        return self._pool_name

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

    async def __aenter__(self) -> 'Wallet':
        """
        Context manager entry. Create and open wallet as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing wallet.

        Raise any IndyError causing failure to open wallet.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.__aenter__: >>>')

        rv = await self.open()
        logger.debug('Wallet.__aenter__: <<<')
        return rv

    async def open(self) -> 'Wallet':
        """
        Explicit entry. Open wallet as configured, for later closure via close().
        For use when keeping wallet open across multiple calls.

        Raise any IndyError causing failure to open wallet.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.open: >>>')

        cfg = json.loads(json.dumps(self._cfg))  # deep copy
        if 'auto-remove' in cfg:
            cfg.pop('auto-remove')

        try:
            await wallet.create_wallet(
                pool_name=self.pool_name,
                name=self.name,
                xtype=None,
                config=json.dumps(cfg) if cfg else None,
                credentials=None)
            logger.info('Created wallet {} on handle {}'.format(self.name, self.handle))
        except IndyError as e:
            if e.error_code == ErrorCode.WalletAlreadyExistsError:
                logger.info('Opening existing wallet: {}'.format(self.name))
            else:
                logger.debug('Wallet.open: <!< indy error code {}'.format(self.e.error_code))
                raise

        self._handle = await wallet.open_wallet(self.name, json.dumps(cfg) if cfg else None, None)
        logger.info('Opened wallet {} on handle {}'.format(self.name, self.handle))

        (self._did, self._verkey) = await did.create_and_store_my_did(  # apparently does no harm to overwrite it
            self._handle,
            json.dumps({'seed': self._seed}))
        logger.debug('Wallet.open: stored {}, {}'.format(self._did, self._verkey))

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
        auto_remove = self.cfg.get('auto-remove', False)
        if auto_remove:
            await self.remove()

        logger.debug('Wallet.close: <<<')

    async def remove(self) -> None:
        """
        Remove serialized wallet configuration data if it exists.
        """

        logger = logging.getLogger(__name__)
        logger.debug('Wallet.close: >>>')

        try:
            await wallet.delete_wallet(self.name, None)
        except Exception:
            logger.info('Abstaining from wallet removal: {}'.format(sys.exc_info()[0]))

        logger.debug('Wallet.close: <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """
        
        return '{}({}, [SEED], {}, {})'.format(
            self.__class__.__name__,
            self.pool_name,
            self.name,
            self.cfg)
