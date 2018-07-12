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

from indy import pool
from indy.error import IndyError, ErrorCode
from von_anchor.validate_config import validate_config


LOGGER = logging.getLogger(__name__)


class NodePool:
    """
    Class encapsulating indy-sdk node pool.
    """

    def __init__(self, name: str, genesis_txn_path: str, cfg: dict = None) -> None:
        """
        Initializer for node pool. Does not open the pool, only retains input parameters.

        :param name: name of the pool
        :param genesis_txn_path: path to genesis transaction file
        :param cfg: configuration, None for default;
            i.e., {
                'auto-remove': bool (default False), whether to remove serialized indy configuration data on close
            }
        """

        LOGGER.debug('NodePool.__init__ >>> name: %s, genesis_txn_path: %s, cfg: %s', name, genesis_txn_path, cfg)

        self._cfg = cfg or {}
        validate_config('pool', self._cfg)

        # pop and retain configuration specific to von_anchor.NodePool, extrinsic to indy-sdk
        self._auto_remove = self._cfg.pop('auto-remove') if self._cfg and 'auto-remove' in self._cfg else False
        if 'refresh_on_open' not in self._cfg:
            self._cfg['refresh_on_open'] = True
        if 'auto_refresh_time' not in self._cfg:
            self._cfg['auto_refresh_time'] = 0

        self._name = name
        self._genesis_txn_path = genesis_txn_path
        self._handle = None

        LOGGER.debug('NodePool.__init__ <<<')

    @property
    def name(self) -> str:
        """
        Accessor for pool name.

        :return: pool name
        """

        return self._name

    @property
    def genesis_txn_path(self) -> str:
        """
        Accessor for path to genesis transaction file.

        :return: path to genesis transaction file
        """

        return self._genesis_txn_path

    @property
    def handle(self) -> int:
        """
        Accessor for indy-sdk pool handle.

        :return: indy-sdk pool handle
        """

        return self._handle

    @property
    def cfg(self) -> dict:
        """
        Accessor for pool config.

        :return: pool config
        """

        return self._cfg

    @property
    def auto_remove(self) -> bool:
        """
        Accessor for auto-remove pool config setting.

        :return: auto-remove pool config setting
        """

        return self._auto_remove

    async def __aenter__(self) -> 'NodePool':
        """
        Context manager entry. Opens pool as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing the pool.

        :return: current object
        """

        LOGGER.debug('NodePool.__aenter__ >>>')

        rv = await self.open()

        LOGGER.debug('NodePool.__aenter__ <<<')
        return rv

    async def open(self) -> 'NodePool':
        """
        Explicit entry. Opens pool as configured, for later closure via close().
        For use when keeping pool open across multiple calls.

        Raise any IndyError causing failure to create ledger configuration.

        :return: current object
        """

        LOGGER.debug('NodePool.open >>>')

        try:
            await pool.set_protocol_version(2)  # 1 for indy-node 1.3, 2 for indy-node 1.4
            await pool.create_pool_ledger_config(self.name, json.dumps({'genesis_txn': str(self.genesis_txn_path)}))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                LOGGER.info('Pool ledger config for %s already exists', self.name)
            else:
                LOGGER.debug('NodePool.open: <!< indy error code %s', x_indy.error_code)
                raise x_indy

        self._handle = await pool.open_pool_ledger(self.name, json.dumps(self.cfg))

        LOGGER.debug('NodePool.open <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Closes pool and deletes its configuration to ensure clean next entry.
        For use in monolithic call opening, using, and closing the pool.

        Raise any IndyError causing failure to create ledger configuration.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        LOGGER.debug('NodePool.__aexit__ >>>')

        await self.close()

        LOGGER.debug('NodePool.__aexit__ <<<')

    async def close(self) -> None:
        """
        Explicit exit. Closes pool and deletes its configuration to ensure clean next entry.
        For use when keeping pool open across multiple calls.
        """

        LOGGER.debug('NodePool.close >>>')

        if not self.handle:
            LOGGER.warning('Abstaining from closing pool %s: already closed', self.name)
        else:
            await pool.close_pool_ledger(self.handle)
            if self.auto_remove:
                await self.remove()
        self._handle = None

        LOGGER.debug('NodePool.close <<<')

    async def remove(self) -> None:
        """
        Remove serialized pool info if it exists.
        """

        LOGGER.debug('NodePool.remove >>>')

        try:
            await pool.delete_pool_ledger_config(self.name)
        except IndyError as x_indy:
            LOGGER.info('Abstaining from pool removal; indy-sdk error code %s', x_indy.error_code)

        LOGGER.debug('NodePool.remove <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'NodePool({}, {})'.format(self.name, self.genesis_txn_path)
