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

from indy import pool
from indy.error import IndyError, ErrorCode
from von_agent.validate_config import validate_config

import json
import logging


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

        logger = logging.getLogger(__name__)
        logger.debug('NodePool.__init__: >>> name: {}, genesis_txn_path: {}, cfg: {}'.format(
            name,
            genesis_txn_path,
            cfg))

        self._cfg = cfg or {}
        validate_config('pool', self._cfg)

        self._name = name
        self._genesis_txn_path = genesis_txn_path
        self._handle = None

        logger.debug('NodePool.__init__: <<<')

    @property
    def name(self) -> str:
        """
        Accessor for pool name

        :return: pool name
        """

        return self._name

    @property
    def genesis_txn_path(self) -> str:
        """
        Accessor for path to genesis transaction file

        :return: path to genesis transaction file
        """

        return self._genesis_txn_path

    @property
    def handle(self) -> int:
        """
        Accessor for indy-sdk pool handle

        :return: indy-sdk pool handle
        """

        return self._handle

    async def __aenter__(self) -> 'NodePool':
        """
        Context manager entry. Opens pool as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing the pool.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('NodePool.__aenter__: >>>')

        rv = await self.open()

        logger.debug('NodePool.__aenter__: <<<')
        return rv

    async def open(self) -> 'NodePool':
        """
        Explicit entry. Opens pool as configured, for later closure via close().
        For use when keeping pool open across multiple calls.

        Raise any IndyError causing failure to create ledger configuration.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('NodePool.open: >>>')

        try:
            await pool.create_pool_ledger_config(self.name, json.dumps({'genesis_txn': str(self.genesis_txn_path)}))
        except IndyError as e:
            if e.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                logger.info('Pool ledger config for {} already exists'.format(self.name))
            else:
                logger.debug('NodePool.open: <!< indy error code {}'.format(e.error_code))
                raise e

        self._handle = await pool.open_pool_ledger(self.name, None)

        logger.debug('NodePool.open: <<<')
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

        logger = logging.getLogger(__name__)
        logger.debug('NodePool.__aexit__: >>>')

        await self.close()

        logger.debug('NodePool.__aexit__: <<<')

    async def close(self) -> None:
        """
        Explicit exit. Closes pool and deletes its configuration to ensure clean next entry.
        For use when keeping pool open across multiple calls.
        """

        logger = logging.getLogger(__name__)
        logger.debug('NodePool.close: >>>')

        await pool.close_pool_ledger(self.handle)
        if self._cfg and 'auto-remove' in self._cfg and self._cfg['auto-remove']:
            await pool.delete_pool_ledger_config(self.name)

        logger.debug('NodePool.close: <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'NodePool({}, {})'.format(self.name, self.genesis_txn_path)
