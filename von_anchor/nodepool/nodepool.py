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

from indy import pool
from indy.error import IndyError, ErrorCode

from von_anchor.error import AbsentPool
from von_anchor.nodepool.protocol import Protocol
from von_anchor.validcfg import validate_config


LOGGER = logging.getLogger(__name__)


class NodePool:
    """
    Class encapsulating indy-sdk node pool.
    """

    def __init__(self, name: str, protocol: Protocol = None, config: dict = None) -> None:
        """
        Initializer for node pool. Does not open the pool, only retains input parameters.

        :param name: name of the pool
        :param protocol: indy-node protocol
        :param config: configuration, None for default
        """

        LOGGER.debug('NodePool.__init__ >>> name: %s, protocol: %s, config: %s', name, protocol, config)

        self._protocol = protocol or Protocol.DEFAULT
        self._name = name
        self._handle = None
        self._config = config or {}
        validate_config('pool', self._config)

        LOGGER.debug('NodePool.__init__ <<<')

    @property
    def name(self) -> str:
        """
        Accessor for pool name.

        :return: pool name
        """

        return self._name

    @property
    def handle(self) -> int:
        """
        Accessor for indy-sdk pool handle.

        :return: indy-sdk pool handle
        """

        return self._handle

    @property
    def config(self) -> dict:
        """
        Accessor for pool config.

        :return: pool config
        """

        return self._config

    @property
    def protocol(self) -> str:
        """
        Accessor for protocol version pool config setting.

        :return: protocol version pool config setting
        """

        return self._protocol

    async def __aenter__(self) -> 'NodePool':
        """
        Context manager entry. Opens pool as configured, for closure on context manager exit.
        Creates pool if it does not yet exist, using configured genesis transaction file.
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
        Creates pool if it does not yet exist, using configured genesis transaction file.
        For use when keeping pool open across multiple calls.

        Raise any AbsentPool if node pool ledger configuration is not available.

        :return: current object
        """

        LOGGER.debug('NodePool.open >>>')

        await pool.set_protocol_version(self.protocol.indy())
        LOGGER.info('Pool ledger %s set protocol %s', self.name, self.protocol)

        try:
            self._handle = await pool.open_pool_ledger(self.name, json.dumps(self.config))
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.PoolLedgerNotCreatedError:
                LOGGER.debug('NodePool.open <!< Absent node pool %s ledger configuration', self.name)
                raise AbsentPool('Absent node pool {} ledger configuration'.format(self.name))
            LOGGER.debug(
                'NodePool.open <!< cannot open node pool %s: indy error code %s',
                self.name,
                x_indy.error_code)
            raise

        LOGGER.debug('NodePool.open <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Closes pool. For use in monolithic call opening, using, and closing the pool.

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
        Explicit exit. Closes pool. For use when keeping pool open across multiple calls.
        """

        LOGGER.debug('NodePool.close >>>')

        if not self.handle:
            LOGGER.warning('Abstaining from closing pool %s: already closed', self.name)
        else:
            await pool.close_pool_ledger(self.handle)
        self._handle = None

        LOGGER.debug('NodePool.close <<<')

    async def refresh(self) -> None:
        """
        Refresh local copy of pool ledger and update node pool connections.
        """

        LOGGER.debug('NodePool.refresh >>>')

        await pool.refresh_pool_ledger(self.handle)

        LOGGER.debug('NodePool.refresh <<<')


    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'NodePool({}, {}, {})'.format(self.name, self.protocol, self.config)
