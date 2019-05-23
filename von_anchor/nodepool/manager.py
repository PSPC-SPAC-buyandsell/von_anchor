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

from os import remove
from os.path import expanduser, expandvars, isfile, realpath
from tempfile import NamedTemporaryFile
from typing import List

from indy import pool
from indy.error import IndyError

from von_anchor.error import AbsentPool, ExtantPool
from von_anchor.nodepool.nodepool import NodePool
from von_anchor.nodepool.protocol import Protocol


LOGGER = logging.getLogger(__name__)


class NodePoolManager:
    """
    Class for managing indy node pools.
    """

    def __init__(self, protocol: Protocol = None):
        """
        Initializer for node pool manager. Set protocol.
        """

        LOGGER.debug('NodePoolManager.__init__ >>> protocol %s', protocol)

        self._protocol = protocol or Protocol.DEFAULT

        LOGGER.debug('NodePoolManager.__init__ <<<')

    @property
    def protocol(self) -> str:
        """
        Accessor for protocol.

        :return: current node manager protocol
        """

        return self._protocol

    @protocol.setter
    def protocol(self, value: Protocol) -> None:
        """
        Set protocol

        :param value: protocol
        """

        self._protocol = value

    async def add_config(self, name: str, genesis: str = None) -> None:
        """
        Given pool name and genesis transaction path or data, add node pool
        configuration to indy home directory.

        Raise ExtantPool if node pool configuration on input name already exists.
        Raise AbsentPool if unable to create the pool ledger configuration.

        :param name: pool name
        :param genesis: genesis transaction path or raw data
        """

        LOGGER.debug('NodePoolManager.add_config >>> name: %s, genesis: %s', name, genesis)

        if name in await self.list():
            LOGGER.debug('NodePoolManager.add_config: <!< Node pool %s configuration already present', name)
            raise ExtantPool('Node pool {} configuration already present'.format(name))

        genesis_tmp = None
        path_gen = realpath(expanduser(expandvars(genesis)))
        try:
            if not isfile(path_gen):
                genesis_tmp = NamedTemporaryFile(mode='w+b', buffering=0, delete=False)
                with genesis_tmp:
                    genesis_tmp.write(genesis.encode())
            await pool.create_pool_ledger_config(
                name,
                json.dumps({
                    'genesis_txn': path_gen if isfile(path_gen) else genesis_tmp.name
                }))
        except IndyError as x_indy:
            LOGGER.debug(
                'NodePoolManager.add_config <!< could not create pool %s ledger configuration: indy error %s',
                name,
                x_indy.error_code)
            raise AbsentPool('Could not create pool {} ledger configuration: indy error {}'.format(
                name,
                x_indy.error_code))

        finally:
            if genesis_tmp:
                remove(genesis_tmp.name)

        LOGGER.debug('NodePoolManager.add_config <<<')

    async def list(self) -> List[str]:
        """
        Return list of pool names configured, empty list for none.

        :return: list of pool names.
        """

        LOGGER.debug('NodePoolManager.list >>>')

        rv = [p['pool'] for p in await pool.list_pools()]

        LOGGER.debug('NodePoolManager.list <<< %s', rv)
        return rv

    def get(self, name: str, config: dict = None) -> NodePool:
        """
        Return node pool in input name and optional configuration.

        :param name: name of configured pool
        :param config: pool configuration with optional 'timeout' int, 'extended_timeout' int,
            'preordered_nodes' array of strings
        :return: node pool
        """

        LOGGER.debug('NodePoolManager.node_pool >>>')

        rv = NodePool(name, self.protocol, config)

        LOGGER.debug('NodePoolManager.node_pool <<< %s', rv)
        return rv

    async def remove(self, name: str) -> None:
        """
        Remove serialized pool info if it exists. Abstain from removing open node pool.
        Raise ExtantPool if deletion fails.
        """

        LOGGER.debug('NodePoolManager.remove >>> name: %s', name)

        try:
            await pool.delete_pool_ledger_config(name)
        except IndyError as x_indy:
            LOGGER.debug(
                'NodePoolManager.remove <!< could not remove %s ledger configuration: indy error %s',
                name,
                x_indy.error_code)
            raise ExtantPool('Could not remove {} ledger configuration: indy error {}'.format(
                name,
                x_indy.error_code))

        LOGGER.debug('NodePool.remove <<<')
