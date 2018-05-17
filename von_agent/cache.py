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


import logging

from threading import RLock
from typing import Union
from von_agent.error import CacheIndex
from von_agent.tails import Tails
from von_agent.util import SchemaKey, schema_key


class SchemaCache:
    """
    Retain schemata and fetch by schema key (origin_did, name, version) or by sequence number.
    Note that schema key is isomorphic to schema_id, but since schema_id is a str and indy-sdk
    stores sequence number as a str in some cases, it is more defensive to index by schema key
    than schema_id.

    A lock shares access to critical sections as relying code specifies them (e.g., check and get/set).
    Note that this one lock applies across all instances - the design of this class intends it to be a singleton.
    """

    lock = RLock()

    def __init__(self) -> None:
        """
        Initialize schema cache data.
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaCache.__init__: >>>')

        self._schema_key2schema = {}
        self._seq_no2schema_key = {}

        logger.debug('SchemaCache.__init__: <<<')

    def __setitem__(self, index: Union[SchemaKey, int], schema: dict) -> dict:
        """
        Put schema into cache and return it.

        :param index: schema key or sequence number
        :param schema: schema to put into cache
        :return: input schema
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaCache.__setitem__: >>> index: {}, schema: {}'.format(index, schema))

        if isinstance(index, SchemaKey):
            self._schema_key2schema[index] = schema
            self._seq_no2schema_key[schema['seqNo']] = index
        elif isinstance(index, int):
            s_key = schema_key(schema['id'])
            self._schema_key2schema[s_key] = schema
            self._seq_no2schema_key[index] = s_key
        else:
            logger.debug(
                'SchemaCache.__setitem__: <!< Bad index {} must be a schema key or a sequence number'.format(index))
            raise CacheIndex('Bad index {} must be a schema key or a sequence number'.format(index))

        logger.debug('SchemaCache.__setitem__: <<< {}'.format(schema))
        return schema

    def contains(self, index: Union[SchemaKey, int]) -> bool:
        """
        Return whether the cache contains a schema for the input key or sequence number.

        :param index: schema key or sequence number
        :return: whether the cache contains a schema for the input index
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaCache.contains: >>> index: {}'.format(index))

        rv = None
        if isinstance(index, SchemaKey):
            rv = (index in self._schema_key2schema)
        elif isinstance(index, int):
            rv = (index in self._seq_no2schema_key)
        else:
            rv = False

        logger.debug('SchemaCache.contains: <<< {}'.format(rv))
        return rv

    def index(self) -> dict:
        """
        Return dict mapping content sequence numbers to schema keys.

        :return: dict mapping sequence numbers to schema keys
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaCache.index: >>>')

        rv = self._seq_no2schema_key
        logger.debug('SchemaCache.index: <<< {}'.format(rv))
        return rv

    def __getitem__(self, index: Union[SchemaKey, int]) -> dict:
        """
        Get schema by key or sequence number, or raise CacheIndex for no such schema.

        Raise CacheIndex for no such index in schema store.

        :param index: schema key or sequence number
        :return: corresponding schema or None
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaCache.__getitem__: >>> index: {}'.format(index))

        rv = None
        if isinstance(index, SchemaKey):
            rv = self._schema_key2schema[index]
        elif isinstance(index, int):
            try:
                rv = self._schema_key2schema[self._seq_no2schema_key[index]]
            except KeyError:
                logger.debug('SchemaCache.__getitem__: <!< index {} not present'.format(index))
                raise CacheIndex('{}'.format(index))
        else:
            logger.debug('SchemaCache.__getitem__: <!< index {} must be int or SchemaKey'.format(index))
            raise CacheIndex('{} must be int or SchemaKey'.format(index))

        logger.debug('SchemaCache.__getitem__: <<< {}'.format(rv))
        return rv

    def schema_key_for(self, seq_no: int) -> SchemaKey:
        """
        Get schema key for schema by sequence number if known, None for no such schema in cache.

        :param seq_no: sequence number
        :return: corresponding schema key or None
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaCache.schema_key_for: >>> seq_no: {}'.format(seq_no))

        rv = self._seq_no2schema_key.get(seq_no, None)

        logger.debug('SchemaCache.schema_key_for: <<< {}'.format(rv))
        return rv

    def dict(self) -> dict:
        """
        Return flat dict with schemata cached.

        :return: flat dict, indexed by sequence number plus schema key data
        """

        return {'{}; {}'.format(seq_no, tuple(self._seq_no2schema_key[seq_no])):
            self._schema_key2schema[self._seq_no2schema_key[seq_no]]
                for seq_no in self._seq_no2schema_key}

    def __str__(self) -> str:
        """
        Return string pretty-print.

        :return: string pretty-print
        """

        return 'SchemaCache({})'.format(self.dict())


class RevoCacheEntry:
    """
    Class for revocation cache entry, housing a revocation registry definition and a Tails structure
    """

    def __init__(self, rev_reg_def: dict, tails: Tails = None):
        """
        Initialize with revocation registry definition and optional tails file.

        :param rev_reg_def: revocation registry definition
        :param tails: current tails file object
        """

        self._rev_reg_def = rev_reg_def or None
        self._tails = tails or None

    @property
    def rev_reg_def(self) -> dict:
        """
        Return rev reg def from cache entry.
        """

        return self._rev_reg_def

    @property
    def tails(self) -> Tails:
        """
        Return current tails file from cache entry.
        """

        return self._tails


SCHEMA_CACHE = SchemaCache()
CRED_DEF_CACHE = type('CredDefCache', (dict,), {'lock': RLock()})()
REVO_CACHE = type('RevoCache', (dict,), {'lock': RLock()})()
# REVO_STATE_CACHE = type('RevoStateCache', (dict,), {'lock': RLock()})()  # only HolderProver needs
