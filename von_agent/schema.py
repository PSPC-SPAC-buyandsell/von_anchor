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

from collections import namedtuple
from typing import Union
from von_agent.error import SchemaKeySpec, SchemaStoreIndex

import logging


SchemaKey = namedtuple('SchemaKey', 'origin_did name version')


def schema_key_for(spec: dict) -> SchemaKey:
    """
    Given schema key specifier in protocol (on keys origin-did, name, version) or indy-sdk API
    (on keys did/issuer/identifier/etc., name, version), return corresponding SchemaKey namedtuple.

    Raise SchemaKeySpec on bad schema key specification.

    :param spec: schema key specifier
    :return: SchemaKey
    """

    if (len(spec) == 3) and 'name' in spec and 'version' in spec:
        return SchemaKey(
            name=spec['name'],
            version=spec['version'],
            origin_did=spec[set(spec.keys() - {'name', 'version'}).pop()])

    raise SchemaKeySpec('Bad schema key specification {}'.format(spec))


class SchemaStore:
    """
    Retain schemata and fetch by key (origin_did, name, version) or by sequence number.
    """

    def __init__(self) -> None:
        """
        Initialize schema store data.
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaStore.__init__: >>>')

        self._schema_key2schema = {}
        self._seq_no2schema_key = {}

        logger.debug('SchemaStore.__init__: <<<')

    def __setitem__(self, index: Union[SchemaKey, int], schema: dict) -> dict:
        """
        Put schema into store and return it.

        :param index: schema key or sequence number
        :param schema: schema to put into store
        :return: input schema
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaStore.__setitem__: >>> index: {}, schema: {}'.format(index, schema))

        if isinstance(index, SchemaKey):
            self._schema_key2schema[index] = schema
            self._seq_no2schema_key[schema['seqNo']] = index
        elif isinstance(index, int):
            s_key = SchemaKey(schema['identifier'], schema['data']['name'], schema['data']['version'])
            self._schema_key2schema[s_key] = schema
            self._seq_no2schema_key[index] = s_key

        logger.debug('SchemaStore.__setitem__: <<< {}'.format(schema))
        return schema

    def contains(self, index: Union[SchemaKey, int]) -> bool:
        """
        Return whether the store contains a schema for the input key or sequence number.

        :param index: schema key or sequence number
        :return: whether the store contains a schema for the input index
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaStore.contains: >>> index: {}'.format(index))

        rv = None
        if isinstance(index, SchemaKey):
            rv = (index in self._schema_key2schema)
        elif isinstance(index, int):
            rv = (index in self._seq_no2schema_key)
        else:
            rv = False

        logger.debug('SchemaStore.contains: <<< {}'.format(rv))
        return rv

    def index(self) -> dict:
        """
        Return dict mapping content sequence numbers to schema keys.

        :return: dict mapping sequence numbers to schema keys
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaStore.index: >>>')

        rv = self._seq_no2schema_key
        logger.debug('SchemaStore.index: <<< {}'.format(rv))
        return rv

    def __getitem__(self, index: Union[SchemaKey, int]) -> dict:
        """
        Get schema by key or sequence number, or raise SchemaStoreIndex for no such schema.

        Raise SchemaStoreIndex for no such index in schema store.

        :param index: schema key or sequence number
        :return: corresponding schema or None
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaStore.__getitem__: >>> index: {}'.format(index))

        rv = None
        if isinstance(index, SchemaKey):
            rv = self._schema_key2schema[index]
        elif isinstance(index, int):
            try:
                rv = self._schema_key2schema[self._seq_no2schema_key[index]]
            except KeyError:
                logger.debug('SchemaStore.__getitem__: <!< index {} not present'.format(index))
                raise SchemaStoreIndex('{}'.format(index))
        else:
            logger.debug('SchemaStore.__getitem__: <!< index {} must be int or SchemaKey'.format(index))
            raise SchemaStoreIndex('{} must be int or SchemaKey'.format(index))

        logger.debug('SchemaStore.__getitem__: <<< {}'.format(rv))
        return rv

    def schema_key_for(self, seq_no: int) -> SchemaKey:
        """
        Get schema key for schema by sequence number if known, None for no such schema in store.

        :param seq_no: sequence number
        :return: corresponding schema key or None
        """

        logger = logging.getLogger(__name__)
        logger.debug('SchemaStore.schema_key_for: >>> seq_no: {}'.format(seq_no))

        rv = self._seq_no2schema_key.get(seq_no, None)

        logger.debug('SchemaStore.schema_key_for: <<< {}'.format(rv))
        return rv

    def dict(self) -> dict:
        """
        Return flat dict with schemata stored.

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

        return 'SchemaStore({})'.format(self.dict())
