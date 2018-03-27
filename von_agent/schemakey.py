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
from von_agent.error import SchemaKeySpec


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
