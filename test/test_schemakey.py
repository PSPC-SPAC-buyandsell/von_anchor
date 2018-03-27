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

from von_agent.error import SchemaKeySpec
from von_agent.schemakey import SchemaKey, schema_key_for
from von_agent.util import ppjson

import pytest


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_schema_key_for():
    spec = {'origin-did-specifier-of-choice': 'o-did', 'name': 'schema-name', 'version': '1.0'}
    assert schema_key_for(spec) == SchemaKey('o-did', 'schema-name', '1.0')

    for x_spec in (
            {},
            {'origin-did': 'o-did', 'x-missing-name': 'schema-name', 'version': '1.0'},
            {'name': 'schema-name', 'version': '1.0'},
            {'origin-did': 'o-did', 'name': 'schema-name', 'version': '1.0', 'too-many-keys': ''}):
        try:
            schema_key_for(x_spec)
            assert False
        except SchemaKeySpec:
            pass
