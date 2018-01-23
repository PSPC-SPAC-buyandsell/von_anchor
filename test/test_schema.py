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

from von_agent.schema import SchemaKey, SchemaStore
from von_agent.util import ppjson

import pytest

from pprint import pprint

#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_schema_store():
    N = 5 
    ss = SchemaStore()
    s_key = []
    schema = []
    for i in range(N):
        s_key.append(SchemaKey('did.{}'.format(i), 'schema-{}'.format(i//5), '{}'.format(i%5)))
        schema.append({
            'seqNo': i,
            'identifier': s_key[i].origin,
            'data': {
                'name': s_key[i].name,
                'version': s_key[i].version
            }
        })

    for i in range(N):
        if i % 2:
            ss[s_key[i]] = schema[i]
        else:
            ss[schema[i]['seqNo']] = schema[i]

    for i in range(N):
        assert ss.contains(s_key[i])
        assert ss.contains(schema[i]['seqNo'])
        assert ss[s_key[i]] == ss[schema[i]['seqNo']]

    assert len(ss.index()) == N
    assert not ss.contains(-1)

    print(str(ss))
    print(ppjson(ss.dict()))

    try:
        ss[-1]
    except KeyError:
        pass
