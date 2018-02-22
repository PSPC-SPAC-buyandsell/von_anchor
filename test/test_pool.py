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

from von_agent.error import JSONValidation
from von_agent.nodepool import NodePool

import pytest
import json


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_pool_open(
    pool_name,
    pool_genesis_txn_path,
    pool_genesis_txn_file):

    for pool_cfg in ({'extra-property': True}, {'auto-remove': 'non-boolean'}):
        try:
            NodePool(pool_name, pool_genesis_txn_path, pool_cfg)
            assert False
        except JSONValidation:
            pass

    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True})
    await p.open()
    assert p.handle is not None
    await p.close()

    p = NodePool(pool_name, pool_genesis_txn_path)  # auto-remove default: False
    await p.open()
    assert p.handle is not None
    await p.close()

    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True})  # check survival on re-opening existing pool
    await p.open()
    assert p.handle is not None
    await p.close()
