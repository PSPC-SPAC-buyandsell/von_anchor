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

from pathlib import Path

from von_anchor.error import JSONValidation
from von_anchor.frill import Ink
from von_anchor.nodepool import NodePool, Protocol

import pytest
import json


@pytest.mark.asyncio
async def test_pool_open(
    path_home,
    pool_name,
    pool_genesis_txn_path,
    pool_genesis_txn_file):

    print(Ink.YELLOW('\n\n== Testing Pool Config =='))

    assert Protocol.V_13.indy() != Protocol.V_14.indy()
    assert Protocol.V_14.indy() == Protocol.V_15.indy()
    assert Protocol.V_15.indy() == Protocol.V_16.indy()
    assert Protocol.V_16.indy() == Protocol.DEFAULT.indy()

    path = Path(path_home, 'pool', pool_name)

    try:
        NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': 'non-boolean'})
        assert False
    except JSONValidation:
        pass

    try:
        NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True, 'protocol': '0.0a'})
        assert False
    except JSONValidation:
        pass


    try:
        pool = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True, 'extra-property': True})
        await pool.remove()
        assert not path.exists(), 'Pool path {} still present'.format(path)
    except JSONValidation:
        assert False

    pool = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True, 'protocol': '1.6'})
    await pool.open()
    assert pool.handle is not None
    await pool.close()
    assert not path.exists(), 'Pool path {} still present'.format(path)

    pool = NodePool(pool_name, pool_genesis_txn_path)  # auto-remove default: False, protocol default: latest
    await pool.open()
    assert pool.handle is not None
    await pool.close()
    assert path.exists(), 'Pool path {} not present'.format(path)

    pool = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True})  # check survival re-opening existing pool
    await pool.open()
    assert pool.handle is not None
    await pool.close()
    assert not path.exists(), 'Pool path {} still present'.format(path)
