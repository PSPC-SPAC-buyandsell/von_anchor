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


import pytest

from tempfile import NamedTemporaryFile
from time import sleep, time

from von_anchor.error import AbsentGenesis, AbsentPool, ExtantPool, JSONValidation
from von_anchor.frill import Ink
from von_anchor.nodepool import NodePool, NodePoolManager, Protocol


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_protocol():

    print(Ink.YELLOW('\n\n== Testing Node Pool Protocols =='))

    assert Protocol.V_13.indy() != Protocol.V_14.indy()  # all the same except indy-node 1.3
    assert Protocol.V_14.indy() == Protocol.V_15.indy()
    assert Protocol.V_15.indy() == Protocol.V_16.indy()
    assert Protocol.V_16.indy() == Protocol.V_17.indy()
    assert Protocol.V_17.indy() == Protocol.V_18.indy()
    assert Protocol.V_18.indy() == Protocol.DEFAULT.indy()

    print('\n\n== 1 == Protocols OK')

@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_manager(path_home, pool_genesis_txn_data, pool_ip):

    print(Ink.YELLOW('\n\n== Testing Node Pool Manager vs. IP {} =='.format(pool_ip)))

    # Create node pool manager
    manager = NodePoolManager()
    assert manager.protocol == Protocol.DEFAULT

    # Create new pool on raw data
    name = 'pool-{}'.format(int(time()))
    assert name not in await manager.list()
    print('\n\n== 1 == Pool {} not initially configured'.format(name))

    await manager.add_config(name, pool_genesis_txn_data)
    assert name in await manager.list()
    print('\n\n== 2 == Added pool {} configuration on genesis transaction data'.format(name))

    try:
        await manager.add_config(name, pool_genesis_txn_data)
        assert False
    except ExtantPool:
        pass

    try:
        pool = manager.get('no-such-pool.{}'.format(int(time())))
        await pool.open()
        assert False
    except AbsentPool:
        pass

    pool = manager.get(name)
    await pool.open()
    await pool.refresh()
    assert pool.handle is not None
    await pool.close()
    print('\n\n== 3 == Opened, refreshed, and closed pool {} on default configuration'.format(name))

    cache_id = pool.cache_id
    sleep(1)
    x_name = 'pool-{}'.format(int(time()))
    await manager.add_config('pool-{}'.format(int(time())), '\n'.join(pool_genesis_txn_data.split('\n')[::-1]))
    x_pool = manager.get(x_name)
    assert x_pool.cache_id == cache_id
    await manager.remove(x_name)
    print('\n\n== 4 == Confirmed cache id consistency: {}'.format(cache_id))

    pool = manager.get(name, {'timeout': 3600, 'extended_timeout': 7200})
    await pool.open()
    await pool.refresh()
    assert pool.handle is not None
    await pool.close()
    print('\n\n== 5 == Opened, refreshed, and closed pool {} on explicit configuration'.format(name))

    await manager.remove(name)
    assert name not in await manager.list()
    print('\n\n== 6 == Removed pool {} configuration'.format(name))

    with NamedTemporaryFile(mode='w+b', buffering=0) as fh_gen:
        fh_gen.write(pool_genesis_txn_data.encode())
        await manager.add_config(name, fh_gen.name)
    assert name in await manager.list()
    print('\n\n== 7 == Added pool {} configuration on genesis transaction file'.format(name))

    pool = manager.get(name, {'timeout': 3600, 'extended_timeout': 7200})
    await pool.open()
    await pool.refresh()
    assert pool.handle is not None
    await pool.close()
    print('\n\n== 8 == Opened, refreshed, and closed pool {} on explicit configuration'.format(name))

    await manager.remove(name)
    assert name not in await manager.list()
    print('\n\n== 9 == Removed pool {} configuration'.format(name))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_pool_open(path_home, pool_name, pool_genesis_txn_data, pool_ip):

    print(Ink.YELLOW('\n\n== Testing Node Pool Config vs. IP {} =='.format(pool_ip)))

    try:
        NodePool(pool_name, config={'extra': 'not allowed'})
        assert False
    except JSONValidation:
        pass

    # Set up node pool ledger config and wallets, open pool, init anchors
    manager = NodePoolManager()
    if pool_name not in await manager.list():
        await manager.add_config(pool_name, pool_genesis_txn_data)
    pool = manager.get(pool_name)
    await pool.open()
    assert pool.handle is not None
    await pool.close()

    print('\n\n== 1 == Pool {} opens and closes OK from existing ledger configuration'.format(pool_name))
