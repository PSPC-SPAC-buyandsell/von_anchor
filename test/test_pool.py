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
import pytest

from tempfile import NamedTemporaryFile
from time import sleep, time

from indy.error import IndyError, ErrorCode

from von_anchor.error import AbsentPool, ExtantPool, JSONValidation
from von_anchor.indytween import SchemaKey
from von_anchor.frill import Ink, ppjson
from von_anchor.nodepool import NodePool, NodePoolManager, Protocol


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_protocol():

    print(Ink.YELLOW('\n\n== Testing Node Pool Protocols =='))

    assert Protocol.V1_3.indy() != Protocol.V1_4.indy()  # all the same except indy-node 1.3
    assert Protocol.V1_4.indy() == Protocol.V1_5.indy()
    assert Protocol.V1_5.indy() == Protocol.V1_6.indy()
    assert Protocol.V1_6.indy() == Protocol.V1_7.indy()
    assert Protocol.V1_7.indy() == Protocol.V1_8.indy()
    assert Protocol.V1_8.indy() == Protocol.V1_9.indy()
    assert Protocol.V1_9.indy() == Protocol.V1_10.indy()
    assert Protocol.V1_10.indy() == Protocol.V1_11.indy()
    assert Protocol.get('1.11') == Protocol.DEFAULT
    print('\n\n== 1 == Protocol enum values correspond OK to indy values')

    issuer_did = 'ZqhtaRvibYPQ23456789ee'
    seq_no = 123
    assert Protocol.V1_3.cred_def_id(issuer_did, seq_no) == '{}:3:CL:{}'.format(issuer_did, seq_no)
    assert Protocol.DEFAULT.cred_def_id(issuer_did, seq_no) == '{}:3:CL:{}:tag'.format(issuer_did, seq_no)

    assert Protocol.V1_3.cd_id_tag(for_box_id=True) == ''
    assert Protocol.V1_3.cd_id_tag(for_box_id=False) == 'tag'  # indy-sdk refuses empty string on issue-cred-def
    assert Protocol.DEFAULT.cd_id_tag(for_box_id=True) == ':tag'
    assert Protocol.DEFAULT.cd_id_tag(for_box_id=False) == 'tag'  # indy-sdk refuses empty string on issue-cred-def
    print('\n\n== 2 == Protocol enum values build cred def id and tags as expected')

    txn_13 = json.loads('''{
        "op": "REPLY",
        "result": {
            "data": {
                "identifier": "WgWxqztrNooG92RXvxSTWv",
                "data": {
                    "name": "green",
                    "version": "1.0",
                    "...": "..."
                },
                "...": "..."
            },
            "txnTime": 1234567890,
            "...": "..."
        },
        "...": "..."
    }''')
    assert json.loads(Protocol.V1_3.txn2data(txn_13)) == txn_13['result']['data']
    assert Protocol.V1_3.txn2epoch(txn_13) == 1234567890
    assert Protocol.V1_3.txn_data2schema_key(json.loads(Protocol.V1_3.txn2data(txn_13))) == SchemaKey(
        'WgWxqztrNooG92RXvxSTWv',
        'green',
        '1.0')

    txn_18 = json.loads('''{
        "op": "REPLY",
        "result": {
            "data": {
                "txn": {
                    "data": {
                        "data": {
                            "name": "green",
                            "version": "1.0",
                            "...": "..."
                        }
                    },
                    "metadata": {
                        "from": "WgWxqztrNooG92RXvxSTWv",
                        "...": "..."
                    },
                    "...": "..."
                },
                "...": "..."
            },
            "txnMetadata": {
                "txnTime": 1234567890,
                "...": "..."
            },
            "...": "..."
        },
        "...": "..."
    }''')
    assert json.loads(Protocol.DEFAULT.txn2data(txn_18)) == txn_18['result']['data']['txn']
    assert Protocol.DEFAULT.txn2epoch(txn_18) == 1234567890
    assert Protocol.DEFAULT.txn_data2schema_key(json.loads(Protocol.DEFAULT.txn2data(txn_18))) == SchemaKey(
        'WgWxqztrNooG92RXvxSTWv',
        'green',
        '1.0')
    print('\n\n== 3 == Protocol enum values extricate transaction data as expected')


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_manager(path_home, pool_genesis_txn_data, pool_ip):

    print(Ink.YELLOW('\n\n== Testing Node Pool Manager vs. IP {} =='.format(pool_ip)))

    # Create node pool manager
    p_mgr = NodePoolManager()
    p_mgr.protocol = Protocol.DEFAULT
    assert p_mgr.protocol == Protocol.DEFAULT

    # Create new pool on raw data
    name = 'pool-{}'.format(int(time()))
    assert name not in await p_mgr.list()
    print('\n\n== 1 == Pool {} not initially configured'.format(name))

    try:  # exercise bad pool addition
        await p_mgr.add_config(name, 'Not genesis transaction data')
        assert False
    except AbsentPool:
        pass

    await p_mgr.add_config(name, pool_genesis_txn_data)
    assert name in await p_mgr.list()
    print('\n\n== 2 == Added pool {} configuration on genesis transaction data'.format(name))

    try:
        await p_mgr.add_config(name, pool_genesis_txn_data)
        assert False
    except ExtantPool:
        pass

    try:
        pool = p_mgr.get('no-such-pool.{}'.format(int(time())))
        await pool.open()
        assert False
    except AbsentPool:
        pass

    pool = p_mgr.get(name)
    await pool.open()
    await pool.refresh()
    assert pool.handle is not None
    await pool.close()
    print('\n\n== 3 == Opened, refreshed, and closed pool {} on default configuration'.format(name))

    pool = p_mgr.get(name, {'timeout': 3600, 'extended_timeout': 7200})
    await pool.open()
    await pool.refresh()
    assert pool.handle is not None
    await pool.close()
    print('\n\n== 4 == Opened, refreshed, and closed pool {} on explicit configuration'.format(name))

    await p_mgr.remove(name)
    assert name not in await p_mgr.list()
    print('\n\n== 5 == Removed pool {} configuration'.format(name))

    with NamedTemporaryFile(mode='w+b', buffering=0) as fh_gen:
        fh_gen.write(pool_genesis_txn_data.encode())
        await p_mgr.add_config(name, fh_gen.name)
    assert name in await p_mgr.list()
    print('\n\n== 6 == Added pool {} configuration on genesis transaction file'.format(name))

    pool = p_mgr.get(name, {'timeout': 3600, 'extended_timeout': 7200})
    await pool.open()
    await pool.refresh()
    assert pool.handle is not None
    try:
        await p_mgr.remove(name)  # exercise non-removal of open pool
        assert False
    except ExtantPool:
        pass
    await pool.close()
    print('\n\n== 7 == Opened, refreshed, and closed pool {} on explicit configuration'.format(name))

    await p_mgr.remove(name)
    assert name not in await p_mgr.list()
    print('\n\n== 8 == Removed pool {} configuration'.format(name))


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
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_data)
    pool = p_mgr.get(pool_name)
    async with pool:
        assert pool.handle is not None
    assert pool.handle is None
    await pool.close()  # exercise double-close: should silently carry on

    pool.config['timeout'] = 'should be an integer'
    try:
        async with pool:
            assert False
    except IndyError as x_indy:
        assert x_indy.error_code == ErrorCode.CommonInvalidStructure
    pool.config.pop('timeout')

    print('\n\n== 1 == Pool {} opens and closes OK from existing ledger configuration'.format(pool))
