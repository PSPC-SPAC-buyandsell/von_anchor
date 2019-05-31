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
import subprocess

from os import unlink
from os.path import dirname, join, realpath
from tempfile import NamedTemporaryFile
from time import time

import pytest

from von_anchor import NominalAnchor, TrusteeAnchor, ProctorAnchor
from von_anchor.error import AbsentPool, ErrorCode, ExtantWallet
from von_anchor.frill import Ink, inis2dict, ppjson
from von_anchor.indytween import Role
from von_anchor.nodepool import NodePool, NodePoolManager
from von_anchor.op import AnchorData, NodePoolData
from von_anchor.wallet import Wallet, WalletManager


async def get_wallets(wallet_data, open_all, auto_remove=False):
    rv = {}
    w_mgr = WalletManager()
    for name in wallet_data:
        w = None
        creation_data = {'seed', 'did'} & {n for n in wallet_data[name]}
        if creation_data:
            w = await w_mgr.create(
                {
                    'id': name,
                    **{k: wallet_data[name][k] for k in creation_data},
                    'auto_remove': auto_remove
                },
                replace=True)
        else:
            w = w_mgr.get({'id': name, 'auto_remove': auto_remove})
        if open_all:
            await w.open()
        assert w.did
        assert w.verkey
        rv[name] = w
    return rv


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_formalisms(
        pool_ip,
        pool_name,
        pool_genesis_txn_data,
        seed_trustee1,
        path_setnym_ini,
        setnym_ini_file):

    print(Ink.YELLOW('\n\n== Testing usage screed and data structures'))

    # Run setnym with no parameters to engage usage message
    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py')
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert sub_proc.returncode == 1
    print('\n\n== 1 == Missing parameter invokes usage message OK')

    # Exercise namedtuples for syntax
    nodepool_data = NodePoolData('name', None)
    anchor_data = AnchorData('role', 'name', 'seed', 'did', 'wallet_create', 'wallet_type', 'wallet_access')
    print('\n\n== 2 == Data structures create OK')


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_setnym(
        pool_ip,
        pool_name,
        pool_genesis_txn_data,
        seed_trustee1,
        path_setnym_ini,
        setnym_ini_file):

    print(Ink.YELLOW('\n\n== Testing setnym operation on node pool {} =='.format(pool_ip)))

    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 1 == Initial configuration:\n{}'.format(cfg_fh.read()))
    cfg = inis2dict(str(path_setnym_ini))

    # Set up node pool ledger config and wallets, open pool, init anchors
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_data)

    wallets = await get_wallets(
        {
            'trustee-anchor': {
                'seed': seed_trustee1
            },
            cfg['VON Anchor']['name']: {
                'seed': cfg['VON Anchor']['seed']
            },
            'x-anchor': {
                'seed': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            }
        },
        open_all=True)

    try:
        async with NominalAnchor(wallets['x-anchor']) as xan:
            await xan.get_nym()
    except AbsentPool:
        pass
    wallets.pop('x-anchor')

    # Open pool, check if nym already present
    pool = p_mgr.get(pool_name)
    await pool.open()
    assert pool.handle

    tan = TrusteeAnchor(wallets['trustee-anchor'], pool)
    await tan.open()

    noman = NominalAnchor(wallets[cfg['VON Anchor']['name']], pool)

    nym = json.loads(await noman.get_nym(noman.did))
    print('\n\n== 2 == Nym {} on ledger for anchor {} on DID {}'.format(
        '{} already'.format(ppjson(nym)) if nym else 'not yet',
        noman.wallet.name,
        noman.did))

    await tan.close()
    await pool.close()

    # Run setnym on initial configuration, check ledger
    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 3 == Set nym with TRUST_ANCHOR role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    assert nym and Role.get(nym['role']) == Role.TRUST_ANCHOR
    print('\n\n== 4 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))
    await noman.close()
    await pool.close()

    # Run setnym on configuration with DID and explicit storage type, check ledger
    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                if section == 'VON Anchor':
                    if key == 'seed':
                        print('did={}'.format(noman.did), file=ini_fh)
                    elif key == 'wallet.type':
                        print('wallet.type=default', file=ini_fh)
                    else:
                        print('{}={}'.format(key, value), file=ini_fh)
                else:
                    print('{}={}'.format(key, value), file=ini_fh)
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 5 == Next configuration, on DID instead of seed and explicit wallet type:\n{}'.format(
            cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 6 == Set nym with TRUST_ANCHOR role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    assert nym and Role.get(nym['role']) == Role.TRUST_ANCHOR
    last_nym_seqno = nym['seqNo']
    print('\n\n== 7 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))
    await noman.close()
    await pool.close()

    # Run setnym on configuration with no seeds nor VON Anchor role, check ledger
    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                if key in ('seed', 'genesis.txn.path'):
                    continue
                print('{}={}'.format(key, '${X_ROLE:-}' if key == 'role' else value), file=ini_fh)  # exercise default
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 8 == Next configuration, no seeds, no VON Anchor role:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 9 == Set nym with USER role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    assert nym and Role.get(nym['role']) == Role.USER
    last_nym_seqno = nym['seqNo']
    print('\n\n== 10 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))
    await noman.close()
    await pool.close()

    # Run again to check idempotence
    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 11 == Set nym again with default role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    last_nym_seqno = nym['seqNo']
    print('\n\n== 12 == Got (same) nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))
    await noman.close()
    await pool.close()

    # Run setnym on configuration with no seeds and bad VON Anchor role, check ledger
    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                if key in ('seed', 'genesis.txn.path'):
                    continue
                print('{}={}'.format(key, 'BAD_ROLE' if key == 'role' else value), file=ini_fh)
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 13 == Next configuration, no seeds, bad VON Anchor role:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert sub_proc.returncode
    assert str(int(ErrorCode.BadRole)) in sub_proc.stdout.decode()
    print('\n\n== 14 == Called to set bad role for {}, got error text {}'.format(
        noman.wallet.name,
        sub_proc.stdout.decode()))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    noman_role = await noman.get_nym_role()
    assert nym and nym['seqNo'] == last_nym_seqno
    await noman.close()
    await pool.close()
    print('\n\n== 15 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))

    # Exercise reseed, ensure no side effect to role on ledger
    await pool.open()
    pan = ProctorAnchor(wallets[cfg['VON Anchor']['name']], pool, rrbx=False)
    await pan.open()
    next_seed = '{}000000000000VonAnchor1'.format(int(time()) + 1)
    await pan.reseed(next_seed)
    nym = json.loads(await pan.get_nym(noman.did))
    pan_role = await pan.get_nym_role()
    await pool.close()
    assert nym and nym['seqNo'] != last_nym_seqno
    assert pan_role == noman_role
    print('\n\n== 16 == As Proctor Anchor, reseeded, then got nym transaction from ledger for DID {} ({}): {}'.format(
        pan.did,
        pan.wallet.name,
        ppjson(nym)))
    last_nym_seqno = nym['seqNo']

    # Run setnym on configuration with same wallet for trustee and VON anchor
    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                if section == 'VON Anchor' and key == 'name':
                    print('{}={}'.format(key, cfg['Trustee Anchor']['name']), file=ini_fh)
                else:
                    print('{}={}'.format(key, value), file=ini_fh)
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 17 == Next configuration, same wallet for trustee anchor and VON anchor:\n{}'.format(
            cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert sub_proc.returncode
    assert str(int(ErrorCode.ExtantWallet)) in sub_proc.stdout.decode()
    print('\n\n== 18 == Called with same wallet for trustee anchor and VON anchor, got error text {}'.format(
        sub_proc.stdout.decode()))

    # Run setnym on configuration with new ledger node pool configuration
    genesis_tmp = NamedTemporaryFile(mode='w+b', buffering=0, delete=False)
    with genesis_tmp:
        genesis_tmp.write(pool_genesis_txn_data.encode())
    pool_copy = '{}.{}'.format(cfg['Node Pool']['name'], int(time()))
    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                if section == 'Node Pool':
                    if key == 'name':
                        print('name={}'.format(pool_copy), file=ini_fh)
                    elif key == 'genesis.txn.path':
                        print('genesis.txn.path={}'.format(genesis_tmp.name), file=ini_fh)  # includes /tmp/ path
                    else:
                        print('{}={}.xxx'.format(key, value), file=ini_fh)
                else:
                    print('{}={}'.format(key, value), file=ini_fh)
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 19 == Next configuration, calling for copy of node pool ledger config:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 20 == Called for new copy {} of node pool ledger config'.format(pool_copy))

    unlink(genesis_tmp.name)
    await p_mgr.remove(pool_copy)
    await pool.open()
    await pan.open()
    nym = json.loads(await pan.get_nym(pan.did))
    assert nym and Role.get(nym['role']) == Role.TRUST_ANCHOR
    assert nym and nym['seqNo'] != last_nym_seqno
    print('\n\n== 21 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        pan.did,
        pan.wallet.name,
        ppjson(nym)))
    await pan.close()
    await pool.close()

    # Run setnym on configuration with wrong genesis transaction path
    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                if section == 'Node Pool':
                    print('{}={}.xxx'.format(key, value), file=ini_fh)
                else:
                    print('{}={}'.format(key, value), file=ini_fh)
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 22 == Next configuration, missing pool and bad genesis txn path:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert sub_proc.returncode
    assert str(int(ErrorCode.AbsentPool)) in sub_proc.stdout.decode()
    print('\n\n== 23 == Called with missing pool and bad genesis txn path, got error text {}'.format(
        sub_proc.stdout.decode()))

    # Run setnym on configuration with no node pool ledger configuration
    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                if section == 'Node Pool':
                    if key == 'name':
                        print('{}={}.xxx'.format(key, value), file=ini_fh)
                    elif key == 'genesis.txn.path':
                        print('genesis.txn.path=', file=ini_fh)
                    else:
                        print('{}={}'.format(key, value), file=ini_fh)
                else:
                    print('{}={}'.format(key, value), file=ini_fh)
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 24 == Next configuration, missing pool and no genesis txn path:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert sub_proc.returncode
    assert str(int(ErrorCode.AbsentPool)) in sub_proc.stdout.decode()
    print('\n\n== 25 == Called with missing pool and no genesis txn path, got error text {}'.format(
        sub_proc.stdout.decode()))

    # Run again without trustee anchor wallet present
    await wallets['trustee-anchor'].close()
    await wallets['trustee-anchor'].remove()
    wallets.pop('trustee-anchor')
    noman = NominalAnchor(wallets[cfg['VON Anchor']['name']], pool)

    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                print('{}={}'.format(key, value), file=ini_fh)
            print(file=ini_fh)
    with open(path_setnym_ini, 'r') as cfg_fh:
        print('\n\n== 26 == Set VON anchor configuration, no Trustee anchor wallet a priori:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 27 == Set nym with TRUST_ANCHOR role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    assert nym and Role.get(nym['role']) == Role.TRUST_ANCHOR
    print('\n\n== 28 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))
    await noman.close()
    await pool.close()

    await pan.close()
    for name in wallets:
        await wallets[name].close()
