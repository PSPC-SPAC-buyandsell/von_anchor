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

from os.path import dirname, join, realpath
from time import time

import pytest

from von_anchor import NominalAnchor, TrusteeAnchor, SRIAnchor
from von_anchor.error import AbsentPool, ExtantWallet
from von_anchor.frill import Ink, inis2dict, ppjson
from von_anchor.indytween import Role
from von_anchor.nodepool import NodePool, NodePoolManager
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
            w = await w_mgr.get({'id': name, 'auto_remove': auto_remove})
        if open_all:
            await w.open()
        assert w.did
        assert w.verkey
        rv[name] = w
    return rv


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
    manager = NodePoolManager()
    if pool_name not in await manager.list():
        await manager.add_config(pool_name, pool_genesis_txn_data)

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
    pool = manager.get(pool_name)
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
        print('\n\n== 5 == Next configuration, no seeds, no VON Anchor role:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 6 == Set nym with USER role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    assert nym and Role.get(nym['role']) == Role.USER
    last_nym_seqno = nym['seqNo']
    print('\n\n== 7 == Got nym transaction from ledger for DID {} ({}): {}'.format(
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
    print('\n\n== 8 == Set nym again with default role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    last_nym_seqno = nym['seqNo']
    print('\n\n== 9 == Got (same) nym transaction from ledger for DID {} ({}): {}'.format(
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
        print('\n\n== 10 == Next configuration, no seeds, bad VON Anchor role:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert sub_proc.returncode
    print('\n\n== 11 == Called to set bad role for {}, got error text {}'.format(
        noman.wallet.name,
        sub_proc.stdout.decode()))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    noman_role = await noman.get_nym_role()
    assert nym and nym['seqNo'] == last_nym_seqno
    await noman.close()
    await pool.close()

    print('\n\n== 12 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))

    await pool.open()
    san = SRIAnchor(wallets[cfg['VON Anchor']['name']], pool, rrbx=False)
    await san.open()
    next_seed = '{}000000000000VonAnchor1'.format(int(time()) + 1)
    await san.reseed(next_seed)
    nym = json.loads(await san.get_nym(noman.did))
    san_role = await san.get_nym_role()
    await pool.close()
    assert nym and nym['seqNo'] != last_nym_seqno
    assert san_role == noman_role  # ensure that reseed does not side-effect role on ledger

    print('\n\n== 13 == As SRI Anchor, reseeded, then got nym transaction from ledger for DID {} ({}): {}'.format(
        san.did,
        san.wallet.name,
        ppjson(nym)))

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
        print('\n\n== 14 == Set VON anchor configuration, no Trustee anchor wallet a priori:\n{}'.format(cfg_fh.read()))

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 15 == Set nym with TRUST_ANCHOR role on {} for {}'.format(noman.did, noman.wallet.name))

    await pool.open()
    await noman.open()
    nym = json.loads(await noman.get_nym(noman.did))
    assert nym and Role.get(nym['role']) == Role.TRUST_ANCHOR
    last_nym_seqno = nym['seqNo']
    print('\n\n== 16 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        noman.did,
        noman.wallet.name,
        ppjson(nym)))
    await noman.close()
    await pool.close()

    await san.close()
    for name in wallets:
        await wallets[name].close()
