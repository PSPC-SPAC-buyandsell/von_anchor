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

import pytest

from von_anchor import NominalAnchor, TrusteeAnchor
from von_anchor.frill import Ink, inis2dict, ppjson
from von_anchor.indytween import Role
from von_anchor.nodepool import NodePool
from von_anchor.wallet import Wallet


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_setnym(
        pool_ip,
        pool_name,
        pool_genesis_txn_file,
        pool_genesis_txn_path,
        seed_trustee1,
        path_setnym_ini,
        setnym_ini_file):

    print(Ink.YELLOW('\n\n== Testing setnym operation on node pool {} =='.format(pool_ip)))

    # Open pool, check if nym already present
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False})
    await p.open()
    assert p.handle

    tan = TrusteeAnchor(await Wallet(seed_trustee1, 'trustee-anchor').create(), p)
    await tan.open()

    cfg = inis2dict(str(path_setnym_ini))
    van = NominalAnchor(await Wallet(cfg['VON Anchor']['seed'], cfg['VON Anchor']['wallet.name']).create(), p)

    nym = json.loads(await van.get_nym(van.did))
    print('\n\n== 0 == Nym {} on ledger for anchor {} on DID {}'.format(
        '{} already'.format(ppjson(nym)) if nym else 'not yet',
        van.wallet.name,
        van.did))

    await tan.close()
    await p.close()

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 1 == Set nym with TRUST_ANCHOR role on {} for {}'.format(van.did, van.wallet.name))

    await p.open()
    await tan.open()
    nym = json.loads(await tan.get_nym(van.did))
    assert nym and Role.get(nym['role']) == Role.TRUST_ANCHOR
    print('\n\n== 2 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        van.did,
        van.wallet.name,
        ppjson(nym)))
    await tan.close()
    await p.close()

    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                print('{}={}'.format(key, '' if key == 'role' else value), file=ini_fh)
            print(file=ini_fh)

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 3 == Set nym with USER role on {} for {}'.format(van.did, van.wallet.name))

    await p.open()
    await tan.open()
    nym = json.loads(await tan.get_nym(van.did))
    assert nym and Role.get(nym['role']) == Role.USER
    last_nym_seqno = nym['seqNo']
    print('\n\n== 4 == Got nym transaction from ledger for DID {} ({}): {}'.format( 
        van.did,
        van.wallet.name,
        ppjson(nym)))
    await tan.close()
    await p.close()

    sub_proc = subprocess.run(  #  do it again
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert not sub_proc.returncode
    print('\n\n== 5 == Set nym again with USER role on {} for {}'.format(van.did, van.wallet.name))

    await p.open()
    await tan.open()
    nym = json.loads(await tan.get_nym(van.did))
    last_nym_seqno = nym['seqNo']
    print('\n\n== 6 == Got (same) nym transaction from ledger for DID {} ({}): {}'.format(  
        van.did,
        van.wallet.name,
        ppjson(nym)))
    await tan.close()
    await p.close()

    with open(path_setnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                print('{}={}'.format(key, 'BAD_ROLE' if key == 'role' else value), file=ini_fh)
            print(file=ini_fh)

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'setnym.py'),
            str(path_setnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    assert sub_proc.returncode
    print('\n\n== 7 == Called to set bad role for {}, got error text {}'.format(
        van.wallet.name,
        sub_proc.stdout.decode()))

    await p.open()
    await tan.open()
    nym = json.loads(await tan.get_nym(van.did))
    assert nym and nym['seqNo'] == last_nym_seqno
    await tan.close()
    await p.close()

    print('\n\n== 8 == Got nym transaction from ledger for DID {} ({}): {}'.format(
        van.did,
        van.wallet.name,
        ppjson(nym)))
