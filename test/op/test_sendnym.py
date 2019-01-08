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
from von_anchor.nodepool import NodePool
from von_anchor.wallet import Wallet


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_sendnym(
        pool_ip,
        pool_name,
        pool_genesis_txn_file,
        pool_genesis_txn_path,
        seed_trustee1,
        path_sendnym_ini,
        sendnym_ini_file):

    print(Ink.YELLOW('\n\n== Testing sendnym operation on node pool {} =='.format(pool_ip)))

    # Open pool, check if nym already present
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False})
    await p.open()
    assert p.handle

    tan = TrusteeAnchor(await Wallet(seed_trustee1, 'trustee-anchor').create(), p)
    await tan.open()

    cfg = inis2dict(str(path_sendnym_ini))
    newan = NominalAnchor(await Wallet(cfg['New Anchor']['seed'], cfg['New Anchor']['wallet.name']).create(), p)

    nym = json.loads(await newan.get_nym(newan.did))
    print('\n\n== 0 == Nym {} on ledger for anchor {} on DID {}'.format(
        '{} already'.format(ppjson(nym)) if nym else 'not yet',
        newan.wallet.name,
        newan.did))

    await tan.close()
    await p.close()

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'sendnym.py'),
            str(path_sendnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    assert not sub_proc.returncode
    print('\n\n== 1 == Sent: {} for {}'.format(newan.did, newan.wallet.name))

    await p.open()
    await tan.open()

    nym = json.loads(await tan.get_nym(newan.did))
    assert nym

    with open(path_sendnym_ini, 'w+') as ini_fh:
        for section in cfg:
            print('[{}]'.format(section), file=ini_fh)
            for (key, value) in cfg[section].items():
                print('{}={}'.format(key, 'XXXXX' if key == 'role' else value), file=ini_fh)
            print(file=ini_fh)

    sub_proc = subprocess.run(
        [
            'python',
            join(dirname(dirname(dirname(realpath(__file__)))), 'von_anchor', 'op', 'sendnym.py'),
            str(path_sendnym_ini)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    assert sub_proc.returncode
    print('\n\n== 2 == Sent bad role for {}, got {}'.format(
        newan.wallet.name,
        sub_proc.stderr.decode().split('\n')[-2]))  # ignore trailing empty line, indy-sdk ERROR logs

    await tan.close()
    await p.close()

    print('\n\n== 3 == Nym {} on ledger for anchor {} on DID {}'.format(ppjson(nym), newan.wallet.name, newan.did))
