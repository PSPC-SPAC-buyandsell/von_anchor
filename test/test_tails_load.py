"""
Copyright 2017-2020 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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

import asyncio
import json
import subprocess
import time

import pytest

from von_anchor import OrgHubAnchor, RevRegBuilder, TrusteeAnchor
from von_anchor.error import AbsentSchema, ExtantWallet
from von_anchor.frill import Ink, ppjson, Stopwatch
from von_anchor.nodepool import NodePoolManager
from von_anchor.tails import Tails
from von_anchor.util import (
    cred_def_id,
    rev_reg_id2tag,
    schema_id,
    schema_key)
from von_anchor.wallet import WalletManager


WALLET_NAME = 'superstar'


def rrbx_prox():
    return int(subprocess.check_output(
        "ps -ef | grep 'rrbuilder.py -n {}' | grep python | grep -v grep | wc -l".format(WALLET_NAME),
        stderr=subprocess.STDOUT,
        shell=True))


async def beep(msg, n):
    print('(waiting for {})'.format(msg))
    for _ in range(n):
        await asyncio.sleep(1)
        print('.', end='', flush=True)
    print()


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_tails_load(
        pool_name,
        pool_genesis_txn_data,
        seed_trustee1):

    rrbx = True
    print(Ink.YELLOW('\n\n== Load-testing tails on {}ternal rev reg builder ==').format("ex" if rrbx else "in"))

    await RevRegBuilder.stop(WALLET_NAME)  # in case of re-run

    # Set up node pool ledger config and wallets, open pool, init anchors
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_data)
    pool = p_mgr.get(pool_name)
    await pool.open()

    w_mgr = WalletManager()
    wallets = {
        'trustee-anchor': {
            'seed': seed_trustee1,
            'storage_type': None,
            'config': None,
            'access_creds': None
        },
        WALLET_NAME: {
            'seed': 'Superstar-Anchor-000000000000000',
            'storage_type': None,
            'config': None,
            'access_creds': {
                'key': 'rrbx-test'
            }
        }
    }
    for (name, wdata) in wallets.items():
        try:
            wdata['wallet'] = await w_mgr.create({
                'id': name,
                'seed': wdata['seed']
            })
        except ExtantWallet:
            wdata['wallet'] = w_mgr.get({'id': name})
        finally:
            await wdata['wallet'].open()

    tan = TrusteeAnchor(wallets['trustee-anchor']['wallet'], pool)
    no_prox = rrbx_prox()
    san = OrgHubAnchor(wallets[WALLET_NAME]['wallet'], pool, rrbx=rrbx)
    if rrbx:
        await beep('external rev reg builder process on {}'.format(WALLET_NAME), 15)
        if rrbx_prox() != no_prox + 1:
            await RevRegBuilder.stop(WALLET_NAME)
            assert False, "External rev reg builder process did not start"
        async with OrgHubAnchor(
                wallets[WALLET_NAME]['wallet'],
                pool,
                rrbx=rrbx):  # check for exactly 1 external rev reg builder process
            await beep('external rev reg builder process uniqueness test on {}'.format(WALLET_NAME), 5)
            if rrbx_prox() != no_prox + 1:
                await RevRegBuilder.stop(WALLET_NAME)
                assert False, "External rev reg builder process was not unique"

    assert pool.handle

    await tan.open()
    await san.open()

    # Publish anchor particulars to ledger if not yet present
    for an in (tan, san):
        if not json.loads(await tan.get_nym(an.did)):
            await tan.send_nym(an.did, an.verkey, an.wallet.name, an.least_role())

    nyms = {
        'tan': json.loads(await tan.get_nym(tan.did)),
        'san': json.loads(await tan.get_nym(san.did))
    }
    print('\n\n== 1 == nyms: {}'.format(ppjson(nyms)))

    for k in nyms:
        assert 'dest' in nyms[k]

    # Publish schema to ledger if not yet present; get from ledger
    S_ID = schema_id(san.did, 'tails_load', '{}.0'.format(int(time.time())))
    S_KEY = schema_key(S_ID)

    schema_data = {
        'name': schema_key(S_ID).name,
        'version': schema_key(S_ID).version,
        'attr_names': [
            'number',
            'remainder'
        ]
    }

    try:
        await san.get_schema(S_KEY)  # may exist (almost certainly not)
    except AbsentSchema:
        await san.send_schema(json.dumps(schema_data))
    schema_json = await san.get_schema(S_KEY)
    schema = json.loads(schema_json)
    assert schema  # should exist now
    print('\n\n== 2 == SCHEMA [{} v{}]: {}'.format(S_KEY.name, S_KEY.version, ppjson(schema)))

    # Setup link secret for creation of cred req or proof
    await san.create_link_secret('LinkSecret')

    # SRI anchor create, store, publish cred definitions to ledger; create cred offers
    await san.send_cred_def(S_ID, revo=True)
    cd_id = cred_def_id(S_KEY.origin_did, schema['seqNo'], pool.protocol)

    assert ((not Tails.unlinked(san.dir_tails)) and
        [f for f in Tails.links(san.dir_tails, san.did) if cd_id in f])

    cred_def_json = await san.get_cred_def(cd_id)  # ought to exist now
    cred_def = json.loads(cred_def_json)
    print('\n\n== 3.0 == Cred def [{} v{}]: {}'.format(
        S_KEY.name,
        S_KEY.version,
        ppjson(json.loads(cred_def_json))))
    assert cred_def.get('schemaId', None) == str(schema['seqNo'])

    cred_offer_json = await san.create_cred_offer(schema['seqNo'])
    print('\n\n== 3.1 == Credential offer [{} v{}]: {}'.format(
        S_KEY.name,
        S_KEY.version,
        ppjson(cred_offer_json)))

    (cred_req_json, cred_req_metadata_json) = await san.create_cred_req(cred_offer_json, cd_id)
    print('\n\n== 4 == Credential request [{} v{}]: metadata {}, cred-req {}'.format(
        S_KEY.name,
        S_KEY.version,
        ppjson(cred_req_metadata_json),
        ppjson(cred_req_json)))
    assert json.loads(cred_req_json)

    # BC Reg anchor (as Issuer) issues creds and stores at HolderProver: get cred req, create cred, store cred
    CREDS = 4034  # enough to kick off rev reg on size 4096 and issue two creds in it: 1 needing set-rev-reg, 1 not
    print('\n\n== 5 == creating {} credentials'.format(CREDS))
    swatch = Stopwatch(2)
    optima = {}  # per rev-reg, fastest/slowest pairs
    for number in range(CREDS):
        swatch.mark()
        (cred_json, _) = await san.create_cred(
            cred_offer_json,
            cred_req_json,
            {
                'number': str(number),
                'remainder': str(number % 100)
            })
        elapsed = swatch.mark()
        tag = rev_reg_id2tag(Tails.current_rev_reg_id(san.dir_tails, cd_id))
        if tag not in optima:
            optima[tag] = (elapsed, elapsed)
        else:
            optima[tag] = (min(optima[tag][0], elapsed), max(optima[tag][1], elapsed))
        print('.', end='', flush=True)
        if ((number + 1) % 100) == 0:
            print('{}: #{}: {:.2f}-{:.2f}s'.format(number + 1, tag, *optima[tag]), flush=True)

        assert json.loads(cred_json)
    print('{}: #{}: {:.2f}-{:.2f}s'.format(number + 1, tag, *optima[tag]), flush=True)

    print('\n\n== 6 == best, worst times by revocation registry: {}'.format(ppjson(optima)))
    assert (not rrbx) or (max(optima[tag][1] for tag in optima) <
        4 * min(optima[tag][1] for tag in optima if int(tag) > 0))  # if waiting on rr beyond #0, sizes increase as 2^n

    await san.close()
    if rrbx:
        await RevRegBuilder.stop(WALLET_NAME)
    await tan.close()
    for (name, wdata) in wallets.items():
        await wdata['wallet'].close()
    await pool.close()
