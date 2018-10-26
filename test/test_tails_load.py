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

import json
import time

import pytest

from von_anchor import OrgHubAnchor, TrusteeAnchor
from von_anchor.error import AbsentSchema
from von_anchor.frill import Ink, ppjson
from von_anchor.nodepool import NodePool
from von_anchor.tails import Tails
from von_anchor.util import (
    cred_def_id,
    rev_reg_id2tag,
    schema_id,
    schema_key)
from von_anchor.wallet import Wallet


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_tails_load(
        pool_ip,
        pool_name,
        pool_genesis_txn_file,
        pool_genesis_txn_path,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing low-level API vs. IP {} =='.format(pool_ip)))

    # Open pool, init anchors
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False})

    tan = TrusteeAnchor(await Wallet(seed_trustee1, 'trust-anchor').create(), p)
    san = OrgHubAnchor(await Wallet('Superstar-Anchor-000000000000000', 'superstar').create(), p)

    await p.open()
    assert p.handle

    await tan.open()
    await san.open()

    # Publish anchor particulars to ledger if not yet present
    for an in (tan, san):
        if not json.loads(await tan.get_nym(an.did)):
            await tan.send_nym(an.did, an.verkey, an.wallet.name, an.role())

    nyms = {
        'tan': json.loads(await tan.get_nym(tan.did)),
        'san': json.loads(await tan.get_nym(san.did))
    }
    print('\n\n== 1 == nyms: {}'.format(ppjson(nyms)))

    for k in nyms:
        assert 'dest' in nyms[k]

    # Publish schema to ledger if not yet present; get from ledger
    S_ID = {
        'TAILS-LOAD': schema_id(san.did, 'tails_load', '{}.0'.format(int(time.time())))
    }

    schema_data = {
        S_ID['TAILS-LOAD']: {
            'name': schema_key(S_ID['TAILS-LOAD']).name,
            'version': schema_key(S_ID['TAILS-LOAD']).version,
            'attr_names': [
                'number',
                'remainder'
            ]
        }
    }

    # index by transaction number
    seq_no2schema = {}
    seq_no2schema_id = {}

    # index by schema id
    schema_json = {}
    schema = {}
    cred_offer_json = {}
    cred_offer = {}
    cred_def_json = {}
    cred_def = {}
    cd_id = {}
    cred_data = {}
    cred_req_json = {}
    cred_req = {}
    cred_json = {}
    cred_req_metadata_json = {}

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        try:
            await san.get_schema(s_key)  # may exist
        except AbsentSchema:
            await san.send_schema(json.dumps(schema_data[s_id]))
        schema_json[s_id] = await san.get_schema(s_key)
        assert json.loads(schema_json[s_id])  # should exist now

        schema_by_id_json = await san.get_schema(s_id)  # exercise get_schema on schema_id
        schema[s_id] = json.loads(schema_json[s_id])
        assert json.loads(schema_by_id_json)['seqNo'] == schema[s_id]['seqNo']

        seq_no2schema_id[schema[s_id]['seqNo']] = s_id
        seq_no2schema[schema[s_id]['seqNo']] = schema[s_id]
        print('\n\n== 2.{} == SCHEMA [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
        assert schema[s_id]
        i += 1

    # Setup link secrets, cred reqs at HolderProver anchor
    await san.create_link_secret('LinkSecret')

    # SRI anchor create, store, publish cred definitions to ledger; create cred offers
    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)

        await san.send_cred_def(s_id, True)
        cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'], p.protocol)

        assert ((not Tails.unlinked(san._dir_tails)) and
            [f for f in Tails.links(san._dir_tails, san.did) if cd_id[s_id] in f])

        cred_def_json[s_id] = await san.get_cred_def(cd_id[s_id])  # ought to exist now
        cred_def[s_id] = json.loads(cred_def_json[s_id])
        print('\n\n== 3.{}.0 == Cred def [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(json.loads(cred_def_json[s_id]))))
        assert cred_def[s_id].get('schemaId', None) == str(schema[s_id]['seqNo'])

        cred_offer_json[s_id] = await san.create_cred_offer(schema[s_id]['seqNo'])
        cred_offer[s_id] = json.loads(cred_offer_json[s_id])
        print('\n\n== 3.{}.1 == Credential offer [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(cred_offer_json[s_id])))
        i += 1

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await san.create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id])
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 4.{} == Credential request [{} v{}]: metadata {}, cred {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(cred_req_metadata_json[s_id]),
            ppjson(cred_req_json[s_id])))
        assert json.loads(cred_req_json[s_id])
        i += 1

    # BC Reg anchor (as Issuer) issues creds and stores at HolderProver: get cred req, create cred, store cred
    cred_data = {
        S_ID['TAILS-LOAD']: []
    }

    i = 0
    print('\n\n== 5 == creating 80000 credentials')
    worst = 0.0
    for s_id in cred_data:
        for number in range(80000):
            start = time.time()
            (cred_json[s_id], cred_revoc_id, epoch_creation) = await san.create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                {
                    'number': str(number),
                    'remainder': str(number % 100)
                }
            )
            elapsed = time.time() - start
            if elapsed > worst:
                worst = elapsed
            print('.', end='', flush=True)
            if ((i + 1) % 100) == 0:
                tag = rev_reg_id2tag(Tails.current_rev_reg_id(san._dir_tails, cd_id[s_id]))
                print('{}: rr#{}, <= {:.2f}s'.format(i + 1, tag, worst), flush=True)
                worst = 0.0

            assert json.loads(cred_json[s_id])

            i += 1

    await san.close()
    await tan.close()
    await p.close()
