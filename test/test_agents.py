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

from collections import namedtuple
from indy import agent, anoncreds, ledger, signus, pool, wallet, IndyError
from indy.error import ErrorCode
from von_agent.demo_agents import TrustAnchorAgent, SRIAgent, OrgBookAgent, BCRegistrarAgent
from von_agent.nodepool import NodePool
from von_agent.schema import SchemaKey
from von_agent.util import decode, encode, revealed_attrs, claims_for, prune_claims_json, schema_seq_nos_for, ppjson

import datetime
import pytest
import json


def claim_value_pair(plain):
    return [str(plain), encode(plain)]


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_agents_direct(
        pool_name,
        pool_genesis_txn_path,
        seed_trustee1,
        pool_genesis_txn_file,
        path_home):

    # 1. Open pool, init agents
    p = NodePool(pool_name, pool_genesis_txn_path)
    await p.open()
    assert p.handle

    tag = TrustAnchorAgent(
        p,
        seed_trustee1,
        'trustee_wallet',
        None,
        '127.0.0.1',
        8000,
        'api/v0')
    sag = SRIAgent(
        p,
        'SRI-Agent-0000000000000000000000',
        'sri-agent-wallet',
        None,
        '127.0.0.1',
        8001,
        'api/v0')
    pspcobag = OrgBookAgent(
        p,
        'PSPC-Org-Book-Agent-000000000000',
        'pspc-org-book-agent-wallet',
        None,
        '127.0.0.1',
        8002,
        'api/v0')
    bcobag = OrgBookAgent(
        p,
        'BC-Org-Book-Agent-00000000000000',
        'bc-org-book-agent-wallet',
        None,
        '127.0.0.1',
        8003,
        'api/v0')
    bcrag = BCRegistrarAgent(
        p,
        'BC-Registrar-Agent-0000000000000',
        'bc-registrar-agent-wallet',
        None,
        '127.0.0.1',
        8004,
        'api/v0')

    await tag.open()
    await sag.open()
    await pspcobag.open()
    await bcobag.open()
    await bcrag.open()

    # print('TAG DID {}'.format(tag.did))            # V4SG...
    # print('SAG DID {}'.format(sag.did))            # FaBA...
    # print('PSPCOBAG DID {}'.format(pspcobag.did))  # 45Ue...
    # print('BCOBAG DID {}'.format(bcobag.did))      # Rzra...
    # print('BCRAG DID {}'.format(bcrag.did))        # Q4zq...

    # 2. Publish agent particulars to ledger if not yet present
    for ag in (tag, sag, pspcobag, bcobag, bcrag):
        if not json.loads(await tag.get_nym(ag.did)):
            await tag.send_nym(ag.did, ag.verkey)
        if not json.loads(await tag.get_endpoint(ag.did)):
            await ag.send_endpoint()

    nyms = {
        'tag': await tag.get_nym(tag.did),
        'sag': await tag.get_nym(sag.did),
        'pspcobag': await tag.get_nym(pspcobag.did),
        'bcobag': await tag.get_nym(bcobag.did),
        'bcrag': await tag.get_nym(bcrag.did)
    }
    endpoints = {
        'tag': await tag.get_endpoint(tag.did),
        'sag': await tag.get_endpoint(sag.did),
        'pspcobag': await tag.get_endpoint(pspcobag.did),
        'bcobag': await tag.get_endpoint(bcobag.did),
        'bcrag': await tag.get_endpoint(bcrag.did)
    }

    print('\n\n== 1 == nyms {}\nendpoints {}\n'.format(nyms, endpoints))

    for k in nyms:
        assert 'dest' in nyms[k]
    for k in endpoints:
        assert 'host' in endpoints[k]
        assert 'port' in endpoints[k]

    # 3. Publish schema to ledger if not yet present; get from ledger
    S_KEY = {
        'BC': SchemaKey(bcrag, 'bc-reg', '1.0'),
        'SRI-1.0': SchemaKey(sag, 'sri', '1.0'),
        'SRI-1.1': SchemaKey(sag, 'sri', '1.1'),
        'GREEN': SchemaKey(sag, 'green', '1.0'),
    }

    schema_data = {
        S_KEY['BC']: {
            'name': S_KEY['BC'].name,
            'version': S_KEY['BC'].version,
            'attr_names': [
                'id',
                'busId',
                'orgTypeId',
                'jurisdictionId',
                'legalName',
                'effectiveDate',
                'endDate'
            ]
        },
        S_KEY['SRI-1.0']: {
            'name': S_KEY['SRI-1.0'].name,
            'version': S_KEY['SRI-1.0'].version,
            'attr_names': [
                'legalName',
                'jurisdictionId',
                'sriRegDate'
            ]
        },
        S_KEY['SRI-1.1']: {
            'name': S_KEY['SRI-1.1'].name,
            'version': S_KEY['SRI-1.1'].version,
            'attr_names': [
                'legalName',
                'jurisdictionId',
                'businessLang',
                'sriRegDate'
            ]
        },
        S_KEY['GREEN']: {
            'name': S_KEY['GREEN'].name,
            'version': S_KEY['GREEN'].version,
            'attr_names': [
                'legalName',
                'greenLevel',
                'auditDate'
            ]
        }
    }

    # index by transaction number
    seq_no2schema = {}
    seq_no2schema_key = {}

    # index by SchemaKey
    schema_json = {}
    schema = {}
    claim_def_json = {}
    claim_def = {}
    claim_data = {}
    claim_req = {}
    claim_req_json = {}
    claim = {}
    claim_json = {}
    find_req = {}
    claims_found = {}
    claims_found_json = {}

    holder_prover = {
        bcrag: bcobag,
        sag: pspcobag
    }

    try:
        await tag.get_schema(tag.did, 'Xxxx', 'X.x')  # Bad version number
    except IndyError as e:
        assert ErrorCode.LedgerInvalidTransaction == e.error_code

    i = 0
    for s_key in schema_data:
        swab_json = await bcrag.get_schema(  # may exist
            s_key.origin.did,
            s_key.name,
            s_key.version)
        if not json.loads(swab_json):
            await s_key.origin.send_schema(json.dumps(schema_data[s_key]))
        schema_json[s_key] = await s_key.origin.get_schema(
            s_key.origin.did,
            s_key.name,
            s_key.version)  # should exist now
        schema[s_key] = json.loads(schema_json[s_key])
        seq_no2schema_key[schema[s_key]['seqNo']] = s_key
        seq_no2schema[schema[s_key]['seqNo']] = schema[s_key]
        print('\n\n== 2.{} == SCHEMA [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_key])))
        assert schema[s_key]
        i += 1

    # 4. BC Registrar and SRI agents (as Issuers) create, store, and publish claim definitions to ledger
    non_claim_def_json = await bcobag.get_claim_def(999999, bcrag.did)  # ought not exist
    assert not json.loads(non_claim_def_json)

    i = 0
    for s_key in schema_data:
        await s_key.origin.send_claim_def(schema_json[s_key])
        claim_def_json[s_key] = await holder_prover[s_key.origin].get_claim_def(
            schema[s_key]['seqNo'],
            s_key.origin.did)  # ought to exist now
        claim_def[s_key] = json.loads(claim_def_json[s_key])
        print('\n\n== 3.{} == Claim def [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(json.loads(claim_def_json[s_key]))))
        assert json.loads(claim_def_json[s_key])['ref'] == schema[s_key]['seqNo']
        i += 1

    # 5. Setup master secrets, claim reqs at HolderProver agents
    await bcobag.create_master_secret('MasterSecret')
    await pspcobag.create_master_secret('SecretMaster')

    for ag in (bcobag, pspcobag):
        wallet_num = ag.wallet.num
        assert (await ag.reset_wallet()) > wallet_num  # makes sure later ops are OK on reset wallet

    i = 0
    for s_key in schema_data:
        await holder_prover[s_key.origin].store_claim_offer(s_key.origin.did, schema[s_key]['seqNo'])
        claim_req_json[s_key] = await holder_prover[s_key.origin].store_claim_req(
            s_key.origin.did,
            claim_def_json[s_key])
        claim_req[s_key] = json.loads(claim_req_json[s_key])
        print('\n\n== 4.{} == Claim req [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(claim_req_json[s_key])))
        assert json.loads(claim_req_json[s_key])
        i += 1

    # 6. BC Reg agent (as Issuer) issues claims and stores at HolderProver: get claim req, create claim, store claim
    claim_data = {
        S_KEY['BC']: [
            {
                'id': claim_value_pair('1'),
                'busId': claim_value_pair('11121398'),
                'orgTypeId': claim_value_pair('2'),
                'jurisdictionId': claim_value_pair('1'),
                'legalName': claim_value_pair('The Original House of Pies'),
                'effectiveDate': claim_value_pair('2010-10-10'),
                'endDate': claim_value_pair(None)
            },
            {
                'id': claim_value_pair('2'),
                'busId': claim_value_pair('11133333'),
                'orgTypeId': claim_value_pair('1'),
                'jurisdictionId': claim_value_pair('1'),
                'legalName': claim_value_pair('Planet Cake'),
                'effectiveDate': claim_value_pair('2011-10-01'),
                'endDate': claim_value_pair(None)
            },
            {
                'id': claim_value_pair('3'),
                'busId': claim_value_pair('11144444'),
                'orgTypeId': claim_value_pair('2'),
                'jurisdictionId': claim_value_pair('1'),
                'legalName': claim_value_pair('Tart City'),
                'effectiveDate': claim_value_pair('2012-12-01'),
                'endDate': claim_value_pair(None)
            }
        ],
        S_KEY['SRI-1.0']: [],
        S_KEY['SRI-1.1']: [],
        S_KEY['GREEN']: []
    }
    for s_key in claim_data:
        for c in claim_data[s_key]:
            (_, claim_json[s_key]) = await s_key.origin.create_claim(claim_req_json[s_key], c)
            assert json.loads(claim_json[s_key])
            await holder_prover[s_key.origin].store_claim(claim_json[s_key])

    # 7. BC Org Book agent (as HolderProver) finds claims; actuator filters post hoc
    find_req[S_KEY['BC']] = {
        'nonce': '1000',
        'name': 'bc_proof_req',
        'version': '0',
        'requested_attrs': {
            '{}_{}_uuid'.format(schema[S_KEY['BC']]['seqNo'], attr): {
                'schema_seq_no': schema[S_KEY['BC']]['seqNo'],
                'name': attr
            } for attr in claim_data[S_KEY['BC']][0]
        },
        'requested_predicates': {}
    }
    (bc_claim_uuids_all, claims_found_json[S_KEY['BC']]) = await bcobag.get_claims(json.dumps(find_req[S_KEY['BC']]))
    print('\n\n== 5 == All BC claims, no filter {}; {}'.format(
        bc_claim_uuids_all,
        ppjson(claims_found_json[S_KEY['BC']])))
    claims_found[S_KEY['BC']] = json.loads(claims_found_json[S_KEY['BC']])
    bc_display_pruned_filt_post_hoc = claims_for(
        claims_found[S_KEY['BC']],
        [{
            'schema_seq_no': schema[S_KEY['BC']]['seqNo'],
            'match': {
                'legalName': decode(claim_data[S_KEY['BC']][2]['legalName'][1])
            }
        }])
    print('\n\n== 6 == BC claims display, filtered post hoc matching {}: {}'.format(
        decode(claim_data[S_KEY['BC']][2]['legalName'][1]),
        ppjson(bc_display_pruned_filt_post_hoc)))
    bc_display_pruned = prune_claims_json(
        claims_found[S_KEY['BC']],
        {k for k in bc_display_pruned_filt_post_hoc})
    print('\n\n== 7 == BC claims, stripped down {}'.format(ppjson(bc_display_pruned)))

    filt = [{
        'schema': {
            'origin-did': S_KEY['BC'].origin.did,
            'name': S_KEY['BC'].name,
            'version': S_KEY['BC'].version
        },
        'match': {
            k: decode(claim_data[S_KEY['BC']][2][k][1]) for k in claim_data[S_KEY['BC']][2]
                if k in ('jurisdictionId', 'busId')
        }
    }]
    (bc_claim_uuids_filt, claims_found_json[S_KEY['BC']]) = await bcobag.get_claims(
        json.dumps(find_req[S_KEY['BC']]),
        filt)
    print('\n\n== 8 == BC claims, filtered a priori {}; {}'.format(
        bc_claim_uuids_filt,
        ppjson(claims_found_json[S_KEY['BC']])))
    assert set([*bc_display_pruned_filt_post_hoc]) == bc_claim_uuids_filt
    assert len(bc_display_pruned_filt_post_hoc) == 1

    bc_claim_uuid = bc_claim_uuids_filt.pop()

    # 8. BC Org Book agent (as HolderProver) creates proof for claim specified by filter
    claims_found[S_KEY['BC']] = json.loads(claims_found_json[S_KEY['BC']])
    bc_requested_claims = {
        'self_attested_attributes': {},
        'requested_attrs': {
            attr: [bc_claim_uuid, True]
                for attr in find_req[S_KEY['BC']]['requested_attrs'] if attr in claims_found[S_KEY['BC']]['attrs']
        },
        'requested_predicates': {
            pred: bc_claim_uuid
                for pred in find_req[S_KEY['BC']]['requested_predicates']
        }
    }
    wallet_claim_uuid2schema = {
        claims_found[S_KEY['BC']]['attrs'][attr_uuid][0]['claim_uuid']:
            seq_no2schema[claims_found[S_KEY['BC']]['attrs'][attr_uuid][0]['schema_seq_no']]
                for attr_uuid in claims_found[S_KEY['BC']]['attrs']
    }
    wallet_claim_uuid2claim_def = {
        claims_found[S_KEY['BC']]['attrs'][attr_uuid][0]['claim_uuid']:
            claim_def[seq_no2schema_key[claims_found[S_KEY['BC']]['attrs'][attr_uuid][0]['schema_seq_no']]]
                for attr_uuid in claims_found[S_KEY['BC']]['attrs']
    }
    bc_proof_json = await bcobag.create_proof(
        find_req[S_KEY['BC']],
        claims_found[S_KEY['BC']],
        bc_requested_claims)
    print('\n\n== 9 == BC proof (by filter) {}'.format(ppjson(bc_proof_json)))

    # 9. SRI agent (as Verifier) verifies proof (by filter)
    rc_json = await sag.verify_proof(
        find_req[S_KEY['BC']],
        json.loads(bc_proof_json))
    print('\n\n== 10 == The SRI agent verifies the BC proof (by filter) as {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # 10. BC Org Book agent (as HolderProver) finds claim by claim-uuid, no claim by non-claim-uuid
    seq_no = set(schema_seq_nos_for(claims_found[S_KEY['BC']], {bc_claim_uuid}).values()).pop()  # it's unique
    req_attrs = {
       '{}_{}_uuid'.format(seq_no, attr_name): {
           'schema_seq_no': seq_no,
           'name': attr_name
       } for attr_name in schema_data[S_KEY['BC']]['attr_names']
    }
    bc_claim_found_by_uuid = json.loads(await bcobag.get_claim_by_claim_uuid(bc_claim_uuid, req_attrs))
    print('\n\n== 11 == BC claim by claim-uuid={}: {}'.format(
        bc_claim_uuid,
        ppjson(bc_claim_found_by_uuid)))
    assert bc_claim_found_by_uuid
    assert bc_claim_found_by_uuid['attrs']

    bc_non_claim_by_uuid = json.loads(await bcobag.get_claim_by_claim_uuid(
        'claim::ffffffff-ffff-ffff-ffff-ffffffffffff',
        req_attrs))
    print('\n\n== 12 == BC non-claim: {}'.format(ppjson(bc_non_claim_by_uuid)))
    assert bc_non_claim_by_uuid
    assert all(not bc_non_claim_by_uuid['attrs'][attr] for attr in bc_non_claim_by_uuid['attrs'])

    # 11. BC Org Book agent (as HolderProver) creates proof for claim specified by claim-uuid
    bc_requested_claims = {
        'self_attested_attributes': {},
        'requested_attrs': {
            attr: [bc_claim_uuid, True]
                for attr in bc_claim_found_by_uuid['attrs']
        },
        'requested_predicates': {}
    }
    bc_proof_json = await bcobag.create_proof(
        find_req[S_KEY['BC']],
        bc_claim_found_by_uuid,
        bc_requested_claims)
    bc_proof = json.loads(bc_proof_json)
    print('\n\n== 13 == BC proof by claim-uuid={} {}'.format(bc_claim_uuid, ppjson(bc_proof_json)))

    # 12. SRI agent (as Verifier) verifies proof (by claim-uuid)
    rc_json = await sag.verify_proof(
        find_req[S_KEY['BC']],
        bc_proof)
    print('\n\n== 14 == SRI agent verifies BC proof by claim-uuid={} as: {}'.format(bc_claim_uuid, ppjson(rc_json)))
    assert json.loads(rc_json)

    # 13. Create and store SRI registration completion claims, green claim from verified proof + extra data
    revealed = revealed_attrs(bc_proof)
    claim_data[S_KEY['SRI-1.0']].append({
        **{k: claim_value_pair(revealed[k]) for k in revealed if k in schema_data[S_KEY['SRI-1.0']]['attr_names']},
        'sriRegDate': claim_value_pair(datetime.date.today().strftime('%Y-%m-%d'))
    })
    claim_data[S_KEY['SRI-1.1']].append({
        **{k: claim_value_pair(revealed[k]) for k in revealed if k in schema_data[S_KEY['SRI-1.1']]['attr_names']},
        'sriRegDate': claim_value_pair(datetime.date.today().strftime('%Y-%m-%d')),
        'businessLang': claim_value_pair('EN-CA')
    })
    claim_data[S_KEY['GREEN']].append({
        **{k: claim_value_pair(revealed[k]) for k in revealed if k in schema_data[S_KEY['GREEN']]['attr_names']},
        'greenLevel': claim_value_pair('Silver'),
        'auditDate': claim_value_pair(datetime.date.today().strftime('%Y-%m-%d'))
    })

    i = 0
    for s_key in claim_data:
        if s_key == S_KEY['BC']:
            continue
        for c in claim_data[s_key]:
            (_, claim_json[s_key]) = await s_key.origin.create_claim(claim_req_json[s_key], c)
            print('\n\n== 15.{} == SRI created claim [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(claim_json[s_key])))
            i += 1
            assert json.loads(claim_json[s_key])
            await holder_prover[s_key.origin].store_claim(claim_json[s_key])

    # 14. PSPC Org Book agent (as HolderProver) finds all claims, one schema at a time
    i = 0
    for s_key in schema:
        if s_key == S_KEY['BC']:
            continue
        find_req[s_key] = {
            'nonce': str(1234 + i),
            'name': 'sri_find_req',
            'version': '0',
            'requested_attrs': {
                '{}_{}_uuid'.format(schema[s_key]['seqNo'], attr): {
                    'schema_seq_no': schema[s_key]['seqNo'],
                    'name': attr
                } for attr in claim_data[s_key][0]
            },
            'requested_predicates': {}
        }

        (sri_claim_uuids, claims_found_json[s_key]) = await holder_prover[s_key.origin].get_claims(
            json.dumps(find_req[s_key]))

        print('\n\n== 16.{} == Claims on [{} v{}], no filter {}: {}'.format(
            i,
            s_key.name,
            s_key.version,
            sri_claim_uuids,
            ppjson(claims_found_json[s_key])))
        i += 1
    
    # 15. PSPC Org Book agent (as HolderProver) finds all claims on all schemata at once; actuator filters post hoc
    req_attrs_sri_find_all = {}
    for s_key in schema_data:
        if s_key == S_KEY['BC']:
            continue
        seq_no = schema[s_key]['seqNo']
        for attr_name in schema_data[s_key]['attr_names']:
            req_attrs_sri_find_all['{}_{}_uuid'.format(seq_no, attr_name)] = {
                'schema_seq_no': seq_no,
                'name': attr_name
            }
    find_req_sri_all = {
        'nonce': '9999',
        'name': 'sri_find_req_all',
        'version': '0',
        'requested_attrs': req_attrs_sri_find_all,
        'requested_predicates': {}
    }

    (sri_claim_uuids_all, sri_claims_found_all_json) = await pspcobag.get_claims(json.dumps(find_req_sri_all))
    print('\n\n== 17 == All SRI-issued claims (no filter) at PSPC Org Book {}: {}'.format(
        sri_claim_uuids_all,
        ppjson(sri_claims_found_all_json)))

    sri_claims_found_all = json.loads(sri_claims_found_all_json)
    sri_display_pruned_filt_post_hoc = claims_for(
        sri_claims_found_all,
        [{
            'schema_seq_no': schema[S_KEY['GREEN']]['seqNo'],
            'match': {
                'legalName': decode(claim_data[S_KEY['GREEN']][0]['legalName'][1])
            }
        }])
    print('\n\n== 18 == SRI claims display, filtered post hoc matching {}: {}'.format(
        decode(claim_data[S_KEY['GREEN']][0]['legalName'][1]),
        ppjson(sri_display_pruned_filt_post_hoc)))
    sri_display_pruned = prune_claims_json(
        sri_claims_found_all,
        {k for k in sri_display_pruned_filt_post_hoc})
    print('\n\n== 19 == SRI claims, stripped down {}'.format(ppjson(sri_display_pruned)))

    filt = [{
        'schema': {
            'origin-did': S_KEY['GREEN'].origin.did,
            'name': S_KEY['GREEN'].name,
            'version': S_KEY['GREEN'].version
        },
        'match': {
            'legalName': decode(claim_data[S_KEY['GREEN']][0]['legalName'][1])
        }
    }]
    (sri_claim_uuids_filt, claims_found_json[S_KEY['GREEN']]) = await pspcobag.get_claims(
        json.dumps(find_req[S_KEY['GREEN']]),
        filt)
    print('\n\n== 20 == SRI claims, filtered a priori {}; {}'.format(
        sri_claim_uuids_filt,
        ppjson(claims_found_json[S_KEY['GREEN']])))
    assert set([*sri_display_pruned_filt_post_hoc]) == sri_claim_uuids_filt
    assert len(sri_display_pruned_filt_post_hoc) == 1

    sri_claims_found_all = json.loads(sri_claims_found_all_json)
    # sri_claim_uuids_all
    sri_req_attrs4sri_req_claims = {}
    for attr_uuid in sri_claims_found_all['attrs']:
        sri_req_attrs4sri_req_claims[attr_uuid] = [sri_claims_found_all['attrs'][attr_uuid][0]['claim_uuid'], True]

    # 16. PSPC Org Book agent (as HolderProver) creates proof for multiple claims
    sri_requested_claims = {
        'self_attested_attributes': {},
        'requested_attrs': sri_req_attrs4sri_req_claims,
        'requested_predicates': {}
    }
    sri_proof_json = await pspcobag.create_proof(
        find_req_sri_all,
        sri_claims_found_all,
        sri_requested_claims)
    print('\n\n== 21 == PSPC Org Book proof on claim-uuid={} {}'.format(sri_claim_uuids_all, ppjson(sri_proof_json)))
    sri_proof = json.loads(sri_proof_json)

    # 17. SRI (as Verifier) verify proof
    rc_json = await sag.verify_proof(
        find_req_sri_all,
        sri_proof)

    print('\n\n== 22 == the SRI agent verifies the PSPC Org Book proof by claim-uuid={} as {}'.format(
        sri_claim_uuids_all,
        ppjson(rc_json)))
    assert json.loads(rc_json)

    await bcrag.close()
    await bcobag.close()
    await pspcobag.close()
    await sag.close()
    await tag.close()
    await p.close()


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_agents_process_forms_local(
        pool_name,
        pool_genesis_txn_path,
        seed_trustee1,
        pool_genesis_txn_file,
        path_home):

    # 1. Open pool, init agents
    async with NodePool(pool_name, pool_genesis_txn_path) as p, (
            TrustAnchorAgent(
                p,
                seed_trustee1,
                'trustee_wallet',
                None,
                '127.0.0.1',
                '8000',
                'api/v0')) as tag, (
            SRIAgent(
                p,
                'SRI-Agent-0000000000000000000000',
                'sri-agent-wallet',
                None,
                '127.0.0.1',
                8001,
                'api/v0')) as sag, (
            OrgBookAgent(
                p,
                'PSPC-Org-Book-Agent-000000000000',
                'pspc-org-book-agent-wallet',
                None,
                '127.0.0.1',
                8003,
                'api/v0')) as pspcobag, (
            OrgBookAgent(
                p,
                'BC-Org-Book-Agent-00000000000000',
                'bc-org-book-agent-wallet',
                None,
                '127.0.0.1',
                8003,
                'api/v0')) as bcobag, (
            BCRegistrarAgent(
                p,
                'BC-Registrar-Agent-0000000000000',
                'bc-reg-agent-wallet',
                None,
                '127.0.0.1',
                8004,
                'api/v0')) as bcrag:

        assert p.handle is not None

        # print('TAG DID {}'.format(tag.did))            # V4SG...
        # print('SAG DID {}'.format(sag.did))            # FaBA...
        # print('PSPCOBAG DID {}'.format(pspcobag.did))  # 45Ue...
        # print('BCOBAG DID {}'.format(bcobag.did))      # Rzra...
        # print('BCRAG DID {}'.format(bcrag.did))        # Q4zq...

        # 2. Publish agent particulars to ledger if not yet present
        for ag in (tag, sag, pspcobag, bcobag, bcrag):
            nym_lookup_form = {
                'type': 'agent-nym-lookup',
                'data': {
                    'agent-nym': {
                        'did': ag.did
                    }
                }
            }
            nym = json.loads(await ag.process_post(nym_lookup_form))
            if not nym:
                resp_json = await tag.process_post({
                    'type': 'agent-nym-send',
                    'data': {
                        'agent-nym': {
                            'did': ag.did,
                            'verkey': ag.verkey
                        }
                    }
                })

            nym = json.loads(await ag.process_post(nym_lookup_form))
            assert nym

            endpoint_lookup_form = {
                'type': 'agent-endpoint-lookup',
                'data': {
                    'agent-endpoint': {
                        'did': ag.did
                    }
                }
            }
            endpoint = json.loads(await tag.process_post(endpoint_lookup_form))
            if not endpoint:
                resp_json = await ag.process_post({
                    'type': 'agent-endpoint-send',
                    'data': {
                    }
                })
            endpoint = json.loads(await ag.process_post(endpoint_lookup_form))
            assert endpoint

        try:  # Make sure only a trust anchor can register an agent
            await sag.process_post({
                'type': 'agent-nym-send',
                'data': {
                    'agent-nym': {
                        'did': sag.did,
                        'verkey': sag.verkey
                    }
                }
            })
            assert False
        except NotImplementedError:
            pass

        # 3. Publish schema to ledger if not yet present; get from ledger
        S_KEY = {
            'BC': SchemaKey(bcrag, 'bc-reg', '1.0'),
            'SRI-1.0': SchemaKey(sag, 'sri', '1.0'),
            'SRI-1.1': SchemaKey(sag, 'sri', '1.1'),
            'GREEN': SchemaKey(sag, 'green', '1.0'),
        }

        schema_data = {
            S_KEY['BC']: {
                'name': S_KEY['BC'].name,
                'version': S_KEY['BC'].version,
                'attr_names': [
                    'id',
                    'busId',
                    'orgTypeId',
                    'jurisdictionId',
                    'legalName',
                    'effectiveDate',
                    'endDate'
                ]
            },
            S_KEY['SRI-1.0']: {
                'name': S_KEY['SRI-1.0'].name,
                'version': S_KEY['SRI-1.0'].version,
                'attr_names': [
                    'legalName',
                    'jurisdictionId',
                    'sriRegDate'
                ]
            },
            S_KEY['SRI-1.1']: {
                'name': S_KEY['SRI-1.1'].name,
                'version': S_KEY['SRI-1.1'].version,
                'attr_names': [
                    'legalName',
                    'jurisdictionId',
                    'businessLang',
                    'sriRegDate'
                ]
            },
            S_KEY['GREEN']: {
                'name': S_KEY['GREEN'].name,
                'version': S_KEY['GREEN'].version,
                'attr_names': [
                    'legalName',
                    'greenLevel',
                    'auditDate'
                ]
            }
        }

        # index by transaction number
        seq_no2schema = {}
        seq_no2schema_key = {}

        # index by SchemaKey
        schema_lookup_form = {}
        schema_json = {}
        schema = {}
        claim_def_json = {}
        claim_def = {}
        claim_data = {}
        claim_req = {}
        claim_req_json = {}
        claim = {}
        claim_json = {}
        find_req = {}
        claims_found = {}
        claims_found_json = {}

        holder_prover = {
            bcrag: bcobag,
            sag: pspcobag
        }

        schema_lookup_form = {
            S_KEY['BC']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': bcrag.did,
                        'name': S_KEY['BC'].name,
                        'version': S_KEY['BC'].version
                    }
                }
            },
            S_KEY['SRI-1.0']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': sag.did,
                        'name': S_KEY['SRI-1.0'].name,
                        'version': S_KEY['SRI-1.0'].version
                    }
                }
            },
            S_KEY['SRI-1.1']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': sag.did,
                        'name': S_KEY['SRI-1.1'].name,
                        'version': S_KEY['SRI-1.1'].version
                    }
                }
            },
            S_KEY['GREEN']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': sag.did,
                        'name': S_KEY['GREEN'].name,
                        'version': S_KEY['GREEN'].version
                    }
                }
            }
        }

        try:
            schema_lookup_form[S_KEY['BC']]['data']['schema']['version'] = 'xxx'
            schema_json = await bcrag.process_post(schema_lookup_form[S_KEY['BC']])  # Bad version number
            assert False
        except IndyError:
            pass

        schema_lookup_form[S_KEY['BC']]['data']['schema']['version'] = '999.999'
        assert not json.loads(await bcrag.process_post(schema_lookup_form[S_KEY['BC']]))  # ought not exist
        schema_lookup_form[S_KEY['BC']]['data']['schema']['version'] = schema_data[S_KEY['BC']]['version']  # restore

        i = 0
        for s_key in schema_data:
            swab_json = await bcrag.get_schema(  # may exist
                s_key.origin.did,
                s_key.name,
                s_key.version)
            if not json.loads(swab_json):
                await s_key.origin.send_schema(json.dumps(schema_data[s_key]))
                await s_key.origin.process_post({
                    'type': 'schema-send',
                    'data': {
                        'schema': {
                            'origin-did': s_key.origin.did,
                            'name': s_key.name,
                            'version': s_key.version
                        },
                        'attr-names': schema_data[s_key]['attr_names']
                    }
                })
            schema_json[s_key] = await s_key.origin.get_schema(
                s_key.origin.did,
                s_key.name,
                s_key.version)  # should exist now
            schema[s_key] = json.loads(schema_json[s_key])
            assert schema[s_key]
            seq_no2schema_key[schema[s_key]['seqNo']] = s_key
            seq_no2schema[schema[s_key]['seqNo']] = schema[s_key]
            print('\n\n== 2.{} == SCHEMA [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_key])))
            i += 1

        for ag in (pspcobag, bcobag):
            try:  # Make sure only an origin can send a schema
                await ag.process_post({
                    'type': 'schema-send',
                    'data': {
                        'schema': {
                            'origin-did': ag.did,
                            'name': S_KEY['BC'].name,
                            'version': S_KEY['BC'].version
                        },
                        'attr-names': schema_data[S_KEY['BC']]['attr_names']
                    }
                })
                assert False
            except NotImplementedError:
                pass

        # 4. BC Registrar and SRI agents (as Issuers) create, store,  and publish claim def to ledger
        i = 0
        for s_key in schema_data:
            claim_def_send_form = {
                'type': 'claim-def-send',
                'data': {
                    'schema': {
                        'origin-did': s_key.origin.did,
                        'name': s_key.name,
                        'version': s_key.version
                    }
                }
            }
            await s_key.origin.process_post(claim_def_send_form)
            claim_def_json[s_key] = await holder_prover[s_key.origin].get_claim_def(
                schema[s_key]['seqNo'],
                s_key.origin.did)  # ought to exist now (short-circuit to low-level API)
            claim_def[s_key] = json.loads(claim_def_json[s_key])
            print('\n\n== 3.{} == Claim def [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(json.loads(claim_def_json[s_key]))))
            assert json.loads(claim_def_json[s_key])['ref'] == schema[s_key]['seqNo']
            i += 1

        # 5. Setup master secrets, claim reqs at HolderProver agents
        master_secret_set_form = {
            'type': 'master-secret-set',
            'data': {
                'label': 'maestro'
            }
        }
        claim_hello_form = {
            s_key: {
                'type': 'claim-hello',
                'data': {
                    'issuer-did': s_key.origin.did,
                    'schema': {
                        'origin-did': s_key.origin.did,
                        'name': s_key.name,
                        'version': s_key.version
                    }
                }
            } for s_key in schema_data
        }

        try:  # master secret unspecified, ought to fail
            await bcobag.process_post(claim_hello_form[S_KEY['BC']])
        except ValueError:
            pass

        await bcobag.process_post(master_secret_set_form)
        master_secret_set_form['data']['label'] = 'shhhhhhh'
        await pspcobag.process_post(master_secret_set_form)

        claims_reset_form = {
            'type': 'claims-reset',
            'data': {}
        }
        for ag in (bcobag, pspcobag):  # reset all HolderProvers
            assert not json.loads(await bcobag.process_post(claims_reset_form))  # response is {} if OK

        i = 0
        for s_key in schema_data:
            claim_req_json[s_key] = await holder_prover[s_key.origin].process_post(claim_hello_form[s_key])
            claim_req[s_key] = json.loads(claim_req_json[s_key])
            assert claim_req[s_key]

        # 6. BC Reg agent (as Issuer) issues claims and stores at HolderProver: get claim req, create claim, store claim
        claim_data = {
            S_KEY['BC']: [
                {
                    'id': '1',
                    'busId': '11121398',
                    'orgTypeId': '2',
                    'jurisdictionId': '1',
                    'legalName': 'The Original House of Pies',
                    'effectiveDate': '2010-10-10',
                    'endDate': None
                },
                {
                    'id': '2',
                    'busId': '11133333',
                    'orgTypeId': '1',
                    'jurisdictionId': '1',
                    'legalName': 'Planet Cake',
                    'effectiveDate': '2011-10-01',
                    'endDate': None
                },
                {
                    'id': '3',
                    'busId': '11144444',
                    'orgTypeId': '2',
                    'jurisdictionId': '1',
                    'legalName': 'Tart City',
                    'effectiveDate': '2012-12-01',
                    'endDate': None
                }
            ],
            S_KEY['SRI-1.0']: [],
            S_KEY['SRI-1.1']: [],
            S_KEY['GREEN']: []
        }
        for s_key in claim_data:
            for c in claim_data[s_key]:
                claim_json[s_key] = await s_key.origin.process_post({
                    'type': 'claim-create',
                    'data': {
                        'claim-req': claim_req[s_key],
                        'claim-attrs': c
                    }
                })
                claim[s_key] = json.loads(claim_json[s_key])
                assert claim[s_key]
                await holder_prover[s_key.origin].process_post({
                    'type': 'claim-store',
                    'data': {
                        'claim': claim[s_key]
                    }
                })

        # 7. BC Org Book agent (as HolderProver) finds claims; actuator filters post hoc
        find_req[S_KEY['BC']] = {
            'nonce': '2000',
            'name': 'bc_proof_req',
            'version': '0',
            'requested_attrs': {
                '{}_{}_uuid'.format(schema[S_KEY['BC']]['seqNo'], attr): {
                    'schema_seq_no': schema[S_KEY['BC']]['seqNo'],
                    'name': attr
                } for attr in claim_data[S_KEY['BC']][0]
            },
            'requested_predicates': {}
        }
        claims_found[S_KEY['BC']] = json.loads(await bcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': [
                    {
                        'origin-did': bcrag.did,
                        'name': S_KEY['BC'].name,
                        'version': S_KEY['BC'].version
                    }
                ],
                'claim-filter': {
                    'attr-match': {},
                    'predicate-match': [],
                },
                'requested-attrs': []
            }
        }))

        print('\n\n== 4 == All BC claims, no filter: {}'.format(ppjson(claims_found[S_KEY['BC']])))
        bc_display_pruned_filt_post_hoc = claims_for(
            claims_found[S_KEY['BC']]['claims'],
            [{
                'schema_seq_no': schema[S_KEY['BC']]['seqNo'],
                'match': {
                    'legalName': claim_data[S_KEY['BC']][2]['legalName']
                }
            }])

        try:  # exercise proof restriction to one claim per attribute
            await bcobag.process_post({
                'type': 'proof-request',
                'data': {
                    'schemata': [
                        {
                            'origin-did': bcrag.did,
                            'name': S_KEY['BC'].name,
                            'version': S_KEY['BC'].version
                        }
                    ],
                    'claim-filter': {
                        'attr-match': [],
                        'predicate-match': [],
                    },
                    'requested-attrs': []
                }
            })
            assert False
        except ValueError:
            pass  # carry on: proof supports at most one claim per attribute

        print('\n\n== 5 == display BC claims filtered post hoc matching {}: {}'.format(
            claim_data[S_KEY['BC']][2]['legalName'],
            ppjson(bc_display_pruned_filt_post_hoc)))
        bc_display_pruned = prune_claims_json(
            claims_found[S_KEY['BC']]['claims'],
            {k for k in bc_display_pruned_filt_post_hoc})
        print('\n\n== 6 == BC claims, stripped down {}'.format(ppjson(bc_display_pruned)))

        bc_claims_prefilt_json = await bcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': [{
                    'origin-did': bcrag.did,
                    'name': S_KEY['BC'].name,
                    'version': S_KEY['BC'].version
                }],
                'claim-filter': {
                    'attr-match': [{
                        'schema': {
                            'origin-did': bcrag.did,
                            'name': S_KEY['BC'].name,
                            'version': S_KEY['BC'].version
                        },
                        'match': {
                            k: claim_data[S_KEY['BC']][2][k] for k in claim_data[S_KEY['BC']][2]
                                if k in ('jurisdictionId', 'busId')
                        }
                    }],
                    'predicate-match': []
                },
                'requested-attrs': []
            }
        })
        bc_claims_prefilt = json.loads(bc_claims_prefilt_json)
        print('\n\n== 6 == BC claims, with filter a priori, process-post {}'.format(ppjson(bc_claims_prefilt)))
        bc_display_pruned_prefilt = claims_for(bc_claims_prefilt['claims'])
        print('\n\n== 7 == BC display claims filtered a priori matching {}: {}'.format(
            claim_data[S_KEY['BC']][2]['legalName'],
            ppjson(bc_display_pruned_prefilt)))
        assert set([*bc_display_pruned_filt_post_hoc]) == set([*bc_display_pruned_prefilt])
        assert len(bc_display_pruned_filt_post_hoc) == 1

        # 8. BC Org Book agent (as HolderProver) creates proof (by filter)
        bc_proof_resp = json.loads(await bcobag.process_post({
            'type': 'proof-request',
            'data': {
                'schemata': [{
                    'origin-did': bcrag.did,
                    'name': S_KEY['BC'].name,
                    'version': S_KEY['BC'].version
                }],
                'claim-filter': {
                    'attr-match': [{
                        'schema': {
                            'origin-did': bcrag.did,
                            'name': S_KEY['BC'].name,
                            'version': S_KEY['BC'].version
                        },
                        'match': {
                            k: claim_data[S_KEY['BC']][2][k] for k in claim_data[S_KEY['BC']][2]
                                if k in ('jurisdictionId', 'busId')
                        }
                    }],
                    'predicate-match': []
                },
                'requested-attrs': []
            }
        }))
        print('\n\n== 8 == BC proof response (by filter) {}'.format(ppjson(bc_proof_resp)))

        # 9. SRI agent (as Verifier) verifies proof (by filter)
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': bc_proof_resp
        })
        print('\n\n== 9 == the SRI agent verifies the BC proof (by filter) as {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 10. BC Org Book agent (as HolderProver) creates proof (by claim-uuid)
        bc_claim_uuid = set([*bc_display_pruned_prefilt]).pop()
        seq_no = set(schema_seq_nos_for(bc_claims_prefilt['claims'], {bc_claim_uuid}).values()).pop()  # it's unique
        bc_proof_resp = json.loads(await bcobag.process_post({
            'type': 'proof-request-by-claim-uuid',
            'data': {
                'schemata': [{
                    'origin-did': seq_no2schema_key[seq_no].origin.did,
                    'name': seq_no2schema_key[seq_no].name,
                    'version': seq_no2schema_key[seq_no].version
                }],
                'claim-uuids': [
                    bc_claim_uuid
                ],
                'requested-attrs': []
            }
        }))
        print('\n\n== 10 == BC proof response by claim-uuid={}: {}'.format(bc_claim_uuid, ppjson(bc_proof_resp)))

        # 11. BC Org Book agent (HolderProver) creates non-proof (by non-claim-uuid)
        bc_non_claim_uuid = 'claim::ffffffff-ffff-ffff-ffff-ffffffffffff'
        try:
            json.loads(await bcobag.process_post({
                'type': 'proof-request-by-claim-uuid',
                'data': {
                    'schemata': [{
                        'origin-did': seq_no2schema_key[seq_no].origin.did,
                        'name': seq_no2schema_key[seq_no].name,
                        'version': seq_no2schema_key[seq_no].version
                    }],
                    'claim-uuids': [
                        bc_non_claim_uuid
                    ],
                    'requested-attrs': []
                }
            }))
            assert False
        except ValueError:
            pass

        # 12. SRI agent (as Verifier) verifies proof (by claim-uuid)
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': bc_proof_resp
        })
        print('\n\n== 12 == SRI agent verifies BC proof by claim_uuid={} as {}'.format(
            bc_claim_uuid,
            ppjson(rc_json)))
        assert json.loads(rc_json)

        # 13. Create and store SRI registration completion claims, green claims from verified proof + extra data
        revealed = revealed_attrs(bc_proof_resp['proof'])
        claim_data[S_KEY['SRI-1.0']].append({
            **{k: revealed[k] for k in revealed if k in schema_data[S_KEY['SRI-1.0']]['attr_names']},
            'sriRegDate': datetime.date.today().strftime('%Y-%m-%d')
        })
        claim_data[S_KEY['SRI-1.1']].append({
            **{k: revealed[k] for k in revealed if k in schema_data[S_KEY['SRI-1.1']]['attr_names']},
            'sriRegDate': datetime.date.today().strftime('%Y-%m-%d'),
            'businessLang': 'EN-CA'
        })
        claim_data[S_KEY['GREEN']].append({
            **{k: revealed[k] for k in revealed if k in schema_data[S_KEY['GREEN']]['attr_names']},
            'greenLevel': 'Silver',
            'auditDate': datetime.date.today().strftime('%Y-%m-%d')
        })

        i = 0
        for s_key in claim_data:
            if s_key == S_KEY['BC']:
                continue
            for c in claim_data[s_key]:
                print('\n\n== 13.{} == Data for SRI claim on [{} v{}]: {}'.format(
                    claim_data[s_key].index(c),
                    s_key.name,
                    s_key.version,
                    ppjson(c)))
                claim_json[s_key] = await s_key.origin.process_post({
                    'type': 'claim-create',
                    'data': {
                        'claim-req': claim_req[s_key],
                        'claim-attrs': c
                    }
                })
                claim[s_key] = json.loads(claim_json[s_key])
                assert claim[s_key]
                await holder_prover[s_key.origin].process_post({
                    'type': 'claim-store',
                    'data': {
                        'claim': claim[s_key]
                    }
                })
                i += 1

        # 14. PSPC Org Book agent (as HolderProver) finds all claims, one schema at a time
        i = 0
        for s_key in schema:
            if s_key == S_KEY['BC']:
                continue
            sri_claim = json.loads(await holder_prover[s_key.origin].process_post({
                'type': 'claim-request',
                'data': {
                    'schemata': [{
                        'origin-did': s_key.origin.did,
                        'name': s_key.name,
                        'version': s_key.version
                    }],
                    'claim-filter': {
                        'attr-match': [],
                        'predicate-match': []
                    },
                    'requested-attrs': []
                }
            }))
            print('\n\n== 14.{} == SRI claims on [{} v{}], no filter: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(sri_claim)))
            i += 1

        # 15. PSPC Org Book agent (as HolderProver) finds all claims, for all schemata at once, on first attr per schema
        sri_claims_all = json.loads(await pspcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': [{
                    'origin-did': s_key.origin.did,
                    'name': s_key.name,
                    'version': s_key.version
                } for s_key in schema_data if s_key != S_KEY['BC']],
                'claim-filter': {
                    'attr-match': {
                    },
                    'predicate-match': [
                    ]
                },
                'requested-attrs': [{
                    'schema': {
                        'origin-did': s_key.origin.did,
                        'name': s_key.name,
                        'version': s_key.version
                    },
                    'names': [
                        schema_data[s_key]['attr_names'][0]
                    ]
                } for s_key in schema_data if s_key != S_KEY['BC']]
            }
        }))
        print('\n\n== 15 == All SRI claims at PSPC Org Book, first attr only: {}'.format(ppjson(sri_claims_all)))
        assert len(sri_claims_all['claims']['attrs']) == (len(schema_data) - 1)  # all schema_data except BC

        # 16. PSPC Org Book agent (as HolderProver) finds all claims on all schemata at once
        sri_claims_all = json.loads(await pspcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': [{
                    'origin-did': s_key.origin.did,
                    'name': s_key.name,
                    'version': s_key.version
                } for s_key in schema_data if s_key != S_KEY['BC']],
                'claim-filter': {
                    'attr-match': [],
                    'predicate-match': []
                },
                'requested-attrs': []
            }
        }))
        print('\n\n== 16 == All SRI claims at PSPC Org Book: {}'.format(ppjson(sri_claims_all)))
        sri_display = claims_for(sri_claims_all['claims'])
        print('\n\n== 17 == All SRI claims at PSPC Org Book by claim-uuid: {}'.format(ppjson(sri_display)))

        # 17. PSPC Org Book agent (as HolderProver) creates (multi-claim) proof
        sri_proof_resp = json.loads(await pspcobag.process_post({
            'type': 'proof-request',
            'data': {
                'schemata': [{
                    'origin-did': s_key.origin.did,
                    'name': s_key.name,
                    'version': s_key.version
                } for s_key in schema_data if s_key != S_KEY['BC']],
                'claim-filter': {
                    'attr-match': [],
                    'predicate-match': []
                },
                'requested-attrs': []
            }
        }))
        print('\n\n== 18 == SRI proof to all-claims response: {}'.format(ppjson(sri_proof_resp)))

        # 18. SRI (as Verifier) verifies proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': sri_proof_resp
        })
        print('\n\n== 19 == SRI agent verifies SRI proof as {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 19. PSPC Org Book Agent (as HolderProver) creates (multi-claim) proof by claim-uuid
        seq_nos = schema_seq_nos_for(sri_claims_all['claims'], {k for k in sri_display})
        sri_proof_resp = json.loads(await pspcobag.process_post({
            'type': 'proof-request-by-claim-uuid',
                'data': {
                    'schemata': [{
                        'origin-did': seq_no2schema_key[seq_nos[claim_uuid]].origin.did,
                        'name': seq_no2schema_key[seq_nos[claim_uuid]].name,
                        'version': seq_no2schema_key[seq_nos[claim_uuid]].version
                    } for claim_uuid in sri_display],
                'claim-uuids': [
                    claim_uuid for claim_uuid in sri_display
                ],
                'requested-attrs': []
            }
        }))
        print('\n\n== 20 == SRI proof to all-claims on claim-uuids {}: {}'.format(
            [claim_uuid for claim_uuid in sri_display],
            ppjson(sri_proof_resp)))

        # 20. SRI (as Verifier) verifies proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': sri_proof_resp
        })
        print('\n\n== 21 == SRI agent verifies SRI proof as {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 21. PSPC Org Book Agent (as HolderProver) creates (multi-claim) proof by claim-uuid, schemata implicit
        seq_nos = schema_seq_nos_for(sri_claims_all['claims'], {k for k in sri_display})
        sri_proof_resp = json.loads(await pspcobag.process_post({
            'type': 'proof-request-by-claim-uuid',
            'data': {
                'schemata': [],
                'claim-uuids': [
                    claim_uuid for claim_uuid in sri_display
                ],
                'requested-attrs': [{
                    'schema': {
                        'origin-did': s_key.origin.did,
                        'name': s_key.name,
                        'version': s_key.version
                    },
                    'names': [
                        schema_data[s_key]['attr_names'][0]
                    ]
                } for s_key in schema_data if s_key != S_KEY['BC']]
            }
        }))
        print('\n\n== 22 == SRI proof to all-claims on claim-uuids, first attrs only, schemata implicit {}: {}'.format(
            [claim_uuid for claim_uuid in sri_display],
            ppjson(sri_proof_resp)))

        # 22. SRI (as Verifier) verifies proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': sri_proof_resp
        })
        print('\n\n== 23 == SRI agent verifies SRI proof as {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 23. Exercise helper GET calls
        txn_json = await sag.process_get_txn(schema[S_KEY['GREEN']]['seqNo'])
        print('\n\n== 24 == GREEN schema by txn #{}: {}'.format(schema[S_KEY['GREEN']]['seqNo'], ppjson(txn_json)))
        assert json.loads(txn_json)
        txn_json = await sag.process_get_txn(99999)  # ought not exist
        assert not json.loads(txn_json)

        did_json = await bcrag.process_get_did()
        print('\n\n== 25 == BC Registrar agent did: {}'.format(ppjson(did_json)))
        assert json.loads(did_json)
