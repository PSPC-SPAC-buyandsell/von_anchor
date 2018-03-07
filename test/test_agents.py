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

from indy import IndyError
from indy.error import ErrorCode
from von_agent.demo_agents import TrustAnchorAgent, SRIAgent, OrgBookAgent, BCRegistrarAgent
from von_agent.error import (
    AbsentAttribute,
    AbsentMasterSecret,
    ClaimsFocus,
    JSONValidation,
    ProxyRelayConfig,
    TokenType)
from von_agent.nodepool import NodePool
from von_agent.proto.proto_util import attr_match, list_schemata, pred_match, pred_match_match, req_attrs
from von_agent.schema import SchemaKey
from von_agent.util import decode, encode, revealed_attrs, claims_for, prune_claims_json, schema_keys_for, ppjson
from von_agent.wallet import Wallet

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
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True})
    await p.open()
    assert p.handle

    tag = TrustAnchorAgent(
        p,
        Wallet(p.name, seed_trustee1, 'trustee-wallet'),
        {'endpoint': 'http://127.0.0.1:8000/api/v0', 'proxy-relay': True})
    sag = SRIAgent(
        p,
        Wallet(p.name, 'SRI-Agent-0000000000000000000000', 'sri-agent-wallet'),
        {'endpoint': 'http://127.0.0.1:8001/api/v0', 'proxy-relay': True})
    pspcobag = OrgBookAgent(
        p,
        Wallet(p.name, 'PSPC-Org-Book-Agent-000000000000', 'pspc-org-book-agent-wallet'),
        {'endpoint': 'http://127.0.0.1:8002/api/v0', 'proxy-relay': True})
    bcobag = OrgBookAgent(
        p,
        Wallet(p.name, 'BC-Org-Book-Agent-00000000000000', 'bc-org-book-agent-wallet'),
        {'endpoint': 'http://127.0.0.1:8003/api/v0', 'proxy-relay': True})
    bcrag = BCRegistrarAgent(
        p,
        Wallet(p.name, 'BC-Registrar-Agent-0000000000000', 'bc-registrar-agent-wallet'),
        {'endpoint': 'http://127.0.0.1:8004/api/v0', 'proxy-relay': True})

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
    did2ag = {}
    for ag in (tag, sag, pspcobag, bcobag, bcrag):
        did2ag[ag.did] = ag
        if not json.loads(await tag.get_nym(ag.did)):
            await tag.send_nym(ag.did, ag.verkey)
        if not json.loads(await tag.get_endpoint(ag.did)):
            await ag.send_endpoint()

    nyms = {
        'tag': json.loads(await tag.get_nym(tag.did)),
        'sag': json.loads(await tag.get_nym(sag.did)),
        'pspcobag': json.loads(await tag.get_nym(pspcobag.did)),
        'bcobag': json.loads(await tag.get_nym(bcobag.did)),
        'bcrag': json.loads(await tag.get_nym(bcrag.did))
    }
    endpoints = {
        'tag': json.loads(await tag.get_endpoint(tag.did)),
        'sag': json.loads(await tag.get_endpoint(sag.did)),
        'pspcobag': json.loads(await tag.get_endpoint(pspcobag.did)),
        'bcobag': json.loads(await tag.get_endpoint(bcobag.did)),
        'bcrag': json.loads(await tag.get_endpoint(bcrag.did))
    }

    print('\n\n== 1 == nyms: {}\nendpoints: {}\n'.format(ppjson(nyms), ppjson(endpoints)))

    for k in nyms:
        assert 'dest' in nyms[k]
    for k in endpoints:
        assert 'endpoint' in endpoints[k]

    # 3. Publish schema to ledger if not yet present; get from ledger
    S_KEY = {
        'BC': SchemaKey(bcrag.did, 'bc-reg', '1.0'),
        'SRI-1.0': SchemaKey(sag.did, 'sri', '1.0'),
        'SRI-1.1': SchemaKey(sag.did, 'sri', '1.1'),
        'GREEN': SchemaKey(sag.did, 'green', '1.0'),
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
    claim_offer_json = {}
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
        bcrag.did: bcobag,
        sag.did: pspcobag
    }

    x_json = await tag.get_schema(SchemaKey(tag.did, 'Xxxx', 'X.x'))  # Bad version number
    assert not json.loads(x_json)

    i = 0
    for s_key in schema_data:
        swab_json = await bcrag.get_schema(s_key)  # may exist
        if not json.loads(swab_json):
            await did2ag[s_key.origin_did].send_schema(json.dumps(schema_data[s_key]))
        schema_json[s_key] = await did2ag[s_key.origin_did].get_schema(s_key)  # should exist now
        schema[s_key] = json.loads(schema_json[s_key])
        seq_no2schema_key[schema[s_key]['seqNo']] = s_key
        seq_no2schema[schema[s_key]['seqNo']] = schema[s_key]
        print('\n\n== 2.{} == SCHEMA [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_key])))
        assert schema[s_key]
        i += 1
    assert not json.loads(await did2ag[S_KEY['BC'].origin_did].send_schema(
        json.dumps(schema_data[S_KEY['BC']])))  # forbid multiple write of multiple schema on same key

    # 4. BC Registrar and SRI agents (Issuers) create, store, publish claim definitions to ledger; create claim offers
    non_claim_def_json = await bcobag.get_claim_def(999999, bcrag.did)  # ought not exist
    assert not json.loads(non_claim_def_json)

    i = 0
    for s_key in schema_data:
        await did2ag[s_key.origin_did].send_claim_def(schema_json[s_key])
        claim_def_json[s_key] = await holder_prover[s_key.origin_did].get_claim_def(
            schema[s_key]['seqNo'],
            s_key.origin_did)  # ought to exist now
        claim_def[s_key] = json.loads(claim_def_json[s_key])
        print('\n\n== 3.{}.0 == Claim def [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(json.loads(claim_def_json[s_key]))))
        assert json.loads(claim_def_json[s_key])['ref'] == schema[s_key]['seqNo']

        repeat_claim_def = json.loads(await did2ag[s_key.origin_did].send_claim_def(schema_json[s_key]))
        assert repeat_claim_def  # check idempotence and non-crashing on duplicate claim-def send

        claim_offer_json[s_key] = await did2ag[s_key.origin_did].create_claim_offer(
            schema_json[s_key],
            holder_prover[s_key.origin_did].did)
        print('\n\n== 3.{}.1 == Claim offer [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(claim_offer_json[s_key])))
        i += 1

    # 5. Setup master secrets, claim reqs at HolderProver agents
    await bcobag.create_master_secret('MasterSecret')
    await pspcobag.create_master_secret('SecretMaster')

    for ag in (bcobag, pspcobag):
        wallet_name = ag.wallet.name
        assert (await ag.reset_wallet()) == wallet_name

    i = 0
    for s_key in schema_data:
        # await holder_prover[s_key.origin_did].store_claim_offer(claim_offer_json[s_key])
        claim_req_json[s_key] = await holder_prover[s_key.origin_did].store_claim_req(
            claim_offer_json[s_key],
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
                'id': claim_value_pair(1),
                'busId': claim_value_pair('11121398'),
                'orgTypeId': claim_value_pair(2),
                'jurisdictionId': claim_value_pair(1),
                'legalName': claim_value_pair('The Original House of Pies'),
                'effectiveDate': claim_value_pair('2010-10-10'),
                'endDate': claim_value_pair(None)
            },
            {
                'id': claim_value_pair(2),
                'busId': claim_value_pair('11133333'),
                'orgTypeId': claim_value_pair(1),
                'jurisdictionId': claim_value_pair(1),
                'legalName': claim_value_pair('Planet Cake'),
                'effectiveDate': claim_value_pair('2011-10-01'),
                'endDate': claim_value_pair(None)
            },
            {
                'id': claim_value_pair(3),
                'busId': claim_value_pair('11144444'),
                'orgTypeId': claim_value_pair(2),
                'jurisdictionId': claim_value_pair(1),
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
            (_, claim_json[s_key]) = await did2ag[s_key.origin_did].create_claim(claim_req_json[s_key], c)
            assert json.loads(claim_json[s_key])
            await holder_prover[s_key.origin_did].store_claim(claim_json[s_key])

    # 7. BC Org Book agent (as HolderProver) finds claims; actuator filters post hoc
    find_req[S_KEY['BC']] = {
        'nonce': '1000',
        'name': 'bc_proof_req',
        'version': '0',
        'requested_attrs': {
            '{}_{}_uuid'.format(schema[S_KEY['BC']]['seqNo'], attr): {
                'name': attr,
                'restrictions': [{
                    'schema_key': {
                        'did': S_KEY['BC'].origin_did,
                        'name': S_KEY['BC'].name,
                        'version':  S_KEY['BC'].version
                    }
                }]
            } for attr in claim_data[S_KEY['BC']][0]
        },
        'requested_predicates': {}
    }
    (bc_referents_all, claims_found_json[S_KEY['BC']]) = await bcobag.get_claims(json.dumps(find_req[S_KEY['BC']]))
    print('\n\n== 5 == All BC claims, no filter {}: {}'.format(
        bc_referents_all,
        ppjson(claims_found_json[S_KEY['BC']])))
    claims_found[S_KEY['BC']] = json.loads(claims_found_json[S_KEY['BC']])
    bc_display_pruned_filt_post_hoc = claims_for(
        claims_found[S_KEY['BC']],
        {
            S_KEY['BC']: {
                'legalName': decode(claim_data[S_KEY['BC']][2]['legalName'][1])
            }
        })
    print('\n\n== 6 == BC claims display, filtered post hoc matching {}: {}'.format(
        decode(claim_data[S_KEY['BC']][2]['legalName'][1]),
        ppjson(bc_display_pruned_filt_post_hoc)))
    bc_display_pruned = prune_claims_json(
        claims_found[S_KEY['BC']],
        {k for k in bc_display_pruned_filt_post_hoc})
    print('\n\n== 7 == BC claims, stripped down: {}'.format(ppjson(bc_display_pruned)))

    filt = {
        S_KEY['BC']: {
            'attr-match': {
                k: decode(claim_data[S_KEY['BC']][2][k][1]) for k in claim_data[S_KEY['BC']][2]
                    if k in ('jurisdictionId', 'busId')
            }
        }
    }
    (bc_referents_filt, claims_found_json[S_KEY['BC']]) = await bcobag.get_claims(
        json.dumps(find_req[S_KEY['BC']]),
        filt)
    print('\n\n== 8 == BC claims, filtered a priori {}: {}'.format(
        bc_referents_filt,
        ppjson(claims_found_json[S_KEY['BC']])))
    assert set([*bc_display_pruned_filt_post_hoc]) == bc_referents_filt
    assert len(bc_display_pruned_filt_post_hoc) == 1

    bc_referent = bc_referents_filt.pop()

    # 8. BC Org Book agent (as HolderProver) creates proof for claim specified by filter
    claims_found[S_KEY['BC']] = json.loads(claims_found_json[S_KEY['BC']])
    bc_requested_claims = {
        'self_attested_attributes': {},
        'requested_attrs': {
            attr: [bc_referent, True]
                for attr in find_req[S_KEY['BC']]['requested_attrs'] if attr in claims_found[S_KEY['BC']]['attrs']
        },
        'requested_predicates': {
            pred: bc_referent
                for pred in find_req[S_KEY['BC']]['requested_predicates']
        }
    }
    bc_proof_json = await bcobag.create_proof(
        find_req[S_KEY['BC']],
        claims_found[S_KEY['BC']],
        bc_requested_claims)
    print('\n\n== 9 == BC proof (by filter): {}'.format(ppjson(bc_proof_json)))

    # 9. SRI agent (as Verifier) verifies proof (by filter)
    rc_json = await sag.verify_proof(
        find_req[S_KEY['BC']],
        json.loads(bc_proof_json))
    print('\n\n== 10 == The SRI agent verifies the BC proof (by filter) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # 10. BC Org Book agent (as HolderProver) finds claim by referent, no claim by non-referent
    s_key = set(schema_keys_for(claims_found[S_KEY['BC']], {bc_referent}).values()).pop()  # it's unique
    req_attrs = {
       '{}_{}_uuid'.format(schema[s_key]['seqNo'], attr_name): {
            'name': attr_name,
            'restrictions': [{
                'schema_key': {
                    'did': s_key.origin_did,
                    'name': s_key.name,
                    'version': s_key.version
                }
            }]
       } for attr_name in schema_data[S_KEY['BC']]['attr_names']
    }
    bc_claim_found_by_referent = json.loads(await bcobag.get_claim_by_referent(bc_referent, req_attrs))
    print('\n\n== 11 == BC claim by referent={}: {}'.format(
        bc_referent,
        ppjson(bc_claim_found_by_referent)))
    assert bc_claim_found_by_referent
    assert bc_claim_found_by_referent['attrs']

    bc_non_claim_by_referent = json.loads(await bcobag.get_claim_by_referent(
        'claim::ffffffff-ffff-ffff-ffff-ffffffffffff',
        req_attrs))
    print('\n\n== 12 == BC non-claim: {}'.format(ppjson(bc_non_claim_by_referent)))
    assert bc_non_claim_by_referent
    assert all(not bc_non_claim_by_referent['attrs'][attr] for attr in bc_non_claim_by_referent['attrs'])

    # 11. BC Org Book agent (as HolderProver) creates proof for claim specified by referent
    bc_requested_claims = {
        'self_attested_attributes': {},
        'requested_attrs': {
            attr: [bc_referent, True]
                for attr in bc_claim_found_by_referent['attrs']
        },
        'requested_predicates': {}
    }
    bc_proof_json = await bcobag.create_proof(
        find_req[S_KEY['BC']],
        bc_claim_found_by_referent,
        bc_requested_claims)
    bc_proof = json.loads(bc_proof_json)
    print('\n\n== 13 == BC proof by referent={}: {}'.format(bc_referent, ppjson(bc_proof_json)))

    # 12. SRI agent (as Verifier) verifies proof (by referent)
    rc_json = await sag.verify_proof(
        find_req[S_KEY['BC']],
        bc_proof)
    print('\n\n== 14 == SRI agent verifies BC proof by referent={} as: {}'.format(bc_referent, ppjson(rc_json)))
    assert json.loads(rc_json)

    # 13. BC Org Book agent (as HolderProver) finds claims by predicate
    find_req_pred = {
        'nonce': '1111',
        'name': 'bc_proof_req',
        'version': '0',
        'requested_attrs': {
            '{}_{}_uuid'.format(schema[S_KEY['BC']]['seqNo'], attr): {
                'name': attr,
                'restrictions': [{
                    'schema_key': {
                        'did': S_KEY['BC'].origin_did,
                        'name': S_KEY['BC'].name,
                        'version':  S_KEY['BC'].version
                    }
                }]
            } for attr in claim_data[S_KEY['BC']][2] if attr != 'id'
        },
        'requested_predicates': {
            '{}_id_uuid'.format(schema[S_KEY['BC']]['seqNo']): {
                'attr_name': 'id',
                'p_type': '>=',
                'value': int(claim_data[S_KEY['BC']][2]['id'][0]),
                'restrictions': [{
                    'schema_key': {
                        'did': S_KEY['BC'].origin_did,
                        'name': S_KEY['BC'].name,
                        'version':  S_KEY['BC'].version
                    }
                }]
            }
        }
    }
    filt_pred = {
        S_KEY['BC']: {
            'pred-match': [{
                'attr': 'id',
                'pred-type': '>=',
                'value': int(claim_data[S_KEY['BC']][2]['id'][0]),
            }]
        }
    }
    (bc_referents_pred, claims_found_pred_json) = await bcobag.get_claims(json.dumps(find_req_pred), filt_pred)
    print('\n\n== 15 == BC claims, filtered by predicate id >= 3: {}'.format(
        ppjson(claims_found_pred_json)))
    claims_found_pred = json.loads(claims_found_pred_json)
    bc_display_pred = claims_for(claims_found_pred)
    print('\n\n== 16 == BC claims display, filtered by predicate id >= 3: {}'.format(ppjson(bc_display_pred)))
    assert len(bc_referents_pred) == 1
    bc_referent_pred = bc_referents_pred.pop()  # it's unique

    # 14. BC Org Book agent (as HolderProver) creates proof for claims structure filtered by predicate
    bc_requested_claims_pred = {
        'self_attested_attributes': {},
        'requested_attrs': {
            a_referent: [bc_referent_pred, True]
                for a_referent in find_req_pred['requested_attrs'] if a_referent in claims_found_pred['attrs']
        },
        'requested_predicates': {
            p_referent: bc_referent_pred
                for p_referent in find_req_pred['requested_predicates'] if p_referent in claims_found_pred['predicates']
        }
    }
    bc_proof_pred_json = await bcobag.create_proof(
        find_req_pred,
        claims_found_pred,
        bc_requested_claims_pred)
    print('\n\n== 17 == BC proof by predicate id >= 3: {}'.format(ppjson(bc_proof_pred_json)))

    # 15. SRI agent (as Verifier) verifies proof (by predicate)
    rc_json = await sag.verify_proof(
        find_req_pred,
        json.loads(bc_proof_pred_json))
    print('\n\n== 18 == The SRI agent verifies the BC proof (by predicate) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # 16. Create and store SRI registration completion claims, green claim from verified proof + extra data
    revealed = revealed_attrs(bc_proof)[bc_referent]
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
            (_, claim_json[s_key]) = await did2ag[s_key.origin_did].create_claim(claim_req_json[s_key], c)
            print('\n\n== 19.{} == SRI created claim [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(claim_json[s_key])))
            assert json.loads(claim_json[s_key])
            await holder_prover[s_key.origin_did].store_claim(claim_json[s_key])
            i += 1

    # 17. PSPC Org Book agent (as HolderProver) finds all claims, one schema at a time
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
                    'name': attr,
                    'restrictions': [{
                        'schema_key': {
                            'did': s_key.origin_did,
                            'name': s_key.name,
                            'version': s_key.version
                        }
                    }]
                } for attr in claim_data[s_key][0]
            },
            'requested_predicates': {}
        }

        (sri_referents, claims_found_json[s_key]) = await holder_prover[s_key.origin_did].get_claims(
            json.dumps(find_req[s_key]))

        print('\n\n== 20.{} == Claims on [{} v{}], no filter {}: {}'.format(
            i,
            s_key.name,
            s_key.version,
            sri_referents,
            ppjson(claims_found_json[s_key])))
        i += 1

    # 18. PSPC Org Book agent (as HolderProver) finds all claims on all schemata at once; actuator filters post hoc
    req_attrs_sri_find_all = {}
    for s_key in schema_data:
        if s_key == S_KEY['BC']:
            continue
        seq_no = schema[s_key]['seqNo']
        for attr_name in schema_data[s_key]['attr_names']:
            req_attrs_sri_find_all['{}_{}_uuid'.format(seq_no, attr_name)] = {
                'name': attr_name,
                'restrictions': [{
                    'schema_key': {
                        'did': s_key.origin_did,
                        'name': s_key.name,
                        'version': s_key.version
                    }
                }]
            }
    find_req_sri_all = {
        'nonce': '9999',
        'name': 'sri_find_req_all',
        'version': '0',
        'requested_attrs': req_attrs_sri_find_all,
        'requested_predicates': {}
    }

    (sri_referents_all, sri_claims_found_all_json) = await pspcobag.get_claims(json.dumps(find_req_sri_all))
    print('\n\n== 21 == All SRI-issued claims (no filter) at PSPC Org Book {}: {}'.format(
        sri_referents_all,
        ppjson(sri_claims_found_all_json)))

    sri_claims_found_all = json.loads(sri_claims_found_all_json)
    sri_display_pruned_filt_post_hoc = claims_for(
        sri_claims_found_all,
        {
            S_KEY['GREEN']: {
                'legalName': decode(claim_data[S_KEY['GREEN']][0]['legalName'][1])
            }
        })
    print('\n\n== 22 == SRI claims display, filtered post hoc matching {}: {}'.format(
        decode(claim_data[S_KEY['GREEN']][0]['legalName'][1]),
        ppjson(sri_display_pruned_filt_post_hoc)))
    sri_display_pruned = prune_claims_json(
        sri_claims_found_all,
        {k for k in sri_display_pruned_filt_post_hoc})
    print('\n\n== 23 == SRI claims, stripped down: {}'.format(ppjson(sri_display_pruned)))

    filt = {
        S_KEY['GREEN']: {
            'legalName': decode(claim_data[S_KEY['GREEN']][0]['legalName'][1])
        }
    }
    (sri_referents_filt, claims_found_json[S_KEY['GREEN']]) = await pspcobag.get_claims(
        json.dumps(find_req[S_KEY['GREEN']]),
        filt)
    print('\n\n== 24 == SRI claims, filtered a priori {}: {}'.format(
        sri_referents_filt,
        ppjson(claims_found_json[S_KEY['GREEN']])))
    assert set([*sri_display_pruned_filt_post_hoc]) == sri_referents_filt
    assert len(sri_display_pruned_filt_post_hoc) == 1

    sri_claims_found_all = json.loads(sri_claims_found_all_json)
    sri_req_attrs4sri_req_claims = {}
    for attr_uuid in sri_claims_found_all['attrs']:
        sri_req_attrs4sri_req_claims[attr_uuid] = [sri_claims_found_all['attrs'][attr_uuid][0]['referent'], True]

    # 19. PSPC Org Book agent (as HolderProver) creates proof for multiple claims
    sri_requested_claims = {
        'self_attested_attributes': {},
        'requested_attrs': sri_req_attrs4sri_req_claims,
        'requested_predicates': {}
    }
    sri_proof_json = await pspcobag.create_proof(
        find_req_sri_all,
        sri_claims_found_all,
        sri_requested_claims)
    print('\n\n== 25 == PSPC Org Book proof on referent={}: {}'.format(sri_referents_all, ppjson(sri_proof_json)))
    sri_proof = json.loads(sri_proof_json)

    # 20. SRI agent (as Verifier) verify proof
    rc_json = await sag.verify_proof(
        find_req_sri_all,
        sri_proof)

    print('\n\n== 26 == the SRI agent verifies the PSPC Org Book proof by referent={} as: {}'.format(
        sri_referents_all,
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

    # 1. Open pool, init agents, exercise bad configuration and ops inconsistent with configuration
    async with NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True}) as p, (
            TrustAnchorAgent(
                p,
                Wallet(p.name, seed_trustee1, 'trustee-wallet'),
                {'endpoint': 'http://127.0.0.1:8000/api/v0', 'proxy-relay': True})) as tag, (
            SRIAgent(
                p,
                Wallet(p.name, 'SRI-Agent-0000000000000000000000', 'sri-agent-wallet'),
                {'endpoint': 'http://127.0.0.1:8001/api/v0', 'proxy-relay': True})) as sag, (
            OrgBookAgent(
                p,
                Wallet(p.name, 'PSPC-Org-Book-Agent-000000000000', 'pspc-org-book-agent-wallet'),
                {'endpoint': 'http://127.0.0.1:8002/api/v0', 'proxy-relay': True})) as pspcobag, (
            OrgBookAgent(
                p,
                Wallet(p.name, 'BC-Org-Book-Agent-00000000000000', 'bc-org-book-agent-wallet'),
                {'endpoint': 'http://127.0.0.1:8003/api/v0', 'proxy-relay': True})) as bcobag, (
            BCRegistrarAgent(
                p,
                Wallet(p.name, 'BC-Registrar-Agent-0000000000000', 'bc-registrar-agent-wallet'),
                {'endpoint': 'http://127.0.0.1:8004/api/v0', 'proxy-relay': True})) as bcrag:

        assert p.handle is not None

        try:  # additional property in config
            SRIAgent(
                p,
                Wallet(p.name, 'SRI-Agent-0000000000000000000000', 'sri-agent-wallet'),
                {'endpoint': 'http://127.0.0.1:8001/api/v0', 'proxy-relay': True, 'additional-property': True})
            assert False
        except JSONValidation:
            pass

        async with SRIAgent(  # send endpoint not included in configuration
            p,
            Wallet(
                p.name,
                'SRI-Agent-Non-Proxy0000000000000',
                'sri-agent-non-proxy-wallet',
                {'auto-remove': True})) as xag:
            nym_lookup_form = {
                'type': 'agent-nym-lookup',
                'data': {
                    'agent-nym': {
                        'did': xag.did
                    }
                }
            }
            nym = json.loads(await xag.process_post(nym_lookup_form))  # register xag nym first if need be
            if not nym:
                await tag.process_post({
                    'type': 'agent-nym-send',
                    'data': {
                        'agent-nym': {
                            'did': xag.did,
                            'verkey': xag.verkey
                        }
                    }
                })
                nym = json.loads(await xag.process_post(nym_lookup_form))
                assert nym
            try:
                resp_json = await xag.process_post({
                    'type': 'agent-endpoint-send',
                    'data': {
                    }
                })
                assert False
            except AbsentAttribute:
                pass

        async with SRIAgent(  # proxy via non-proxy-relay
                p,
                Wallet(p.name, 'SRI-Agent-Non-Proxy0000000000000', 'sri-agent-non-proxy-wallet', {'auto-remove': True}),
                {'endpoint': 'http://127.0.0.1:8999/api/v0'}) as xag:
            nym_lookup_form = {
                'type': 'agent-nym-lookup',
                'data': {
                    'proxy-did': sag.did,
                    'agent-nym': {
                        'did': xag.did
                    }
                }
            } 
            try:
                await xag.process_post(nym_lookup_form)
                assert False
            except ProxyRelayConfig:
                pass

        # TAG DID: V4SG...
        # SAG DID: FaBA...
        # PSPCOBAG DID: 45Ue...
        # BCOBAG DID: Rzra...
        # BCRAG DID: Q4zq...
        print('\n\n== 1 == Agent DIDs: {}'.format(ppjson(
            {ag.wallet.name.replace('-wallet',''): ag.did for ag in (tag, sag, pspcobag, bcobag, bcrag)})))

        # 2. Publish agent particulars to ledger if not yet present
        did2ag = {}
        for ag in (tag, sag, pspcobag, bcobag, bcrag):
            did2ag[ag.did] = ag
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
        except TokenType:
            pass

        # 3. Publish schema to ledger if not yet present; get from ledger
        S_KEY = {
            'BC': SchemaKey(bcrag.did, 'bc-reg', '1.0'),
            'SRI-1.0': SchemaKey(sag.did, 'sri', '1.0'),
            'SRI-1.1': SchemaKey(sag.did, 'sri', '1.1'),
            'GREEN': SchemaKey(sag.did, 'green', '1.0'),
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
        claim_offer_json = {}
        claim_def_json = {}
        claim_def = {}
        claim_data = {}
        claim_req = {}
        claim_req_json = {}
        claim = {}
        claim_json = {}
        claims_found = {}
        claims_found_json = {}

        holder_prover = {
            bcrag.did: bcobag,
            sag.did: pspcobag
        }

        schema_lookup_form = {
            S_KEY['BC']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': S_KEY['BC'].origin_did,
                        'name': S_KEY['BC'].name,
                        'version': S_KEY['BC'].version
                    }
                }
            },
            S_KEY['SRI-1.0']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': S_KEY['SRI-1.0'].origin_did,
                        'name': S_KEY['SRI-1.0'].name,
                        'version': S_KEY['SRI-1.0'].version
                    }
                }
            },
            S_KEY['SRI-1.1']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': S_KEY['SRI-1.1'].origin_did,
                        'name': S_KEY['SRI-1.1'].name,
                        'version': S_KEY['SRI-1.1'].version
                    }
                }
            },
            S_KEY['GREEN']: {
                'type': 'schema-lookup',
                'data': {
                    'schema': {
                        'origin-did': S_KEY['GREEN'].origin_did,
                        'name': S_KEY['GREEN'].name,
                        'version': S_KEY['GREEN'].version
                    }
                }
            }
        }

        schema_lookup_form[S_KEY['BC']]['data']['schema']['version'] = 'xxx'
        x_json = await bcrag.process_post(schema_lookup_form[S_KEY['BC']])  # Bad version number
        assert not json.loads(x_json)

        schema_lookup_form[S_KEY['BC']]['data']['schema']['version'] = '999.999'
        assert not json.loads(await bcrag.process_post(schema_lookup_form[S_KEY['BC']]))  # ought not exist
        schema_lookup_form[S_KEY['BC']]['data']['schema']['version'] = schema_data[S_KEY['BC']]['version']  # restore

        i = 0
        for s_key in schema_data:
            swab_json = await bcrag.get_schema(s_key)  # may exist
            if not json.loads(swab_json):
                await did2ag[s_key.origin_did].process_post({
                    'type': 'schema-send',
                    'data': {
                        'schema': {
                            'origin-did': s_key.origin_did,
                            'name': s_key.name,
                            'version': s_key.version
                        },
                        'attr-names': schema_data[s_key]['attr_names']
                    }
                })
            schema_json[s_key] = await did2ag[s_key.origin_did].process_post(
                schema_lookup_form[s_key])  # should exist now
            schema[s_key] = json.loads(schema_json[s_key])
            assert schema[s_key]
            seq_no2schema_key[schema[s_key]['seqNo']] = s_key
            seq_no2schema[schema[s_key]['seqNo']] = schema[s_key]
            print('\n\n== 2.{} == SCHEMA [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_key])))
            i += 1

        for xag in (pspcobag, bcobag):
            try:  # Make sure only an origin can send a schema
                await xag.process_post({
                    'type': 'schema-send',
                    'data': {
                        'schema': {
                            'origin-did': xag.did,
                            'name': S_KEY['BC'].name,
                            'version': S_KEY['BC'].version
                        },
                        'attr-names': schema_data[S_KEY['BC']]['attr_names']
                    }
                })
                assert False
            except TokenType:
                pass

        # 4. BC Registrar and SRI agents (as Issuers) create, store,  and publish claim def to ledger
        i = 0
        for s_key in schema_data:
            claim_def_send_form = {
                'type': 'claim-def-send',
                'data': {
                    'schema': {
                        'origin-did': s_key.origin_did,
                        'name': s_key.name,
                        'version': s_key.version
                    }
                }
            }
            await did2ag[s_key.origin_did].process_post(claim_def_send_form)
            claim_def_json[s_key] = await holder_prover[s_key.origin_did].get_claim_def(
                schema[s_key]['seqNo'],
                s_key.origin_did)  # ought to exist now (short-circuit to low-level API)
            claim_def[s_key] = json.loads(claim_def_json[s_key])
            print('\n\n== 3.{}.0 == Claim def [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(json.loads(claim_def_json[s_key]))))
            assert json.loads(claim_def_json[s_key])['ref'] == schema[s_key]['seqNo']

            await did2ag[s_key.origin_did].process_post(claim_def_send_form)
            repeat_claim_def = json.loads(await holder_prover[s_key.origin_did].get_claim_def(
                schema[s_key]['seqNo'],
                s_key.origin_did))  # check idempotence and non-crashing on duplicate claim-def send
            assert repeat_claim_def

            claim_offer_create_form = {
                'type': 'claim-offer-create',
                'data': {
                    'schema': {
                        'origin-did': s_key.origin_did,
                        'name': s_key.name,
                        'version': s_key.version
                    },
                    'holder-did': holder_prover[s_key.origin_did].did
                }
            }
            claim_offer_json[s_key] = await did2ag[s_key.origin_did].process_post(claim_offer_create_form)
            print('\n\n== 3.{}.1 == Claim offer [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(claim_offer_json[s_key])))
            i += 1

        # 5. Setup master secrets, claim reqs at HolderProver agents
        master_secret_set_form = {
            'type': 'master-secret-set',
            'data': {
                'label': 'maestro'
            }
        }
        claim_offer_store_form = {
            s_key: {
                'type': 'claim-offer-store',
                'data': {
                    'claim-offer': json.loads(claim_offer_json[s_key])
                }
            } for s_key in schema_data
        }

        try:  # master secret unspecified, ought to fail
            await bcobag.process_post(claim_offer_store_form[S_KEY['BC']])
        except AbsentMasterSecret:
            pass

        await bcobag.process_post(master_secret_set_form)
        master_secret_set_form['data']['label'] = 'shhhhhhh'
        await pspcobag.process_post(master_secret_set_form)

        claims_reset_form = {
            'type': 'claims-reset',
            'data': {}
        }
        for ag in (bcobag, pspcobag):  # reset all HolderProvers
            assert not json.loads(await ag.process_post(claims_reset_form))  # response is {} if OK

        i = 0
        for s_key in schema_data:
            claim_req_json[s_key] = await holder_prover[s_key.origin_did].process_post(claim_offer_store_form[s_key])
            claim_req[s_key] = json.loads(claim_req_json[s_key])
            print('\n\n== 4.{} == claim req [{}]: {}'.format(i, s_key, ppjson(claim_req[s_key])))
            i += 1
            assert claim_req[s_key]

        # 6. BC Reg agent (as Issuer) issues claims and stores at HolderProver: get claim req, create claim, store claim
        claim_data = {
            S_KEY['BC']: [
                {
                    'id': 1,
                    'busId': '11121398',
                    'orgTypeId': 2,
                    'jurisdictionId': 1,
                    'legalName': 'The Original House of Pies',
                    'effectiveDate': '2010-10-10',
                    'endDate': None
                },
                {
                    'id': 2,
                    'busId': '11133333',
                    'orgTypeId': 1,
                    'jurisdictionId': 1,
                    'legalName': 'Planet Cake',
                    'effectiveDate': '2011-10-01',
                    'endDate': None
                },
                {
                    'id': 3,
                    'busId': '11144444',
                    'orgTypeId': 2,
                    'jurisdictionId': 1,
                    'legalName': 'Tart City',
                    'effectiveDate': '2012-12-01',
                    'endDate': None
                }
            ],
            S_KEY['SRI-1.0']: [],
            S_KEY['SRI-1.1']: [],
            S_KEY['GREEN']: []
        }
        i = 0
        for s_key in claim_data:
            for c in claim_data[s_key]:
                claim_json[s_key] = await did2ag[s_key.origin_did].process_post({
                    'type': 'claim-create',
                    'data': {
                        'claim-req': claim_req[s_key],
                        'claim-attrs': c
                    }
                })
                claim[s_key] = json.loads(claim_json[s_key])
                print('\n\n== 5.{} == claim for {}: {}'.format(i, s_key, ppjson(claim[s_key])))
                assert claim[s_key]
                i += 1
                await holder_prover[s_key.origin_did].process_post({
                    'type': 'claim-store',
                    'data': {
                        'claim': claim[s_key]
                    }
                })

        # 7. BC Org Book agent (as HolderProver) finds claims; actuator filters post hoc
        claims_found[S_KEY['BC']] = json.loads(await bcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': list_schemata([S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': [],
                },
                'requested-attrs': []
            }
        }))

        print('\n\n== 6 == All BC claims, no filter: {}'.format(ppjson(claims_found[S_KEY['BC']])))
        bc_display_pruned_filt_post_hoc = claims_for(
            claims_found[S_KEY['BC']]['claims'],
            {
                S_KEY['BC']: {
                    'legalName': claim_data[S_KEY['BC']][2]['legalName']
                }
            })

        try:  # exercise proof restriction to one claim per attribute
            await bcobag.process_post({
                'type': 'proof-request',
                'data': {
                    'schemata': list_schemata([S_KEY['BC']]),
                    'claim-filter': {
                        'attr-match': [],
                        'pred-match': [],
                    },
                    'requested-attrs': []
                }
            })
            assert False
        except ClaimsFocus:
            pass  # carry on: proof supports at most one claim per attribute

        print('\n\n== 7 == display BC claims filtered post hoc matching {}: {}'.format(
            claim_data[S_KEY['BC']][2]['legalName'],
            ppjson(bc_display_pruned_filt_post_hoc)))
        bc_display_pruned = prune_claims_json(
            claims_found[S_KEY['BC']]['claims'],
            {k for k in bc_display_pruned_filt_post_hoc})
        print('\n\n== 8 == BC claims, stripped down {}'.format(ppjson(bc_display_pruned)))

        bc_claims_prefilt_json = await bcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': list_schemata([S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [
                        attr_match(
                            S_KEY['BC'], 
                            {
                                k: claim_data[S_KEY['BC']][2][k] for k in claim_data[S_KEY['BC']][2]
                                    if k in ('jurisdictionId', 'busId')
                            }
                        )
                    ],
                    'pred-match': []
                },
                'requested-attrs': []
            }
        })
        bc_claims_prefilt = json.loads(bc_claims_prefilt_json)
        print('\n\n== 9 == BC claims, with filter a priori, process-post: {}'.format(ppjson(bc_claims_prefilt)))
        bc_display_pruned_prefilt = claims_for(bc_claims_prefilt['claims'])
        print('\n\n== 10 == BC display claims filtered a priori matching {}: {}'.format(
            claim_data[S_KEY['BC']][2]['legalName'],
            ppjson(bc_display_pruned_prefilt)))
        assert set([*bc_display_pruned_filt_post_hoc]) == set([*bc_display_pruned_prefilt])
        assert len(bc_display_pruned_filt_post_hoc) == 1

        # 8. BC Org Book agent (as HolderProver) creates proof (by filter)
        bc_proof_resp = json.loads(await bcobag.process_post({
            'type': 'proof-request',
            'data': {
                'schemata': list_schemata([S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [
                        attr_match(
                            S_KEY['BC'], 
                            {
                                k: claim_data[S_KEY['BC']][2][k] for k in claim_data[S_KEY['BC']][2]
                                    if k in ('jurisdictionId', 'busId')
                            }
                        )
                    ],
                    'pred-match': []
                },
                'requested-attrs': []
            }
        }))
        print('\n\n== 11 == BC proof response (by filter): {}'.format(ppjson(bc_proof_resp)))

        # 9. SRI agent (as Verifier) verifies proof (by filter)
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': bc_proof_resp
        })
        print('\n\n== 12 == the SRI agent verifies the BC proof (by filter) as: {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 10. BC Org Book agent (as HolderProver) creates proof (by referent)
        bc_referent = set([*bc_display_pruned_prefilt]).pop()
        s_key = set(schema_keys_for(bc_claims_prefilt['claims'], {bc_referent}).values()).pop()  # it's unique
        bc_proof_resp = json.loads(await bcobag.process_post({
            'type': 'proof-request-by-referent',
            'data': {
                'schemata': list_schemata([s_key]),
                'referents': [
                    bc_referent
                ],
                'requested-attrs': []
            }
        }))
        print('\n\n== 13 == BC proof response by referent={}: {}'.format(bc_referent, ppjson(bc_proof_resp)))

        # 11. BC Org Book agent (as HolderProver) creates non-proof (by non-referent)
        bc_non_referent = 'claim::ffffffff-ffff-ffff-ffff-ffffffffffff'
        try:
            json.loads(await bcobag.process_post({
                'type': 'proof-request-by-referent',
                'data': {
                    'schemata': list_schemata([s_key]),
                    'referents': [
                        bc_non_referent
                    ],
                    'requested-attrs': []
                }
            }))
            assert False
        except ClaimsFocus:
            pass

        # 12. SRI agent (as Verifier) verifies proof (by referent)
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': bc_proof_resp
        })
        print('\n\n== 14 == SRI agent verifies BC proof by referent={} as: {}'.format(
            bc_referent,
            ppjson(rc_json)))
        assert json.loads(rc_json)

        # 13. BC Org Book agent (as HolderProver) finds claims by predicate on default attr-match, req-attrs w/schema
        claims_found_pred = json.loads(await bcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': list_schemata([S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': [
                        pred_match( 
                            S_KEY['BC'],
                            [
                                pred_match_match('id', '>=', claim_data[S_KEY['BC']][2]['id'])
                            ])
                    ],
                },
                'requested-attrs': [req_attrs(S_KEY['BC'])]
            }
        }))
        assert (set(req_attr['name'] for req_attr in claims_found_pred['proof-req']['requested_attrs'].values()) ==
            set(schema_data[S_KEY['BC']]['attr_names']) - {'id'})
        assert (set(req_pred['attr_name']
            for req_pred in claims_found_pred['proof-req']['requested_predicates'].values()) == {'id'})

        # 14. BC Org Book agent (as HolderProver) finds claims by predicate on default attr-match and req-attrs
        claims_found_pred = json.loads(await bcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': list_schemata([S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': [
                        pred_match( 
                            S_KEY['BC'],
                            [
                                pred_match_match('id', '>=', claim_data[S_KEY['BC']][2]['id'])
                            ])
                    ],
                },
                'requested-attrs': []
            }
        }))
        assert (set(req_attr['name'] for req_attr in claims_found_pred['proof-req']['requested_attrs'].values()) ==
            set(schema_data[S_KEY['BC']]['attr_names']) - {'id'})
        assert (set(req_pred['attr_name']
            for req_pred in claims_found_pred['proof-req']['requested_predicates'].values()) == {'id'})

        print('\n\n== 15 == BC claims structure by predicate: {}'.format(ppjson(claims_found_pred)))
        bc_display_pred = claims_for(claims_found_pred['claims'])
        print('\n\n== 16 == BC display claims by predicate: {}'.format(ppjson(bc_display_pred)))
        assert len(bc_display_pred) == 1

        # 15. BC Org Book agent (as HolderProver) creates proof by predicate, default req-attrs
        bc_proof_resp_pred = json.loads(await bcobag.process_post({
            'type': 'proof-request',
            'data': {
                'schemata': list_schemata([S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': [
                        pred_match(
                            S_KEY['BC'],
                            [
                                pred_match_match('id', '>=', 2),
                                pred_match_match('orgTypeId', '>=', 2)
                            ])  # resolves to one claim
                    ]
                },
                'requested-attrs': []
            }
        }))
        print('\n\n== 17 == BC proof by predicates id, orgTypeId >= 2: {}'.format(ppjson(bc_proof_resp_pred)))
        revealed = revealed_attrs(bc_proof_resp_pred['proof'])
        print('\n\n== 18 == BC proof revealed attrs by predicates id, orgTypeId >= 2: {}'.format(ppjson(revealed)))
        assert len(revealed) == 1
        assert (set(revealed[set(revealed.keys()).pop()].keys()) ==
            set(schema_data[S_KEY['BC']]['attr_names']) - set(('id', 'orgTypeId')))

        # 16. SRI agent (as Verifier) verifies proof (by predicates)
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': bc_proof_resp_pred
        })
        print('\n\n== 19 == SRI agent verifies BC proof by predicates id, orgTypeId >= 2 as: {}'.format(
            ppjson(rc_json)))
        assert json.loads(rc_json)

        # 17. Create and store SRI registration completion claims, green claims from verified proof + extra data
        revealed = revealed_attrs(bc_proof_resp['proof'])[bc_referent]
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
                print('\n\n== 20.{} == Data for SRI claim on [{} v{}]: {}'.format(
                    i,
                    s_key.name,
                    s_key.version,
                    ppjson(c)))
                claim_json[s_key] = await did2ag[s_key.origin_did].process_post({
                    'type': 'claim-create',
                    'data': {
                        'claim-req': claim_req[s_key],
                        'claim-attrs': c
                    }
                })
                claim[s_key] = json.loads(claim_json[s_key])
                assert claim[s_key]
                await holder_prover[s_key.origin_did].process_post({
                    'type': 'claim-store',
                    'data': {
                        'claim': claim[s_key]
                    }
                })
                i += 1

        # 18. PSPC Org Book agent (as HolderProver) finds all claims, one schema at a time
        i = 0
        for s_key in schema:
            if s_key == S_KEY['BC']:
                continue
            sri_claim = json.loads(await holder_prover[s_key.origin_did].process_post({
                'type': 'claim-request',
                'data': {
                    'schemata': list_schemata([s_key]),
                    'claim-filter': {
                        'attr-match': [],
                        'pred-match': []
                    },
                    'requested-attrs': []
                }
            }))
            print('\n\n== 21.{}.0 == SRI claims on [{} v{}], no filter: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(sri_claim)))
            assert len(sri_claim['claims']['attrs']) == (len(schema_data[s_key]['attr_names']))

            sri_claim = json.loads(await holder_prover[s_key.origin_did].process_post({
                'type': 'claim-request',
                'data': {
                    'schemata': [],
                    'claim-filter': {
                        'attr-match': [attr_match(s_key)],
                        'pred-match': []
                    },
                    'requested-attrs': []
                }
            }))
            print('\n\n== 22.{}.1 == SRI claims, filter for all attrs in schema [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(sri_claim)))
            i += 1
            assert len(sri_claim['claims']['attrs']) == (len(schema_data[s_key]['attr_names']))
            
        # 19. PSPC Org Book agent (as HolderProver) finds all claims, for all schemata, on first attr per schema
        sri_claims_all = json.loads(await pspcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': list_schemata([s_key for s_key in schema_data if s_key != S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': [
                    ]
                },
                'requested-attrs': [req_attrs(s_key, [schema_data[s_key]['attr_names'][0]])
                    for s_key in schema_data if s_key != S_KEY['BC']]
            }
        }))
        print('\n\n== 23 == All SRI claims at PSPC Org Book, first attr only: {}'.format(ppjson(sri_claims_all)))
        assert len(sri_claims_all['claims']['attrs']) == (len(schema_data) - 1)  # all schema_data except BC

        # 20. PSPC Org Book agent (as HolderProver) finds all claims on all schemata at once
        sri_claims_all = json.loads(await pspcobag.process_post({
            'type': 'claim-request',
            'data': {
                'schemata': list_schemata([s_key for s_key in schema_data if s_key != S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': []
                },
                'requested-attrs': []
            }
        }))
        print('\n\n== 24 == All SRI claims at PSPC Org Book: {}'.format(ppjson(sri_claims_all)))
        sri_display = claims_for(sri_claims_all['claims'])
        print('\n\n== 25 == All SRI claims at PSPC Org Book by referent: {}'.format(ppjson(sri_display)))

        # 21. PSPC Org Book agent (as HolderProver) creates (multi-claim) proof
        sri_proof_resp = json.loads(await pspcobag.process_post({
            'type': 'proof-request',
            'data': {
                'schemata': list_schemata([s_key for s_key in schema_data if s_key != S_KEY['BC']]),
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': []
                },
                'requested-attrs': []
            }
        }))
        print('\n\n== 26 == PSPC org book proof to all-claims response: {}'.format(ppjson(sri_proof_resp)))
        assert len(sri_proof_resp['proof']['proof']['proofs']) == len(sri_display)

        # 22. SRI agent (as Verifier) verifies proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': sri_proof_resp
        })
        print('\n\n== 27 == SRI agent verifies PSPC org book proof as: {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 23. PSPC Org Book agent (as HolderProver) creates (multi-claim) proof by referent
        referent2schema_key = schema_keys_for(sri_claims_all['claims'], {k for k in sri_display})
        sri_proof_resp = json.loads(await pspcobag.process_post({
            'type': 'proof-request-by-referent',
            'data': {
                'schemata': list_schemata([referent2schema_key[referent] for referent in sri_display]),
                'referents': [
                    referent for referent in sri_display
                ],
                'requested-attrs': []
            }
        }))
        print('\n\n== 28 == PSPC org book proof to all-claims on referents {}: {}'.format(
            [referent for referent in sri_display],
            ppjson(sri_proof_resp)))
        assert len(sri_proof_resp['proof']['proof']['proofs']) == len(sri_display)

        # 24. SRI agent (as Verifier) verifies proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': sri_proof_resp
        })
        print('\n\n== 29 == SRI agent verifies PSPC org book proof as: {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 25. PSPC Org Book agent (as HolderProver) creates multi-claim proof, schemata implicit, first attrs only
        sri_proof_resp = json.loads(await pspcobag.process_post({
            'type': 'proof-request-by-referent',
            'data': {
                'schemata': [],
                'referents': [
                    referent for referent in sri_display
                ],
                'requested-attrs': [req_attrs(s_key, [schema_data[s_key]['attr_names'][0]])
                    for s_key in schema_data if s_key != S_KEY['BC']]
            }
        }))
        print('\n\n== 30 == PSPC org book proof to all claims by referent, first attrs, schemata implicit {}: {}'
            .format(
                [referent for referent in sri_display],
                ppjson(sri_proof_resp)))
        assert {sri_proof_resp['proof-req']['requested_attrs'][k]['name']
            for k in sri_proof_resp['proof-req']['requested_attrs']} == {
                schema_data[s_key]['attr_names'][0] for s_key in schema_data if s_key != S_KEY['BC']}

        # 26. SRI agent (as Verifier) verifies proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': sri_proof_resp
        })
        print('\n\n== 31 == SRI agent verifies PSPC org book proof as: {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 27. PSPC Org Book agent (as HolderProver) creates proof on req-attrs for all green schema attrs
        sri_proof_resp = json.loads(await pspcobag.process_post({
            'type': 'proof-request',
            'data': {
                'schemata': [],
                'claim-filter': {
                    'attr-match': [],
                    'pred-match': []
                },
                'requested-attrs': [req_attrs(S_KEY['GREEN'])]
            }
        }))
        print('\n\n== 32 == PSPC org book proof to green claims response: {}'.format(ppjson(sri_proof_resp)))
        assert {sri_proof_resp['proof-req']['requested_attrs'][k]['name']
            for k in sri_proof_resp['proof-req']['requested_attrs']} == set(schema_data[S_KEY['GREEN']]['attr_names'])

        # 28. SRI agent (as Verifier) verifies proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': sri_proof_resp
        })
        print('\n\n== 33 == SRI agent verifies PSPC Org Book proof as: {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 29. Exercise helper GET calls
        txn_json = await sag.process_get_txn(schema[S_KEY['GREEN']]['seqNo'])
        print('\n\n== 34 == GREEN schema by txn #{}: {}'.format(schema[S_KEY['GREEN']]['seqNo'], ppjson(txn_json)))
        assert json.loads(txn_json)
        txn_json = await sag.process_get_txn(99999)  # ought not exist
        assert not json.loads(txn_json)

        did_json = await bcrag.process_get_did()
        print('\n\n== 35 == BC Registrar agent did: {}'.format(ppjson(did_json)))
        assert json.loads(did_json)
