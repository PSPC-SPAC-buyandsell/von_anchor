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


from copy import deepcopy
from indy import IndyError
from indy.error import ErrorCode
from math import ceil
from os import listdir, makedirs
from os.path import basename, dirname, expanduser, isdir, isfile, join
from pathlib import Path
from string import printable
from random import choice, randint, shuffle
from shutil import copyfile, move, rmtree
from threading import current_thread, Thread
from time import sleep, time

from von_anchor import BCRegistrarAnchor, OrgBookAnchor, SRIAnchor, TrusteeAnchor
from von_anchor.cache import Caches, CRED_DEF_CACHE, REVO_CACHE, SCHEMA_CACHE
from von_anchor.codec import canon
from von_anchor.error import (
    AbsentCred,
    AbsentCredDef,
    AbsentInterval,
    AbsentLinkSecret,
    AbsentSchema,
    AbsentTails,
    AbsentWallet,
    BadLedgerTxn,
    BadRevocation,
    BadRevStateTime,
    BadWalletQuery,
    CacheIndex,
    ClosedPool,
    CredentialFocus,
    JSONValidation)
from von_anchor.nodepool import NodePool
from von_anchor.tails import Tails
from von_anchor.util import (
    box_ids,
    cred_def_id,
    cred_def_id2seq_no,
    creds_display,
    ppjson,
    proof_req2wql_all,
    proof_req_attr_referents,
    proof_req_briefs2req_creds,
    proof_req_infos2briefs,
    prune_creds_json,
    revealed_attrs,
    revoc_info,
    rev_reg_id,
    schema_id,
    schema_key)
from von_anchor.wallet import Wallet

import asyncio
import datetime
import pytest
import json


DIR_TAILS = join(expanduser('~'), '.indy_client', 'tails')
DIR_TAILS_BAK = join(expanduser('~'), '.indy_client', 'tails_bak')
SCHEMA_CACHE_BAK = deepcopy(SCHEMA_CACHE)
CRED_DEF_CACHE_BAK = deepcopy(CRED_DEF_CACHE)
REVO_CACHE_BAK = deepcopy(REVO_CACHE)


def _set_tails_state(set_on: bool):
    assert set_on == isdir(DIR_TAILS_BAK)
    if set_on:
        # restore state
        rmtree(DIR_TAILS)
        move(DIR_TAILS_BAK, DIR_TAILS)
    else:
        # simulate HolderProver not having any tails files
        move(DIR_TAILS, DIR_TAILS_BAK)
        makedirs(DIR_TAILS, exist_ok=True)
    # print('\n... Presto! Made tails tree cache {}APPEAR'.format('RE' if set_on else 'DIS'))


def _set_cache_state(set_on: bool):
    if set_on:
        # restore state
        SCHEMA_CACHE.clear()
        SCHEMA_CACHE.feed(SCHEMA_CACHE_BAK.schemata())
        SCHEMA_CACHE_BAK.clear()

        CRED_DEF_CACHE.clear()
        CRED_DEF_CACHE.update(CRED_DEF_CACHE_BAK)
        CRED_DEF_CACHE_BAK.clear()

        REVO_CACHE.clear()
        REVO_CACHE.update(REVO_CACHE_BAK)
        REVO_CACHE_BAK.clear()
    else:
        # simulate fresh cache with no content from other anchor activity
        SCHEMA_CACHE_BAK.clear()
        SCHEMA_CACHE_BAK.feed(SCHEMA_CACHE.schemata())
        SCHEMA_CACHE.clear()

        CRED_DEF_CACHE_BAK.clear()
        CRED_DEF_CACHE_BAK.update(CRED_DEF_CACHE)
        CRED_DEF_CACHE.clear()

        REVO_CACHE_BAK.clear()
        REVO_CACHE_BAK.update(REVO_CACHE)
        REVO_CACHE.clear()
    # print('\n... Presto! Made caches {}APPEAR'.format( 'RE' if set_on else 'DIS'))


def _download_tails(rr_id):
    # simulate downloading tails file (get it from DIR_TAILS_BAK)
    src = Tails.linked(DIR_TAILS_BAK, rr_id)
    dest = str(Path(Tails.dir(DIR_TAILS, rr_id), basename(src)))
    makedirs(dirname(dest), exist_ok=True)
    copyfile(src, dest)
    assert len(Tails.unlinked(DIR_TAILS)) == 1


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_low_level_api(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print('\n\n== Testing low-level API ==')

    EPOCH_START = 1234567890  # guaranteed to be before any revocation registry creation

    # Open pool, init anchors
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False})

    try:
        xan = SRIAnchor(Wallet('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'xxx', None, {'auto-remove': True}), p)
    except AbsentWallet:
        pass

    tan = TrusteeAnchor(await Wallet(seed_trustee1, 'trust-anchor').create(), p)
    san = SRIAnchor(await Wallet('SRI-Anchor-000000000000000000000', 'sri').create(), p)
    pspcoban = OrgBookAnchor(
        await Wallet('PSPC-Org-Book-Anchor-00000000000', 'pspc-org-book').create(),
        p,
        {
            'parse-cache-on-open': True,
            'archive-cache-on-close': True
        })
    bcoban = OrgBookAnchor(await Wallet('BC-Org-Book-Anchor-0000000000000', 'bc-org-book').create(), p)
    bcran = BCRegistrarAnchor(await Wallet('BC-Registrar-Anchor-000000000000', 'bc-registrar').create(), p)

    await tan.open()

    try:  # exercise requirement for open node pool to write to ledger
        await tan.get_nym(tan.did)
        assert False
    except ClosedPool:
        pass

    await p.open()
    assert p.handle

    await san.open()
    await pspcoban.open()
    await bcoban.open()
    await bcran.open()

    # print('TAN DID {}'.format(tan.did))            # V4SG...
    # print('SAN DID {}'.format(san.did))            # WgWx...
    # print('PSPCOBAN DID {}'.format(pspcoban.did))  # CwM7...
    # print('BCOBAN DID {}'.format(bcoban.did))      # Rhd3...
    # print('BCRAN DID {}'.format(bcran.did))        # Ljgp...

    # Publish anchor particulars to ledger if not yet present
    did2an = {}
    for an in (tan, san, pspcoban, bcoban, bcran):
        did2an[an.did] = an
        if not json.loads(await tan.get_nym(an.did)):
            await tan.send_nym(an.did, an.verkey, an.wallet.name, an.role())

    nyms = {
        'tan': json.loads(await tan.get_nym(tan.did)),
        'san': json.loads(await tan.get_nym(san.did)),
        'pspcoban': json.loads(await tan.get_nym(pspcoban.did)),
        'bcoban': json.loads(await tan.get_nym(bcoban.did)),
        'bcran': json.loads(await tan.get_nym(bcran.did))
    }
    print('\n\n== 1 == nyms: {}'.format(ppjson(nyms)))

    for k in nyms:
        assert 'dest' in nyms[k]

    # Publish schema to ledger if not yet present; get from ledger
    ''' 4
        'NON-REVO': schema_id(bcran.did, 'non-revo', '1.0'),
        'SRI-1.0': schema_id(san.did, 'sri', '1.0'),
        'SRI-1.1': schema_id(san.did, 'sri', '1.1'),
        'GREEN': schema_id(san.did, 'green', '1.0'),
    '''
    S_ID = {
        'BC': schema_id(bcran.did, 'bc-reg', '1.0'),
        'NON-REVO': schema_id(bcran.did, 'non-revo', '1.0'),
        'SRI-1.0': schema_id(san.did, 'sri', '1.0'),
        'SRI-1.1': schema_id(san.did, 'sri', '1.1'),
        'GREEN': schema_id(san.did, 'green', '1.0'),
    }

    ''' 36
        S_ID['SRI-1.0']: {
            'name': schema_key(S_ID['SRI-1.0']).name,
            'version': schema_key(S_ID['SRI-1.0']).version,
            'attr_names': [
                'legalName',
                'jurisdictionId',
                'sriRegDate'
            ]
        },
        S_ID['NON-REVO']: {
            'name': schema_key(S_ID['NON-REVO']).name,
            'version': schema_key(S_ID['NON-REVO']).version,
            'attr_names': [
                'name',
                'favouriteDrink'
            ]
        },
        S_ID['SRI-1.1']: {
            'name': schema_key(S_ID['SRI-1.1']).name,
            'version': schema_key(S_ID['SRI-1.1']).version,
            'attr_names': [
                'legalName',
                'jurisdictionId',
                'businessLang',
                'sriRegDate'
            ]
        },
        S_ID['GREEN']: {
            'name': schema_key(S_ID['GREEN']).name,
            'version': schema_key(S_ID['GREEN']).version,
            'attr_names': [
                'legalName',
                'greenLevel',
                'auditDate'
            ]
        }
    '''
    schema_data = {
        S_ID['BC']: {
            'name': schema_key(S_ID['BC']).name,
            'version': schema_key(S_ID['BC']).version,
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
        S_ID['NON-REVO']: {
            'name': schema_key(S_ID['NON-REVO']).name,
            'version': schema_key(S_ID['NON-REVO']).version,
            'attr_names': [
                'name',
                'thing'
            ]
        },
        S_ID['SRI-1.0']: {
            'name': schema_key(S_ID['SRI-1.0']).name,
            'version': schema_key(S_ID['SRI-1.0']).version,
            'attr_names': [
                'legalName',
                'jurisdictionId',
                'sriRegDate'
            ]
        },
        S_ID['SRI-1.1']: {
            'name': schema_key(S_ID['SRI-1.1']).name,
            'version': schema_key(S_ID['SRI-1.1']).version,
            'attr_names': [
                'legalName',
                'jurisdictionId',
                'businessLang',
                'sriRegDate'
            ]
        },
        S_ID['GREEN']: {
            'name': schema_key(S_ID['GREEN']).name,
            'version': schema_key(S_ID['GREEN']).version,
            'attr_names': [
                'legalName',
                'greenLevel',
                'auditDate'
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
    cred = {}
    proof_req = {}

    holder_prover = {
        bcran.did: bcoban,
        san.did: pspcoban
    }

    try:
        x_json = await tan.get_schema(schema_key(schema_id(tan.did, 'Xxxx', 'X.x')))  # Bad version number
        assert False
    except BadLedgerTxn:
        pass

    i = 0
    seq_no = None
    for s_id in schema_data:
        s_key = schema_key(s_id)
        try:
            swab_json = await bcran.get_schema(s_key)  # may exist
        except AbsentSchema:
            await did2an[s_key.origin_did].send_schema(json.dumps(schema_data[s_id]))
        schema_json[s_id] = await did2an[s_key.origin_did].get_schema(s_key)
        assert json.loads(schema_json[s_id])  # should exist now

        schema_by_id_json = await did2an[s_key.origin_did].get_schema(s_id)  # exercise get_schema on schema_id
        schema[s_id] = json.loads(schema_json[s_id])
        assert json.loads(schema_by_id_json)['seqNo'] == schema[s_id]['seqNo']
        seq_no = schema[s_id]['seqNo']  # retain the last one for post-loop get_schema() by seq num

        seq_no2schema_id[schema[s_id]['seqNo']] = s_id
        seq_no2schema[schema[s_id]['seqNo']] = schema[s_id]
        print('\n\n== 2.{} == SCHEMA [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
        assert schema[s_id]
        i += 1

    try:
        json.loads(await did2an[schema_key(S_ID['BC']).origin_did].send_schema(
            json.dumps(schema_data[S_ID['BC']])))  # check idempotence

        _set_cache_state(False)
        s = json.loads(await tan.get_schema(seq_no))  # exercise get_schema() by seq num if not cached
        assert s['seqNo'] == seq_no
        _set_cache_state(True)
    except Exception as x:
        assert False, x

    # BC Registrar and SRI anchors (Issuers) create, store, publish cred definitions to ledger; create cred offers
    try:
        x_cred_def_json = await bcoban.get_cred_def(cred_def_id(bcran.did, 99999))  # ought not exist
        assert False
    except AbsentCredDef:
        pass

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        an = did2an[s_key.origin_did]

        await an.send_cred_def(
            s_id,
            s_id != S_ID['NON-REVO'],
            4 if s_id == S_ID['BC'] else None)  # make initial BC rev reg tiny: exercise rev reg rollover in cred issue
        cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

        assert (s_id == S_ID['NON-REVO']) or (
            [f for f in Tails.links(str(an._dir_tails), an.did)
                if cd_id[s_id] in f] and not Tails.unlinked(str(an._dir_tails)))

        cred_def_json[s_id] = await holder_prover[s_key.origin_did].get_cred_def(cd_id[s_id])  # ought to exist now
        cred_def[s_id] = json.loads(cred_def_json[s_id])
        print('\n\n== 3.{}.0 == Cred def [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(json.loads(cred_def_json[s_id]))))
        assert cred_def[s_id].get('schemaId', None) == str(schema[s_id]['seqNo'])

        repeat_cred_def = json.loads(await an.send_cred_def(
            s_id,
            s_id != S_ID['NON-REVO'],
            4 if s_id == S_ID['BC'] else None))  # make initial BC rev reg tiny: exercise rev reg rollover in cred issue
        assert repeat_cred_def  # check idempotence and non-crashing on duplicate cred-def send

        cred_offer_json[s_id] = await an.create_cred_offer(schema[s_id]['seqNo'])
        cred_offer[s_id] = json.loads(cred_offer_json[s_id])
        print('\n\n== 3.{}.1 == Credential offer [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(cred_offer_json[s_id])))
        i += 1

    big_proof_req_json = await san.build_proof_req_json({
        cd_id[s_id]: {
            'attrs': schema_data[seq_no2schema_id[cred_def_id2seq_no(cd_id[s_id])]]['attr_names'][0:2]
        } for s_id in schema_data
    })
    print('\n\n== 4 == Built sample proof request: {}'.format(ppjson(big_proof_req_json)))
    assert len(json.loads(big_proof_req_json)['requested_attributes']) == 2 * len(schema_data)

    # Setup link secrets, cred reqs at HolderProver anchors
    await bcoban.create_link_secret('LinkSecret')
    await pspcoban.create_link_secret('SecretLink')

    for an in (bcoban, pspcoban):
        wallet_name = an.wallet.name
        assert (await an.reset_wallet()) == wallet_name

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await holder_prover[s_key.origin_did].create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id])
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 5.{} == Credential request [{} v{}]: metadata {}, cred {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(cred_req_metadata_json[s_id]),
            ppjson(cred_req_json[s_id])))
        assert json.loads(cred_req_json[s_id])
        i += 1

    # BC Reg anchor (as Issuer) issues creds and stores at HolderProver: get cred req, create cred, store cred
    ''' 13
        S_ID['NON-REVO']: [
            {
                'name': 'J.R. "Bob" Dobbs',
                'thing': 'slack'
            },
            {
                'name': 'Chicken Hawk',
                'thing': 'chicken'
            }
        ],
        S_ID['SRI-1.0']: [],
        S_ID['SRI-1.1']: [],
        S_ID['GREEN']: []
    '''
    cred_data = {
        S_ID['BC']: [
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
            },
            {
                'id': 4,
                'busId': '11198765',
                'orgTypeId': 2,
                'jurisdictionId': 1,
                'legalName': 'Flan Nebula',
                'effectiveDate': '2018-01-01',
                'endDate': None
            },
            {
                'id': 5,
                'busId': '11155555',
                'orgTypeId': 1,
                'jurisdictionId': 1,
                'legalName': 'Babka Galaxy',
                'effectiveDate': '2012-12-01',
                'endDate': None
            },
        ],
        S_ID['NON-REVO']: [
            {
                'name': 'J.R. "Bob" Dobbs',
                'thing': 'slack'
            },
            {
                'name': 'Chicken Hawk',
                'thing': 'chicken'
            }
        ],
        S_ID['SRI-1.0']: [],
        S_ID['SRI-1.1']: [],
        S_ID['GREEN']: []
    }

    EPOCH_CRED_CREATE = {}
    i = 0
    for s_id in cred_data:
        origin_did = schema_key(s_id).origin_did
        EPOCH_CRED_CREATE[s_id] = []
        for c in cred_data[s_id]:
            (cred_json[s_id], cred_revoc_id, epoch_creation) = await did2an[origin_did].create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                c)
            EPOCH_CRED_CREATE[s_id].append(epoch_creation)
            if s_id != S_ID['NON-REVO']:
                sleep(2)  # put an interior second between each cred creation
            assert json.loads(cred_json[s_id])
            print('\n\n== 6.{} == BCReg created cred (revoc id {}) at epoch {}: {}'.format(
                i,
                cred_revoc_id,
                epoch_creation,
                ppjson(cred_json[s_id])))
            cred = json.loads(cred_json[s_id])

            if s_id != S_ID['NON-REVO']:
                _set_tails_state(False)
                _set_cache_state(False)
                try:
                    cred_id = await holder_prover[origin_did].store_cred(
                        cred_json[s_id],
                        cred_req_metadata_json[s_id])
                    assert False
                except AbsentTails:
                    pass

                _download_tails(cred['rev_reg_id'])

            cred_id = await holder_prover[origin_did].store_cred(
                cred_json[s_id],
                cred_req_metadata_json[s_id])
            assert (s_id == S_ID['NON-REVO'] or
                len(Tails.unlinked(DIR_TAILS)) == 0)  # storage should get rev reg def from ledger and link its id

            if s_id != S_ID['NON-REVO']:
                _set_tails_state(True)
                _set_cache_state(True)
            print('\n\n== 6.{}.1 == BC cred id in wallet: {}'.format(i, cred_id))
            i += 1

    # BC Org Book anchor (as HolderProver) exercises finding cred-infos by query
    bc_infos_wql_json = await bcoban.get_cred_infos_by_q()
    bc_all_card = len(json.loads(bc_infos_wql_json))
    print('\n\n== 7 == All ({}) BC cred infos by vacuous query, coarsely: {}'.format(
        bc_all_card,
        ppjson(bc_infos_wql_json, 1000)))
    wql_json = json.dumps({
        '$not': {
            'attr::thing::value': 'slack'
        }
    })
    assert len(json.loads(await bcoban.get_cred_infos_by_q(wql_json))) == bc_all_card - 1

    wql_json = json.dumps({
        'attr::id::marker': '1',
        'attr::id::value': '5'
    })  # and, equals
    assert len(json.loads(await bcoban.get_cred_infos_by_q(wql_json))) == 1

    wql_json = json.dumps({
        'attr::id::value': {
            '$in': ['5', '999999']
        }
    })  # $in
    assert len(json.loads(await bcoban.get_cred_infos_by_q(wql_json))) == 1

    wql_json = json.dumps({
        'attr::thing::marker': '1',
        '$not': {
            'attr::thing::value': {
                '$neq': 'slack'
            }
        }
    })  # and, $not, $neq
    assert len(json.loads(await bcoban.get_cred_infos_by_q(wql_json))) == 1

    wql_json = json.dumps({
        'attr::legalName::value': {
            '$in': ['Flan Nebula', 'Tart City']
        },
        'schema_id': S_ID['BC']
    })  # schema_id, $in, attribute name canonicalization in outer key
    infos = json.loads(await bcoban.get_cred_infos_by_q(wql_json))
    assert {info['attrs']['legalName'] for info in infos} == {'Flan Nebula', 'Tart City'}

    wql_json = json.dumps({
        '$not': {
            '$or': [
                {
                    'attr::legalName::value': {
                        '$in': ['Flan Nebula', 'Tart City']
                    }
                },
                {
                    'attr::legalName::value': {
                        '$in': ['Babka Galaxy', 'The Original House of Pies']
                    }
                }
            ]
        },
        'cred_def_id': cd_id[S_ID['BC']]
    })  # cred def id, $not, $or, and, $in, attribute canonicalization in inner key
    infos = json.loads(await bcoban.get_cred_infos_by_q(wql_json))
    assert {info['attrs']['legalName'] for info in infos} == {'Planet Cake'}

    try:
        wql_json = json.dumps({
            '$or': {  # should be a list
                'attr::legalName::value': {
                    '$in': ['Flan Nebula', 'Tart City']
                },
                'attr::legalName::value': {
                    '$in': ['Babka Galaxy', 'The Original House of Pies']
                }
            },
            'cred_def_id': cd_id[S_ID['BC']]
        })  # $or value wrong: not a list
        infos = json.loads(await bcoban.get_cred_infos_by_q(wql_json))
        assert False
    except BadWalletQuery:
        pass

    # BC Org Book anchor (as HolderProver) finds creds by coarse filters
    bc_infos_filt_json = await bcoban.get_cred_infos_by_filter()
    print('\n\n== 8 == All BC cred infos by vacuous filter: {}'.format(ppjson(bc_infos_filt_json)))
    assert len(json.loads(bc_infos_filt_json)) == len(cred_data[S_ID['BC']]) + len(cred_data[S_ID['NON-REVO']])

    for s_id in cred_data:
        s_key = schema_key(s_id)
        assert (len(json.loads(await bcoban.get_cred_infos_by_filter(
            {
                'schema_name': s_key.name,
                'schema_version': s_key.version
            }))) == (len(cred_data[s_id]) if holder_prover[s_key.origin_did].did == bcoban.did else 0))

    # BC Org Book anchor (as HolderProver) finds creds; actuator filters post hoc
    EPOCH_PRE_BC_REVOC = int(time())
    proof_req[S_ID['BC']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': (EPOCH_START, EPOCH_PRE_BC_REVOC)
        }
    }))
    (bc_cred_ids_all, bc_creds_found_all_json) = await bcoban.get_creds(json.dumps(proof_req[S_ID['BC']]))

    print('\n\n== 9 == All BC creds, no filter {}: {}'.format(bc_cred_ids_all, ppjson(bc_creds_found_all_json)))
    bc_creds_found_all = json.loads(bc_creds_found_all_json)
    bc_display_pruned_filt_post_hoc = creds_display(
        bc_creds_found_all,
        {
            cd_id[S_ID['BC']]: {
                'legalName': cred_data[S_ID['BC']][2]['legalName']
            }
        })
    print('\n\n== 10 == BC creds display, filtered post hoc matching {}: {}'.format(
        cred_data[S_ID['BC']][2]['legalName'],
        ppjson(bc_display_pruned_filt_post_hoc)))
    bc_display_pruned = prune_creds_json(
        bc_creds_found_all,
        {k for k in bc_display_pruned_filt_post_hoc})
    print('\n\n== 11 == BC cred displays, pruned: {}'.format(ppjson(bc_display_pruned)))
    bc_revoc_info = revoc_info(bc_creds_found_all)
    print('\n\n== 12 == BC cred revocation info:\n{}'.format(ppjson(bc_revoc_info)))

    filt_get_creds = {
        cd_id[S_ID['BC']]: {
            'attr-match': {  # Tart City, at index 2
                k: cred_data[S_ID['BC']][2][k] for k in cred_data[S_ID['BC']][2]
                    if k in ('jurisdictionId', 'busId')
            }
        }
    }
    (bc_cred_ids_filt, bc_creds_found_filt_json) = await bcoban.get_creds(
        json.dumps(proof_req[S_ID['BC']]),
        filt_get_creds)
    bc_creds_found_filt = json.loads(bc_creds_found_filt_json)
    print('\n\n== 13 == BC creds, filtered a priori {}: {}'.format(
        bc_cred_ids_filt,
        ppjson(bc_creds_found_filt)))
    assert set([*bc_display_pruned_filt_post_hoc]) == bc_cred_ids_filt
    assert len(bc_display_pruned_filt_post_hoc) == 1
    bc_box_ids_filt = box_ids(bc_creds_found_filt, bc_cred_ids_filt)  # exercise box_ids
    assert bc_box_ids_filt.items() == box_ids(bc_creds_found_filt).items() and len(bc_box_ids_filt) == 1

    tart_city_id = bc_cred_ids_filt.pop()  # Tart City

    # BC Org Book anchor (as HolderProver) exercises finding creds by query
    proof_req[S_ID['NON-REVO']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['NON-REVO']]: None
    }))
    '''
    proof req: {
        "nonce": "1532429687",
        "name": "proof_req",
        "version": "0.0",
        "requested_predicates": {},
        "requested_attributes": {
            "17_name_uuid": {
                "restrictions": [
                    {
                        "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:17:0"
                    }
                ],
                "name": "name"
            },
            "17_thing_uuid": {
                "restrictions": [
                    {
                        "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:17:0"
                    }
                ],
                "name": "thing"
            }
        }
    }
    '''
    nr_refts = proof_req_attr_referents(proof_req[S_ID['NON-REVO']])
    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]][k]: {
            '$or': [
                {
                    'attr::name::value': 'Chicken Hawk'
                },
                {
                    'attr::thing::value': 'slack'
                }
            ]
        } for k in nr_refts[cd_id[S_ID['NON-REVO']]]
    })
    (nr_cred_ids_q, nr_briefs_found_q_json) = await bcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json)
    nr_briefs_found_q = json.loads(nr_briefs_found_q_json)
    print('\n\n== 14 == [{}] non-revo cred briefs, via $or query {}:\ncred-ids {}\ncreds {}'.format(
        len(nr_briefs_found_q),
        ppjson(wql_get_briefs_json),
        nr_cred_ids_q,
        ppjson(nr_briefs_found_q)))
    assert len(nr_cred_ids_q) == 2
    nr_box_ids_q = box_ids(nr_briefs_found_q, nr_cred_ids_q)  # exercise box_ids
    print('\n\n== 15 == box-ids for non-revo cred briefs via $or query: {}'.format(ppjson(nr_box_ids_q)))

    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]][k]: {  # AND (no-match)
            'attr::name::value': 'Chicken Hawk',
            'attr::thing::value': 'slack'
        } for k in nr_refts[cd_id[S_ID['NON-REVO']]]
    })
    (nr_cred_ids_q, nr_briefs_found_q_json) = await bcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json)
    nr_briefs_found_q = json.loads(nr_briefs_found_q_json)
    print('\n\n== 16 == [{}] non-revo cred synopses, via no-match AND query {}:\ncred-ids {}\ncreds {}'.format(
        len(nr_briefs_found_q),
        ppjson(wql_get_briefs_json),
        nr_cred_ids_q,
        ppjson(nr_briefs_found_q)))
    assert len(nr_cred_ids_q) == 0
    nr_box_ids_q = box_ids(nr_briefs_found_q, nr_cred_ids_q)  # exercise box_ids
    print('\n\n== 17 == box-ids for non-revo cred briefs via no-match AND query: {}'.format(ppjson(nr_box_ids_q)))

    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]][k]: {  # AND (single-match)
            'attr::name::value': 'Chicken Hawk',
            'attr::thing::value': 'chicken'
        } for k in nr_refts[cd_id[S_ID['NON-REVO']]]
    })
    (nr_cred_ids_q, nr_briefs_found_q_json) = await bcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json)
    nr_briefs_found_q = json.loads(nr_briefs_found_q_json)
    print('\n\n== 18 == [{}] non-revo cred briefs, via single-match AND query {}:\ncred-ids {}\ncreds {}'.format(
        len(nr_briefs_found_q),
        ppjson(wql_get_briefs_json),
        nr_cred_ids_q,
        ppjson(nr_briefs_found_q)))
    assert len(nr_cred_ids_q) == 1
    nr_box_ids_q = box_ids(nr_briefs_found_q, nr_cred_ids_q)  # exercise box_ids
    print('\n\n== 19 == box-ids for non-revo cred briefs via single-match AND query: {}'.format(ppjson(nr_box_ids_q)))

    bc_refts = proof_req_attr_referents(proof_req[S_ID['BC']])
    print('\n\n== 20 == BC referents from proof req: {}'.format(ppjson(bc_refts)))
    wql_get_briefs_json = json.dumps({
        bc_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Tart City'
        }
    })
    (bc_cred_ids_q, bc_briefs_found_q_json) = await bcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['BC']]),
        wql_get_briefs_json)
    bc_briefs_found_q = json.loads(bc_briefs_found_q_json)
    print('\n\n== 21 == [{}] BC cred briefs, via query {}: {}'.format(
        len(bc_briefs_found_q),
        bc_cred_ids_q,
        ppjson(bc_briefs_found_q)))
    assert len(bc_cred_ids_q) == 1
    bc_box_ids_q = box_ids(bc_briefs_found_q, bc_cred_ids_q)  # exercise box_ids
    assert bc_box_ids_q.items() == box_ids(bc_briefs_found_q).items() and len(bc_box_ids_q) == 1

    bc_revoc_info_q = revoc_info(bc_briefs_found_q)
    assert bc_revoc_info_q.items() <= bc_revoc_info.items() and len(bc_revoc_info_q) == 1

    # BC Org Book anchor (as HolderProver) creates proof for cred specified by filter
    bc_req_creds = json.loads(await bcoban.build_req_creds_json(bc_creds_found_filt))
    print('\n\n== 22 == BC req creds by filt {}'.format(ppjson(bc_req_creds)))
    bc_req_creds_q = proof_req_briefs2req_creds(proof_req[S_ID['BC']], bc_briefs_found_q)
    print('\n\n== 23 == BC req creds by query {}'.format(ppjson(bc_req_creds_q)))
    assert bc_req_creds == bc_req_creds_q

    _set_tails_state(False)  # simulate not having tails file first
    _set_cache_state(False)
    try:
        bc_proof_json = await bcoban.create_proof(
            proof_req[S_ID['BC']],
            bc_creds_found_filt,
            bc_req_creds)
        assert False
    except AbsentTails:
        pass

    x_proof_req = deepcopy(proof_req[S_ID['BC']])
    for attr_uuid in x_proof_req['requested_attributes']:
        x_proof_req['requested_attributes'][attr_uuid].pop('non_revoked')
    (_, x_creds_found_json) = await bcoban.get_creds(json.dumps(x_proof_req), filt_get_creds)
    rr_id = list(revoc_info(json.loads(x_creds_found_json), {'legalName': 'Tart City'}).keys())[0][0]
    _download_tails(rr_id)  # simulate sending tails file to HolderProver

    try:
        await bcoban.create_proof(
            x_proof_req,
            json.loads(x_creds_found_json),
            bc_req_creds)
        assert False
    except AbsentInterval:  # check: skipping non-revocation interval raises AbsentInterval for cred def w/revocation
        pass

    bc_proof_json = await bcoban.create_proof(proof_req[S_ID['BC']], bc_creds_found_filt, bc_req_creds)
    assert len(Tails.unlinked(DIR_TAILS)) == 0  # proof creation should get rev reg def from ledger and link its rr_id

    _set_tails_state(True)  # restore state
    _set_cache_state(True)

    print('\n\n== 24 == BC proof (by filter): {}'.format(ppjson(bc_proof_json, 1000)))

    # SRI anchor (as Verifier) verifies proof (by filter)
    rc_json = await san.verify_proof(
        proof_req[S_ID['BC']],
        json.loads(bc_proof_json))
    print('\n\n== 25 == SRI anchor verifies BC proof (by filter) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Registrar anchor creates proof from cred-infos via query
    bc_proof_q_json = await bcoban.create_proof(proof_req[S_ID['BC']], bc_briefs_found_q, bc_req_creds_q)
    print('\n\n== 26 == BC proof (by query): {}'.format(ppjson(bc_proof_json, 1000)))

    assert len(Tails.unlinked(DIR_TAILS)) == 0  # proof creation should get rev reg def from ledger and link its rr_id

    # SRI anchor (as Verifier) verifies proof (by query)
    rc_json = await san.verify_proof(
        proof_req[S_ID['BC']],
        json.loads(bc_proof_q_json))
    print('\n\n== 27 == SRI anchor verifies BC proof (by query) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    sleep(1)  # make sure EPOCH_BC_REVOC > EPOCH_PRE_BC_REVOC

    # BC Registrar anchor creates proof (by filter) for non-revocable cred, for verification
    proof_req[S_ID['NON-REVO']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['NON-REVO']]: None
    }))
    nr_filt_get_creds = {
        cd_id[S_ID['NON-REVO']]: {
            'attr-match': {
                'thing': 'slack'
            }
        }
    }
    (nr_cred_ids, nr_creds_found_json) = await bcoban.get_creds(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        nr_filt_get_creds)
    assert len(nr_cred_ids) == 1
    nr_cred_id = nr_cred_ids.pop()
    nr_creds_found = json.loads(nr_creds_found_json)
    nr_req_creds = json.loads(await bcoban.build_req_creds_json(nr_creds_found))
    nr_proof_json = await bcoban.create_proof(
        proof_req[S_ID['NON-REVO']],
        nr_creds_found,
        nr_req_creds)
    print('\n\n== 28 == Proof (by filter) of non-revocable cred: {}'.format(ppjson(nr_proof_json, 1000)))

    # Verifier anchor attempts to verify proof (by filter) of non-revocable cred
    rc_json = await san.verify_proof(proof_req[S_ID['NON-REVO']], json.loads(nr_proof_json))
    print('\n\n== 29 == SRI anchor verifies proof (by filter) of non-revocable cred as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Registrar anchor creates proof (by query) for non-revocable cred, for verification
    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]]['thing']: {
            'attr::thing::value': 'slack'
        }
    })
    (nr_cred_ids_q, nr_briefs_found_q_json) = await bcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json)
    nr_briefs_found_q = json.loads(nr_briefs_found_q_json)
    assert len(nr_cred_ids_q) == 1
    nr_cred_id = nr_cred_ids_q.pop()
    nr_briefs_found_q = json.loads(nr_briefs_found_q_json)
    nr_req_creds_q = proof_req_briefs2req_creds(proof_req[S_ID['NON-REVO']], nr_briefs_found_q)
    nr_proof_q_json = await bcoban.create_proof(
        proof_req[S_ID['NON-REVO']],
        nr_briefs_found_q,
        nr_req_creds_q)
    print('\n\n== 30 == Proof (by query) of non-revocable cred: {}'.format(ppjson(nr_proof_json, 1000)))

    # Verifier anchor attempts to verify proof (by query) of non-revocable cred
    rc_json = await san.verify_proof(proof_req[S_ID['NON-REVO']], json.loads(nr_proof_json))
    print('\n\n== 31 == SRI anchor verifies proof (by query) of non-revocable cred as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # Exercise build_proof_req_json parameter permutations
    preq = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: None for s_id in schema_data if s_id != S_ID['BC']
    }))
    assert not len(preq['requested_predicates'])
    assert len(preq['requested_attributes']) == sum(len(schema_data[s_id]['attr_names'])
        for s_id in schema_data if s_id != S_ID['BC'])
    assert all(preq['requested_attributes'][uuid].get('non_revoked', None)
        or preq['requested_attributes'][uuid]['restrictions'][0]['cred_def_id'] == cd_id[S_ID['NON-REVO']]
            for uuid in preq['requested_attributes'])

    preq = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {},
        cd_id[S_ID['SRI-1.1']]: {
            'attrs': ['endDate', 'legalName'],
            'minima': {
                'id': 1,
                'jurisdictionId': '1',
                'orgTypeId': 1.0
            },
            'interval': EPOCH_START
        }
    }))
    assert len(preq['requested_predicates']) == 3
    assert len(preq['requested_attributes']) == len(schema_data[S_ID['BC']]['attr_names']) + 2
    assert all(preq['requested_attributes'][uuid]['non_revoked'] for uuid in preq['requested_attributes'])
    assert all(preq['requested_predicates'][uuid]['non_revoked'] for uuid in preq['requested_predicates'])

    schema_data.pop(S_ID['NON-REVO'])  # all done with non-revocable cred def
    schema.pop(S_ID['NON-REVO'])
    cred_data.pop(S_ID['NON-REVO'])
    S_ID.pop('NON-REVO')

    # BC Registrar anchor revokes Flan Nebula credential
    wql_get_briefs_json = json.dumps({
        bc_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Flan Nebula'
        }
    })
    (_, bc_briefs_found_q_json) = await bcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['BC']]),
        wql_get_briefs_json)
    r = set(revoc_info(json.loads(bc_briefs_found_q_json)))
    assert len(r) == 1
    (x_rr_id, x_cr_id) = r.pop()  # it's unique
    assert (x_rr_id, x_cr_id) != (None, None)

    try:
        await san.revoke_cred(x_rr_id, x_cr_id)  # check: only a cred's issuer can revoke it
        assert False
    except BadRevocation:
        pass

    EPOCH_BC_REVOC = await did2an[schema_key(S_ID['BC']).origin_did].revoke_cred(x_rr_id, x_cr_id)
    print('\n\n== 32 == BC registrar anchor revoked ({}, {}) -> {}'.format(
        x_rr_id,
        x_cr_id,
        bc_revoc_info[(x_rr_id, x_cr_id)]['legalName']))
    sleep(1)
    EPOCH_POST_BC_REVOC = int(time())
    print('\n\n== 33 == EPOCH times re: BC revocation: pre-revoc {}, revoc {}, post-revoc {}'.format(
        EPOCH_PRE_BC_REVOC,
        EPOCH_BC_REVOC,
        EPOCH_POST_BC_REVOC))

    try:
        await did2an[schema_key(S_ID['BC']).origin_did].revoke_cred(x_rr_id, x_cr_id)  # check: double-revocation
        assert False
    except BadRevocation:
        pass

    # BC Org Book anchor (as HolderProver) finds creds after revocation
    proof_req[S_ID['BC']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': (EPOCH_PRE_BC_REVOC, EPOCH_POST_BC_REVOC)  #  should take latest = post-revocation
        }
    }))
    (bc_cred_ids_all, _) = await bcoban.get_creds(json.dumps(proof_req[S_ID['BC']]))
    assert len(bc_cred_ids_all) == len(cred_data[S_ID['BC']])  # indy-sdk get-creds includes revoked creds here

    # BC Org Book anchor (as HolderProver) finds cred-briefs after revocation
    (bc_cred_ids_all_q, _) = await bcoban.get_cred_briefs_by_proof_req_q(json.dumps(proof_req[S_ID['BC']]))
    assert len(bc_cred_ids_all_q) == len(cred_data[S_ID['BC']])  # indy-sdk get-creds includes revoked creds here

    # BC Org Book anchor (as HolderProver) creates non-proof (by filter) for revoked cred, for non-verification
    x_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': (EPOCH_PRE_BC_REVOC, EPOCH_POST_BC_REVOC)  # should take latest = post-revocation
        }
    }))
    x_filt_get_creds = {
        cd_id[S_ID['BC']]: {
            'attr-match': {
                'legalName': 'Flan Nebula'
            }
        }
    }
    (x_cred_ids, x_creds_found_json) = await bcoban.get_creds(json.dumps(x_proof_req), x_filt_get_creds)
    assert len(x_cred_ids) == 1
    x_cred_id = x_cred_ids.pop()
    x_creds_found = json.loads(x_creds_found_json)
    x_req_creds = json.loads(await bcoban.build_req_creds_json(x_creds_found))
    x_proof_json = await bcoban.create_proof(x_proof_req, x_creds_found, x_req_creds)

    print('\n\n== 34 == Proof (by filter) of revoked cred: {}'.format(ppjson(x_proof_json, 1000)))

    # Verifier anchor attempts to verify non-proof (by filter) of revoked cred
    rc_json = await san.verify_proof(x_proof_req, json.loads(x_proof_json))
    print('\n\n== 35 == SRI anchor verifies proof (by filter) of revoked cred as: {}'.format(ppjson(rc_json)))
    assert not json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates non-proof (by query) for revoked cred, for non-verification
    x_refts = proof_req_attr_referents(x_proof_req)
    wql_get_briefs_json = json.dumps({
        x_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Flan Nebula'
        }
    })

    (x_cred_ids, x_briefs_found_q_json) = await bcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(x_proof_req),
        wql_get_briefs_json)
    assert len(x_cred_ids) == 1

    x_cred_id = x_cred_ids.pop()
    x_briefs_found_q = json.loads(x_briefs_found_q_json)
    x_req_creds_q = proof_req_briefs2req_creds(x_proof_req, x_briefs_found_q)
    x_proof_q_json = await bcoban.create_proof(x_proof_req, x_briefs_found_q, x_req_creds_q)
    print('\n\n== 36 == Proof (by filter) of revoked cred: {}'.format(ppjson(x_proof_q_json, 1000)))

    # Verifier anchor attempts to verify non-proof (by filter) of revoked cred
    rc_json = await san.verify_proof(x_proof_req, json.loads(x_proof_q_json))
    print('\n\n== 37 == SRI anchor verifies proof (by query) of revoked cred as: {}'.format(ppjson(rc_json)))
    assert not json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof for non-revoked cred on same rev reg, for verification
    ok_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_POST_BC_REVOC
        }
    }))
    ok_filt_get_creds = {
        cd_id[S_ID['BC']]: {
            'attr-match': {
                'legalName': 'Tart City'
            }
        }
    }
    (ok_cred_ids, ok_creds_found_json) = await bcoban.get_creds(json.dumps(ok_proof_req), ok_filt_get_creds)
    assert len(ok_cred_ids) == 1
    ok_cred_id = ok_cred_ids.pop()
    ok_creds_found = json.loads(ok_creds_found_json)
    ok_req_creds = json.loads(await bcoban.build_req_creds_json(ok_creds_found))
    ok_proof_json = await bcoban.create_proof(ok_proof_req, ok_creds_found, ok_req_creds)
    print('\n\n== 38 == Proof (by filter) of non-revoked cred: {}'.format(ppjson(ok_proof_json, 1000)))

    # Verifier anchor attempts to verify non-proof of revoked cred
    rc_json = await san.verify_proof(ok_proof_req, json.loads(ok_proof_json))
    print('\n\n== 39 == SRI anchor verifies proof (by filter) of non-revoked cred as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof for revoked cred, back-dated just before revocation
    x_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_PRE_BC_REVOC
        }
    }))
    (x_cred_ids, x_creds_found_json) = await bcoban.get_creds(json.dumps(x_proof_req), x_filt_get_creds)
    assert len(x_cred_ids) == 1
    x_cred_id = x_cred_ids.pop()
    x_creds_found = json.loads(x_creds_found_json)
    x_req_creds = json.loads(await bcoban.build_req_creds_json(x_creds_found))
    x_proof_json = await bcoban.create_proof(x_proof_req, x_creds_found, x_req_creds)
    print('\n\n== 40 == Proof (by filter) of cred before revocation: {}'.format(ppjson(x_proof_json, 1000)))

    # Verifier anchor attempts to verify proof of cred before revocation
    rc_json = await san.verify_proof(x_proof_req, json.loads(x_proof_json))
    print('\n\n== 41 == SRI anchor verifies proof (by filter) of cred before revocation as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof for revoked cred, back-dated < rev reg def (indy-sdk cannot)
    x_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_START
        }
    }))
    (x_cred_ids, x_creds_found_json) = await bcoban.get_creds(json.dumps(x_proof_req), x_filt_get_creds)
    assert len(x_cred_ids) == 1
    x_cred_id = x_cred_ids.pop()
    x_creds_found = json.loads(x_creds_found_json)
    x_req_creds = json.loads(await bcoban.build_req_creds_json(x_creds_found))
    try:
        x_proof_json = await bcoban.create_proof(x_proof_req, x_creds_found, x_req_creds)
        assert False
    except BadRevStateTime:
        print('\n\n== 42 == SRI anchor cannot create proof on request with rev reg state before its creation')

    # BC Org Book anchor (as HolderProver) finds cred by cred-id, proof req and cred-id, no cred by non-cred-id
    bc_info_by_cred_id = json.loads(await bcoban.get_cred_info_by_id(tart_city_id))
    print('\n\n== 43 == BC cred (coarsely) by cred_id={}: {}'.format(
        tart_city_id,
        ppjson(bc_info_by_cred_id)))
    proof_req_by_id = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_POST_BC_REVOC
        }
    }))
    bc_info_by_cred_id = json.loads(await bcoban.get_cred_info_by_id(tart_city_id))
    print('\n\n== 44 == BC cred by cred_id={}: {}'.format(
        tart_city_id,
        ppjson(bc_info_by_cred_id)))
    assert bc_info_by_cred_id
    assert bc_info_by_cred_id['attrs']

    try:
        await bcoban.get_cred_info_by_id('ffffffff-ffff-ffff-ffff-ffffffffffff')
        assert False
    except AbsentCred:
        pass

    # BC Org Book anchor (as HolderProver) creates proof for cred specified by cred-id
    bc_briefs = proof_req_infos2briefs(proof_req[S_ID['BC']], [bc_info_by_cred_id])
    print('bc briefs: {}'.format(ppjson(bc_briefs)))
    bc_req_creds = proof_req_briefs2req_creds(proof_req[S_ID['BC']], bc_briefs)
    print('bc req creds: {}'.format(ppjson(bc_req_creds)))
    bc_proof_json = await bcoban.create_proof(
        proof_req[S_ID['BC']],
        bc_briefs,
        bc_req_creds)
    bc_proof = json.loads(bc_proof_json)
    print('\n\n== 45 == BC proof by cred-id={}: {}'.format(tart_city_id, ppjson(bc_proof_json, 1000)))

    # SRI anchor (as Verifier) verifies proof (by cred-id)
    rc_json = await san.verify_proof(proof_req[S_ID['BC']], bc_proof)
    print('\n\n== 46 == SRI anchor verifies BC proof by cred-id={} as: {}'.format(tart_city_id, ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof by attr for non-revoked Babka Galaxy
    bg_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_POST_BC_REVOC
        }
    }))
    bg_filt_get_creds = {
        cd_id[S_ID['BC']]: {
            'attr-match': {
                'legalName': 'Babka Galaxy'
            }
        }
    }
    (bg_cred_ids, bg_creds_found_json) = await bcoban.get_creds(json.dumps(bg_proof_req), bg_filt_get_creds)
    assert len(bg_cred_ids) == 1
    bg_cred_id = bg_cred_ids.pop()
    bg_creds_found = json.loads(bg_creds_found_json)
    bg_req_creds = json.loads(await bcoban.build_req_creds_json(bg_creds_found))
    bg_proof_json = await bcoban.create_proof(bg_proof_req, bg_creds_found, bg_req_creds)
    print('\n\n== 47 == Proof (by filter) of non-revoked Babka Galaxy: {}'.format(ppjson(bg_proof_json, 1000)))

    # Verifier anchor attempts to verify proof of non-revoked Babka Galaxy cred
    rc_json = await san.verify_proof(bg_proof_req, json.loads(bg_proof_json))
    print('\n\n== 48 == SRI anchor verifies proof (by filter) of cred before revocation as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) finds creds by predicate
    bg_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_POST_BC_REVOC
        }
    }))
    proof_req_pred =  json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'attrs': [attr_name for attr_name in schema_data[S_ID['BC']]['attr_names'] if attr_name != 'id'],
            'minima': {
                'id': cred_data[S_ID['BC']][4]['id']
            },
            'interval': EPOCH_POST_BC_REVOC
        }
    }))
    filt_pred = {
        cd_id[S_ID['BC']]: {
            'minima': {
                'id': cred_data[S_ID['BC']][4]['id']
            }
        }
    }
    (bc_cred_ids_pred, bc_creds_found_pred_json) = await bcoban.get_creds(json.dumps(proof_req_pred), filt_pred)
    print('\n\n== 49 == BC creds, filtered by predicate id >= 5: {}'.format(ppjson(bc_creds_found_pred_json)))
    bc_creds_found_pred = json.loads(bc_creds_found_pred_json)
    bc_display_pred = creds_display(bc_creds_found_pred)
    print('\n\n== 50 == BC creds display, filtered by predicate id >= 5: {}'.format(ppjson(bc_display_pred)))
    assert len(bc_cred_ids_pred) == 1
    bc_cred_id_pred = bc_cred_ids_pred.pop()  # it's unique

    # BC Org Book anchor (as HolderProver) creates proof for creds structure filtered by predicate
    bc_req_creds_pred = json.loads(await bcoban.build_req_creds_json(
        bc_creds_found_pred,
        {cd_id[S_ID['BC']]: {}},
        True))
    bc_proof_pred_json = await bcoban.create_proof(
        proof_req_pred,
        bc_creds_found_pred,
        bc_req_creds_pred)
    print('\n\n== 51 == BC proof by predicate id >= 5: {}'.format(ppjson(bc_proof_pred_json, 1000)))

    # SRI anchor (as Verifier) verifies proof (by predicate)
    rc_json = await san.verify_proof(
        proof_req_pred,
        json.loads(bc_proof_pred_json))
    print('\n\n== 52 == SRI anchor verifies BC proof (by predicate) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # Create and store SRI registration completion creds, green cred from verified proof + extra data
    print('\n\n== 53 == Revealed attributes from BC proof: {}'.format(ppjson(revealed_attrs(bc_proof))))
    revealed = revealed_attrs(bc_proof)[cd_id[S_ID['BC']]]

    TODAY = datetime.date.today().strftime('%Y-%m-%d')
    cred_data[S_ID['SRI-1.0']].append({  # map from revealed attrs, taken from indy-sdk proof w/canonicalized attr names
        **{[s for s in schema_data[S_ID['SRI-1.0']]['attr_names'] if canon(s) == k][0]:
            revealed[k] for k in revealed if k in [canon(a) for a in schema_data[S_ID['SRI-1.0']]['attr_names']]},
        'sriRegDate': TODAY
    })
    cred_data[S_ID['SRI-1.1']].append({
        **{[s for s in schema_data[S_ID['SRI-1.1']]['attr_names'] if canon(s) == k][0]:
            revealed[k] for k in revealed if k in [canon(a) for a in schema_data[S_ID['SRI-1.1']]['attr_names']]},
        'sriRegDate': TODAY,
        'businessLang': 'EN-CA'
    })
    cred_data[S_ID['GREEN']].append({
        **{[s for s in schema_data[S_ID['SRI-1.1']]['attr_names'] if canon(s) == k][0]:
            revealed[k] for k in revealed if k in [canon(a) for a in schema_data[S_ID['GREEN']]['attr_names']]},
        'greenLevel': 'Bronze',
        'auditDate': TODAY
    })
    cred_data[S_ID['GREEN']].append({
        **{[s for s in schema_data[S_ID['SRI-1.1']]['attr_names'] if canon(s) == k][0]:
            revealed[k] for k in revealed if k in [canon(a) for a in schema_data[S_ID['GREEN']]['attr_names']]},
        'greenLevel': 'Silver',
        'auditDate': TODAY
    })

    i = 0
    for s_id in cred_data:
        if s_id == S_ID['BC']:
            continue
        s_key = schema_key(s_id)
        for c in cred_data[s_id]:
            (cred_json[s_id], cred_rev_id, epoch_creation) = await did2an[s_key.origin_did].create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                c)
            EPOCH_CRED_CREATE[s_id].append(epoch_creation)
            sleep(2)  # put an interior second between each cred creation
            assert json.loads(cred_json[s_id])
            print('\n\n== 54.{}.0 == SRI created cred (revoc id {}) at epoch {} on schema {}: {}'.format(
                i,
                cred_rev_id,
                epoch_creation,
                s_id,
                ppjson(cred_json[s_id])))
            cred_id = await holder_prover[s_key.origin_did].store_cred(
                cred_json[s_id],
                cred_req_metadata_json[s_id])
            print('\n\n== 54.{}.1 == Cred id in wallet: {}'.format(i, cred_id))
            i += 1
    EPOCH_PRE_SRI_REVOC = int(time())

    # PSPC Org Book anchor (as HolderProver) finds all creds, one schema at a time
    creds_found_pspc_json = {}  # index by s_id
    i = 0
    for s_id in schema:
        if s_id == S_ID['BC']:
            continue
        s_key = schema_key(s_id)
        proof_req[s_id] = json.loads(await san.build_proof_req_json({
            cd_id[s_id]: {
                'interval': EPOCH_PRE_SRI_REVOC
            }
        }))
        (sri_cred_ids, creds_found_pspc_json[s_id]) = await holder_prover[s_key.origin_did].get_creds(
            json.dumps(proof_req[s_id]))

        print('\n\n== 55.{} == Creds on schema {} (no filter) cred_ids: {}; creds: {}'.format(
            i,
            s_id,
            sri_cred_ids,
            ppjson(creds_found_pspc_json[s_id])))
        i += 1

    # PSPC Org Book anchor (as HolderProver) finds all creds on all schemata; actuator filters post hoc
    proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_PRE_SRI_REVOC
        } for s_id in schema_data if s_id != S_ID['BC']
    }))

    (sri_cred_ids, sri_creds_found_json) = await pspcoban.get_creds(json.dumps(proof_req_sri))
    print('\n\n== 56 == All SRI-issued creds (no filter) at PSPC Org Book {}: {}'.format(
        sri_cred_ids,
        ppjson(sri_creds_found_json)))

    sri_creds_found = json.loads(sri_creds_found_json)
    sri_display_filt_post_hoc = creds_display(
        sri_creds_found,
        {
            cd_id[S_ID['GREEN']]: {
                'legalName': cred_data[S_ID['GREEN']][1]['legalName'],
                'greenLevel': cred_data[S_ID['GREEN']][1]['greenLevel']  # [1]: 'greenLevel': 'Silver'
            }
        })
    print('\n\n== 57 == SRI creds display, filtered post hoc matching greenLevel {}: {}'.format(
        cred_data[S_ID['GREEN']][1]['greenLevel'],
        ppjson(sri_display_filt_post_hoc)))
    sri_pruned = prune_creds_json(
        sri_creds_found,
        {k for k in sri_display_filt_post_hoc})
    print('\n\n== 58 == SRI creds, stripped down: {}'.format(ppjson(sri_pruned)))

    filt_get_creds_silver = {
        cd_id[S_ID['GREEN']]: {
            'attr-match': {
                'legalName': cred_data[S_ID['GREEN']][1]['legalName'],
                'greenLevel': cred_data[S_ID['GREEN']][1]['greenLevel']  # [1]: 'greenLevel': 'Silver'
            }
        }
    }
    (sri_cred_ids_filt, creds_found_pspc_json[S_ID['GREEN']]) = await pspcoban.get_creds(
        json.dumps(proof_req[S_ID['GREEN']]),
        filt_get_creds_silver)
    print('\n\n== 59 == SRI creds, filtered a priori {}: {}'.format(
        sri_cred_ids_filt,
        ppjson(creds_found_pspc_json[S_ID['GREEN']])))
    assert set([*sri_display_filt_post_hoc]) == sri_cred_ids_filt
    assert len(sri_display_filt_post_hoc) == 1

    sri_creds_found = json.loads(sri_creds_found_json)
    sri_display_filt = creds_display(
        sri_creds_found,
        {
            cd_id[S_ID['GREEN']]: {
                'greenLevel': 'Silver'
            }
        },
        True)
    assert len(sri_display_filt) == 3
    sri_creds_found_filt = json.loads(prune_creds_json(sri_creds_found, set(sri_display_filt.keys())))
    sri_cred_ids_filt = set(creds_display(sri_creds_found_filt).keys())

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof (by filter)
    sri_req_creds = json.loads(await pspcoban.build_req_creds_json(sri_creds_found_filt))
    sri_proof_json = await pspcoban.create_proof(proof_req_sri, sri_creds_found_filt, sri_req_creds)
    print('\n\n== 60 == PSPC Org Book proof on cred-ids {}: {}'.format(sri_cred_ids_filt, ppjson(sri_proof_json, 1000)))
    sri_proof = json.loads(sri_proof_json)

    # SRI anchor (as Verifier) verifies proof (by filter)
    rc_json = await san.verify_proof(proof_req_sri, sri_proof)
    print('\n\n== 61 == SRI anchor verifies PSPC Org Book proof by cred_ids {} as: {}'.format(
        sri_cred_ids_filt,
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) creates multi-cred non-proof (by query) for >1 creds on a cred def
    sri_refts = proof_req_attr_referents(proof_req_sri)
    wql_all_json = json.dumps(proof_req2wql_all(proof_req_sri))
    (sri_cred_ids_q, sri_briefs_q_json) = await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        wql_all_json)
    sri_briefs_q = json.loads(sri_briefs_q_json)
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q)
    try:
        x_sri_proof_q_json = await pspcoban.create_proof(proof_req_sri, sri_briefs_q, sri_req_creds_q)
        assert False
    except CredentialFocus as x:
        pass

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof (by query)
    wql_not_silver = proof_req2wql_all(proof_req_sri, [cd_id[S_ID['GREEN']]])
    wql_not_silver[sri_refts[cd_id[S_ID['GREEN']]]['greenLevel']] = {
        '$not': {
            'attr::greenLevel::value': 'Silver'
        }
    }
    wql_not_silver_json = json.dumps(wql_not_silver)
    (sri_cred_ids_q, sri_briefs_q_json) = await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        wql_not_silver_json)
    assert len(sri_cred_ids_q) == len(cred_data) - 1  # one for each cred def except BC
    sri_briefs_q = json.loads(sri_briefs_q_json)
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q)
    sri_proof_q_json = await pspcoban.create_proof(proof_req_sri, sri_briefs_q, sri_req_creds_q)
    print('\n\n== 62 == PSPC Org Book proof by query on cred-ids {}: {}'.format(
        sri_cred_ids_q,
        ppjson(sri_proof_q_json, 1000)))
    sri_proof_q = json.loads(sri_proof_q_json)

    # SRI anchor (as Verifier) verifies proof (by query)
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 63 == SRI anchor verifies PSPC Org Book proof by cred_ids {} as: {}'.format(
        sri_cred_ids_filt,
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # Exercise build_req_creds_json parameter permutations
    rcreds_sri_all = json.loads(await pspcoban.build_req_creds_json(sri_creds_found))
    assert len(rcreds_sri_all['requested_attributes']) == len(proof_req_sri['requested_attributes'])
    rcreds = json.loads(await pspcoban.build_req_creds_json(
        sri_creds_found,
        {
            cd_id[S_ID['SRI-1.0']]: {}
        },
        True))
    assert len(rcreds['requested_attributes']) == len(rcreds_sri_all['requested_attributes'])
    rcreds = json.loads(await pspcoban.build_req_creds_json(
        sri_creds_found,
        {
            cd_id[S_ID['SRI-1.0']]: {
                'attr-match': {}
            },
            cd_id[S_ID['SRI-1.1']]: {
                'minima': {}
            },
            cd_id[S_ID['GREEN']]: None
        },
        True))
    assert len(rcreds['requested_attributes']) == len(rcreds_sri_all['requested_attributes'])
    rcreds = json.loads(await pspcoban.build_req_creds_json(
        sri_creds_found,
        {
            cd_id[S_ID['SRI-1.0']]: {
                'attr-match': {},
                'minima': {}
            }
        },
        True))
    assert len(rcreds['requested_attributes']) == len(rcreds_sri_all['requested_attributes'])
    rcreds = json.loads(await pspcoban.build_req_creds_json(
        sri_creds_found,
        {
            cd_id[S_ID['SRI-1.0']]: {
                'attr-match': {},
                'minima': {}
            }
        },
        False))
    assert len(rcreds['requested_attributes']) == len(schema_data[S_ID['SRI-1.0']]['attr_names'])
    rcreds = json.loads(await pspcoban.build_req_creds_json(
        sri_creds_found,
        {
            cd_id[S_ID['SRI-1.1']]: {
                'attr-match': {
                    'legalName': 'Tart City'
                }
            }
        },
        False))
    assert len(rcreds['requested_attributes']) == len(schema_data[S_ID['SRI-1.1']]['attr_names'])
    rcreds = json.loads(await pspcoban.build_req_creds_json(
        sri_creds_found,
        {
            cd_id[S_ID['SRI-1.1']]: {
                'attr-match': {
                    'legalName': 'Flan Nebula'
                }
            }
        },
        False))
    assert len(rcreds['requested_attributes']) == 0  # PSPC Org Book anchor has creds only for Tart City

    # PSPC Org Book anchor (as HolderProver) creates multi-cred non-proof; back-dated between Bronze, Silver issue
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_CRED_CREATE[S_ID['GREEN']][1] - 1
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    (x_cred_ids, x_sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(x_proof_req_sri),
        filt_get_creds_silver,
        True)
    x_sri_creds_found = json.loads(x_sri_creds_found_json)
    x_sri_req_creds = json.loads(await pspcoban.build_req_creds_json(x_sri_creds_found))
    x_sri_proof_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_creds_found, x_sri_req_creds)
    print('\n\n== 62 == Org Book proof pre-revoc on cred-ids {}, just before Silver cred creation {}'.format(
        sri_cred_ids_filt,
        ppjson(x_sri_proof_json, 1000)))
    x_sri_proof = json.loads(x_sri_proof_json)

    # SRI anchor (as Verifier) verifies proof
    rc_json = await san.verify_proof(x_proof_req_sri, x_sri_proof)
    print('\n\n== 63 == SRI anchor verifies BC Org Book proof pre-revoc on cred_ids {} < Silver creation as: {}'.format(
        x_cred_ids,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) tries to create multi-cred (non-)proof; post-dated in future
    TOMORROW = int(time()) + 86400
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': TOMORROW
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    (x_cred_ids, x_sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(x_proof_req_sri),
        filt_get_creds_silver,
        True)
    x_sri_creds_found = json.loads(x_sri_creds_found_json)
    x_sri_req_creds = json.loads(await pspcoban.build_req_creds_json(x_sri_creds_found))
    try:
        x_sri_proof_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_creds_found, x_sri_req_creds)
        assert False
    except BadRevStateTime:
        pass

    # SRI anchor (as Issuer) revokes a cred
    sri_revoc_info = revoc_info(sri_creds_found)
    r = set(revoc_info(
        sri_creds_found,
        {
            'legalName': 'Tart City',
            'greenLevel': 'Silver'
        }))
    assert len(r) == 1
    (x_rr_id, x_cr_id) = r.pop()  # it's unique

    sleep(1)
    EPOCH_SRI_REVOC = await did2an[schema_key(S_ID['GREEN']).origin_did].revoke_cred(x_rr_id, x_cr_id)
    print('\n\n== 64 == SRI anchor revoked ({}, {}) -> {} green level {}'.format(
        x_rr_id,
        x_cr_id,
        sri_revoc_info[(x_rr_id, x_cr_id)]['legalName'],
        sri_revoc_info[(x_rr_id, x_cr_id)]['greenLevel']))
    sleep(1)
    EPOCH_POST_SRI_REVOC = int(time())
    print('\n\n== 65 == EPOCH times re: SRI Silver revocation: pre-revoc {}, revoc {}, post-revoc {}'.format(
        EPOCH_PRE_SRI_REVOC,
        EPOCH_SRI_REVOC,
        EPOCH_POST_SRI_REVOC))

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof with revoked cred, for non-verification
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_POST_SRI_REVOC
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    (x_cred_ids, x_sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(x_proof_req_sri),
        filt_get_creds_silver,
        True)
    x_sri_creds_found = json.loads(x_sri_creds_found_json)
    x_sri_req_creds = json.loads(await pspcoban.build_req_creds_json(x_sri_creds_found))
    x_sri_proof_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_creds_found, x_sri_req_creds)
    print('\n\n== 66 == PSPC Org Book proof on cred-ids {} post Silver revocation: {}'.format(
        x_cred_ids,
        ppjson(x_sri_proof_json, 1000)))
    x_sri_proof = json.loads(x_sri_proof_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with revoked cred
    rc_json = await san.verify_proof(x_proof_req_sri, x_sri_proof)
    print('\n\n== 67 == SRI anchor verifies multi-cred proof (by filter) with Silver cred revoked as: {}'.format(
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) creates proof for revoked cred, back-dated just before revocation
    proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_PRE_SRI_REVOC
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    (cred_ids, sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(proof_req_sri),
        filt_get_creds_silver,
        True)
    sri_creds_found = json.loads(sri_creds_found_json)
    sri_req_creds = json.loads(await pspcoban.build_req_creds_json(sri_creds_found))
    sri_proof_json = await pspcoban.create_proof(proof_req_sri, sri_creds_found, sri_req_creds)
    print('\n\n== 68 == Org Book proof on cred-ids {} just before Silver cred revoc: {}'.format(
        cred_ids,
        ppjson(sri_proof_json, 1000)))
    sri_proof = json.loads(sri_proof_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with revoked cred, back-dated pre-revocation
    rc_json = await san.verify_proof(proof_req_sri, sri_proof)
    print('\n\n== 69 == SRI anchor verifies multi-cred proof (by filter) just before Silver cred revoc as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) creates proof for revoked cred, between 1st cred creation and its own
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_CRED_CREATE[S_ID['GREEN']][0] + 1
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    (x_cred_ids, x_sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(x_proof_req_sri),
        filt_get_creds_silver,
        True)
    x_sri_creds_found = json.loads(x_sri_creds_found_json)
    x_sri_req_creds = json.loads(await pspcoban.build_req_creds_json(x_sri_creds_found))
    x_sri_proof_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_creds_found, x_sri_req_creds)
    print('\n\n== 70 == Org Book proof on cred-ids {} just before Silver cred creation: {}'.format(
        x_cred_ids,
        ppjson(x_sri_proof_json, 1000)))
    x_sri_proof = json.loads(x_sri_proof_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with revoked cred
    rc_json = await san.verify_proof(x_proof_req_sri, x_sri_proof)
    print('\n\n== 71 == SRI anchor verifies multi-cred proof (by filter) just before Silver cred creation as {}'.format(
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) creates non-proof for revoked cred, between cred def and 1st cred creation
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_CRED_CREATE[S_ID['GREEN']][0] - 1
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    (x_cred_ids, x_sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(x_proof_req_sri),
        filt_get_creds_silver,
        True)
    x_sri_creds_found = json.loads(x_sri_creds_found_json)
    x_sri_req_creds = json.loads(await pspcoban.build_req_creds_json(x_sri_creds_found))
    x_sri_proof_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_creds_found, x_sri_req_creds)

    x_sri_proof_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_creds_found, x_sri_req_creds)
    print('\n\n== 72 == Org Book proof on cred-ids {} before any Green cred creation: {}'.format(
        x_cred_ids,
        ppjson(x_sri_proof_json, 1000)))
    x_sri_proof = json.loads(x_sri_proof_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with revoked cred
    rc_json = await san.verify_proof(x_proof_req_sri, x_sri_proof)
    print('\n\n== 73 == SRI anchor verifies multi-cred proof (by filter) before any Green cred creation as: {}'.format(
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) tries to create (non-)proof for revoked cred in future
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': TOMORROW
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    (x_cred_ids, x_sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(x_proof_req_sri),
        filt_get_creds_silver,
        True)
    x_sri_creds_found = json.loads(x_sri_creds_found_json)
    x_sri_req_creds = json.loads(await pspcoban.build_req_creds_json(x_sri_creds_found))
    try:
        x_sri_proof_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_creds_found, x_sri_req_creds)
        assert False
    except BadRevStateTime:
        pass

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof with specification of one by pred
    proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['SRI-1.0']]: {
            'attrs': [
                'legalName'
            ],
            'interval': EPOCH_PRE_SRI_REVOC
        },
        cd_id[S_ID['SRI-1.1']]: {
            'attrs': [
            ],
            'minima': {
                'jurisdictionId': 1
            },
            'interval': EPOCH_PRE_SRI_REVOC
        }
    }))
    (cred_ids, sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(proof_req_sri),
        {
            cd_id[S_ID['SRI-1.0']]: {
                'attr-match': {
                    'legalName': 'Tart City'
                }
            },
            cd_id[S_ID['SRI-1.1']]: {
                'minima': {
                    'jurisdictionId': 0  # 0 < 1, so get_creds() should include predicate that proof_req_sri specifies
                }
            }
        },
        False)
    sri_creds_found = json.loads(sri_creds_found_json)
    assert len(sri_creds_found['predicates'])
    sri_req_creds = json.loads(await pspcoban.build_req_creds_json(sri_creds_found))
    sri_proof_json = await pspcoban.create_proof(proof_req_sri, sri_creds_found, sri_req_creds)
    print('\n\n== 74 == PSPC Org Book multi-cred proof on cred-ids {} for Tart City on min jurisdictionId: {}'.format(
        cred_ids,
        ppjson(sri_proof_json, 1000)))
    sri_proof = json.loads(sri_proof_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with specification of one by pred
    rc_json = await san.verify_proof(proof_req_sri, sri_proof)
    print('\n\n== 75 == SRI anchor verifies multi-cred proof (by pred) as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # Exercise helper GET calls
    txn_json = await san.get_txn(schema[S_ID['GREEN']]['seqNo'])
    print('\n\n== 76 == GREEN schema by txn #{}: {}'.format(schema[S_ID['GREEN']]['seqNo'], ppjson(txn_json)))
    assert json.loads(txn_json)
    txn_json = await san.get_txn(99999)  # ought not exist
    assert not json.loads(txn_json)

    bc_box_ids = json.loads(await bcran.get_box_ids_json())
    print('\n\n== 77 == Box identifiers at BC registrar (issuer): {}'.format(ppjson(bc_box_ids)))
    assert all(box_id.startswith(bcran.did) for ids in bc_box_ids.values() for box_id in ids)
    assert len(bc_box_ids['schema_id']) > 1  # bc-reg, non-revo
    assert len(bc_box_ids['cred_def_id']) > 1  # bc-reg, non-revo
    assert len(bc_box_ids['rev_reg_id']) > 1  # bc-reg on initial short rev reg and second longer one

    # Exercise cache serialization, clearing, parsing, purging
    tstamp = Caches.archive(pspcoban.dir_cache)
    timestamps = listdir(pspcoban.dir_cache)
    assert timestamps

    Caches.clear()
    assert not len(SCHEMA_CACHE.schemata())
    assert not len(CRED_DEF_CACHE)
    assert not len(REVO_CACHE)

    Caches.parse(pspcoban.dir_cache)
    assert len(SCHEMA_CACHE.schemata())
    assert len(CRED_DEF_CACHE)
    assert len(REVO_CACHE)

    Caches.purge_archives(pspcoban.dir_cache, True)
    remaining = listdir(pspcoban.dir_cache)
    assert len(remaining) == 1 and remaining[0] == max(timestamps, key=int)

    Caches.purge_archives(pspcoban.dir_cache, False)
    remaining = listdir(pspcoban.dir_cache)
    assert len(remaining) == 0

    print('\n\n== 78 == Caches archive, parse, load, purge OK')

    await bcran.close()
    await bcoban.close()
    await pspcoban.close()
    await san.close()
    await tan.close()
    await p.close()


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_offline(pool_name, pool_genesis_txn_path, pool_genesis_txn_file, path_home):

    print('\n\n== Testing offline anchor operation ==')

    # Open PSPC Org Book anchor and create proof without opening node pool
    path = Path(path_home, 'pool', pool_name)
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True})
    pspcoban = OrgBookAnchor(
        await Wallet('PSPC-Org-Book-Anchor-00000000000', 'pspc-org-book').create(),
        p,
        {
            'parse-cache-on-open': True,
            'archive-cache-on-close': False
        })
    await pspcoban.open()
    await pspcoban.create_link_secret('SecretLink')

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof with specification of one by pred
    cd_id = {}
    schema = {}
    san = SRIAnchor(await Wallet('SRI-Anchor-000000000000000000000', 'sri').create(), p)
    async with san:
        S_ID = {
            'SRI-1.0': schema_id(san.did, 'sri', '1.0'),
            'SRI-1.1': schema_id(san.did, 'sri', '1.1'),
        }
    for s_id in S_ID.values():
        s_key = schema_key(s_id)
        schema[s_id] = json.loads(await pspcoban.get_schema(s_id))
        cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

    cd_id2spec = await pspcoban.offline_intervals([   
        cd_id[S_ID['SRI-1.0']],
        cd_id[S_ID['SRI-1.1']]
    ])
    cd_id2spec[cd_id[S_ID['SRI-1.0']]]['attrs'] = ['legalName']
    cd_id2spec[cd_id[S_ID['SRI-1.1']]]['attrs'] = []
    cd_id2spec[cd_id[S_ID['SRI-1.1']]]['minima'] = {'jurisdictionId': 1}
    proof_req_sri = json.loads(await san.build_proof_req_json(cd_id2spec))
    print('\n\n== 1 == Proof request, default interval from cache content: {}'.format(ppjson(proof_req_sri)))

    (cred_ids, sri_creds_found_json) = await pspcoban.get_creds(
        json.dumps(proof_req_sri),
        {
            cd_id[S_ID['SRI-1.0']]: {
                'attr-match': {
                    'legalName': 'Tart City'
                }
            },
            cd_id[S_ID['SRI-1.1']]: {
                'minima': {
                    'jurisdictionId': 0  # 0 < 1, so get_creds() should include predicate that proof_req_sri specifies
                }
            }
        },
        filt_dflt_incl=False)
    sri_creds_found = json.loads(sri_creds_found_json)
    assert len(sri_creds_found['predicates'])
    sri_req_creds = json.loads(await pspcoban.build_req_creds_json(sri_creds_found))
    sri_proof_json = await pspcoban.create_proof(proof_req_sri, sri_creds_found, sri_req_creds)
    print('\n\n== 2 == PSPC Org Book multi-cred proof on cred-ids {} for Tart City on min jurisdictionId: {}'.format(
        cred_ids,
        ppjson(sri_proof_json, 1000)))
    sri_proof = json.loads(sri_proof_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with specification of one by pred, offline
    san_cfg = {
        'parse-cache-on-open': True,
        'archive-on-close': json.loads(await pspcoban.get_box_ids_json())
    }
    san = SRIAnchor(await Wallet('SRI-Anchor-000000000000000000000', 'sri').create(), p, san_cfg)

    _set_tails_state(False)  # simulate not having tails file & cache
    _set_cache_state(False)
    await p.open()
    await san.open()  # open on-line, cache and archive from ledger ...
    await san.close()  # ... then close ...
    await p.close()
    san.cfg = {
        'parse-cache-on-open': True
    }
    await san.open()  # ... and open off-line

    rc_json = await san.verify_proof(proof_req_sri, sri_proof)
    print('\n\n== 3 == SRI anchor verifies multi-cred proof (by pred) off-line as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    _set_tails_state(True)  # restore state
    _set_cache_state(True)  # restore state

    await pspcoban.close()
    await san.close()

    Caches.purge_archives(pspcoban.dir_cache, False)
    Caches.purge_archives(san.dir_cache, False)
    remaining = listdir(pspcoban.dir_cache)
    assert len(remaining) == 0


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_on_nodepool_restart(pool_name, pool_genesis_txn_path, pool_genesis_txn_file, path_home):

    print('\n\n== Testing anchor survival on node pool restart ==')

    # Open pool, close and auto-remove it
    path = Path(path_home, 'pool', pool_name)
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': True})
    await p.open()
    assert p.handle is not None
    await p.close()
    assert not path.exists(), 'Pool path {} still present'.format(path)

    # Open pool, SRI + PSPC Org Book anchors (the tests above should obviate its need for trust-anchor)
    async with NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False}) as p, (
        SRIAnchor(await Wallet('SRI-Anchor-000000000000000000000', 'sri').create(), p)) as san, (
        OrgBookAnchor(
            await Wallet('PSPC-Org-Book-Anchor-00000000000', 'pspc-org-book').create(),
            p,
            {
                'parse-cache-on-open': True,
                'archive-cache-on-close': True
            })) as pspcoban:

        assert p.handle is not None

        # Get schema (should be present in schema cache)
        s_key = schema_key(schema_id(san.did, 'green', '1.0'))
        schema_json = await san.get_schema(schema_key(schema_id(*s_key)))  # should exist
        schema = json.loads(schema_json)
        assert schema

        # Get cred def (should re-use existing), create cred offer
        await san.send_cred_def(schema_id(*s_key))
        cd_id = cred_def_id(s_key.origin_did, schema['seqNo'])
        assert ([f for f in Tails.links(str(san._dir_tails), san.did)
            if cd_id in f] and not Tails.unlinked(str(san._dir_tails)))

        cred_def_json = await pspcoban.get_cred_def(cred_def_id(san.did, schema['seqNo']))
        cred_def = json.loads(cred_def_json)
        print('\n\n== 1.0 == Cred def [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(json.loads(cred_def_json))))
        assert json.loads(cred_def_json)['schemaId'] == str(schema['seqNo'])

        cred_offer_json = await san.create_cred_offer(schema['seqNo'])
        print('\n\n== 1.1 == Cred offer [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(cred_offer_json)))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_revo_cache_reg_update_maintenance(pool_name, pool_genesis_txn_path, pool_genesis_txn_file):

    print('\n\n== Testing anchor revocation cache reg update maintenance ==')

    async with NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False}) as p, (
        OrgBookAnchor(
            await Wallet(
                'PSPC-Org-Book-Anchor-00000000000',
                'pspc-org-book').create(),
            p)) as pspcoban, (
        SRIAnchor(
            await Wallet(
                'SRI-Anchor-000000000000000000000',
                'sri-0').create(),
            p)) as san:

        nyms = {
            'pspcoban': json.loads(await san.get_nym(pspcoban.did)),
            'san': json.loads(await san.get_nym(san.did))
        }
        print('\n\n== 1 == nyms: {}'.format(ppjson(nyms)))

        # SRI anchor sends schema for revocation cache registry delta exercise
        schema_data = {
            'name': 'revo',
            'version': '{}.0'.format(int(time())),  # ensure it's not already on ledger nor in wallet
            'attr_names': [
                'id',
                'favourite_number'
            ]
        }

        s_id = schema_id(san.did, schema_data['name'], schema_data['version'])
        s_key = schema_key(s_id)
        try:
            await san.send_schema(json.dumps(schema_data))
        except Exception as x:
            print(x)
            assert False
        schema_json = await san.get_schema(s_key)
        assert json.loads(schema_json)  # should exist now
        schema = json.loads(schema_json)
        seq_no = schema['seqNo']
        print('\n\n== 2 == SCHEMA for revocation cache exercise [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(schema)))

        # SRI anchor creates credential definition on revocation registry large enough to clean
        RR_SIZE = 128
        await san.send_cred_def(s_id, True, RR_SIZE)
        cd_id = cred_def_id(s_key.origin_did, seq_no)
        rr_id = Tails.current_rev_reg_id(san._dir_tails, cd_id)

        assert [f for f in Tails.links(str(san._dir_tails), san.did)
            if cd_id in f] and not Tails.unlinked(str(san._dir_tails))

        cred_def_json = await pspcoban.get_cred_def(cd_id)  # ought to exist now
        cred_def = json.loads(cred_def_json)
        print('\n\n== 3.0 == Cred def [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(json.loads(cred_def_json))))
        assert cred_def.get('schemaId', None) == str(seq_no)

        cred_offer_json = await san.create_cred_offer(seq_no)
        cred_offer = json.loads(cred_offer_json)
        print('\n\n== 3.1 == Credential offer [{} v{}]: {}'.format(s_key.name, s_key.version, ppjson(cred_offer_json)))

        # Set up cred req at PSPC Org Book anchor
        await pspcoban.create_link_secret('SecretLink')
        (cred_req_json, cred_req_metadata_json) = await pspcoban.create_cred_req(cred_offer_json, cred_def['id'])
        cred_req = json.loads(cred_req_json)
        print('\n\n== 4 == Credential request [{} v{}]: metadata {}, cred {}'.format(
            s_key.name,
            s_key.version,
            ppjson(cred_req_metadata_json),
            ppjson(cred_req_json)))
        assert json.loads(cred_req_json)

        print('\n\n== 5 == Creating {} credentials'.format(RR_SIZE))
        creation2cred_json = {}  # map creation epoch to cred
        creation2cred_data = {}
        now = int(time())
        for i in range(RR_SIZE):
            while int(time()) == now:
                sleep(0.1)
            now = int(time())
            print('.', end='' if (i + 1) % 10 else '{}\n'.format(i + 1), flush=True)
            now = int(time())
            cred_data = {
                'id': i,
                'favourite_number': now
            }
            (cred_json, cred_revoc_id, epoch_creation) = await san.create_cred(
                cred_offer_json,
                cred_req_json,
                cred_data)
            creation2cred_json[epoch_creation] = cred_json
            creation2cred_data[epoch_creation] = cred_data
            assert json.loads(cred_json)
            cred = json.loads(cred_json)

            cred_id = await pspcoban.store_cred(cred_json, cred_req_metadata_json)

        assert len(REVO_CACHE[rr_id].rr_delta_frames) == 0  # no queries on it yet

        # PSPC Org Book anchor finds each cred and creates a proof, SRI anchor verifies; each touches revo cache frames
        print('\n\n== 6 == Creating and verifying {} proofs'.format(RR_SIZE))
        cache_frames_size = {}
        i = 0
        for creation_epoch in creation2cred_data:
            filt_get_creds = {
                cd_id: {'attr-match': creation2cred_data[creation_epoch]}
            }

            proof_req = json.loads(await san.build_proof_req_json({
                cd_id: {
                    'interval': creation_epoch
                }
            }))
            (cred_ids_filt, creds_found_filt_json) = await pspcoban.get_creds(json.dumps(proof_req), filt_get_creds)
            creds_found_filt = json.loads(creds_found_filt_json)
            assert len(cred_ids_filt) == 1

            req_creds = json.loads(await pspcoban.build_req_creds_json(creds_found_filt))
            proof_json = await pspcoban.create_proof(proof_req, creds_found_filt, req_creds)
            assert await san.verify_proof(proof_req, json.loads(proof_json))

            cache_frames_size[creation_epoch] = (
                len(REVO_CACHE[rr_id].rr_delta_frames),
                len(REVO_CACHE[rr_id].rr_state_frames))
            print('  .. 6.{}: after proof for {}, {} revo cache reg (delta, state) frames'.format(
                i,
                creation_epoch,
                cache_frames_size[creation_epoch]))
            i += 1

        MARK = 4096**0.5  # replicated from cache heuristic: if cache code changes, this test has to change with it
        assert int(MARK * 0.75) <= len(REVO_CACHE[rr_id].rr_delta_frames) <= int(MARK * 1.25)
        assert int(MARK * 0.75) <= len(REVO_CACHE[rr_id].rr_state_frames) <= int(MARK * 1.25)

        print('\n\n== 7 == Revocation cache {} reg delta frames cleaned, now ({}, {}) (delta, state) frames'.format(
            rr_id,
            len(REVO_CACHE[rr_id].rr_delta_frames),
            len(REVO_CACHE[rr_id].rr_state_frames)))


def do(coro):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _get_cacheable(anchor, schema_key, seq_no, issuer_did):
    discriminant = hash(current_thread()) % 4
    if discriminant == 0:
        result = do(anchor.get_schema(seq_no))
        print('.. Thread {} got schema {} v{} by seq #{}'.format(
            current_thread().name,
            schema_key.name,
            schema_key.version,
            seq_no))
    elif discriminant == 1:
        result = do(anchor.get_schema(schema_key))
        print('.. Thread {} got schema {} v{} by key'.format(
            current_thread().name,
            schema_key.name,
            schema_key.version))
    elif discriminant == 2:
        cd_id = cred_def_id(issuer_did, seq_no)
        result = do(anchor.get_cred_def(cd_id))
        print('.. Thread {} got cred def {}'.format(current_thread().name, cd_id))
    else:
        rr_id = rev_reg_id(cred_def_id(issuer_did, seq_no), '0')
        result = do(anchor._get_rev_reg_def(rr_id))
        print('.. Thread {} got rev reg def {}'.format(current_thread().name, rr_id))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_cache_locking(pool_name, pool_genesis_txn_path, pool_genesis_txn_file):
    THREADS = 256
    threads = []

    print('\n\n== Testing anchor cache locking ==')

    async with NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False}) as p, (
        OrgBookAnchor(
            await Wallet(
                'PSPC-Org-Book-Anchor-00000000000',
                'pspc-org-book',
                None,
                {'auto-remove': True}).create(),
            p)) as pspcoban, (
        SRIAnchor(
            await Wallet(
                'SRI-Anchor-000000000000000000000',
                'sri-0',
                None,
                {'auto-remove': True}).create(),
            p)) as san0, (
        SRIAnchor(
            await Wallet(
                'SRI-Anchor-111111111111111111111',
                'sri-1',
                None,
                {'auto-remove': True}).create(),
            p)) as san1, (
        SRIAnchor(
            await Wallet(
                'SRI-Anchor-222222222222222222222',
                'sri-2',
                None,
                {'auto-remove': True}).create(),
            p)) as san2:

        sri_did = san0.did
        schema_key2seq_no = {
            schema_key(schema_id(sri_did, 'sri', '1.0')): 0,
            schema_key(schema_id(sri_did, 'sri', '1.1')): 0,
            schema_key(schema_id(sri_did, 'green', '1.0')): 0,
        }

        for s_key in schema_key2seq_no:
            schema_json = await san0.get_schema(s_key)  # should exist from prior test
            seq_no = json.loads(schema_json)['seqNo']
            schema_key2seq_no[s_key] = seq_no
            assert isinstance(seq_no, int) and seq_no > 0

        # SRI Anchors exercise cache locks
        sri_anchors = [san0, san1, san2]

        epoch_start = time()
        modulus = len(schema_key2seq_no)

        for t in range(THREADS):
            s_key = choice(list(schema_key2seq_no.keys()))
            threads.append(Thread(
                name='#{}'.format(t),
                target=_get_cacheable,
                args=(
                    sri_anchors[t % modulus],
                    s_key,
                    schema_key2seq_no[s_key],
                    sri_did)))

        shuffle(threads)
        for thread in threads:
            # print('Starting thread {}'.format(threads.index(thread)))
            thread.start()
        for thread in threads:
            thread.join()
        elapsed = ceil(int(time()) - epoch_start)

        print('\n\n== 1 == Exercised cache locks, elapsed time: {} sec'.format(elapsed))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_cache_only(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print('\n\n== Testing proof/verification from cache only ==')

    _set_cache_state(False)

    # Open pool, init anchors
    p = NodePool(pool_name, pool_genesis_txn_path, {'auto-remove': False})

    san = SRIAnchor(await Wallet('SRI-Anchor-000000000000000000000', 'sri').create(), p)
    pspcoban = OrgBookAnchor(
        await Wallet('PSPC-Org-Book-Anchor-00000000000', 'pspc-org-book').create(),
        p,
        {
            'parse-cache-on-open': True,
            'archive-cache-on-close': True
        })

    await p.open()
    assert p.handle

    await san.open()
    await pspcoban.open()
    await pspcoban.create_link_secret('SecretLink')
    await pspcoban.reset_wallet()

    # Publish schema to ledger if not yet present; get from ledger
    ''' 3
        'IDENT': schema_id(san.did, 'ident', '1.0'),  # non-revocable
        'FAV-NUM': schema_id(san.did, 'fav-num', '1.0'),
        'FAV-CHAR': schema_id(san.did, 'fav-char', '1.0')
    '''
    S_ID = {
        'IDENT': schema_id(san.did, 'ident', '1.0'),  # non-revocable
        'FAV-NUM': schema_id(san.did, 'fav-num', '1.0'),
        'FAV-CHAR': schema_id(san.did, 'fav-char', '1.0')
    }

    ''' 24
        S_ID['IDENT']: {
            'name': schema_key(S_ID['IDENT']).name,
            'version': schema_key(S_ID['IDENT']).version,
            'attr_names': [
                'ident',
                'regEpoch'
            ]
        },
        S_ID['FAV-NUM']: {
            'name': schema_key(S_ID['FAV-NUM']).name,
            'version': schema_key(S_ID['FAV-NUM']).version,
            'attr_names': [
                'ident',
                'num'
            ]
        },
        S_ID['FAV-CHAR']: {
            'name': schema_key(S_ID['FAV-CHAR']).name,
            'version': schema_key(S_ID['FAV-CHAR']).version,
            'attr_names': [
                'ident',
                'char'
            ]
        }
    '''
    schema_data = {
        S_ID['IDENT']: {
            'name': schema_key(S_ID['IDENT']).name,
            'version': schema_key(S_ID['IDENT']).version,
            'attr_names': [
                'ident',
                'regEpoch'
            ]
        },
        S_ID['FAV-NUM']: {
            'name': schema_key(S_ID['FAV-NUM']).name,
            'version': schema_key(S_ID['FAV-NUM']).version,
            'attr_names': [
                'ident',
                'num'
            ]
        },
        S_ID['FAV-CHAR']: {
            'name': schema_key(S_ID['FAV-CHAR']).name,
            'version': schema_key(S_ID['FAV-CHAR']).version,
            'attr_names': [
                'ident',
                'char'
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
    cred_req_json = {}
    cred_req = {}
    cred_req_metadata_json = {}

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        try:
            swab_json = await san.get_schema(s_key)  # may exist
        except AbsentSchema:
            await san.send_schema(json.dumps(schema_data[s_id]))
        schema_json[s_id] = await san.get_schema(s_key)
        schema[s_id] = json.loads(schema_json[s_id])
        assert schema[s_id]  # should exist now

        seq_no2schema_id[schema[s_id]['seqNo']] = s_id
        seq_no2schema[schema[s_id]['seqNo']] = schema[s_id]
        print('\n\n== 1.{} == SCHEMA [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
        assert schema[s_id]
        i += 1

    RR_SIZE = 4
    RR_PER_CD = 6
    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)

        await san.send_cred_def(s_id, s_id != S_ID['IDENT'], RR_SIZE)  # make rev regs tiny: want many rev regs in cache
        cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

        assert (s_id == S_ID['IDENT']) or (
            [f for f in Tails.links(str(san._dir_tails), san.did)
                if cd_id[s_id] in f] and not Tails.unlinked(str(san._dir_tails)))

        cred_def_json[s_id] = await pspcoban.get_cred_def(cd_id[s_id])  # ought to exist now
        cred_def[s_id] = json.loads(cred_def_json[s_id])
        print('\n\n== 2.{}.0 == Cred def [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(json.loads(cred_def_json[s_id]))))
        assert cred_def[s_id].get('schemaId', None) == str(schema[s_id]['seqNo'])

        cred_offer_json[s_id] = await san.create_cred_offer(schema[s_id]['seqNo'])
        cred_offer[s_id] = json.loads(cred_offer_json[s_id])
        print('\n\n== 2.{}.1 == Credential offer [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(cred_offer_json[s_id])))
        i += 1

    try:  # exercise non-buildability of cache-only proof req when there is no cache data
        cd_id2spec = await pspcoban.offline_intervals([   
            cd_id[s_id] for s_id in cd_id
        ])
        print('\n\n** cd_id2spec {}'.format(ppjson(cd_id2spec)))
        assert False
    except CacheIndex:
        pass

    # Setup link secrets, cred reqs at HolderProver anchors
    await pspcoban.create_link_secret('SecretLink')

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await pspcoban.create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id])
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 3.{} == Credential request [{} v{}]: metadata {}, cred {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(cred_req_metadata_json[s_id]),
            ppjson(cred_req_json[s_id])))
        assert json.loads(cred_req_json[s_id])
        i += 1

    # SRI anchor creates credentials each with distinct timestamp and over several rev regs per cred def
    print('\n\n== 4 == Creating {} credentials on {} rev regs for {} cred defs ({} revocable)'.format(
        len(cred_def) * RR_PER_CD * RR_SIZE,
        (len(cred_def) - 1) * RR_PER_CD,  # cred def on BIRTH does not support revocation
        len(cred_def),
        len(cred_def) - 1))
    cd_id2creation2cred_json = {cd_id[s_id]: {} for s_id in cd_id}  # map cd_id to creation epoch to cred
    cd_id2creation2cred_data = {cd_id[s_id]: {} for s_id in cd_id}
    now = int(time())
    for i in range(len(cd_id) * RR_PER_CD * RR_SIZE):
        while int(time()) == now:
            sleep(0.1)
        now = int(time())
        print('.', end='' if (i + 1) % 10 else '{}\n'.format(i + 1), flush=True)

        s_id = [S_ID['IDENT'], S_ID['FAV-NUM'], S_ID['FAV-CHAR']][i % len(cd_id)]
        cred_data = [
            {
                'ident': i//3,
                'regEpoch': now
            },
            {
                'ident': i//3,
                'num': randint(0, 100)
            },
            {
                'ident': i//3,
                'char': choice(printable)
            }
        ][i % len(cd_id)]
        (cred_json, cred_revoc_id, epoch_creation) = await san.create_cred(
            cred_offer_json[s_id],
            cred_req_json[s_id],
            cred_data,
            RR_SIZE)
        cd_id2creation2cred_json[cd_id[s_id]][epoch_creation] = cred_json
        cd_id2creation2cred_data[cd_id[s_id]][epoch_creation] = cred_data
        assert json.loads(cred_json)

        cred_id = await pspcoban.store_cred(cred_json, cred_req_metadata_json[s_id])

    await pspcoban.load_cache(False)
    san_cfg = {
        'parse-cache-on-open': True,
        'archive-on-close': json.loads(await pspcoban.get_box_ids_json())
    }
    san.cfg = san_cfg
    await san.load_cache(False)
    await p.close()  # The pool is now closed - from here on in, we are off-line

    cd_id2spec = await pspcoban.offline_intervals([
        cd_id[s_id] for s_id in cd_id
    ])
    for c in cd_id2spec:
        cd_id2spec[c]['attrs'] = schema_data[seq_no2schema_id[cred_def_id2seq_no(c)]]['attr_names']
    proof_req_json = await san.build_proof_req_json(cd_id2spec)
    proof_req = json.loads(proof_req_json)
    print('\n\n== 5 == Proof req from cache data: {}'.format(ppjson(proof_req_json)))

    (cred_ids, creds_found_json) = await pspcoban.get_creds(proof_req_json)
    creds_found = json.loads(creds_found_json)
    display_filt = creds_display(
        creds_found,
        {
            cd_id[s_id]: {
                'ident': 0
            } for s_id in cd_id
        })
    print('\n\n== 6 == Creds display, filtered post hoc matching ident=0: {}'.format(ppjson(display_filt)))
    creds_pruned = json.loads(prune_creds_json(creds_found, {k for k in display_filt}))
    print('\n\n== 7 == Creds, pruned: {}'.format(ppjson(creds_pruned)))
    req_creds = json.loads(await pspcoban.build_req_creds_json(creds_pruned))
    print('\n\n== 8 == Requested credentials: {}'.format(ppjson(req_creds)))
    proof_json = await pspcoban.create_proof(proof_req, creds_pruned, req_creds)
    print('\n\n== 9 == PSPC Org Book proof: {}'.format(ppjson(proof_json, 1000)))
    proof = json.loads(proof_json)

    rc_json = await san.verify_proof(proof_req, proof)
    print('\n\n== 10 == SRI anchor verifies multi-cred proof off-line as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    await san.close()
    await pspcoban.close()

    _set_cache_state(True)
    Caches.purge_archives(pspcoban.dir_cache, False)
