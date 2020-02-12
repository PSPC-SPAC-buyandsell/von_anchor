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
import datetime
import json
import logging

from atexit import register
from copy import deepcopy
from math import ceil
from os import listdir, makedirs, readlink, unlink
from os.path import basename, dirname, expanduser, isdir, isfile, join
from pathlib import Path
from string import printable
from random import choice, randint, shuffle
from shutil import copyfile, move, rmtree
from threading import current_thread, Thread
from time import sleep, time
from sys import float_info

import pytest

from indy import anoncreds, did

from von_anchor import (
    RegistrarAnchor,
    HolderProver,
    OrgBookAnchor,
    OrgHubAnchor,
    RevRegBuilder,
    ProctorAnchor,
    NominalAnchor,
    TrusteeAnchor,
    Verifier)
from von_anchor.a2a import DIDDoc, PublicKey
from von_anchor.cache import ArchivableCaches, CRED_DEF_CACHE, REVO_CACHE, SCHEMA_CACHE, RevoCacheEntry
from von_anchor.canon import canon
from von_anchor.error import (
    AbsentCred,
    AbsentCredDef,
    AbsentInterval,
    AbsentLinkSecret,
    AbsentNym,
    AbsentPool,
    AbsentRecord,
    AbsentRevReg,
    AbsentSchema,
    AbsentTails,
    AbsentWallet,
    BadAttribute,
    BadIdentifier,
    BadKey,
    BadLedgerTxn,
    BadRevocation,
    BadRevStateTime,
    BadWalletQuery,
    CacheIndex,
    ClosedPool,
    CorruptWallet,
    CredentialFocus,
    ExtantWallet,
    JSONValidation,
    WalletState)
from von_anchor.frill import Ink, ppjson
from von_anchor.indytween import encode, raw, Restriction, Role
from von_anchor.nodepool import NodePool, NodePoolManager
from von_anchor.tails import Tails
from von_anchor.util import (
    box_ids,
    cred_def_id,
    cred_def_id2schema_seq_no_or_id,
    creds_display,
    proof_req2wql_all,
    proof_req_attr_referents,
    proof_req_briefs2req_creds,
    proof_req_infos2briefs,
    revealed_attrs,
    revoc_info,
    rev_reg_id,
    schema_id,
    schema_key)
from von_anchor.wallet import DIDInfo, EndpointInfo, Wallet, WalletManager


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


async def get_wallets(wallet_data, open_all, auto_remove=False):
    rv = {}
    w_mgr = WalletManager()
    for name in wallet_data:
        w = None
        creation_data = {'seed', 'did'} & {n for n in wallet_data[name]}  # create for tests when seed or did specifies
        if creation_data:
            config = {
                'id': name,
                **{k: wallet_data[name][k] for k in creation_data},
                'auto_remove': auto_remove
            }
            if 'link_secret_label' in wallet_data[name]:
                config['link_secret_label'] = wallet_data[name]['link_secret_label']
            try:
                w = await w_mgr.create(config, replace=False)
                assert w.did
                assert w.verkey
            except ExtantWallet:
                w = w_mgr.get({'id': name, 'auto_remove': auto_remove})
        else:
            w = w_mgr.get({'id': name, 'auto_remove': auto_remove})
        if open_all:
            await w.open()
            assert w.did
            assert w.verkey
        rv[name] = w
    return rv


def do(coro):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _stop_rrbx(wallet_name):
    asyncio.new_event_loop().run_until_complete(RevRegBuilder.stop(wallet_name))
    # do(RevRegBuilder.stop(wallet_name))


def _get_cacheable(anchor, s_key, seq_no, issuer_did):
    discriminant = hash(current_thread()) % 4
    if discriminant == 0:
        do(anchor.get_schema(seq_no))
        print('.. Thread {} got schema {} v{} by seq #{}'.format(
            current_thread().name,
            s_key.name,
            s_key.version,
            seq_no))
    elif discriminant == 1:
        do(anchor.get_schema(s_key))
        print('.. Thread {} got schema {} v{} by key'.format(
            current_thread().name,
            s_key.name,
            s_key.version))
    elif discriminant == 2:
        cd_id = cred_def_id(issuer_did, seq_no)
        do(anchor.get_cred_def(cd_id))
        print('.. Thread {} got cred def {}'.format(current_thread().name, cd_id))
    else:
        rr_id = rev_reg_id(cred_def_id(issuer_did, seq_no), '0')
        do(anchor.get_rev_reg_def(rr_id))
        print('.. Thread {} got rev reg def {}'.format(current_thread().name, rr_id))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_api(
        pool_ip,
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing API vs. IP {} =='.format(pool_ip)))

    EPOCH_START = 1234567890  # guaranteed to be before any revocation registry creation

    # Set up node pool ledger config and wallets, open pool, init anchors
    p_mgr = NodePoolManager()
    w_mgr = WalletManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)
    p = p_mgr.get(pool_name)

    try:  # exercise creation on nonexistent wallet, OK to open later
        ProctorAnchor(w_mgr.get({'id': 'xxx', 'auto_remove': True}), p, rrbx=False)
    except AbsentWallet:
        assert False

    seeds = {
        'trustee-anchor': seed_trustee1,
        'sri': 'SRI-Anchor-000000000000000000000',
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000',
        'bc-org-hub': 'BC-Org-Book-Anchor-0000000000000',
        'bc-registrar': 'BC-Registrar-Anchor-000000000000',
        'x-anchor': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    }

    try:  # before opening wallet for the first time, creating a public DID ...
        wallet_x = (await get_wallets({'x-anchor': seeds['x-anchor']}, open_all=False))['x-anchor']
        xan = NominalAnchor(wallet_x)
        await xan.get_nym()  # ... exercise error path; never been opened hence no public DID
        assert False
    except WalletState:
        pass

    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=True)

    try:  # exercise some anchor methods with absent pool
        async with NominalAnchor(wallets['x-anchor']) as xan:
            assert str(xan) == 'NominalAnchor(x-anchor)'  # exercise str for coverage
            await xan.get_nym()  # exercise error path failing to get nym from absent pool
        assert False
    except AbsentPool:
        pass
    try:  # exercise error path: cannot send cred def to absent pool
        async with ProctorAnchor(wallets['x-anchor']) as xan:
            await xan.send_cred_def(schema_id(xan.did, 'name', '1.0'))
        assert False
    except AbsentPool:
        pass
    try:  # exercise error path: cannot create cred offer without pool (as protocol, hence cred def id format, unknown)
        async with ProctorAnchor(wallets['x-anchor']) as xan:
            await xan.create_cred_offer(99999)
        assert False
    except AbsentPool:
        pass
    await wallets['x-anchor'].close()
    await wallets['x-anchor'].remove()
    wallets.pop('x-anchor')

    async with p:  # exercise some anchor methods with wallet in all states
        xwallet = w_mgr.get({'id': 'xxx', 'auto_remove': True})
        await xwallet.remove()  # could still be there from prior abend; silently fails if not present
        xan = ProctorAnchor(xwallet, p)
        try:
            await xan.get_nym()  # wallet never opened: no public DID
            assert False
        except WalletState:
            pass
        try:
            await xan.send_cred_def(schema_id(wallets['sri'].did, 'name', '1.0'))  # wallet closed
            assert False
        except WalletState:
            pass
        try:
            await xan.create_cred_offer(99999)  # wallet closed
            assert False
        except WalletState:
            pass
        try:
            await xan.create_cred(None, None, None)  # wallet closed
            assert False
        except WalletState:
            pass
        try:
            await xan.revoke_cred(None, None)  # wallet closed
            assert False
        except WalletState:
            pass
        try:
            xwallet = await w_mgr.create({'id': xwallet.name, 'seed': '{}0000000000000000000000'.format(int(time()))})
            xan = NominalAnchor(xwallet, p)
            await xan.get_nym()
            await xwallet.open()
            await xan.get_nym()
            await xwallet.close()
            await xan.get_nym()
        except WalletState:
            assert False

    tan = TrusteeAnchor(wallets['trustee-anchor'], p)
    san = ProctorAnchor(wallets['sri'], p, rrbx=False)
    pspcoban = OrgBookAnchor(
        wallets['pspc-org-book'],
        p,
        config={
            'parse-caches-on-open': True,
            'archive-holder-prover-caches-on-close': True
        })
    bcohan = OrgHubAnchor(
        wallets['bc-org-hub'],
        p,
        config={
            'parse-caches-on-open': True,
            'archive-holder-prover-caches-on-close': True,
            'archive-verifier-caches-on-close': {
                'schema_id': [  # only schema identifiers are known on close at this point
                    schema_id(san.did, 'sri', '1.0'),
                    schema_id(san.did, 'sri', '1.1'),
                    schema_id(san.did, 'green', '1.0')
                ]
            }
        },
        rrbx=False)
    bcran = RegistrarAnchor(wallets['bc-registrar'], p, rrbx=False)

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
    await bcohan.open()
    await bcran.open()

    # print('TAN DID {}'.format(tan.did))            # V4SG...
    # print('SAN DID {}'.format(san.did))            # WgWx...
    # print('PSPCOBAN DID {}'.format(pspcoban.did))  # CwM7...
    # print('BCOHAN DID {}'.format(bcohan.did))      # Rhd3...
    # print('BCRAN DID {}'.format(bcran.did))        # Ljgp...

    # Publish anchor particulars to ledger if not yet present
    did2an = {}
    for an in (tan, san, pspcoban, bcohan, bcran):
        did2an[an.did] = an
        if not json.loads(await tan.get_nym(an.did)):
            await tan.send_nym(an.did, an.verkey, an.wallet.name, an.least_role())

    try:
        await tan.send_nym('not-a-DID')  # exercise error path
        assert False
    except BadIdentifier:
        pass

    assert json.loads(await tan.get_nym()) == json.loads(await tan.get_nym())  # check default param
    nyms = {
        'tan': json.loads(await tan.get_nym()),
        'san': json.loads(await tan.get_nym(san.did)),
        'pspcoban': json.loads(await tan.get_nym(pspcoban.did)),
        'bcohan': json.loads(await tan.get_nym(bcohan.did)),
        'bcran': json.loads(await tan.get_nym(bcran.did))
    }
    print('\n\n== 1 == Nyms on ledger: {}'.format(ppjson(nyms)))

    for k in nyms:
        assert 'dest' in nyms[k]

    # Publish schema to ledger if not yet present; get from ledger
    S_ID = {
        'BC': schema_id(bcran.did, 'bc-reg', '1.0'),
        'NON-REVO': schema_id(bcran.did, 'non-revo', '{}.0'.format(int(time()))),  # new version: bcohan resets wallet
        'SRI-1.0': schema_id(san.did, 'sri', '1.0'),
        'SRI-1.1': schema_id(san.did, 'sri', '1.1'),
        'GREEN': schema_id(san.did, 'green', '1.0'),
    }

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
                'Preferred Name',
                'Must Have'
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
        bcran.did: bcohan,
        san.did: pspcoban
    }

    try:
        await tan.get_schema(schema_key(schema_id(tan.did, 'Xxxx', 'X.x')))  # Bad version number
        assert False
    except BadLedgerTxn:
        pass

    try:
        x_schema_data = {  # exercise bad attribute check
            'name': 'bad-schema',
            'version': '0.0',
            'attr_names': [
                'ok',
                'no%good'
            ]
        }
        await bcran.send_schema(json.dumps(x_schema_data))
        assert False
    except BadAttribute:
        pass

    i = 0
    seq_no = None
    for s_id in schema_data:
        s_key = schema_key(s_id)
        try:
            await bcran.get_schema(s_key)  # may exist
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
        print('\n\n== 2.{} == Schema [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
        assert schema[s_id]
        i += 1

    try:  # check idempotence
        await did2an[schema_key(S_ID['BC']).origin_did].send_schema(json.dumps(schema_data[S_ID['BC']]))

        _set_cache_state(False)
        s = json.loads(await tan.get_schema(seq_no))  # exercise get_schema() by seq num if not cached
        assert s['seqNo'] == seq_no
    except Exception as x:
        assert False, x
    finally:
        _set_cache_state(True)

    # Setup link secret for creation of cred req or proof
    await bcohan.create_link_secret('LinkSecret')
    await pspcoban.create_link_secret('SecretLink')

    for an in (bcohan, pspcoban):
        wallet_id = id(an.wallet)
        wallet_name = an.wallet.name
        await an.reset_wallet(seeds[wallet_name])
        assert id(an.wallet) != wallet_id
        assert an.wallet.name == wallet_name
        wallets[wallet_name] = an.wallet

    # BC Registrar and SRI anchors (Issuers) create, store, publish cred definitions to ledger; create cred offers
    try:
        await bcohan.get_cred_def(cred_def_id(bcran.did, 99999))  # ought not exist
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
            [f for f in Tails.links(str(an.dir_tails), an.did)
                if cd_id[s_id] in f] and not Tails.unlinked(str(an.dir_tails)))

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

    # Build proof request
    try:  # exercise error path: bad cred def id
        await san.build_proof_req_json({
            'not-a-cdid': {
                'attrs': schema_data[seq_no2schema_id[cred_def_id2schema_seq_no_or_id(cd_id[s_id])]]['attr_names'][0:2]
            } for s_id in schema_data
        })
        assert False
    except BadIdentifier:
        pass

    x_proof_req = json.loads(await san.build_proof_req_json({  # exercise shady path: discard non-int predicate
        cd_id[S_ID['BC']]: {
            'attrs': ['busId'],
            '>=': {
                'orgTypeId': 2.5
            }
        } for s_id in schema_data
    }))
    assert {'busId'} == {x_proof_req['requested_attributes'][k]['name'] for k in x_proof_req['requested_attributes']}
    assert not x_proof_req['requested_predicates']

    big_proof_req_json = await san.build_proof_req_json({
        cd_id[s_id]: {
            'attrs': schema_data[seq_no2schema_id[cred_def_id2schema_seq_no_or_id(cd_id[s_id])]]['attr_names'][0:2]
        } for s_id in schema_data
    })
    print('\n\n== 4 == Built big sample proof request: {}'.format(ppjson(big_proof_req_json)))
    assert sum(
        [len(reqa.get('names', [''])) for reqa in json.loads(big_proof_req_json)['requested_attributes'].values()]
    ) == 2 * len(schema_data)

    small_proof_req_json = await san.build_proof_req_json({
        cd_id[s_id]: {
            'attrs': schema_data[seq_no2schema_id[cred_def_id2schema_seq_no_or_id(cd_id[s_id])]]['attr_names'][0:1]
        } for s_id in schema_data
    })
    print('\n\n== 5 == Built sample proof request, 1 attr per cred def id: {}'.format(ppjson(small_proof_req_json)))
    assert sum(  # count 1 for each req-attr without 'names' list: it has 'name' scalar value
        [len(reqa.get('names', [''])) for reqa in json.loads(small_proof_req_json)['requested_attributes'].values()]
    ) == len(schema_data)

    try:  # exercise error case for coverage: bad cred def id
        await pspcoban.create_cred_req(cred_offer_json[s_id], 'not-a-cdid')
        assert False
    except BadIdentifier:
        pass

    await pspcoban.wallet.close()
    try:  # exercise error case for coverage: closed wallet
        await pspcoban.create_cred_req(cred_offer_json[s_id], cd_id[S_ID['BC']])
        assert False
    except WalletState:
        pass
    finally:
        await pspcoban.wallet.open()

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await holder_prover[s_key.origin_did].create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id])
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 6.{} == Credential request [{} v{}]: metadata {}, cred req {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(cred_req_metadata_json[s_id]),
            ppjson(cred_req_json[s_id])))
        assert json.loads(cred_req_json[s_id])
        i += 1

    # BC Reg anchor (as Issuer) issues creds and stores at HolderProver: get cred req, create cred, store cred
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
                'Preferred Name': 'J.R. "Bob" Dobbs',
                'Must Have': 'slack'
            },
            {
                'Preferred Name': 'Chicken Hawk',
                'Must Have': 'chicken'
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
            (cred_json[s_id], cred_revoc_id) = await did2an[origin_did].create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                c)
            epoch_creation = int(time())
            EPOCH_CRED_CREATE[s_id].append(epoch_creation)
            if s_id != S_ID['NON-REVO']:
                sleep(2)  # put an interior second between each cred creation
            assert json.loads(cred_json[s_id])
            print('\n\n== 7.{}.0 == BCReg created cred (revoc id {}) at epoch {}: {}'.format(
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
                not Tails.unlinked(DIR_TAILS))  # storage should get rev reg def from ledger and link its id

            if s_id != S_ID['NON-REVO']:
                _set_tails_state(True)
                _set_cache_state(True)
            print('\n\n== 7.{}.1 == BC cred id in wallet {}: {}'.format(
                i,
                holder_prover[origin_did].wallet.name,
                cred_id))
            i += 1

    # Exercise rev reg sync on existing tails files for coverage
    await bcran.send_cred_def(S_ID['BC'], True)

    # Exercise error paths for bad input on holder-prover credential storage
    x_cred = json.loads(cred_json[S_ID['BC']])
    x_cred['rev_reg_id'] = 'not-a-rrid'
    try:  # exercise error path: bad rev reg id on holder-prover sync-revoc-for-proof
        await bcohan.store_cred(
            json.dumps(x_cred),
            cred_req_metadata_json[S_ID['BC']])
        assert False
    except BadIdentifier:
        pass

    x_cred = json.loads(cred_json[S_ID['BC']])
    x_cred['cred_def_id'] = cred_def_id(bcran.did, cred_def_id2schema_seq_no_or_id(x_cred['cred_def_id']) + 100)
    try:  # exercise error path: cred def id not present
        await bcohan.store_cred(
            json.dumps(x_cred),
            cred_req_metadata_json[S_ID['BC']])
        assert False
    except AbsentCredDef:
        pass

    x_cred['rev_reg_id'] = rev_reg_id(x_cred['cred_def_id'], 0)
    x_cred['cred_def_id'] = json.loads(cred_json[S_ID['BC']])['cred_def_id']
    try:  # exercise error path: rev reg id built (as formalism) on absent cred def id
        await bcohan.store_cred(
            json.dumps(x_cred),
            cred_req_metadata_json[S_ID['BC']])
        assert False
    except AbsentCredDef:
        pass

    await bcohan.wallet.close()
    try:  # exercise error path: closed wallet
        await bcohan.store_cred(
            cred_json[S_ID['BC']],
            cred_req_metadata_json[S_ID['BC']])
        assert False
    except WalletState:
        pass
    finally:
        await bcohan.wallet.open()
    print('\n\n== 8 == BC Org Hub anchor sync-revoc-for-proof fails as expected for typical error paths')

    # BC Org Book anchor (as HolderProver) exercises finding cred-infos by query, WQL canonicalization
    bc_infos_wql_json = await bcohan.get_cred_infos_by_q(json.dumps({
        '$not': {
            'schema_id': ''
        }
    }))
    bc_all_card = len(json.loads(bc_infos_wql_json))
    print('\n\n== 9 == All ({}) BC cred infos by vacuous query: {}'.format(
        bc_all_card,
        ppjson(bc_infos_wql_json, 4096)))
    wql_json = json.dumps({
        '$not': {
            'attr::must have::value': 'slack'  # exercise WQL canonicalization
        }
    })
    assert len(json.loads(await bcohan.get_cred_infos_by_q(wql_json, limit=-1))) == bc_all_card - 1  # exercise limit<0

    wql_json = json.dumps({
        'attr::id::marker': 1,
        'attr::id::value': 5
    })  # and, equals
    assert len(json.loads(await bcohan.get_cred_infos_by_q(wql_json))) == 1

    wql_json = json.dumps({
        'attr::id::value': {
            '$in': [5, 999999]
        }
    })  # $in
    assert len(json.loads(await bcohan.get_cred_infos_by_q(wql_json))) == 1

    wql_json = json.dumps({
        'attr::must have::marker': 1, # exercise WQL canonicalization
        '$not': {
            'attr::musthave::value': {  # exercise WQL canonicalization
                '$neq': 'slack'
            }
        }
    })  # and, $not, $neq
    assert len(json.loads(await bcohan.get_cred_infos_by_q(wql_json))) == 1

    await bcohan.wallet.close()
    try:  # exercise error path: closed wallet
        await bcohan.get_cred_infos_by_q(wql_json)
        assert False
    except WalletState:
        pass
    finally:
        await bcohan.wallet.open()

    wql_json = json.dumps({
        'attr::legalName::value': {
            '$in': ['Flan Nebula', 'Tart City']
        },
        'schema_id': S_ID['BC']
    })  # schema_id, $in, attribute name canonicalization in outer key
    infos = json.loads(await bcohan.get_cred_infos_by_q(wql_json))
    assert {info['attrs']['legalName'] for info in infos} == {'Flan Nebula', 'Tart City'}

    wql_json = json.dumps({
        'cred_def_id': cd_id[S_ID['BC']],
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
        }
    })  # cred def id, $not, $or, and, $in, attribute canonicalization in inner key
    infos = json.loads(await bcohan.get_cred_infos_by_q(wql_json))
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
        infos = json.loads(await bcohan.get_cred_infos_by_q(wql_json))
        assert False
    except BadWalletQuery:
        pass

    # BC Org Book anchor (as HolderProver) finds cred-infos by filter
    bc_infos_filt_json = await bcohan.get_cred_infos_by_filter()
    print('\n\n== 10 == All BC cred infos by null filter: {}'.format(ppjson(bc_infos_filt_json)))
    assert len(json.loads(bc_infos_filt_json)) == len(cred_data[S_ID['BC']]) + len(cred_data[S_ID['NON-REVO']])

    await bcohan.wallet.close()
    try:  # exercise error path: closed wallet
        await bcohan.get_cred_infos_by_filter()
        assert False
    except WalletState:
        pass
    finally:
        await bcohan.wallet.open()

    for s_id in cred_data:
        s_key = schema_key(s_id)
        assert (len(json.loads(await bcohan.get_cred_infos_by_filter(
            {
                'schema_name': s_key.name,
                'schema_version': s_key.version
            }))) == (len(cred_data[s_id]) if holder_prover[s_key.origin_did].did == bcohan.did else 0))

    # SRI anchor builds proof request
    EPOCH_PRE_BC_REVOC = int(time())
    proof_req[S_ID['BC']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': (EPOCH_START, EPOCH_PRE_BC_REVOC)
        }
    }))
    bc_briefs_all = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['BC']])))

    print('\n\n== 11 == All BC cred briefs {}'.format(ppjson(bc_briefs_all)))
    bc_display_pruned = creds_display(
        bc_briefs_all,
        {
            cd_id[S_ID['BC']]: {
                'legalName': cred_data[S_ID['BC']][2]['legalName']
            }
        })
    print('\n\n== 12 == BC briefs display, pruned to match {}: {}'.format(
        cred_data[S_ID['BC']][2]['legalName'],
        ppjson(bc_display_pruned)))

    bc_revoc_info = revoc_info(bc_briefs_all)
    print('\n\n== 13 == BC cred revocation info: {}'.format(ppjson(bc_revoc_info)))
                                                    
    bc_box_ids = box_ids(bc_briefs_all.values(), bc_briefs_all.keys())  # exercise box_ids
    assert bc_box_ids.items() == box_ids(bc_briefs_all).items()
    bc_box_ids_by_info = box_ids([b['cred_info'] for b in bc_briefs_all.values()])
    assert bc_box_ids_by_info.items() == box_ids(bc_briefs_all).items()

    # BC Org Book anchor (as HolderProver) exercises finding creds by query
    proof_req[S_ID['NON-REVO']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['NON-REVO']]: None
    }))
    '''
    proof req: {
        "nonce": "1042130321436287373092476",
        "name": "proof_req",
        "version": "0.0",
        "requested_predicates": {},
        "requested_attributes": {
            "17_preferredname_uuid": {
                "restrictions": [
                    {
                        "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:17:0"
                    }
                ],
                    }
                "names": ["Preferred Name", "Must Have"]
            }
        }
    }
    '''
    nr_refts = proof_req_attr_referents(proof_req[S_ID['NON-REVO']])

    wql_get_briefs_json = json.dumps({  # require NON-REVO attr 'Preferred Name' ('Must Have' would also suffice)
        nr_refts[cd_id[S_ID['NON-REVO']]]['Preferred Name']: {
            '$or': [
                {
                    'attr::preferred name::value': 'Chicken Hawk'  # exercise WQL canonicalization
                },
                {
                    'attr::Must Have::value': 'slack'
                }
            ]
        }
    })
    nr_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json))
    print('\n\n== 14 == [{}] non-revo cred briefs, via $or query {}: {}'.format(
        len(nr_briefs_q),
        ppjson(wql_get_briefs_json),
        ppjson(nr_briefs_q)))
    assert len(nr_briefs_q) == 2
    nr_box_ids_q = box_ids(nr_briefs_q)  # exercise box_ids
    print('\n\n== 15 == Box-ids for non-revo cred briefs via $or query: {}'.format(ppjson(nr_box_ids_q)))

    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]]['Must Have']: {  # AND, require presence of this NON-REVO cred def attr
            'attr::preferred name::value': 'Chicken Hawk',
            'attr::must have::value': 'slack'  # (expect no match: Chicken Hawk's must-have is chicken)
        }
    })
    nr_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json))
    print('\n\n== 16 == [{}] non-revo cred briefs, via no-match AND query {}: {}'.format(
        len(nr_briefs_q),
        ppjson(wql_get_briefs_json),
        ppjson(nr_briefs_q)))
    assert len(nr_briefs_q) == 0
    nr_box_ids_q = box_ids(nr_briefs_q.values())  # exercise box_ids on empty content
    print('\n\n== 17 == Box-ids for non-revo cred briefs via no-match AND query: {}'.format(ppjson(nr_box_ids_q)))

    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]]['Preferred Name']: {  # AND
            'attr::preferred name::value': 'Chicken Hawk',
            'attr::must have::value': 'chicken'  # (expect one match)
        }
    })
    nr_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json))
    print('\n\n== 18 == [{}] non-revo cred briefs, via single-match AND query {}: {}'.format(
        len(nr_briefs_q),
        ppjson(wql_get_briefs_json),
        ppjson(nr_briefs_q)))
    assert len(nr_briefs_q) == 1
    nr_box_ids_q = box_ids(nr_briefs_q.values(), nr_briefs_q.keys())  # exercise box_ids
    print('\n\n== 19 == Box-ids for non-revo cred briefs via single-match AND query: {}'.format(ppjson(nr_box_ids_q)))

    bc_refts = proof_req_attr_referents(proof_req[S_ID['BC']])
    print('\n\n== 20 == BC referents from proof req: {}'.format(ppjson(bc_refts)))
    wql_get_briefs_json = json.dumps({
        bc_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Tart City'
        }
    })
    bc_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['BC']]),
        wql_get_briefs_json))
    print('\n\n== 21 == [{}] BC cred briefs, via query {}: {}'.format(
        len(bc_briefs_q),
        ppjson(wql_get_briefs_json),
        ppjson(bc_briefs_q)))
    assert len(bc_briefs_q) == 1

    bc_revoc_info_q = revoc_info([brief['cred_info'] for brief in bc_briefs_q.values()])  # exercise for cred-info(s)
    assert len(bc_revoc_info_q) == 1
    tart_city_id = set(list(bc_briefs_q.keys())).pop()

    # BC Org Book anchor (as HolderProver) exercises finding cred by query, proof by single attr
    nr1_proof_req = json.loads(await san.build_proof_req_json(
        {
            cd_id[S_ID['NON-REVO']]: {
                'attrs': ['Preferred Name']
            }
        }
    ))
    nr1_refts = proof_req_attr_referents(nr1_proof_req)
    print('\n\n== 22 == Attr referents {} for non-revo single-attr proof req {}'.format(
        ppjson(nr1_refts),
        ppjson(nr1_proof_req)))

    wql_get_briefs_json = json.dumps({  # require NON-REVO attr 'Preferred Name'
        nr_refts[cd_id[S_ID['NON-REVO']]]['Preferred Name']: {
            'attr::preferred name::value': 'Chicken Hawk'  # exercise WQL canonicalization
        }
    })
    nr1_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(nr1_proof_req),
        wql_get_briefs_json
    ))
    assert len(nr1_briefs_q) == 1
    print('\n\n== 23 == Non-revo cred brief, via single-attr query {}: {}'.format(
        ppjson(wql_get_briefs_json),
        ppjson(nr1_briefs_q)))

    nr1_req_creds_q = proof_req_briefs2req_creds(nr1_proof_req, nr1_briefs_q)
    print('\n\n== 24 == Non-revo req cred by query {}'.format(ppjson(nr1_req_creds_q)))

    # BC Registrar anchor creates proof from cred-briefs via query
    nr1_proof_json = await bcohan.create_proof(nr1_proof_req, nr1_briefs_q.values(), nr1_req_creds_q)
    print('\n\n== 25 == Non-revo proof on single attr (by query): {}'.format(ppjson(nr1_proof_json, 4096)))
    assert 'revealed_attr_groups' not in json.loads(nr1_proof_json)['requested_proof']
    nr1_proof = json.loads(nr1_proof_json)

    # SRI anchor (as Verifier) verifies single-attr proof (by query)
    rc_json = await san.verify_proof(
        nr1_proof_req,
        json.loads(nr1_proof_json))
    print('\n\n== 26 == SRI anchor verifies single-attr proof (by query) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify single-attr proof with raw tamper in proof's revealed attrs
    uuid = set(list(nr1_proof['requested_proof']['revealed_attrs'].keys())).pop()
    revealed = nr1_proof['requested_proof']['revealed_attrs'][uuid]
    revealed['raw'] = 'tampered value'
    rc_json = await san.verify_proof(nr1_proof_req, nr1_proof)
    print('\n\n== 27 == SRI anchor verifies single-attr proof with revealed raw value tampering {} at {} as: {}'.format(
        ppjson(revealed),
        uuid,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with raw & encoded tamper in proof's revealed attrs
    x_enco = encode(revealed['raw'])
    revealed['encoded'] = x_enco
    rc_json = await san.verify_proof(nr1_proof_req, nr1_proof)
    print('\n\n== 28 == SRI anchor verifies single-attr proof with raw+encoded tampering {} at {} as: {}'.format(
        ppjson(revealed),
        uuid,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with raw & encoded tamper extended to primary proof
    idx = revealed['sub_proof_index']
    nr1_proof['proof']['proofs'][idx]['primary_proof']['eq_proof']['revealed_attrs']['preferredname'] = x_enco
    rc_json = await san.verify_proof(nr1_proof_req, nr1_proof)
    print('\n\n== 29 == SRI anchor verifies single-attr proof with raw+encoded tampering {} throughout as: {}'.format(
        ppjson(revealed),
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof for cred specified by query
    bc_req_creds_q = proof_req_briefs2req_creds(proof_req[S_ID['BC']], bc_briefs_q)
    print('\n\n== 30 == BC req creds by query {}'.format(ppjson(bc_req_creds_q)))

    _set_tails_state(False)  # simulate not having tails file first
    _set_cache_state(False)
    try:
        bc_proof_json = await bcohan.create_proof(proof_req[S_ID['BC']], bc_briefs_q, bc_req_creds_q)
        assert False
    except AbsentTails:
        pass

    x_proof_req = deepcopy(proof_req[S_ID['BC']])
    for attr_uuid in x_proof_req['requested_attributes']:
        x_proof_req['requested_attributes'][attr_uuid].pop('non_revoked')
    x_bc_refts = proof_req_attr_referents(x_proof_req)
    x_wql_get_briefs_json = json.dumps({
        x_bc_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Tart City'
        }
    })
    x_briefs = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(json.dumps(x_proof_req), x_wql_get_briefs_json))
    rr_id = list(revoc_info(x_briefs, {'legalName': 'Tart City'}).keys())[0][0]
    _download_tails(rr_id)  # simulate sending tails file to HolderProver

    try:
        await bcohan.create_proof(
            x_proof_req,
            x_briefs.values(),
            bc_req_creds_q)
        assert False
    except AbsentInterval:  # check: skipping non-revocation interval raises AbsentInterval for cred def w/revocation
        pass

    # BC Registrar anchor creates proof from cred-briefs via query
    bc_proof_json = await bcohan.create_proof(proof_req[S_ID['BC']], bc_briefs_q.values(), bc_req_creds_q)
    assert len(Tails.unlinked(DIR_TAILS)) == 0  # proof creation should get rev reg def from ledger and link its rr_id

    _set_tails_state(True)  # restore state
    _set_cache_state(True)

    print('\n\n== 31 == BC proof (by query): {}'.format(ppjson(bc_proof_json, 4096)))

    # SRI anchor (as Verifier) verifies proof (by query)
    rc_json = await san.verify_proof(
        proof_req[S_ID['BC']],
        json.loads(bc_proof_json))
    print('\n\n== 32 == SRI anchor verifies BC proof (by query) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    sleep(1)  # make sure EPOCH_BC_REVOC > EPOCH_PRE_BC_REVOC

    # BC Registrar anchor creates proof (by query) for non-revocable cred, for verification
    proof_req[S_ID['NON-REVO']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['NON-REVO']]: None
    }))
    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]]['Must Have']: {
            'attr::Must Have::value': 'slack'
        }
    })
    nr_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json))
    assert len(nr_briefs_q) == 1
    nr_req_creds_q = proof_req_briefs2req_creds(proof_req[S_ID['NON-REVO']], nr_briefs_q.values())
    nr_proof_q_json = await bcohan.create_proof(
        proof_req[S_ID['NON-REVO']],
        nr_briefs_q.values(),
        nr_req_creds_q)
    print('\n\n== 33 == Proof (by query) of non-revocable cred: {}'.format(ppjson(nr_proof_q_json, 4096)))

    # Verifier anchor attempts to verify proof (by query) of non-revocable cred
    rc_json = await san.verify_proof(proof_req[S_ID['NON-REVO']], json.loads(nr_proof_q_json))
    print('\n\n== 34 == SRI anchor verifies proof (by query) of non-revocable cred as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # Exercise build_proof_req_json parameter permutations
    preq = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: None for s_id in schema_data if s_id != S_ID['BC']
    }))
    assert not len(preq['requested_predicates'])

    assert sum(
        [len(reqa.get('names', [''])) for reqa in preq['requested_attributes'].values()]
    ) == sum(len(schema_data[s_id]['attr_names']) for s_id in schema_data if s_id != S_ID['BC'])
    assert all(preq['requested_attributes'][uuid].get('non_revoked', None)
        or preq['requested_attributes'][uuid]['restrictions'][0]['cred_def_id'] == cd_id[S_ID['NON-REVO']]
            for uuid in preq['requested_attributes'])

    preq = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {},
        cd_id[S_ID['SRI-1.1']]: {
            'attrs': ['endDate', 'legalName'],
            '>=': {
                'id': 1,
                'jurisdictionId': '1',
                'orgTypeId': 1
            },
            'interval': EPOCH_START
        }
    }))
    assert len(preq['requested_predicates']) == 3
    # assert len(preq['requested_attributes']) == len(schema_data[S_ID['BC']]['attr_names']) + 2
    assert sum(
        [len(reqa.get('names', [''])) for reqa in preq['requested_attributes'].values()]
    ) == len(schema_data[S_ID['BC']]['attr_names']) + 2
    assert all(preq['requested_attributes'][uuid]['non_revoked'] for uuid in preq['requested_attributes'])
    assert all(preq['requested_predicates'][uuid]['non_revoked'] for uuid in preq['requested_predicates'])

    # Exercise Org Hub Anchor capacities to issue, verify with simple non-revo schema
    try:
        orghub_cred_def = json.loads(await bcohan.send_cred_def(
            S_ID['NON-REVO'],
            False,
            None))
        orghub_cd_id = orghub_cred_def['id']
    except:
        assert False
    s_key = schema_key(S_ID['NON-REVO'])

    try:  # exercise error path: no such schema at specified txn no
        await bcohan.create_cred_offer(99999)
        assert False
    except CorruptWallet:
        pass

    orghub_cred_offer_json = await bcohan.create_cred_offer(schema[S_ID['NON-REVO']]['seqNo'])
    print('\n\n== 35 == BC Org Hub cred offer [{} v{}]: {}'.format(
        s_key.name,
        s_key.version,
        ppjson(orghub_cred_offer_json)))

    (orghub_cred_req_json, orghub_cred_req_metadata_json) = await bcohan.create_cred_req(
        orghub_cred_offer_json,
        orghub_cd_id)
    print('\n\n== 36 == BC Org Hub credential request [{} v{}]: metadata {}, cred req {}'.format(
        s_key.name,
        s_key.version,
        ppjson(orghub_cred_req_metadata_json),
        ppjson(orghub_cred_req_json)))
    assert json.loads(orghub_cred_req_json)

    x_cred_offer = json.loads(orghub_cred_offer_json)
    x_cred_offer['cred_def_id'] = 'not-a-cdid'
    try:  # exercise bad cred def id in offer for coverage
        await bcohan.create_cred(json.dumps(x_cred_offer), orghub_cred_req_json, None)
        assert False
    except BadIdentifier:
        pass

    print('\n\n== 37 == BC Org Hub creating credential')
    (orghub_cred_json, _) = await bcohan.create_cred(
        orghub_cred_offer_json,
        orghub_cred_req_json,
        {
            'Preferred Name': 'Chicken Lady',
            'Must Have': 'Fifty Bucks'
        })
    assert json.loads(orghub_cred_json)
    orghub_cred = json.loads(orghub_cred_json)
    orghub_cred_id = await bcohan.store_cred(orghub_cred_json, orghub_cred_req_metadata_json)

    # Org Hub anchor creates proof (by query) for non-revocable cred, for verification
    proof_req[S_ID['NON-REVO']] = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['NON-REVO']]: None
    }))
    wql_get_briefs_json = json.dumps({
        nr_refts[cd_id[S_ID['NON-REVO']]]['Must Have']: {
            'attr::Must Have::value': 'slack'
        }
    })
    nr_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['NON-REVO']]),
        wql_get_briefs_json))
    assert len(nr_briefs_q) == 1
    nr_req_creds_q = proof_req_briefs2req_creds(proof_req[S_ID['NON-REVO']], nr_briefs_q.values())
    nr_proof_q_json = await bcohan.create_proof(
        proof_req[S_ID['NON-REVO']],
        nr_briefs_q.values(),
        nr_req_creds_q)
    print('\n\n== 38 == Proof (by query) of non-revocable cred: {}'.format(ppjson(nr_proof_q_json, 4096)))

    # Verifier anchor attempts to verify proof (by query) of non-revocable cred
    rc_json = await san.verify_proof(proof_req[S_ID['NON-REVO']], json.loads(nr_proof_q_json))
    print('\n\n== 39 == SRI anchor verifies proof (by query) of non-revocable cred as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # Org Hub anchor creates proof (by query) for non-revocable cred, for verification
    orghub_proof_req = json.loads(await bcohan.build_proof_req_json({
        orghub_cd_id: None
    }))
    orghub_refts = proof_req_attr_referents(orghub_proof_req)
    wql_get_briefs_json = json.dumps({
        orghub_refts[orghub_cd_id]['Must Have']: {
            'attr::Must Have::value': 'Fifty Bucks'
        }
    })
    orghub_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(orghub_proof_req),
        wql_get_briefs_json))
    assert len(orghub_briefs_q) == 1
    non_revo_cred_id_x = [k for k in orghub_briefs_q][0]

    orghub_req_creds_q = proof_req_briefs2req_creds(orghub_proof_req, orghub_briefs_q.values())
    orghub_proof_q_json = await bcohan.create_proof(
        orghub_proof_req,
        orghub_briefs_q.values(),
        orghub_req_creds_q)
    print('\n\n== 40 == BC Org Hub anchor creates proof (by query) of non-revocable cred: {}'.format(
        ppjson(orghub_proof_q_json, 4096)))

    # Org Hub Anchor attempts to verify proof (by query) of non-revocable cred
    rc_json = await bcohan.verify_proof(orghub_proof_req, json.loads(orghub_proof_q_json))
    print('\n\n== 41 == BC Org Hub anchor verifies proof (by query) of non-revocable cred as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # Org Hub Anchor deletes credential; exercise double-deletion
    if callable(getattr(anoncreds, 'prover_delete_credential', None)):
        await bcohan.delete_cred(non_revo_cred_id_x);
        try:
            await bcohan.delete_cred(non_revo_cred_id_x);
        except AbsentCred:
            pass
        print('\n\n== 42a == BC Org Hub anchor deletes cred {} once, fails as expected to delete it twice'.format(
            ppjson(rc_json)))
    else:
        print('\n\n== 42b == BC Org Hub anchor abstaining from credential deletion: not yet in indy-sdk')

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
    bc_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req[S_ID['BC']]),
        wql_get_briefs_json))
    revo = revoc_info(bc_briefs_q.values())
    assert len(revo) == 1
    (x_rr_id, x_cr_id) = choice(list(revo.keys()))  # it's unique
    assert (x_rr_id, x_cr_id) != (None, None)

    try:
        await san.revoke_cred(x_rr_id, x_cr_id)  # check: only a cred's issuer can revoke it
        assert False
    except BadRevocation:
        pass
    try:
        await san.revoke_cred('not-a-rrid', x_cr_id)  # exercise error case: bad rr_id
        assert False
    except BadIdentifier:
        pass

    EPOCH_BC_REVOC = await did2an[schema_key(S_ID['BC']).origin_did].revoke_cred(x_rr_id, x_cr_id)
    print('\n\n== 43 == BC Registrar anchor revoked ({}, {}) -> {}'.format(
        x_rr_id,
        x_cr_id,
        bc_revoc_info[(x_rr_id, x_cr_id)]['legalName']))
    sleep(1)
    EPOCH_POST_BC_REVOC = int(time())
    print('\n\n== 44 == EPOCH times re: BC revocation: pre-revoc {}, revoc {}, post-revoc {}'.format(
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

    # BC Org Book anchor (as HolderProver) finds cred-briefs after revocation
    bc_briefs_all_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(json.dumps(proof_req[S_ID['BC']])))
    assert len(bc_briefs_all_q) == len(cred_data[S_ID['BC']])  # indy-sdk get-creds includes revoked creds here

    # BC Org Book anchor (as HolderProver) creates proof for revoked cred, for non-verification
    x_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': (EPOCH_PRE_BC_REVOC, EPOCH_POST_BC_REVOC)  # should take latest = post-revocation
        }
    }))
    x_refts = proof_req_attr_referents(x_proof_req)
    x_wql_get_briefs_json = json.dumps({
        x_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Flan Nebula'
        }
    })
    x_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(x_proof_req),
        x_wql_get_briefs_json))
    assert len(x_briefs_q) == 1
    x_req_creds_q = proof_req_briefs2req_creds(x_proof_req, x_briefs_q.values())
    x_proof_json = await bcohan.create_proof(x_proof_req, x_briefs_q.values(), x_req_creds_q)
    print('\n\n== 45 == Proof (by query) of revoked cred: {}'.format(ppjson(x_proof_json, 4096)))

    # Verifier anchor attempts to verify non-proof of revoked cred
    rc_json = await san.verify_proof(x_proof_req, json.loads(x_proof_json))
    print('\n\n== 46 == SRI anchor verifies proof (by query) of revoked cred as: {}'.format(ppjson(rc_json)))
    assert not json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates non-proof (by query) for revoked cred, for non-verification
    x_refts = proof_req_attr_referents(x_proof_req)
    wql_get_briefs_json = json.dumps({
        x_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Flan Nebula'
        }
    })

    x_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(x_proof_req),
        wql_get_briefs_json))
    assert len(x_briefs_q) == 1

    x_req_creds_q = proof_req_briefs2req_creds(x_proof_req, x_briefs_q.values())
    x_proof_q_json = await bcohan.create_proof(x_proof_req, x_briefs_q.values(), x_req_creds_q)
    print('\n\n== 47 == Proof of revoked cred: {}'.format(ppjson(x_proof_q_json, 4096)))

    # Verifier anchor attempts to verify non-proof of revoked cred
    rc_json = await san.verify_proof(x_proof_req, json.loads(x_proof_q_json))
    print('\n\n== 48 == SRI anchor verifies proof (by query) of revoked cred as: {}'.format(ppjson(rc_json)))
    assert not json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof for non-revoked cred on same rev reg, for verification
    ok_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_POST_BC_REVOC
        }
    }))
    ok_refts = proof_req_attr_referents(ok_proof_req)
    ok_wql_get_briefs_json = json.dumps({
        ok_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Tart City'
        }
    })
    ok_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(ok_proof_req),
        ok_wql_get_briefs_json))
    assert len(ok_briefs_q) == 1
    ok_req_creds_q = proof_req_briefs2req_creds(ok_proof_req, ok_briefs_q.values())
    ok_proof_json = await bcohan.create_proof(ok_proof_req, ok_briefs_q.values(), ok_req_creds_q)
    print('\n\n== 49 == Proof (by query) of non-revoked cred: {}'.format(ppjson(ok_proof_json, 4096)))

    # Verifier anchor attempts to verify non-proof of revoked cred
    rc_json = await san.verify_proof(ok_proof_req, json.loads(ok_proof_json))
    print('\n\n== 50 == SRI anchor verifies proof (by query) of non-revoked cred as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof for revoked cred, back-dated just before revocation
    pre_x_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_PRE_BC_REVOC
        }
    }))
    pre_x_refts = proof_req_attr_referents(pre_x_proof_req)
    pre_x_wql_get_briefs_json = json.dumps({
        pre_x_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Flan Nebula'
        }
    })
    pre_x_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(pre_x_proof_req),
        pre_x_wql_get_briefs_json))
    assert len(pre_x_briefs_q) == 1
    pre_x_req_creds_q = proof_req_briefs2req_creds(pre_x_proof_req, pre_x_briefs_q.values())
    pre_x_proof_json = await bcohan.create_proof(pre_x_proof_req, pre_x_briefs_q.values(), pre_x_req_creds_q)
    print('\n\n== 51 == Proof (by query) of cred before revocation: {}'.format(ppjson(pre_x_proof_json, 4096)))

    # Verifier anchor attempts to verify proof of cred before revocation
    rc_json = await san.verify_proof(pre_x_proof_req, json.loads(pre_x_proof_json))
    print('\n\n== 52 == SRI anchor verifies proof (by query) of cred before revocation as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof for revoked cred, back-dated < rev reg def (indy-sdk cannot)
    x_proof_req = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            'interval': EPOCH_START
        }
    }))
    x_refts = proof_req_attr_referents(x_proof_req)
    x_wql_get_briefs_json = json.dumps({
        x_refts[cd_id[S_ID['BC']]]['legalName']: {
            'attr::legalName::value': 'Flan Nebula'
        }
    })
    x_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(x_proof_req),
        x_wql_get_briefs_json))
    assert len(x_briefs_q) == 1
    x_req_creds_q = proof_req_briefs2req_creds(x_proof_req, x_briefs_q.values())
    try:
        x_proof_json = await bcohan.create_proof(x_proof_req, x_briefs_q.values(), x_req_creds_q)
        assert False
    except BadRevStateTime:
        pass
    print('\n\n== 53 == SRI anchor cannot create proof on request with rev reg state before its creation')

    # BC Org Book anchor (as HolderProver) finds cred by cred-id, proof req and cred-id, no cred by non-cred-id
    bc_info_by_cred_id = json.loads(await bcohan.get_cred_info_by_id(tart_city_id))  # tart_city_id: look up, waaay up
    print('\n\n== 54 == BC cred-infos by cred_id={}: {}'.format(tart_city_id, ppjson(bc_info_by_cred_id)))
    assert bc_info_by_cred_id
    assert bc_info_by_cred_id['attrs']

    try:  # exercise error path: no such cred by id
        await bcohan.get_cred_info_by_id('ffffffff-ffff-ffff-ffff-ffffffffffff')
        assert False
    except AbsentCred:
        pass

    await bcohan.wallet.close()
    try:  # exercise error path: closed wallet
        await bcohan.get_cred_info_by_id('ffffffff-ffff-ffff-ffff-ffffffffffff')
        assert False
    except WalletState:
        pass
    finally:
        await bcohan.wallet.open()

    # BC Org Book anchor (as HolderProver) creates proof for cred specified by cred-id
    bc_briefs = proof_req_infos2briefs(proof_req[S_ID['BC']], [bc_info_by_cred_id])
    bc_req_creds = proof_req_briefs2req_creds(proof_req[S_ID['BC']], bc_briefs)
    bc_proof_json = await bcohan.create_proof(
        proof_req[S_ID['BC']],
        bc_briefs,
        bc_req_creds)
    bc_proof = json.loads(bc_proof_json)
    print('\n\n== 55 == BC proof by cred-id={}: {}'.format(tart_city_id, ppjson(bc_proof_json, 4096)))

    # SRI anchor (as Verifier) verifies proof (by cred-id)
    rc_json = await san.verify_proof(proof_req[S_ID['BC']], bc_proof)
    print('\n\n== 56 == SRI anchor verifies BC proof by cred-id={} as: {}'.format(tart_city_id, ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof by multiple predicates on same cred def id
    fn_proof_req_pred = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            '>=': {
                'id': cred_data[S_ID['BC']][3]['id'],  # ordinal 3, id 4: Flan Nebula, Babka Galaxy
                'busId': 11198760  # only Flan Nebula
            },
            'interval': EPOCH_PRE_BC_REVOC  # before its revocation
        }
    }))
    fn_wql = proof_req2wql_all(fn_proof_req_pred)
    fn_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(fn_proof_req_pred),
        json.dumps(fn_wql)))
    assert len(fn_briefs_q) == 1

    await bcohan.wallet.close()
    try:  # exercise error path: closed wallet
        await bcohan.get_cred_briefs_by_proof_req_q(
            json.dumps(fn_proof_req_pred),
            json.dumps(fn_wql))
        assert False
    except WalletState:
        pass
    finally:
        await bcohan.wallet.open()

    fn_req_creds_q = proof_req_briefs2req_creds(fn_proof_req_pred, fn_briefs_q.values())
    fn_proof_pred_json = await bcohan.create_proof(fn_proof_req_pred, fn_briefs_q.values(), fn_req_creds_q)
    fn_proof_pred = json.loads(fn_proof_pred_json)
    print('\n\n== 57 == BC cred briefs, queried by BC id and busId predicates: {}'.format(ppjson(fn_briefs_q)))

    # SRI anchor (as Verifier) verifies proof (by predicates)
    rc_json = await san.verify_proof(fn_proof_req_pred, fn_proof_pred)
    print('\n\n== 58 == SRI anchor verifies BC proof (by predicates) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # BC Org Book anchor (as HolderProver) creates proof by (single) predicate
    bg_proof_req_pred = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['BC']]: {
            '>=': {
                'id': cred_data[S_ID['BC']][4]['id']  # Babka Galaxy, ordinal 4, id 5
            },
            'interval': EPOCH_POST_BC_REVOC
        }
    }))
    bg_wql = proof_req2wql_all(bg_proof_req_pred)
    bg_briefs_q = json.loads(await bcohan.get_cred_briefs_by_proof_req_q(
        json.dumps(bg_proof_req_pred),
        json.dumps(bg_wql)))
    assert len(bg_briefs_q) == 1

    bg_req_creds_q = proof_req_briefs2req_creds(bg_proof_req_pred, bg_briefs_q.values())
    bg_proof_pred_json = await bcohan.create_proof(bg_proof_req_pred, bg_briefs_q.values(), bg_req_creds_q)
    bg_proof_pred = json.loads(bg_proof_pred_json)
    print('\n\n== 59 == BC cred briefs, queried by predicate id >= 5 (Babka Galaxy): {}'.format(ppjson(bg_briefs_q)))

    bc_display_pred = creds_display(bg_briefs_q.values())
    print('\n\n== 60 == BC creds display, filtered by predicate id >= 5: {}'.format(ppjson(bc_display_pred)))
    bc_display_pred_by_cred_infos = creds_display([b['cred_info'] for b in bg_briefs_q.values()])
    assert bc_display_pred == bc_display_pred_by_cred_infos

    # SRI anchor (as Verifier) verifies proof (by predicate)
    rc_json = await san.verify_proof(bg_proof_req_pred, bg_proof_pred)
    print('\n\n== 61 == SRI anchor verifies BC proof (by predicate) as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # Create and store SRI registration completion creds, green cred from verified proof + extra data
    revealed_bc = revealed_attrs(bc_proof)  # bc_proof: carrying on with non-revoked Tart City
    print('\n\n== 62 == Revealed attributes from BC proof: {}'.format(ppjson(revealed_bc)))
    revealed = revealed_bc[cd_id[S_ID['BC']]]
    '''
    Looks like {
        'busid': '11144444',
        'effectivedate': '2012-12-01',
        'enddate': None,
        'id': 3,
        'jurisdictionid': 1,
        'legalname': 'Tart City',
        'orgtypeid': 2
    }
    '''

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
            (cred_json[s_id], cred_rev_id) = await did2an[s_key.origin_did].create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                c)
            epoch_creation = int(time())
            EPOCH_CRED_CREATE[s_id].append(epoch_creation)
            sleep(2)  # put an interior second between each cred creation
            assert json.loads(cred_json[s_id])
            print('\n\n== 63.{}.0 == SRI created cred (revoc id {}) at epoch {} on schema {}: {}'.format(
                i,
                cred_rev_id,
                epoch_creation,
                s_id,
                ppjson(cred_json[s_id])))
            cred_id = await holder_prover[s_key.origin_did].store_cred(
                cred_json[s_id],
                cred_req_metadata_json[s_id])
            print('\n\n== 63.{}.1 == Cred id in wallet {}: {}'.format(
                i,
                holder_prover[s_key.origin_did].name,
                cred_id
            ))
            i += 1
    EPOCH_PRE_SRI_REVOC = int(time())

    # BC Org Book anchor (as HolderProver) finds cred-infos by filter again
    infos = await pspcoban.get_cred_infos_by_filter()
    print('\n\n== 64 == All PSPC cred infos by null filter after SRI proctor issues: {}'.format(ppjson(infos)))

    # PSPC Org Book anchor (as HolderProver) finds all creds, one schema at a time
    briefs_pspc = {}  # index by s_id
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
        briefs_pspc[s_id] = json.loads(await holder_prover[s_key.origin_did].get_cred_briefs_by_proof_req_q(
            json.dumps(proof_req[s_id])))
        print('\n\n== 65.{} == Cred briefs on schema {} (no query): {}'.format(
            i,
            s_id,
            ppjson(briefs_pspc[s_id])))
        i += 1

    # PSPC Org Book anchor (as HolderProver) finds all creds (by query) on all schemata
    proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_PRE_SRI_REVOC
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    sri_refts = proof_req_attr_referents(proof_req_sri)
    sri_wql_all = proof_req2wql_all(proof_req_sri)
    sri_briefs_all_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        json.dumps(sri_wql_all)))
    print('\n\n== 66 == All SRI-issued creds at PSPC Org Book: {}'.format(ppjson(sri_briefs_all_q)))
    assert len(sri_briefs_all_q) == sum([len(cred_data[s_id]) for s_id in cred_data if s_id != S_ID['BC']])

    # PSPC Org Book anchor (as HolderProver) creates multi-cred non-proof (by query) for >1 creds on a cred def
    sri_refts = proof_req_attr_referents(proof_req_sri)
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_all_q.values())
    try:
        x_sri_proof_q_json = await pspcoban.create_proof(proof_req_sri, sri_briefs_all_q.values(), sri_req_creds_q)
        assert False
    except CredentialFocus as x:
        pass

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof (by query)
    wql_not_silver = proof_req2wql_all(proof_req_sri, cd_id[S_ID['GREEN']])
    wql_not_silver[sri_refts[cd_id[S_ID['GREEN']]]['greenLevel']] = {
        '$not': {
            'attr::greenLevel::value': 'Silver'
        }
    }
    sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        json.dumps(wql_not_silver)))
    assert len(sri_briefs_q) == len(cred_data) - 1  # one for each cred def except BC
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q.values())
    sri_proof_q_json = await pspcoban.create_proof(proof_req_sri, sri_briefs_q.values(), sri_req_creds_q)
    print('\n\n== 67 == PSPC Org Book proof by query: {}'.format(ppjson(sri_proof_q_json, 4096)))
    sri_proof_q = json.loads(sri_proof_q_json)

    # SRI anchor (as Verifier) verifies proof (by query)
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 68 == SRI anchor verifies PSPC Org Book proof by query as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof; back-dated between Bronze, Silver issue
    bd_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_CRED_CREATE[S_ID['GREEN']][1] - 1
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    bd_sri_refts = proof_req_attr_referents(bd_proof_req_sri)
    wql_silver = proof_req2wql_all(proof_req_sri, [cd_id[S_ID['GREEN']]])
    wql_silver[bd_sri_refts[cd_id[S_ID['GREEN']]]['greenLevel']] = {
        'attr::greenLevel::value': 'Silver'
    }
    bd_sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(bd_proof_req_sri),
        json.dumps(wql_silver)))
    bd_sri_req_creds_q = proof_req_briefs2req_creds(bd_proof_req_sri, bd_sri_briefs_q.values())
    bd_sri_proof_q_json = await pspcoban.create_proof(bd_proof_req_sri, bd_sri_briefs_q.values(), bd_sri_req_creds_q)

    print('\n\n== 69 == PSPC Org Book proof pre-revoc, just before Silver cred creation {}'.format(
        ppjson(bd_sri_proof_q_json, 4096)))
    bd_sri_proof_q = json.loads(bd_sri_proof_q_json)

    # SRI anchor (as Verifier) verifies proof
    rc_json = await san.verify_proof(bd_proof_req_sri, bd_sri_proof_q)
    print('\n\n== 70 == SRI anchor verifies PSPC proof pre-revocation just before Silver creation as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)  # issue to rev reg is by default, so rev reg creation < timestamp < issue is OK

    # PSPC Org Book anchor (as HolderProver) tries to create multi-cred (non-)proof; post-dated in future
    TOMORROW = int(time()) + 86400
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': TOMORROW
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    x_sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(x_proof_req_sri),
        json.dumps(wql_silver)))
    x_sri_req_creds_q = proof_req_briefs2req_creds(x_proof_req_sri, x_sri_briefs_q.values())
    try:
        x_sri_proof_q_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_briefs_q.values(), x_sri_req_creds_q)
        assert False
    except BadRevStateTime:
        pass

    # SRI anchor (as Issuer) revokes a cred
    sri_revoc_info = revoc_info(sri_briefs_all_q.values())
    revo = revoc_info(
        sri_briefs_all_q.values(),
        {
            'legalName': 'Tart City',
            'greenLevel': 'Silver'
        })
    assert len(revo) == 1
    (x_rr_id, x_cr_id) = next(r for r in revo)  # it's unique

    sleep(1)
    EPOCH_SRI_REVOC = await did2an[schema_key(S_ID['GREEN']).origin_did].revoke_cred(x_rr_id, x_cr_id)
    print('\n\n== 71 == SRI anchor revoked ({}, {}) -> {} green level {}'.format(
        x_rr_id,
        x_cr_id,
        sri_revoc_info[(x_rr_id, x_cr_id)]['legalName'],
        sri_revoc_info[(x_rr_id, x_cr_id)]['greenLevel']))
    sleep(1)
    EPOCH_POST_SRI_REVOC = int(time())
    print('\n\n== 72 == EPOCH times re: SRI Silver revocation: pre-revoc {}, revoc {}, post-revoc {}'.format(
        EPOCH_PRE_SRI_REVOC,
        EPOCH_SRI_REVOC,
        EPOCH_POST_SRI_REVOC))

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof with revoked cred, for non-verification
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_POST_SRI_REVOC
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    x_sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(x_proof_req_sri),
        json.dumps(wql_silver)))
    x_sri_req_creds_q = proof_req_briefs2req_creds(x_proof_req_sri, x_sri_briefs_q.values())
    x_sri_proof_q_json = await pspcoban.create_proof(x_proof_req_sri, x_sri_briefs_q.values(), x_sri_req_creds_q)
    print('\n\n== 73 == PSPC Org Book proof post Silver revocation: {}'.format(
        ppjson(x_sri_proof_q_json, 4096)))
    x_sri_proof_q = json.loads(x_sri_proof_q_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with revoked cred
    rc_json = await san.verify_proof(x_proof_req_sri, x_sri_proof_q)
    print('\n\n== 74 == SRI anchor verifies multi-cred proof with Silver cred revoked as: {}'.format(
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof w/revoked cred, back-dated just before revocation
    proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_PRE_SRI_REVOC
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        json.dumps(wql_silver)))
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q.values())
    sri_proof_q_json = await pspcoban.create_proof(proof_req_sri, sri_briefs_q.values(), sri_req_creds_q)
    print('\n\n== 75 == PSPC proof just before Silver cred revoc: {}'.format(ppjson(sri_proof_q_json, 4096)))
    sri_proof_q = json.loads(sri_proof_q_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with revoked cred, back-dated pre-revocation
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 76 == SRI anchor verifies multi-cred proof just before Silver cred revoc as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with raw tamper in proof's revealed attrs
    uuid = set(list(sri_proof_q['requested_proof']['revealed_attr_groups'].keys())).pop()
    attr = set(list(sri_proof_q['requested_proof']['revealed_attr_groups'][uuid]['values'].keys())).pop()
    revealed = sri_proof_q['requested_proof']['revealed_attr_groups'][uuid]['values'][attr]
    revealed['raw'] = 'tampered value'
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 77 == SRI anchor verifies multi-cred proof with revealed raw value tampering {} at {} as: {}'.format(
        ppjson(revealed),
        uuid,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with raw & encoded tamper in proof's revealed attrs
    x_enco = encode(revealed['raw'])
    revealed['encoded'] = x_enco
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 78 == SRI anchor verifies multi-cred proof with raw+encoded tampering {} at {} as: {}'.format(
        ppjson(revealed),
        uuid,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with raw & encoded tamper extended to primary proof
    idx = sri_proof_q['requested_proof']['revealed_attr_groups'][uuid]['sub_proof_index']
    sri_proof_q['proof']['proofs'][idx]['primary_proof']['eq_proof']['revealed_attrs'][canon(attr)] = x_enco
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 79 == SRI anchor verifies multi-cred proof with raw+encoded tampering {} throughout as: {}'.format(
        ppjson(revealed),
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # PSPC Org Book (as HolderProver) creates multi-cred proof w/revoked cred, between 1st cred creation and its own
    bd_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_CRED_CREATE[S_ID['GREEN']][0] + 1
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    bd_sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(bd_proof_req_sri),
        json.dumps(wql_silver)))
    bd_sri_req_creds_q = proof_req_briefs2req_creds(bd_proof_req_sri, bd_sri_briefs_q.values())
    bd_sri_proof_q = json.loads(await pspcoban.create_proof(
        bd_proof_req_sri,
        bd_sri_briefs_q.values(),
        bd_sri_req_creds_q))
    print('\n\n== 80 == PSPC multi-cred proof just before Silver cred creation: {}'.format(
        ppjson(bd_sri_proof_q, 4096)))

    # SRI anchor (as Verifier) verifies multi-cred proof with revoked cred on non-revo timestamp before its creation
    rc_json = await san.verify_proof(bd_proof_req_sri, bd_sri_proof_q)
    print('\n\n== 81 == SRI anchor verifies multi-cred proof just before Silver cred creation as {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)  # issue to rev reg is by default, so rev reg creation < timestamp < issue is OK

    # PSPC Org Book anchor (as HolderProver) creates proof for revoked cred, between cred def and 1st cred creation
    bd_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': EPOCH_CRED_CREATE[S_ID['GREEN']][0] - 1
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    bd_sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(bd_proof_req_sri),
        json.dumps(wql_silver)))
    bd_sri_req_creds_q = proof_req_briefs2req_creds(bd_proof_req_sri, bd_sri_briefs_q.values())
    bd_sri_proof_q = json.loads(await pspcoban.create_proof(
        bd_proof_req_sri,
        bd_sri_briefs_q.values(),
        bd_sri_req_creds_q))
    print('\n\n== 82 == PSPC Org Book multi-cred proof before any Green cred creation: {}'.format(
        ppjson(bd_sri_proof_q, 4096)))

    # SRI anchor (as Verifier) verifies multi-cred proof on non-revo timestamp before cred creation
    rc_json = await san.verify_proof(bd_proof_req_sri, bd_sri_proof_q)
    print('\n\n== 83 == SRI anchor verifies multi-cred proof before any Green cred creation as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)  # issue to rev reg is by default, so rev reg creation < timestamp < issue is OK

    # PSPC Org Book anchor (as HolderProver) tries to create (non-)proof for revoked cred in future
    x_proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[s_id]: {
            'interval': TOMORROW
        } for s_id in schema_data if s_id != S_ID['BC']
    }))
    x_sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(x_proof_req_sri),
        json.dumps(wql_silver)))
    x_sri_req_creds_q = proof_req_briefs2req_creds(x_proof_req_sri, x_sri_briefs_q.values())
    try:
        x_sri_proof_q = json.loads(await pspcoban.create_proof(
            x_proof_req_sri,
            x_sri_briefs_q.values(),
            x_sri_req_creds_q))
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
            '>=': {
                'jurisdictionId': 1
            },
            'interval': EPOCH_PRE_SRI_REVOC
        }
    }))
    sri_refts = proof_req_attr_referents(proof_req_sri)
    sri_wql = proof_req2wql_all(proof_req_sri, cd_id[S_ID['SRI-1.0']])
    sri_wql[sri_refts[cd_id[S_ID['SRI-1.0']]]['legalName']] = {
        'attr::legalName::value': 'Tart City'
    }
    sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        json.dumps(sri_wql)))
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q.values())

    sri_proof_q = json.loads(await pspcoban.create_proof(proof_req_sri, sri_briefs_q.values(), sri_req_creds_q))
    print('\n\n== 84 == PSPC Org Book multi-cred proof for Tart City on GE jurisdictionId pred: {}'.format(
        ppjson(sri_proof_q, 4096)))

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof with dupl attr name, specification of one by pred
    proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['SRI-1.0']]: {
            'attrs': [
                'legalName',
                'sriRegDate'
            ],
            'interval': EPOCH_PRE_SRI_REVOC
        },
        cd_id[S_ID['SRI-1.1']]: {
            'attrs': [
                'legalName',
                'businessLang'
            ],
            '>=': {
                'jurisdictionId': 1
            },
            'interval': EPOCH_PRE_SRI_REVOC
        }
    }))
    sri_refts = proof_req_attr_referents(proof_req_sri)
    sri_wql = proof_req2wql_all(proof_req_sri, cd_id[S_ID['SRI-1.0']])
    sri_wql[sri_refts[cd_id[S_ID['SRI-1.0']]]['legalName']] = {
        'attr::legalName::value': 'Tart City'
    }
    sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        json.dumps(sri_wql)))
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q.values())

    sri_proof_q = json.loads(await pspcoban.create_proof(proof_req_sri, sri_briefs_q.values(), sri_req_creds_q))
    print('\n\n== 85 == PSPC Org Book multi-cred proof with dupl attr name for Tart City on GE pred: {}'.format(
        ppjson(sri_proof_q, 4096)))

    # SRI anchor (as Verifier) verifies multi-cred proof with specification of one by pred
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 86 == SRI anchor verifies multi-cred proof (1 pred) as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with pred bound tampering in proof req only
    x_proof_req_sri = deepcopy(proof_req_sri)
    x_bound = -2**31
    uuid = [k for k in x_proof_req_sri['requested_predicates']][0]
    canon_attr = canon(x_proof_req_sri['requested_predicates'][uuid]['name'])
    x_proof_req_sri['requested_predicates'][uuid]['p_value'] = x_bound

    rc_json = await san.verify_proof(x_proof_req_sri, sri_proof_q)
    print('\n\n== 87 == SRI anchor verifies multi-cred proof (1 pred) vs. req with tampered pred {}>={} as: {}'.format(
        canon_attr,
        x_bound,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with tampered pred value
    uuid = [k for k in sri_proof_q['requested_proof']['predicates']][0]
    pred = sri_proof_q['requested_proof']['predicates'][uuid]
    idx = pred['sub_proof_index']
    canon_attr = canon(proof_req_sri['requested_predicates'][uuid]['name'])
    for ge_proof in sri_proof_q['proof']['proofs'][idx]['primary_proof']['ge_proofs']:
        if ge_proof['predicate']['attr_name'] == canon_attr:
            ge_proof['predicate']['value'] = x_bound
            break
    else:
        assert False  # by construction, should never happen

    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 88 == SRI anchor verifies multi-cred proof (1 pred) with tampered pred {}>={} as: {}'.format(
        canon_attr,
        x_bound,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # SRI anchor (as Verifier) attempts to verify multi-cred proof and proof-req with tampered pred value
    proof_req_sri['requested_predicates'][uuid]['p_value'] = x_bound
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 89 == SRI anchor verifies multi-cred request, proof (1 pred) with tampered pred {}>={} as: {}'.format(
        canon_attr,
        x_bound,
        ppjson(rc_json)))
    assert not json.loads(rc_json)

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof with specification of two by pred
    proof_req_sri = json.loads(await san.build_proof_req_json({
        cd_id[S_ID['GREEN']]: None,
        cd_id[S_ID['SRI-1.0']]: {
            'attrs': [],
            '>=': {
                'jurisdictionId': 1
            },
            'interval': EPOCH_PRE_SRI_REVOC
        },
        cd_id[S_ID['SRI-1.1']]: {
            'attrs': [
                'jurisdictionId'
            ],
            '>=': {
                'jurisdictionId': 1
            },
            'interval': EPOCH_PRE_SRI_REVOC
        }
    }))
    sri_refts = proof_req_attr_referents(proof_req_sri)
    sri_wql = proof_req2wql_all(proof_req_sri, [cd_id[S_ID['GREEN']]])
    sri_wql[sri_refts[cd_id[S_ID['GREEN']]]['legalName']] = {
        'attr::legalName::value': 'Tart City',
        'attr::greenLevel::value': 'Bronze'
    }
    sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        json.dumps(sri_wql)))
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q.values())

    sri_proof_q = json.loads(await pspcoban.create_proof(proof_req_sri, sri_briefs_q.values(), sri_req_creds_q))
    print('\n\n== 90 == PSPC Org Book multi-cred proof (2 preds jurisdictionId >= 1) for Tart City: {}'.format(
        ppjson(sri_proof_q, 4096)))

    await pspcoban.wallet.close()
    try:  # exercise error path: create proof on closed wallet
        json.loads(await pspcoban.create_proof(proof_req_sri, sri_briefs_q.values(), sri_req_creds_q))
        assert False
    except WalletState:
        pass
    finally:
        await pspcoban.wallet.open()
    print('\n\n== 91 == PSPC Org Book fails as expected to create proof on closed wallet')

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with specification of one by pred
    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 92 == SRI anchor verifies multi-cred proof (2 preds) as: {}'.format(
        ppjson(rc_json)))
    assert json.loads(rc_json)

    revealed_sri = revealed_attrs(sri_proof_q)
    print('\n\n== 93 == Revealed attributes from 2-pred proof: {}'.format(ppjson(revealed_sri)))
    assert (  # do not reveal SRI-1.1:jurisdictionId; in predicates
        [k for k in revealed_sri if revealed_sri[k]] == [cd_id[S_ID['GREEN']]])

    # Exercise helper GET calls
    txn_json = await san.get_txn(schema[S_ID['GREEN']]['seqNo'])
    print('\n\n== 94 == GREEN schema by txn #{}: {}'.format(schema[S_ID['GREEN']]['seqNo'], ppjson(txn_json)))
    assert json.loads(txn_json)
    txn_json = await san.get_txn(99999)  # ought not exist
    assert not json.loads(txn_json)

    bc_box_ids = json.loads(await bcran.get_box_ids_issued())
    print('\n\n== 95 == Box identifiers at BC registrar (issuer): {}'.format(ppjson(bc_box_ids)))
    assert all(box_id.startswith(bcran.did) for ids in bc_box_ids.values() for box_id in ids)
    assert len(bc_box_ids['schema_id']) > 1  # bc-reg, non-revo
    assert len(bc_box_ids['cred_def_id']) > 1  # bc-reg, non-revo
    assert len(bc_box_ids['rev_reg_id']) > 1  # bc-reg on initial short rev reg and second longer one

    # Exercise cache serialization, clearing, parsing, purging
    ArchivableCaches.archive(pspcoban.dir_cache)
    timestamps = listdir(pspcoban.dir_cache)
    assert timestamps

    ArchivableCaches.clear()
    assert not SCHEMA_CACHE.schemata()
    assert not CRED_DEF_CACHE
    assert not REVO_CACHE

    ArchivableCaches.parse(pspcoban.dir_cache)
    assert SCHEMA_CACHE.schemata()
    assert CRED_DEF_CACHE
    assert REVO_CACHE

    ArchivableCaches.purge_archives(pspcoban.dir_cache, True)
    remaining = listdir(pspcoban.dir_cache)
    assert len(remaining) == 1 and remaining[0] == max(timestamps, key=int)

    ArchivableCaches.purge_archives(pspcoban.dir_cache, False)
    remaining = listdir(pspcoban.dir_cache)
    assert not remaining

    print('\n\n== 96 == Archivable caches archive, parse, load, purge OK')

    await bcran.close()
    await bcohan.close()
    await pspcoban.close()
    await san.close()
    await tan.close()
    await p.close()
    await pspcoban.close()  # exercise close on closed pool - should warn and carry on
    for name in wallets:
        await wallets[name].close()

    await bcohan.open()
    await bcohan.close()  # exercise on closed wallet with config to archive caches on close - should warn and carry on


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_offline(pool_name, pool_genesis_txn_path, pool_genesis_txn_file, path_home):

    print(Ink.YELLOW('\n\n== Testing offline anchor operation =='))

    # Set up node pool leder config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    seeds = {
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000',
        'sri': 'SRI-Anchor-000000000000000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    # Open PSPC Org Book anchor and create proof without opening node pool
    p = p_mgr.get(pool_name)
    pspcoban = OrgBookAnchor(
        wallets['pspc-org-book'],
        p,
        config={
            'parse-caches-on-open': True,
            'archive-holder-prover-caches-on-close': False
        })
    await pspcoban.open()
    try:
        await pspcoban.create_link_secret('SecretLink')  # exercise wallet state
        assert False
    except WalletState:
        await wallets['pspc-org-book'].open()
        await pspcoban.create_link_secret('SecretLink')

    # PSPC Org Book anchor (as HolderProver) creates multi-cred proof with specification of one by pred
    cd_id = {}
    schema = {}
    san = ProctorAnchor(wallets['sri'], p, rrbx=False)
    async with wallets['sri']:
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
    ])  # augment to build-proof-req argument
    cd_id2spec[cd_id[S_ID['SRI-1.0']]]['attrs'] = ['legalName']
    cd_id2spec[cd_id[S_ID['SRI-1.1']]]['attrs'] = []
    cd_id2spec[cd_id[S_ID['SRI-1.1']]]['>='] = {'jurisdictionId': 1}

    await san.open()
    proof_req_sri = json.loads(await san.build_proof_req_json(cd_id2spec))
    print('\n\n== 1 == Proof request, default interval from cache content: {}'.format(ppjson(proof_req_sri)))

    sri_refts = proof_req_attr_referents(proof_req_sri)
    sri_wql = proof_req2wql_all(proof_req_sri, [cd_id[S_ID['SRI-1.0']]])
    sri_wql[sri_refts[cd_id[S_ID['SRI-1.0']]]['legalName']] = {
        'attr::legalName::value': 'Tart City'
    }
    sri_briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(
        json.dumps(proof_req_sri),
        json.dumps(sri_wql)))
    sri_req_creds_q = proof_req_briefs2req_creds(proof_req_sri, sri_briefs_q.values())

    sri_proof_q = json.loads(await pspcoban.create_proof(proof_req_sri, sri_briefs_q.values(), sri_req_creds_q))
    print('\n\n== 2 == PSPC Org Book multi-cred proof for Tart City on GE jurisdictionId pred: {}'.format(
        ppjson(sri_proof_q, 4096)))

    # SRI anchor (as Verifier) attempts to verify multi-cred proof with specification of one by pred, offline
    san_cfg = {
        'parse-caches-on-open': True,
        'archive-verifier-caches-on-close': json.loads(await pspcoban.get_box_ids_held())
    }
    san = ProctorAnchor(wallets['sri'], p, config=san_cfg, rrbx=False)

    # Exercise pool/wallet error conditions
    try:
        await san._sign_submit(None)
        assert False
    except ClosedPool:
        pass
    await p.open()
    try:
        await san._sign_submit(None)
        assert False
    except WalletState:
        pass
    await p.close()
    san_pool = san.pool
    san.pool = None
    try:
        await san._sign_submit(None)
        assert False
    except AbsentPool:
        pass
    san.pool = san_pool  # restore pool, carry on
    print('\n\n== 3 == SRI anchor fails as expected on sign-and-submit against bad pool/wallet')

    _set_tails_state(False)  # simulate not having tails file & cache
    _set_cache_state(False)

    await p.open()
    await san.open()  # open on-line, cache and archive from ledger ...
    await san.close()  # ... then close
    await p.close()
    san.config = {
        'parse-caches-on-open': True
    }
    await san.open()  # ... and open off-line

    rc_json = await san.verify_proof(proof_req_sri, sri_proof_q)
    print('\n\n== 4 == SRI anchor verifies multi-cred proof (by pred) off-line as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    _set_tails_state(True)  # restore state
    _set_cache_state(True)  # restore state

    await pspcoban.close()
    await san.close()
    for name in wallets:
        await wallets[name].close()

    ArchivableCaches.purge_archives(pspcoban.dir_cache, False)
    ArchivableCaches.purge_archives(san.dir_cache, False)
    remaining = listdir(pspcoban.dir_cache)
    assert len(remaining) == 0


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_on_nodepool_restart(pool_name, pool_genesis_txn_path, pool_genesis_txn_file, path_home):

    print(Ink.YELLOW('\n\n== Testing anchor survival on node pool restart =='))

    # Set node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    seeds = {
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000',
        'sri': 'SRI-Anchor-000000000000000000000',
        'xxx-org-book': 'XXX-Org-Book-Anchor-000000000000'  # xoban to exercise error cases
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    # Open pool, SRI + Org Book anchors (the tests above should obviate its need for trustee-anchor)
    async with wallets['sri'] as w_sri, (
            wallets['pspc-org-book']) as w_pspc, (
            wallets['xxx-org-book']) as w_xxx, (
            p_mgr.get(pool_name)) as p, (
            ProctorAnchor(w_sri, p, rrbx=False)) as san, (
            OrgBookAnchor(
                w_pspc,
                p,
                config={
                    'parse-caches-on-open': True,
                    'archive-holder-prover-caches-on-close': True
                })) as pspcoban, (
            OrgBookAnchor(w_xxx, p)) as xoban:

        assert p.handle is not None

        xoban.config = {'parse-caches-on-open': False}  # exercise for coverage
        try:  # exercise error path: bad config
            xoban.config = {
                'parse-caches-on-open': 'not-a-bool'
            }
            assert False
        except JSONValidation:
            pass

        # Get schema (should be present in schema cache)
        s_key = schema_key(schema_id(san.did, 'green', '1.0'))
        schema_json = await san.get_schema(schema_key(schema_id(*s_key)))  # should exist
        schema = json.loads(schema_json)
        assert schema

        # Get cred def (should be present in cred def cache), create cred offer
        await san.send_cred_def(schema_id(*s_key))
        cd_id = cred_def_id(s_key.origin_did, schema['seqNo'])
        assert ([f for f in Tails.links(str(san.dir_tails), san.did)
            if cd_id in f] and not Tails.unlinked(str(san.dir_tails)))

        cred_def_json = await pspcoban.get_cred_def(cred_def_id(san.did, schema['seqNo']))
        cred_def = json.loads(cred_def_json)
        print('\n\n== 1 == Cred def [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(json.loads(cred_def_json))))
        assert json.loads(cred_def_json)['schemaId'] == str(schema['seqNo'])

        cred_offer_json = await san.create_cred_offer(schema['seqNo'])
        print('\n\n== 2 == Cred offer [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(cred_offer_json)))

        try:  # exercise error path: cred req creation on no link secret
            await xoban.create_cred_req(cred_offer_json, cred_def_id(san.did, schema['seqNo']))
            assert False
        except AbsentLinkSecret:
            pass
        print('\n\n== 3 == HolderProver fails as expected to create cred req on absent link secret')

    await w_xxx.remove()


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_revo_cache_reg_update_maintenance(pool_name, pool_genesis_txn_path, pool_genesis_txn_file, path_temp):

    print(Ink.YELLOW('\n\n== Testing anchor revocation cache reg update maintenance =='))

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    SRI_NAME = 'sri-0'
    register(_stop_rrbx, SRI_NAME)  # in case of abend

    seeds = {
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000',
        SRI_NAME: 'SRI-Anchor-000000000000000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    path_rrbx_log = join(path_temp, 'rrbx.log')
    rrbx_handler = logging.FileHandler(path_rrbx_log)  # exercise log paths for coverage
    rrbx_handler.setLevel(logging.INFO)
    logging.getLogger('von_anchor.anchor.rrbuilder').addHandler(rrbx_handler)

    async with wallets['pspc-org-book'] as w_pspc, (
            wallets[SRI_NAME]) as w_sri, (
            p_mgr.get(pool_name)) as p, (
            OrgBookAnchor(w_pspc, p, config={
                'parse-caches-on-open': True,
                'archive-holder-prover-caches-on-close': True
            })) as pspcoban, (
            ProctorAnchor(w_sri, p, rrbx=True)) as san:  # exercise external rev reg builder

        nyms = {
            'pspcoban': json.loads(await san.get_nym(pspcoban.did)),
            'san': json.loads(await san.get_nym(san.did))
        }
        try:
            await san.get_nym('not-a-did')  # exercise error path
            assert False
        except BadIdentifier:
            pass
        print('\n\n== 1 == Nyms on ledger: {}'.format(ppjson(nyms)))

        # Exercise error paths for external revocation registry build
        await san.wallet.close()
        try:
            await san.rrb.create_rev_reg(None)
            assert False
        except WalletState:
            pass
        finally:
            await san.wallet.open()
        try:
            await san.rrb.create_rev_reg('not-a-rrid')
            assert False
        except BadIdentifier:
            pass
        print('\n\n== 2 == External revocation registry builder error paths on rev reg build complete OK')

        # Exercise error paths for getting badly specified schema, cred def, rev reg def
        try:
            await san.get_schema(35.5)
            assert False
        except AbsentSchema:
            pass
        try:
            await san.get_schema('ZZZZZZZZZZZZZZZZZZZZZ:2:ZZZZZZ:999.99')
            assert False
        except AbsentSchema:
            pass
        try:
            await san.get_schema(9999999)
            assert False
        except AbsentSchema:
            pass
        try:
            await san.get_cred_def('ZZZZZZZZZZZZZZZZZZZZZ:3:CL:999:tag')
            assert False
        except AbsentCredDef:
            pass
        try:
            await san.get_cred_def('not-a-cdid')
            assert False
        except BadIdentifier:
            pass
        try:
            await san.get_rev_reg_def('ZZZZZZZZZZZZZZZZZZZZZ:4:ZZZZZZZZZZZZZZZZZZZZZ:3:CL:999:tag:CL_ACCUM:99999')
            assert False
        except AbsentRevReg:
            pass
        try:
            await san.get_rev_reg_def('not-a-rrid')
            assert False
        except BadIdentifier:
            pass
        print('\n\n== 3 == SRI anchor fails to get badly specified schema, cred def, rev reg def as expected')

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
        print('\n\n== 4 == Schema for revocation cache exercise [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(schema)))

        # SRI anchor creates credential definition on revocation registry large enough to clean
        RR_SIZE = RevoCacheEntry.MARK[1] + 32
        await san.send_cred_def(s_id, True, RR_SIZE)
        cd_id = cred_def_id(s_key.origin_did, seq_no)
        rr_id = Tails.current_rev_reg_id(san.dir_tails, cd_id)

        # Exercise dir_tails(), path_tails() for coverage
        assert pspcoban.dir_tails(rr_id) == join(DIR_TAILS, cd_id)
        try:
            await pspcoban.dir_tails('not-a-rrid')
            assert False
        except BadIdentifier:
            pass
        assert san.path_tails(rr_id) == join(DIR_TAILS, cd_id, readlink(join(DIR_TAILS, cd_id, rr_id)))
        try:
            await san.path_tails('not-a-rrid')
            assert False
        except BadIdentifier:
            pass
        print('\n\n== 5 == Tails path/dir queries on PSPC Org Book, SRI anchors return as expected')

        assert [f for f in Tails.links(str(san.dir_tails), san.did)
            if cd_id in f] and not Tails.unlinked(str(san.dir_tails))

        cred_def_json = await pspcoban.get_cred_def(cd_id)  # ought to exist now
        cred_def = json.loads(cred_def_json)
        print('\n\n== 6 == Cred def [{} v{}]: {}'.format(
            s_key.name,
            s_key.version,
            ppjson(json.loads(cred_def_json))))
        assert cred_def.get('schemaId', None) == str(seq_no)

        cred_offer_json = await san.create_cred_offer(seq_no)
        print('\n\n== 7 == Credential offer [{} v{}]: {}'.format(s_key.name, s_key.version, ppjson(cred_offer_json)))

        # Set up cred req at PSPC Org Book anchor
        await pspcoban.create_link_secret('SecretLink')
        (cred_req_json, cred_req_metadata_json) = await pspcoban.create_cred_req(cred_offer_json, cred_def['id'])
        print('\n\n== 8 == Credential request [{} v{}]: metadata {}, cred req {}'.format(
            s_key.name,
            s_key.version,
            ppjson(cred_req_metadata_json),
            ppjson(cred_req_json)))
        assert json.loads(cred_req_json)

        print('\n\n== 9 == Creating {} uniquely timestamped credentials and revoking them'.format(RR_SIZE))
        revocation2cred_json = {}  # map creation epoch to cred
        revocation2cred_data = {}
        now = int(time())
        for i in range(RR_SIZE):
            while int(time()) == now:
                sleep(0.1)  # ensure unique timestamps
            print('.', end='' if (i + 1) % 10 else '{}\n'.format(i + 1), flush=True)
            now = int(time())
            cred_data = {
                'id': i,
                'favourite_number': now
            }
            (cred_json, cr_id) = await san.create_cred(
                cred_offer_json,
                cred_req_json,
                cred_data)

            epoch_revocation = await san.revoke_cred(rr_id, cr_id)
            revocation2cred_json[epoch_revocation] = cred_json
            revocation2cred_data[epoch_revocation] = cred_data
            assert json.loads(cred_json)

            await pspcoban.store_cred(cred_json, cred_req_metadata_json)

        assert len(REVO_CACHE[rr_id].rr_delta_frames) == 0  # no queries on it yet

        # PSPC Org Book anchor finds each cred and creates a proof; SRI anchor verifies, which touches revo cache frames
        print('\n\n== 10 == Creating and verifying {} proofs'.format(RR_SIZE))
        cache_frames_size = {}
        i = 0
        for revocation_epoch in revocation2cred_data:
            proof_req = json.loads(await san.build_proof_req_json({
                cd_id: {
                    'interval': revocation_epoch
                }
            }))
            attr_refts = proof_req_attr_referents(proof_req)
            wql_json = json.dumps({
                attr_refts[cd_id][attr]: {
                    'attr::{}::value'.format(attr): revocation2cred_data[revocation_epoch][attr]
                } for attr in revocation2cred_data[revocation_epoch]
            })
            briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(json.dumps(proof_req), wql_json))
            assert len(briefs_q) == 1

            req_creds_q = proof_req_briefs2req_creds(proof_req, briefs_q.values())
            proof_json = await pspcoban.create_proof(proof_req, briefs_q.values(), req_creds_q)
            assert await san.verify_proof(proof_req, json.loads(proof_json))

            cache_frames_size[revocation_epoch] = (
                len(REVO_CACHE[rr_id].rr_delta_frames),
                len(REVO_CACHE[rr_id].rr_state_frames))
            print('  .. 10.{}: after proof for {}, {} revo cache reg (delta, state) frames'.format(
                i,
                revocation_epoch,
                cache_frames_size[revocation_epoch]))
            i += 1

        assert RevoCacheEntry.MARK[0] <= len(REVO_CACHE[rr_id].rr_delta_frames) <= RevoCacheEntry.MARK[1]
        assert RevoCacheEntry.MARK[0] <= len(REVO_CACHE[rr_id].rr_state_frames) <= RevoCacheEntry.MARK[1]

        print('\n\n== 11 == Revocation cache {} reg delta frames cleaned, now ({}, {}) (delta, state) frames'.format(
            rr_id,
            len(REVO_CACHE[rr_id].rr_delta_frames),
            len(REVO_CACHE[rr_id].rr_state_frames)))

    await RevRegBuilder.stop(SRI_NAME)
    assert isfile(path_rrbx_log)
    unlink(path_rrbx_log)
    logging.getLogger('von_anchor.anchor.rrbuilder').removeHandler(rrbx_handler)  # restore original state


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_cache_locking(pool_name, pool_genesis_txn_path, pool_genesis_txn_file):
    THREADS = 256
    threads = []

    print(Ink.YELLOW('\n\n== Testing anchor cache locking =='))

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    seeds = {
        'sri-0': 'SRI-Anchor-000000000000000000000',
        'sri-1': 'SRI-Anchor-111111111111111111111',
        'sri-2': 'SRI-Anchor-222222222222222222222'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False, auto_remove=True)

    async with wallets['sri-0'] as w_sri0, (
            wallets['sri-1']) as w_sri1, (
            wallets['sri-2']) as w_sri2, (
            p_mgr.get(pool_name)) as p, (
            ProctorAnchor(w_sri0, p, rrbx=False)) as san0, (
            ProctorAnchor(w_sri1, p, rrbx=False)) as san1, (
            ProctorAnchor(w_sri2, p, rrbx=False)) as san2:

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
async def test_anchor_reseed(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing anchor reseed'))

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)
    w_mgr = WalletManager()

    now = int(time())  # ten digits, unique and disposable each run
    rsoban_seeds = ['Reseed-Org-Book-Anchor{}'.format(now + i) for i in range(3)]  # makes 32 characters
    # Generate seeds (in case of re-run on existing ledger, use fresh disposable identity every time)
    print('\n\n== 1 == Seeds: {}'.format(rsoban_seeds))

    seeds = {
        'trustee-anchor': seed_trustee1,
        'reseed-org-book': rsoban_seeds[0]
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    # Open pool, init anchors
    async with wallets['trustee-anchor'] as w_trustee, (
            wallets['reseed-org-book']) as w_reseed, (
            p_mgr.get(pool_name)) as p, (
            TrusteeAnchor(w_trustee, p)) as tan, (
            OrgBookAnchor(w_reseed, p)) as rsan, (
            NominalAnchor(w_reseed, p)) as noman:
        assert p.handle

        # Publish anchor particulars to ledger if not yet present (almost certainly absent)
        did2an = {}
        for an in (tan, rsan):
            did2an[an.did] = an
            if not json.loads(await tan.get_nym(an.did)):
                await tan.send_nym(an.did, an.verkey, an.wallet.name, an.least_role())

        nyms = {
            'tan': json.loads(await tan.get_nym(tan.did)),
            'rsan': json.loads(await tan.get_nym(rsan.did))
        }
        print('\n\n== 2 == Nyms on ledger: {}'.format(ppjson(nyms)))

        for k in nyms:
            assert 'dest' in nyms[k]

        await rsan.create_link_secret('SecretLink')

        try:
            terminus = int(time())
            while True:
                cand_did = 'ZZZZZZZZZZZ{}'.format(str(terminus).replace('0', '1'))
                if not json.loads(await tan.get_nym(cand_did)):
                    await tan.get_nym_role(cand_did)  # exercise error path where target DID not on ledger
                    assert False
                terminus += 1
        except AbsentNym:
            pass

        # Anchor reseed wallet
        old_found_did = await rsan.wallet.get_public_did()
        assert old_found_did == rsan.did
        verkey_in_wallet = (await rsan.wallet.get_local_did(rsan.did)).verkey
        print('\n\n== 3 == Public DID {}, verkey in wallet {}'.format(rsan.did, verkey_in_wallet))
        nym_resp = json.loads(await rsan.get_nym(rsan.did))
        print('\n\n== 4 == Anchor nym on ledger {}'.format(ppjson(nym_resp)))

        old_rsan_verkey = rsan.verkey
        old_rsan_nym_role = await rsan.get_nym_role()
        await rsan.reseed(rsoban_seeds[1])
        assert rsan.verkey != old_rsan_verkey
        assert old_found_did == await rsan.wallet.get_public_did()
        assert old_found_did == rsan.did
        assert await rsan.get_nym_role() == old_rsan_nym_role

        verkey_in_wallet = (await rsan.wallet.get_local_did(rsan.did)).verkey
        print('\n\n== 5 == Anchor reseed operation retains DID {} and role {} on rekey from {} to {}'.format(
            rsan.did,
            old_rsan_nym_role.token(),
            old_rsan_verkey,
            rsan.verkey))

        old_rsan_verkey = rsan.verkey
        await noman.reseed(rsoban_seeds[2])
        assert noman.verkey != old_rsan_verkey
        assert rsan.verkey == noman.verkey
        assert old_found_did == await rsan.wallet.get_public_did()
        assert old_found_did == rsan.did
        assert await noman.get_nym_role() == old_rsan_nym_role

        print('\n\n== 6 == Nominal anchor reseed on org book anchor wallet retains DID {} and role {} on rekey'.format(
            rsan.did,
            old_rsan_nym_role.token()))

        old_rsan_verkey = rsan.verkey

    # Open pool, init anchor again for random seed test
    async with p_mgr.get(pool_name) as p, (
            wallets['reseed-org-book']) as w_reseed, (
            OrgBookAnchor(w_reseed, p)) as rsan:
        assert p.handle

        await rsan.create_link_secret('SecretLink')

        # Anchor reseed wallet on random seed
        old_found_did = await rsan.wallet.get_public_did()
        assert old_found_did == rsan.did
        verkey_in_wallet = (await rsan.wallet.get_local_did(rsan.did)).verkey
        print('\n\n== 7 == Public DID {}, verkey in wallet {}'.format(rsan.did, verkey_in_wallet))
        nym_resp = json.loads(await rsan.get_nym(rsan.did))
        print('\n\n== 8 == Anchor nym on ledger {}'.format(ppjson(nym_resp)))

        old_rsan_verkey = rsan.verkey
        old_rsan_nym_role = await rsan.get_nym_role()
        await rsan.reseed()
        assert rsan.verkey != old_rsan_verkey
        assert old_found_did == await rsan.wallet.get_public_did()
        assert old_found_did == rsan.did
        assert await rsan.get_nym_role() == old_rsan_nym_role

        verkey_in_wallet = (await rsan.wallet.get_local_did(rsan.did)).verkey
        print('\n\n== 9 == Anchor random-reseed operation retains DID {} and role {} on rekey from {} to {}'.format(
            rsan.did,
            old_rsan_nym_role.token(),
            old_rsan_verkey,
            rsan.verkey))

    # Re-open and check auto-remove setting survival on reset
    w_rsob = w_mgr.get({'id': 'reseed-org-book', 'auto_remove': True})
    await w_rsob.open()  # avoid context manager open for wallet, since resetting closes it and switches it
    async with NodePool(pool_name) as p, OrgBookAnchor(w_rsob, p) as rsan:
        assert p.handle

        print('\n\n== 10 == Re-opened anchor with wallet on new seed: using verkey {}'.format(rsan.verkey))
        await rsan.reset_wallet(seeds[rsan.wallet.name])
        assert rsan.wallet.auto_remove  # make sure auto-remove configuration survives reset
    await rsan.wallet.close()  # it's a new wallet object

@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_anchors_cache_only(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing proof/verification from cache only =='))

    _set_cache_state(False)

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    seeds = {
        'sri': 'SRI-Anchor-000000000000000000000',
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=True)

    # Create pool, init anchors, then open pool afterward
    p = p_mgr.get(pool_name)

    san = ProctorAnchor(wallets['sri'], p, rrbx=False)
    pspcoban = OrgBookAnchor(
        wallets['pspc-org-book'],
        p,
        config={
            'parse-caches-on-open': True,
            'archive-holder-prover-caches-on-close': True
        })

    await p.open()
    assert p.handle

    await san.open()
    await pspcoban.open()
    await pspcoban.create_link_secret('SecretLink')
    await pspcoban.reset_wallet(seeds[pspcoban.wallet.name])
    wallets[pspcoban.wallet.name] = pspcoban.wallet  # hot-swap: reset already closed and deleted old one

    # Publish schema to ledger if not yet present; get from ledger
    S_ID = {
        'IDENT': schema_id(san.did, 'ident', '1.0'),  # non-revocable
        'FAV-NUM': schema_id(san.did, 'fav-num', '1.0'),
        'FAV-CHAR': schema_id(san.did, 'fav-char', '1.0')
    }

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
            await san.get_schema(s_key)  # may exist
        except AbsentSchema:
            await san.send_schema(json.dumps(schema_data[s_id]))
        schema_json[s_id] = await san.get_schema(s_key)
        schema[s_id] = json.loads(schema_json[s_id])
        assert schema[s_id]  # should exist now

        seq_no2schema_id[schema[s_id]['seqNo']] = s_id
        seq_no2schema[schema[s_id]['seqNo']] = schema[s_id]
        print('\n\n== 1.{} == Schema [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
        assert schema[s_id]
        i += 1

    try:  # exercise error path: bad schema id
        await san.send_cred_def('not-a-schema-id')
        assert False
    except BadIdentifier:
        pass
    RR_SIZE = 4
    RR_PER_CD = 6
    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)

        await san.send_cred_def(s_id, s_id != S_ID['IDENT'], RR_SIZE)  # make rev regs tiny: want many rev regs in cache
        cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

        assert (s_id == S_ID['IDENT']) or (
            [f for f in Tails.links(str(san.dir_tails), san.did)
                if cd_id[s_id] in f] and not Tails.unlinked(str(san.dir_tails)))

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

    # Setup link secret for creation of cred req or proof
    await pspcoban.create_link_secret('SecretLink')

    i = 0
    for s_id in schema_data:
        s_key = schema_key(s_id)
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await pspcoban.create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id])
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 3.{} == Credential request [{} v{}]: metadata {}, cred req {}'.format(
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
    for i in range(len(cred_def) * RR_PER_CD * RR_SIZE):
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
                'num': float_info.max if (i//len(cd_id)) == RR_PER_CD * RR_SIZE - 1  # set one max float last
                    else randint(1, 100) if (i//12)
                    else 0  # set 4 fixed points for querying
                # 'num': randint(1, 100) if (i//12) else 0  # set 4 fixed points for querying
            },
            {
                'ident': i//3,
                'char': choice(printable) if (i//3) else 'Q'  # set fixed points for querying
            }
        ][i % len(cd_id)]
        (cred_json, _) = await san.create_cred(
            cred_offer_json[s_id],
            cred_req_json[s_id],
            cred_data,
            RR_SIZE)
        epoch_creation = int(time())
        cd_id2creation2cred_json[cd_id[s_id]][epoch_creation] = cred_json
        cd_id2creation2cred_data[cd_id[s_id]][epoch_creation] = cred_data
        assert json.loads(cred_json)

        await pspcoban.store_cred(cred_json, cred_req_metadata_json[s_id])

    await pspcoban.load_cache_for_proof(False)
    san_cfg = {
        'parse-caches-on-open': True,
        'archive-verifier-caches-on-close': json.loads(await pspcoban.get_box_ids_held())
    }
    san.config = san_cfg
    await san.load_cache_for_verification(False)

    await pspcoban.wallet.close()
    try:
        await pspcoban.get_box_ids_held()
        assert False
    except WalletState:
        pass
    finally:
        await pspcoban.wallet.open()

    assert any(cd_id[S_ID['FAV-NUM']] in r for r in await pspcoban.rev_regs())  # exercise for coverage
    try:
        await pspcoban.offline_intervals('not-a-cdid')
        assert False
    except BadIdentifier:
        pass
    await pspcoban.offline_intervals([cd_id[S_ID['FAV-NUM']], cd_id[S_ID['FAV-CHAR']]])
    print('\n\n== 5 == Revocation data for HolderProver checks OK')

    await p.close()  # The pool is now closed - from here on in, we are off-line

    try:
        await pspcoban.offline_intervals(cred_def_id(san.did, 99999))
        assert False
    except CacheIndex:
        pass
    print('\n\n== 6 == HolderProver needs pool to get offline intervals for rev reg on cred def id not in wallet: OK')

    # PSPC org book anchor provides default intervals per cred def id, SRI anchor builds proof req
    cd_id2spec = await pspcoban.offline_intervals(list(cd_id.values()))
    for c in cd_id2spec:
        cd_id2spec[c]['attrs'] = schema_data[seq_no2schema_id[cred_def_id2schema_seq_no_or_id(c)]]['attr_names']
    proof_req_json = await san.build_proof_req_json(cd_id2spec)
    proof_req = json.loads(proof_req_json)
    print('\n\n== 7 == Proof req from cache data: {}'.format(ppjson(proof_req_json)))

    # PSPC org book anchor gets cred-briefs via query, creates multi-cred proof
    refts = proof_req_attr_referents(proof_req)
    wql_id0 = {  # everything on ident=0, in all cred defs
        refts[cd_id[s_id]]['ident']: {  # require presence of attr 'ident' of all cred defs
            'attr::ident::value': 0
        } for s_id in cd_id
    }
    print('\n\n== 8 == WQL to find all cred briefs on ident=0 over all cred defs: {}'.format(ppjson(wql_id0)))
    wql_id0_json = json.dumps(wql_id0)
    briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(proof_req_json, wql_id0_json))
    assert len(briefs_q) == len(cred_def)  # by construction, one per cred def
    print('\n\n== 9 == Found cred briefs on ident=0 over all cred defs: briefs {}'.format(ppjson(briefs_q)))
    assert any(brief['cred_info']['attrs'].get('num', None) == raw(0)
        and brief['cred_info']['cred_def_id'] == cd_id[S_ID['FAV-NUM']] for brief in briefs_q.values())
    assert any(brief['cred_info']['attrs'].get('char', None) == raw('Q')
        and brief['cred_info']['cred_def_id'] == cd_id[S_ID['FAV-CHAR']] for brief in briefs_q.values())
    req_creds_q = proof_req_briefs2req_creds(proof_req, briefs_q.values())
    print('\n\n== 10 == Proof req and briefs created req-creds: {}'.format(ppjson(req_creds_q)))
    proof_q = json.loads(await pspcoban.create_proof(proof_req, briefs_q.values(), req_creds_q))
    print('\n\n== 11 == Proof via query: {}'.format(ppjson(proof_q, 4096)))

    # SRI anchor (as Verifier) verifies proof (by query)
    rc_json = await san.verify_proof(proof_req, proof_q)
    print('\n\n== 12 == SRI anchor verifies proof by query as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # PSPC org book anchor gets to many cred-briefs to prove via query, fails to create multi-cred non-proof
    wql_all = proof_req2wql_all(proof_req)
    wql_all_json = json.dumps(wql_all)
    print('\n\n== 13 == WQL to find all {} cred briefs: {}'.format(
        len(cred_def) * RR_PER_CD * RR_SIZE,
        ppjson(wql_all)))
    briefs_all_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(proof_req_json, wql_all_json))
    print('\n\n== 14 == Found {} cred briefs on search for all by query'.format(len(briefs_all_q)))
    assert len(briefs_all_q) == len(cred_def) * RR_PER_CD * RR_SIZE
    req_creds_all_q = proof_req_briefs2req_creds(proof_req, briefs_all_q.values())
    try:
        await pspcoban.create_proof(proof_req, briefs_all_q.values(), req_creds_all_q)
        assert False
    except CredentialFocus:
        pass
    print('\n\n== 15 == Anchor correctly refused to create proof given multiple cred-briefs on a cred def')

    # SRI anchor builds proof req for single cred on FAV-NUM cred-def
    cd_id2spec = await pspcoban.offline_intervals([cd_id[S_ID['FAV-NUM']]])
    cd_id2spec[cd_id[S_ID['FAV-NUM']]]['attrs'] = schema_data[
        seq_no2schema_id[cred_def_id2schema_seq_no_or_id(cd_id[S_ID['FAV-NUM']])]]['attr_names']  # request all attrs
    proof_req_json = await san.build_proof_req_json(cd_id2spec)
    proof_req = json.loads(proof_req_json)
    print('\n\n== 16 == Proof req for single fav-num cred from cache data: {}'.format(ppjson(proof_req_json)))

    # PSPC org book anchor gets cred-brief via query, creates single-cred proof
    refts = proof_req_attr_referents(proof_req)
    wql_1 = {
        refts[cd_id[S_ID['FAV-NUM']]]['ident']: {
            'attr::ident::value': 1
        }
    }
    print('\n\n== 17 == WQL to find single cred brief on ident=1 for fav-num cred def: {}'.format(ppjson(wql_1)))
    wql_1_json = json.dumps(wql_1)
    briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(proof_req_json, wql_1_json))
    assert len(briefs_q) == 1
    print('\n\n== 18 == Found cred brief on ident=1 for fav-num cred def: {}'.format(ppjson(briefs_q)))
    assert any(brief['cred_info']['attrs'].get('ident', None) == raw(1)
        and brief['cred_info']['cred_def_id'] == cd_id[S_ID['FAV-NUM']] for brief in briefs_q.values())
    req_creds_q = proof_req_briefs2req_creds(proof_req, briefs_q.values())
    print('\n\n== 19 == Proof req and briefs created req-creds: {}'.format(ppjson(req_creds_q)))
    proof_q = json.loads(await pspcoban.create_proof(proof_req, briefs_q.values(), req_creds_q))
    print('\n\n== 20 == Proof via query: {}'.format(ppjson(proof_q, 4096)))

    # SRI org book verifies single-cred proof (by query)
    rc_json = await san.verify_proof(proof_req, proof_q)
    print('\n\n== 21 == SRI anchor verifies single-cred proof (by query) off-line as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # SRI anchor builds proof req for single cred on FAV-NUM cred-def
    cd_id2spec = await pspcoban.offline_intervals([cd_id[S_ID['FAV-NUM']]])
    cd_id2spec[cd_id[S_ID['FAV-NUM']]]['attrs'] = schema_data[
        seq_no2schema_id[cred_def_id2schema_seq_no_or_id(cd_id[S_ID['FAV-NUM']])]]['attr_names']  # request all attrs
    proof_req_json = await san.build_proof_req_json(cd_id2spec)
    proof_req = json.loads(proof_req_json)
    print('\n\n== 22 == Proof req for single fav-num cred from cache data: {}'.format(ppjson(proof_req_json)))

    # PSPC org book anchor gets cred-brief via query, creates single-cred proof
    refts = proof_req_attr_referents(proof_req)
    wql_float_max = {
        refts[cd_id[S_ID['FAV-NUM']]]['num']: {
            'attr::num::value': float_info.max - 9.9792e291  # rounds to float_info.max but not for much more error
        }
    }
    print('\n\n== 23 == WQL to find single cred brief on fav-num=max float: {}'.format(ppjson(wql_float_max)))
    wql_float_max_json = json.dumps(wql_float_max)
    briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(proof_req_json, wql_float_max_json))
    assert len(briefs_q) == 1
    print('\n\n== 24 == Found cred brief on fav-num=max float: {}'.format(ppjson(briefs_q)))
    assert any(brief['cred_info']['attrs'].get('num', None) == raw(float_info.max)
        and brief['cred_info']['cred_def_id'] == cd_id[S_ID['FAV-NUM']] for brief in briefs_q.values())
    req_creds_q = proof_req_briefs2req_creds(proof_req, briefs_q.values())
    print('\n\n== 25 == Proof req and briefs created req-creds: {}'.format(ppjson(req_creds_q)))
    proof_q = json.loads(await pspcoban.create_proof(proof_req, briefs_q.values(), req_creds_q))
    print('\n\n== 26 == Proof via query: {}'.format(ppjson(proof_q, 4096)))

    # SRI org book verifies single-cred proof (by query)
    rc_json = await san.verify_proof(proof_req, proof_q)
    print('\n\n== 27 == SRI anchor verifies single-cred proof (by query) off-line as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # PSPC org book anchor gets cred-brief via query, creates single-cred proof for ident 0 and fav num 0
    wql_00 = {
        refts[cd_id[S_ID['FAV-NUM']]]['ident']: {  # require presence of FAV-NUM attr 'ident' ('num' would also do)
            'attr::ident::value': 0,
            'attr::num::value': 0
        }
    }
    print('\n\n== 28 == WQL to find (unique) cred brief on ident=0, num=0 for fav-num cred def: {}'.format(
        ppjson(wql_00)))
    wql_00_json = json.dumps(wql_00)
    briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(proof_req_json, wql_00_json))
    print('\n\n== 29 == Found {} cred brief{} on fav-num cred def: {}'.format(
        len(briefs_q),
        's' if len(briefs_q) > 1 else '',
        ppjson(briefs_q)))
    assert len(briefs_q) == 1
    assert any(brief['cred_info']['attrs'].get('ident', None) == raw(0)
        and brief['cred_info']['cred_def_id'] == cd_id[S_ID['FAV-NUM']] for brief in briefs_q.values())
    assert any(brief['cred_info']['attrs'].get('num', None) == raw(0)
        and brief['cred_info']['cred_def_id'] == cd_id[S_ID['FAV-NUM']] for brief in briefs_q.values())
    req_creds_q = proof_req_briefs2req_creds(proof_req, briefs_q.values())
    print('\n\n== 30 == Proof req, briefs created req-creds: {}'.format(ppjson(req_creds_q)))
    proof_q = json.loads(await pspcoban.create_proof(proof_req, briefs_q.values(), req_creds_q))
    print('\n\n== 31 == Proof via query: {}'.format(ppjson(proof_q, 4096)))

    # SRI org book verifies single-cred proof (by query)
    rc_json = await san.verify_proof(proof_req, proof_q)
    print('\n\n== 32 == SRI anchor verifies single-cred proof (by query) off-line as: {}'.format(ppjson(rc_json)))
    assert json.loads(rc_json)

    # PSPC org book anchor provides default intervals per cred def id, SRI anchor builds proof req
    cd_id2spec = await pspcoban.offline_intervals([cd_id[S_ID['FAV-NUM']]])
    proof_req_json = await san.build_proof_req_json(cd_id2spec)
    proof_req = json.loads(proof_req_json)
    print('\n\n== 33 == Proof req from cache data on fav-num cred def attrs: {}'.format(ppjson(proof_req_json)))

    # PSPC org book anchor gets cred-briefs via query for ident 23 or fav num 0
    refts = proof_req_attr_referents(proof_req)
    wql_230 = {
        refts[cd_id[S_ID['FAV-NUM']]]['ident']: {  # require presence of FAV-NUM attr 'ident' ('num' would also do)
            '$or': [
                {
                    'attr::ident::value': 23
                },
                {
                    'attr::num::value': 0
                },
            ]
        },
    }
    print('\n\n== 34 WQL to find cred briefs on ident=23 or num=0 for fav-num cred def: {}'.format(
        ppjson(wql_230)))
    wql_230_json = json.dumps(wql_230)
    briefs_q = json.loads(await pspcoban.get_cred_briefs_by_proof_req_q(proof_req_json, wql_230_json))
    print('\n\n== 35 == Found {} cred brief{} on fav-num cred def: {}'.format(
        len(briefs_q),
        's' if len(briefs_q) > 1 else '',
        ppjson(briefs_q)))
    assert len(briefs_q) == 5

    await san.close()
    await pspcoban.close()

    for name in wallets:
        await wallets[name].close()

    _set_cache_state(True)
    ArchivableCaches.purge_archives(pspcoban.dir_cache, False)


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_catpol(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing credential attribute tagging policy =='))

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    seeds = {
        'trustee-anchor': seed_trustee1,
        'sri': 'SRI-Anchor-000000000000000000000',
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    # Open pool, init anchors
    async with wallets['trustee-anchor'] as w_trustee, (
            wallets['sri']) as w_sri, (
            wallets['pspc-org-book']) as w_pspc, (
            p_mgr.get(pool_name)) as p, (
            TrusteeAnchor(w_trustee, p)) as tan, (
            ProctorAnchor(w_sri, p, rrbx=False)) as san, (
            OrgBookAnchor(w_pspc, p, config={
                'parse-caches-on-open': True,
                'archive-holder-prover-caches-on-close': True
            })) as pspcoban:

        assert p.handle is not None

        # Publish anchor particulars to ledger if not yet present
        for an in (san, pspcoban):
            if not json.loads(await tan.get_nym(an.did)):
                await tan.send_nym(an.did, an.verkey, an.wallet.name, an.least_role())

        nyms = {
            'san': json.loads(await san.get_nym(san.did)),
            'pspcoban': json.loads(await san.get_nym(pspcoban.did))
        }
        print('\n\n== 1 == Nyms on ledger: {}'.format(ppjson(nyms)))

        for k in nyms:
            assert 'dest' in nyms[k]

        # Publish schema to ledger
        S_ID = {
            'DRINK': schema_id(san.did, 'drink', '{}.0'.format(int(time())))
        }

        schema_data = {
            S_ID['DRINK']: {
                'name': schema_key(S_ID['DRINK']).name,
                'version': schema_key(S_ID['DRINK']).version,
                'attr_names': [
                    'ident',
                    'drink'
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
        cred_id = {}
        cred_info = {}
        cred_brief = {}
        cred_req_json = {}
        cred_req = {}
        cred_json = {}
        cred_req_metadata_json = {}
        cred = {}

        i = 0
        seq_no = None
        for s_id in schema_data:
            s_key = schema_key(s_id)
            try:
                await san.get_schema(s_key)  # may exist
            except AbsentSchema:
                await san.send_schema(json.dumps(schema_data[s_id]))
            schema_json[s_id] = await san.get_schema(s_key)
            assert json.loads(schema_json[s_id])  # should exist now

            schema[s_id] = json.loads(schema_json[s_id])
            seq_no2schema_id[schema[s_id]['seqNo']] = s_id
            print('\n\n== 2.{} == Schema [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
            assert schema[s_id]
            i += 1

        # SRI anchor creates, stores, publishes cred definition to ledger; creates cred offer
        i = 0
        for s_id in schema_data:
            s_key = schema_key(s_id)

            await san.send_cred_def(s_id, False, None)
            cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

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

        # Setup link secret for creation of cred req or proof
        await pspcoban.create_link_secret('SecretLink')

        i = 0
        for s_id in schema_data:
            s_key = schema_key(s_id)
            (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await pspcoban.create_cred_req(
                cred_offer_json[s_id],
                cd_id[s_id])
            cred_req[s_id] = json.loads(cred_req_json[s_id])
            print('\n\n== 4.{} == Credential request [{} v{}]: metadata {}, cred req {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(cred_req_metadata_json[s_id]),
                ppjson(cred_req_json[s_id])))
            assert json.loads(cred_req_json[s_id])
            i += 1

        # Prover sets up credential attr tag policy
        await pspcoban.set_cred_attr_tag_policy(
            cd_id[S_ID['DRINK']],
            ' DR INK',  # exercise scalar, canonicalization
            retroactive=False)
        catpol = json.loads(await pspcoban.get_cred_attr_tag_policy(cd_id[S_ID['DRINK']]))
        assert catpol == ['drink']
        await pspcoban.set_cred_attr_tag_policy(
            cd_id[S_ID['DRINK']],
            ['drink'],  # exercise list
            retroactive=False)
        catpol = json.loads(await pspcoban.get_cred_attr_tag_policy(cd_id[S_ID['DRINK']]))
        assert catpol == ['drink']
        await pspcoban.set_cred_attr_tag_policy(
            cd_id[S_ID['DRINK']],
            {'drink'},  # exercise set
            retroactive=False)

        # Issuer issues creds and stores at HolderProver: get cred req, create cred, store cred
        cred_data = {
            S_ID['DRINK']: {
                'ident': 'GC-12345',
                'drink': 'martini'
            }
        }
        try:  # exercise error case with bad cred def id
            x_cred_offer = json.loads(cred_offer_json[s_id])
            x_cred_offer['cred_def_id'] = 'not-a-cdid'
            await san.create_cred(
                json.dumps(x_cred_offer),
                cred_req_json[s_id],
                cred_data[s_id])
            assert False
        except BadIdentifier:
            pass

        i = 0
        for s_id in cred_data:
            (cred_json[s_id], _) = await san.create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                cred_data[s_id])
            epoch_creation = int(time())
            assert json.loads(cred_json[s_id])
            print('\n\n== 5.{} == Issuer created cred at epoch {}: {}'.format(
                i,
                epoch_creation,
                ppjson(cred_json[s_id])))
            cred = json.loads(cred_json[s_id])

            cred_id[s_id] = await pspcoban.store_cred(
                cred_json[s_id],
                cred_req_metadata_json[s_id])

            print('\n\n== 5.{}.1 == Cred id on {} in wallet: {}'.format(i, s_id, cred_id[s_id]))
            i += 1

        # PSPC Org Book anchor gets cred-briefs via query, exercising credential attr tag policy
        wql = {
            attr: {
                'cred_def_id': cd_id[S_ID['DRINK']],
                'attr::{}::marker'.format(attr): 1  # exercise canonicalization to str(1)
            } for attr in ['ident', 'drink']
        }

        catpol = json.loads(await pspcoban.get_cred_attr_tag_policy(cd_id[S_ID['DRINK']]))
        assert catpol == ['drink']
        print('\n\n== 6 == PSPC Org book anchor credential attribute tagging policy: {}'.format(ppjson(catpol)))

        # PSPC Org Book anchor searches for credentials to exercise attribute tagging policy
        i = 0
        for attr in wql:
            cred_infos = json.loads(await pspcoban.get_cred_infos_by_q(json.dumps(wql[attr])))
            assert len(cred_infos) == (1 if attr in catpol else 0)
            print('\n\n== 7.{} == WQL: {}, found {} as expected'.format(i, ppjson(wql[attr]), len(cred_infos)))
            i += 1

        # PSPC Org Book clears credential attr tag policy, non-retroactively
        await pspcoban.set_cred_attr_tag_policy(cd_id[S_ID['DRINK']], None, retroactive=False)
        catpol = json.loads(await pspcoban.get_cred_attr_tag_policy(cd_id[S_ID['DRINK']]))
        assert catpol == None
        print('\n\n== 8 == PSPC Org book anchor set credential attribute tagging policy non-retroactively: {}'.format(
            ppjson(catpol)))

        # PSPC Org Book anchor searches for credentials to exercise attribute tagging policy
        i = 0
        for attr in wql:
            cred_infos = json.loads(await pspcoban.get_cred_infos_by_q(json.dumps(wql[attr])))
            assert len(cred_infos) == {'drink': 1, 'ident': 0}[attr]  # old policy for creds in wallet before set-catpol
            print('\n\n== 9.{} == WQL: {}, found {} as expected'.format(i, ppjson(wql[attr]), len(cred_infos)))
            i += 1

        # PSPC Org Book sets credential attr tag policy, retroactively
        await pspcoban.set_cred_attr_tag_policy(cd_id[S_ID['DRINK']], ['ident'], retroactive=True)
        catpol = json.loads(await pspcoban.get_cred_attr_tag_policy(cd_id[S_ID['DRINK']]))
        assert catpol == ['ident']
        print('\n\n== 10 == PSPC Org book anchor set credential attribute tagging policy retroactively: {}'.format(
            ppjson(catpol)))

        # PSPC Org Book anchor searches for credentials to exercise attribute tagging policy
        i = 0
        for attr in wql:
            cred_infos = json.loads(await pspcoban.get_cred_infos_by_q(json.dumps(wql[attr])))
            assert len(cred_infos) == (1 if attr in catpol else 0)  # catpol is retroactive
            print('\n\n== 11.{} == WQL: {}, found {} as expected'.format(i, ppjson(wql[attr]), len(cred_infos)))
            i += 1

        # PSPC Org Book clears credential attr tag policy, retroactively
        await pspcoban.set_cred_attr_tag_policy(cd_id[S_ID['DRINK']], None, retroactive=True)
        catpol = json.loads(await pspcoban.get_cred_attr_tag_policy(cd_id[S_ID['DRINK']]))
        assert catpol == None
        print('\n\n== 12 == PSPC Org book anchor set credential attribute tagging policy retroactively: {}'.format(
            ppjson(catpol)))

        # PSPC Org Book anchor searches for credentials to exercise attribute tagging policy
        i = 0
        for attr in wql:
            cred_infos = json.loads(await pspcoban.get_cred_infos_by_q(json.dumps(wql[attr])))
            assert len(cred_infos) == 1  # catpol is retroactive
            print('\n\n== 13.{} == WQL: {}, found {} as expected'.format(i, ppjson(wql[attr]), len(cred_infos)))
            i += 1


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_util_wranglers(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing utility wranglers =='))

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    register(_stop_rrbx, 'sri')  # in case of abend
    seeds = {
        'sri': 'SRI-Anchor-000000000000000000000',
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    # Open pool, init anchors
    async with wallets['sri'] as w_sri, (
            wallets['pspc-org-book']) as w_pspc, (
            p_mgr.get(pool_name)) as p, (
            ProctorAnchor(w_sri, p, rrbx=True)) as san, (
            OrgBookAnchor(w_pspc, p, config={
                'parse-caches-on-open': True,
                'archive-holder-prover-caches-on-close': True
            })) as pspcoban:

        assert p.handle is not None

        nyms = {
            'san': json.loads(await san.get_nym(san.did)),
            'pspcoban': json.loads(await san.get_nym(pspcoban.did))
        }
        print('\n\n== 1 == Nyms on ledger: {}'.format(ppjson(nyms)))

        for k in nyms:
            assert 'dest' in nyms[k]

        # Publish schema to ledger if not yet present; get from ledger
        S_ID = {
            'NON-REVO-X': schema_id(san.did, 'non-revo-x', '1.0'),
            'REVO-X': schema_id(san.did, 'revo-x', '1.0')
        }

        schema_data = {
            S_ID['NON-REVO-X']: {
                'name': schema_key(S_ID['NON-REVO-X']).name,
                'version': schema_key(S_ID['NON-REVO-X']).version,
                'attr_names': [
                    'ident',
                    'role',
                    'epochExpiry'
                ]
            },
            S_ID['REVO-X']: {
                'name': schema_key(S_ID['REVO-X']).name,
                'version': schema_key(S_ID['REVO-X']).version,
                'attr_names': [
                    'ident',
                    'r',
                    'g',
                    'b'
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
        cred_id = {}
        cred_info = {}
        cred_brief = {}
        cred_req_json = {}
        cred_req = {}
        cred_json = {}
        cred_req_metadata_json = {}
        cred = {}

        i = 0
        seq_no = None
        for s_id in schema_data:
            s_key = schema_key(s_id)
            try:
                await san.get_schema(s_key)  # may exist
            except AbsentSchema:
                await san.send_schema(json.dumps(schema_data[s_id]))
            schema_json[s_id] = await san.get_schema(s_key)
            assert json.loads(schema_json[s_id])  # should exist now

            schema[s_id] = json.loads(schema_json[s_id])
            seq_no2schema_id[schema[s_id]['seqNo']] = s_id
            print('\n\n== 2.{} == Schema [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
            assert schema[s_id]
            i += 1

        # SRI anchor creates, stores, publishes cred definitions to ledger; creates cred offers
        i = 0
        for s_id in schema_data:
            s_key = schema_key(s_id)

            await san.send_cred_def(
                s_id,
                s_id != S_ID['NON-REVO-X'],
                4 if s_id == S_ID['REVO-X'] else None)
            cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

            assert (s_id == S_ID['NON-REVO-X']) or (
                [f for f in Tails.links(str(san.dir_tails), san.did)
                    if cd_id[s_id] in f] and not Tails.unlinked(str(san.dir_tails)))

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

        # Setup link secret for creation of cred req or proof
        await pspcoban.create_link_secret('SecretLink')

        i = 0
        for s_id in schema_data:
            s_key = schema_key(s_id)
            (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await pspcoban.create_cred_req(
                cred_offer_json[s_id],
                cd_id[s_id])
            cred_req[s_id] = json.loads(cred_req_json[s_id])
            print('\n\n== 4.{} == Credential request [{} v{}]: metadata {}, cred req {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(cred_req_metadata_json[s_id]),
                ppjson(cred_req_json[s_id])))
            assert json.loads(cred_req_json[s_id])
            i += 1

        # Issuer issues creds and stores at HolderProver: get cred req, create cred, store cred
        cred_data = {
            S_ID['NON-REVO-X']: {
                'ident': 'GC-12345',
                'role': 'supervisor',
                'epochExpiry': int(time()) + (8 * 60 * 60)
            },
            S_ID['REVO-X']: {
                'ident': 'GC-12345',
                'r': choice(range(256)),
                'g': choice(range(256)),
                'b': choice(range(256))
            }
        }

        i = 0
        for s_id in cred_data:
            (cred_json[s_id], cred_revoc_id) = await san.create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                cred_data[s_id])
            epoch_creation = int(time())
            assert json.loads(cred_json[s_id])
            print('\n\n== 5.{} == Issuer created cred (revoc id {}) at epoch {}: {}'.format(
                i,
                cred_revoc_id,
                epoch_creation,
                ppjson(cred_json[s_id])))
            cred = json.loads(cred_json[s_id])

            cred_id[s_id] = await pspcoban.store_cred(
                cred_json[s_id],
                cred_req_metadata_json[s_id])
            assert (s_id == S_ID['NON-REVO-X'] or
                not Tails.unlinked(DIR_TAILS))  # storage should get rev reg def from ledger and link its id

            print('\n\n== 5.{}.1 == Cred id on {} in wallet: {}'.format(i, s_id, cred_id[s_id]))
            i += 1

        max_proof_req_json = await san.build_proof_req_json({
            cd_id[s_id]: {
                'attrs': schema_data[s_id]['attr_names']
            } for s_id in schema_data
        })
        max_proof_req = json.loads(max_proof_req_json)
        print('\n\n== 6 == Built maximal proof request: {}'.format(ppjson(max_proof_req)))
        assert (
            sum([len(reqa.get('names', [''])) for reqa in max_proof_req['requested_attributes'].values()]) ==
                sum([len(schema_data[s_id]['attr_names']) for s_id in schema_data])
        )

        # Get cred info by cred def
        i = 0
        for s_id in cred_data:
            cred_info[s_id] = json.loads(await pspcoban.get_cred_info_by_id(cred_id[s_id]))
            print('\n\n== 7.{}.0 == Cred info on {} by cred_id={}: {}'.format(
                i,
                s_id,
                cred_id[s_id],
                ppjson(cred_info[s_id])))
            assert cred_info[s_id]
            assert cred_info[s_id]['attrs']

            briefs = proof_req_infos2briefs(max_proof_req, cred_info[s_id])
            print('\n\n== 7.{}.1 == Cred briefs for cred info on {} against maximal proof req: {}'.format(
                i,
                s_id,
                ppjson(briefs)))
            assert len(briefs) == 1
            assert bool(cred_def[s_id]['value'].get('revocation', None)) == bool(briefs[0]['interval'])
            i += 1

        briefs = proof_req_infos2briefs(max_proof_req, [cred_info[s_id] for s_id in cred_info])
        print('\n\n== 8 == Cred briefs for all cred infos against maximal proof req: {}'.format(ppjson(briefs)))
        assert len(briefs) == len(cred_info)
        assert all(bool(cred_def[briefs[i]['cred_info']['schema_id']]['value'].get('revocation', None)) ==
            bool(briefs[i]['interval']) for i in range(len(briefs)))

        req_creds = proof_req_briefs2req_creds(max_proof_req, briefs)
        print('\n\n== 9 == Req creds for all cred briefs against maximal proof req: {}'.format(ppjson(req_creds)))
        assert len(req_creds['requested_attributes']) == len(cred_info)  # one requested cred per cred def

        proof_req_json = await san.build_proof_req_json({
            cd_id[s_id]: {
                'attrs': [schema_data[s_id]['attr_names'][0]]
            } for s_id in schema_data
        })
        proof_req = json.loads(proof_req_json)
        print('\n\n== 10 == Built proof request on first attrs: {}'.format(ppjson(proof_req)))
        assert len(proof_req['requested_attributes']) == len(schema_data)
        assert ({cd_id[s_id] for s_id in cd_id} ==
            {proof_req['requested_attributes'][uuid]['restrictions'][0]['cred_def_id']
                for uuid in proof_req['requested_attributes']})

        briefs = proof_req_infos2briefs(proof_req, [cred_info[s_id] for s_id in cred_info])
        print('\n\n== 11 == Cred briefs for all cred infos against first-attrs proof req: {}'.format(ppjson(briefs)))
        assert len(briefs) == len(cred_info)
        assert all(bool(cred_def[briefs[i]['cred_info']['schema_id']]['value'].get('revocation', None)) ==
            bool(briefs[i]['interval']) for i in range(len(briefs)))

        req_creds = proof_req_briefs2req_creds(proof_req, briefs)
        print('\n\n== 12 == Req creds for all cred briefs against first-attrs proof req: {}'.format(ppjson(req_creds)))
        assert len(req_creds['requested_attributes']) == len(cred_info)  # one attr per cred def

        proof_req_json = await san.build_proof_req_json({
            cd_id[S_ID['REVO-X']]: {
                'attrs': schema_data[S_ID['REVO-X']]['attr_names']
            }
        })
        proof_req = json.loads(proof_req_json)
        print('\n\n== 13 == Built proof request for {}: {}'.format(S_ID['REVO-X'], ppjson(proof_req)))
        assert sum(
            [len(reqa.get('names', [''])) for reqa in proof_req['requested_attributes'].values()]
        ) == len(schema_data[S_ID['REVO-X']]['attr_names'])

        assert ({cd_id[S_ID['REVO-X']]} ==
            {proof_req['requested_attributes'][uuid]['restrictions'][0]['cred_def_id']
                for uuid in proof_req['requested_attributes']})

        briefs = proof_req_infos2briefs(proof_req, [cred_info[s_id] for s_id in cred_info])
        print('\n\n== 14 == Cred briefs for all cred infos against {} proof req: {}'.format(
            S_ID['REVO-X'],
            ppjson(briefs)))
        assert len(briefs) == 1
        assert all(bool(cred_def[briefs[i]['cred_info']['schema_id']]['value'].get('revocation', None)) ==
            bool(briefs[i]['interval']) for i in range(len(briefs)))

        req_creds = proof_req_briefs2req_creds(proof_req, briefs)
        print('\n\n== 15 == Req creds for all cred briefs against {} proof req: {}'.format(
            S_ID['REVO-X'],
            ppjson(req_creds)))
        assert len(req_creds['requested_attributes']) == 1  # one req-creds with one group of attr names
        
        briefs = proof_req_infos2briefs(proof_req, cred_info[S_ID['REVO-X']])
        print('\n\n== 16 == Cred briefs for {} cred info against {} proof req: {}'.format(
            S_ID['REVO-X'],
            S_ID['REVO-X'],
            ppjson(briefs)))
        assert len(briefs) == 1
        assert all(bool(cred_def[briefs[i]['cred_info']['schema_id']]['value'].get('revocation', None)) ==
            bool(briefs[i]['interval']) for i in range(len(briefs)))

        req_creds = proof_req_briefs2req_creds(proof_req, briefs)
        print('\n\n== 17 == Req creds for {} cred brief against {} proof req: {}'.format(
            S_ID['REVO-X'],
            S_ID['REVO-X'],
            ppjson(req_creds)))
        assert len(req_creds['requested_attributes']) == 1  # one req-creds with one group of attr names

        briefs = proof_req_infos2briefs(proof_req, cred_info[S_ID['NON-REVO-X']])
        print('\n\n== 18 == Cred briefs for {} cred info against {} proof req: {}'.format(
            S_ID['NON-REVO-X'],
            S_ID['REVO-X'],
            ppjson(briefs)))
        assert not briefs
        assert all(bool(cred_def[briefs[i]['cred_info']['schema_id']]['value'].get('revocation', None)) ==
            bool(briefs[i]['interval']) for i in range(len(briefs)))

        req_creds = proof_req_briefs2req_creds(proof_req, briefs)
        print('\n\n== 19 == Req creds for {} cred brief against {} proof req: {}'.format(
            S_ID['NON-REVO-X'],
            S_ID['REVO-X'],
            ppjson(req_creds)))
        assert not req_creds['requested_attributes']

        proof_req_json = await san.build_proof_req_json({
            cd_id[S_ID['NON-REVO-X']]: {
                'attrs': [schema_data[S_ID['NON-REVO-X']]['attr_names'][0]]
            }
        })
        proof_req = json.loads(proof_req_json)
        print('\n\n== 20 == Built proof request on {} first attr: {}'.format(S_ID['NON-REVO-X'], ppjson(proof_req)))
        assert len(proof_req['requested_attributes']) == 1
        assert ({cd_id[S_ID['NON-REVO-X']]} ==
            {proof_req['requested_attributes'][uuid]['restrictions'][0]['cred_def_id']
                for uuid in proof_req['requested_attributes']})

        briefs = proof_req_infos2briefs(proof_req, [cred_info[s_id] for s_id in cred_info])
        print('\n\n== 21 == Cred briefs for {} cred info against first-attr {} proof req: {}'.format(
            S_ID['NON-REVO-X'],
            S_ID['NON-REVO-X'],
            ppjson(briefs)))
        assert len(briefs) == 1
        assert all(bool(cred_def[briefs[i]['cred_info']['schema_id']]['value'].get('revocation', None)) ==
            bool(briefs[i]['interval']) for i in range(len(briefs)))

        req_creds = proof_req_briefs2req_creds(proof_req, briefs)
        print('\n\n== 22 == Req creds for {} cred brief against first-attr {} proof req: {}'.format(
            S_ID['NON-REVO-X'],
            S_ID['NON-REVO-X'],
            ppjson(req_creds)))
        assert len(req_creds['requested_attributes']) == 1

    await RevRegBuilder.stop('sri')


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_crypto(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing encryption/decryption =='))

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    seeds = {
        'sri': 'SRI-Anchor-000000000000000000000',
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    # Open pool, init anchors
    async with wallets['sri'] as w_sri, (
            wallets['pspc-org-book']) as w_pspc, (
            p_mgr.get(pool_name)) as p, (
            ProctorAnchor(w_sri, p, rrbx=False)) as san, (
            OrgBookAnchor(w_pspc, p)) as pspcoban:

        assert p.handle is not None

        nyms = {
            'san': json.loads(await san.get_nym(san.did)),
            'pspcoban': json.loads(await san.get_nym(pspcoban.did))
        }
        print('\n\n== 1 == With pool; nyms: {}'.format(ppjson(nyms)))

        assert all('dest' in nyms[k] for k in nyms)

        # Exercise error path where DID not on ledger nor known in wallet
        try:
            terminus = int(time())
            while True:
                cand_did = 'ZZZZZZZZZZZ{}'.format(str(terminus).replace('0', '1'))
                if not json.loads(await san.get_nym(cand_did)):
                    await san.encrypt(b'Hello', recip=cand_did)  # exercise error path where target DID not on ledger
                    assert False
                terminus += 1
        except AbsentNym:
            pass
        print('\n\n== 2 == SRI anchor fails to encrypt as expected for unknown DID')

        # SRI anchor anonymously encrypts and decrypts to and from itself, implicitly and explicitly
        plain = 'Hello World'.encode()
        encr = await san.encrypt(plain)
        (decr, key) = await san.decrypt(encr)
        assert decr == plain
        assert key is None
        encr = await san.encrypt(plain, False, san.did)
        (decr, _) = await san.decrypt(encr)
        assert decr == plain
        encr = await san.encrypt(plain, False, san.verkey)
        (decr, _) = await san.decrypt(encr)
        assert decr == plain
        print('\n\n== 3 == SRI anchor auto-encrypted then decrypted: {}'.format(decr.decode()))

        # SRI anchor auth-encrypts and decrypts to and from itself, implicitly and explicitly by DID and verkey
        encr = await san.encrypt(plain, True)
        (decr, key) = await san.decrypt(encr, san.did)
        assert decr == plain
        assert key == san.verkey
        (decr, _) = await san.decrypt(encr, san.verkey)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.did)
        (decr, _) = await san.decrypt(encr, san.did)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.verkey)
        (decr, _) = await san.decrypt(encr, san.did)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.did)
        (decr, _) = await san.decrypt(encr, san.verkey)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.verkey)
        (decr, _) = await san.decrypt(encr, san.verkey)
        assert decr == plain
        print('\n\n== 4 == SRI anchor auto-auth-encrypted then auth-decrypted: {}'.format(decr.decode()))

        # SRI anchor auth-encrypts to itself but fails to decrypt from incorrect senders
        encr = await san.encrypt(plain, True)
        try:
            await san.decrypt(encr, pspcoban.did)
            assert False
        except BadKey:
            pass
        try:
            await san.decrypt(encr, pspcoban.verkey)
            assert False
        except BadKey:
            pass
        print('\n\n== 5 == SRI correctly failed to auth-decrypt from wrong sender')

        # SRI anchor anonymously encrypts to PSPC Org Book anchor, which anonymously decrypts
        encr = await san.encrypt(plain, False, pspcoban.did)
        (decr, _) = await pspcoban.decrypt(encr)
        assert decr == plain
        encr = await san.encrypt(plain, False, pspcoban.verkey)
        (decr, _) = await pspcoban.decrypt(encr)
        assert decr == plain
        print('\n\n== 6 == SRI anchor encrypted to PSPC Org Book anchor, which decrypted: {}'.format(decr.decode()))

        # SRI anchor auth-encrypts (by DID and verkey) to PSPC Org Book anchor, which auth-decrypts (by DID and verkey)
        encr = await san.encrypt(plain, True, pspcoban.did)
        (decr, key) = await pspcoban.decrypt(encr, san.did)
        assert decr == plain
        assert key == san.verkey
        encr = await san.encrypt(plain, True, pspcoban.did)
        (decr, _) = await pspcoban.decrypt(encr, san.verkey)
        assert decr == plain
        encr = await san.encrypt(plain, True, pspcoban.verkey)
        (decr, _) = await pspcoban.decrypt(encr, san.did)
        assert decr == plain
        encr = await san.encrypt(plain, True, pspcoban.verkey)
        (decr, _) = await pspcoban.decrypt(encr, san.verkey)
        assert decr == plain
        print('\n\n== 7 == SRI anchor auth-encrypted to PSPC Org Book anchor, which auth-decrypted: {}'.format(
            decr.decode()))

        # SRI anchor auth-encrypts to PSPC Org Book anchor, which fails to auth-decrypt from incorrect sender
        encr = await san.encrypt(plain, True, pspcoban.did)
        try:
            await pspcoban.decrypt(encr, pspcoban.did)
            assert False
        except BadKey:
            pass
        try:
            await pspcoban.decrypt(encr, pspcoban.verkey)
            assert False
        except BadKey:
            pass
        encr = await san.encrypt(plain, True, pspcoban.verkey)
        try:
            await pspcoban.decrypt(encr, pspcoban.did)
            assert False
        except BadKey:
            pass
        try:
            await pspcoban.decrypt(encr, pspcoban.verkey)
            assert False
        except BadKey:
            pass
        print('\n\n== 8 == PSPC Org Book anchor correctly failed to auth-decrypt from wrong DID')

        # SRI anchor self-signs and verifies
        signature = await san.sign(plain)
        assert await san.verify(plain, signature)
        assert not await san.verify(plain, bytes(0 for b in signature))
        print('\n\n== 9 == SRI anchor signed then verified {}-byte signature from {}, then failed bad signature'.format(
            len(signature),
            plain))

        # PSPC Org Book Anchor verifies
        assert await pspcoban.verify(plain, signature, san.did)
        assert await pspcoban.verify(plain, signature, san.verkey)
        print('\n\n== 10 == SRI anchor signed, PSPC Org Book anchor verified {}-byte signature from: {}'.format(
            len(signature),
            plain))

        assert not await pspcoban.verify(plain, signature)
        print('\n\n== 11 == PSPC Org Book anchor failed auto-verification of SRI anchor signature, as expected')

    # Reset wallet for PSPC Org Book Anchor
    await wallets['pspc-org-book'].open()
    pspcoban = OrgBookAnchor(wallets['pspc-org-book'])
    await pspcoban.open()
    await pspcoban.create_link_secret('SecretLink')
    await pspcoban.reset_wallet(seeds[pspcoban.wallet.name])
    wallets['pspc-org-book'] = pspcoban.wallet  # hot-swap: reset already closed and deleted old one
    await wallets['pspc-org-book'].close()
    try:
        await pspcoban.encrypt(b'text-bytes')  # exercise error path: encrypt on closed wallet
        assert False
    except WalletState:
        pass
    try:
        await pspcoban.decrypt(b'ciphertext-bytes')  # exercise error path: decrypt on closed wallet
        assert False
    except WalletState:
        pass
    try:
        await pspcoban.sign(b'text-bytes')  # exercise error path: sign on closed wallet
        assert False
    except WalletState:
        pass
    try:
        await pspcoban.verify(b'text-bytes', b'signature-bytes')  # exercise error path: verify on closed wallet
        assert False
    except WalletState:
        pass
    await pspcoban.close()

    # Repeat crypto tests with anchors on wallet only
    async with wallets['sri'] as w_sri, (
            wallets['pspc-org-book']) as w_pspc, (
            ProctorAnchor(w_sri, rrbx=False)) as san, (
            OrgBookAnchor(w_pspc)) as pspcoban:

        dids = {
            'san': san.did,
            'pspcoban': pspcoban.did
        }
        print('\n\n== 12 == Without pool; DIDs: {}'.format(ppjson(dids)))

        # SRI anchor anonymously encrypts and decrypts to and from itself, implicitly and explicitly
        plain = 'Hello World'.encode()
        encr = await san.encrypt(plain)
        (decr, _) = await san.decrypt(encr)
        assert decr == plain
        encr = await san.encrypt(plain, False, san.did)
        (decr, _) = await san.decrypt(encr)
        assert decr == plain
        encr = await san.encrypt(plain, False, san.verkey)
        (decr, _) = await san.decrypt(encr)
        assert decr == plain
        print('\n\n== 13 == SRI anchor auto-encrypted then decrypted: {}'.format(decr.decode()))

        # SRI anchor auth-encrypts and decrypts to and from itself, implicitly and explicitly by DID and verkey
        encr = await san.encrypt(plain, True)
        (decr, _) = await san.decrypt(encr, san.did)
        assert decr == plain
        (decr, _) = await san.decrypt(encr, san.verkey)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.did)
        (decr, _) = await san.decrypt(encr, san.did)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.verkey)
        (decr, _) = await san.decrypt(encr, san.did)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.did)
        (decr, _) = await san.decrypt(encr, san.verkey)
        assert decr == plain
        encr = await san.encrypt(plain, True, san.verkey)
        (decr, _) = await san.decrypt(encr, san.verkey)
        assert decr == plain
        print('\n\n== 14 == SRI anchor auto-auth-encrypted then auth-decrypted: {}'.format(decr.decode()))

        # SRI anchor auth-encrypts to itself but fails to decrypt from incorrect senders
        encr = await san.encrypt(plain, True)
        try:
            await san.decrypt(encr, pspcoban.verkey)
            assert False
        except BadKey:
            pass
        try:
            await san.decrypt(encr, pspcoban.did)
            assert False
        except (AbsentPool, BadKey):
            pass
        print('\n\n== 15 == SRI correctly failed to auth-decrypt from wrong sender')

        # SRI anchor anonymously encrypts to PSPC Org Book anchor, which anonymously decrypts
        if not await san.wallet.get_pairwise(pspcoban.did):
            await san.wallet.write_pairwise(pspcoban.did, pspcoban.verkey)
        encr = await san.encrypt(plain, False, pspcoban.did)
        (decr, _) = await pspcoban.decrypt(encr)
        assert decr == plain
        encr = await san.encrypt(plain, False, pspcoban.verkey)
        (decr, _) = await pspcoban.decrypt(encr)
        assert decr == plain
        print('\n\n== 16 == SRI anchor encrypted to PSPC Org Book anchor, which decrypted: {}'.format(decr.decode()))

        # SRI anchor auth-encrypts (by DID and verkey) to PSPC Org Book anchor, which auth-decrypts (by DID and verkey)
        encr = await san.encrypt(plain, True, pspcoban.did)
        assert not await pspcoban.wallet.get_pairwise(san.did)
        try:
            await pspcoban.decrypt(encr, san.did)
            assert False
        except AbsentPool:  # cannot resolve did - no such pairwise in (reset) wallet, no pool available
            pass
        await pspcoban.wallet.write_pairwise(san.did, san.verkey)
        (decr, _) = await pspcoban.decrypt(encr, san.did)
        assert decr == plain
        encr = await san.encrypt(plain, True, pspcoban.did)
        (decr, _) = await pspcoban.decrypt(encr, san.verkey)
        assert decr == plain
        encr = await san.encrypt(plain, True, pspcoban.verkey)
        (decr, _) = await pspcoban.decrypt(encr, san.did)
        assert decr == plain
        encr = await san.encrypt(plain, True, pspcoban.verkey)
        (decr, _) = await pspcoban.decrypt(encr, san.verkey)
        assert decr == plain
        print('\n\n== 17 == SRI anchor auth-encrypted to PSPC Org Book anchor, which auth-decrypted: {}'.format(
            decr.decode()))

        # SRI anchor auth-encrypts to PSPC Org Book anchor, which fails to auth-decrypt from incorrect sender
        encr = await san.encrypt(plain, True, pspcoban.did)
        try:
            await pspcoban.decrypt(encr, pspcoban.did)
            assert False
        except BadKey:
            pass
        try:
            await pspcoban.decrypt(encr, pspcoban.verkey)
            assert False
        except BadKey:
            pass
        encr = await san.encrypt(plain, True, pspcoban.verkey)
        try:
            await pspcoban.decrypt(encr, pspcoban.did)
            assert False
        except BadKey:
            pass
        try:
            await pspcoban.decrypt(encr, pspcoban.verkey)
            assert False
        except BadKey:
            pass
        print('\n\n== 18 == PSPC Org Book anchor correctly failed to auth-decrypt from wrong DID')

        # SRI anchor self-signs and verifies
        signature = await san.sign(plain)
        assert await san.verify(plain, signature)
        print('\n\n== 19 == SRI anchor signed then verified {}-byte signature from: {}'.format(len(signature), plain))

        # PSPC Org Book Anchor verifies
        assert await pspcoban.verify(plain, signature, san.did)
        assert await pspcoban.verify(plain, signature, san.verkey)
        print('\n\n== 20 == SRI anchor signed, PSPC Org Book anchor verified {}-byte signature from: {}'.format(
            len(signature),
            plain))

        assert not await pspcoban.verify(plain, signature)
        print('\n\n== 21 == PSPC Org Book anchor failed auto-verification of SRI anchor signature, as expected')


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_share_wallet(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file):

    print(Ink.YELLOW('\n\n== Testing multiple anchors sharing a wallet =='))

    # Set up node pool ledger config, wallets
    p_mgr = NodePoolManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)

    seeds = {
        'multipass': 'Multi-Pass-000000000000000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False, auto_remove=True)

    # Open pool, init anchors
    async with wallets['multipass'] as w_multi, (
            p_mgr.get(pool_name)) as p, (
            ProctorAnchor(w_multi, p, rrbx=False)) as san, (
            NominalAnchor(w_multi, p)) as noman:

        assert p.handle is not None

        print('\n\n== 1 == DIDs: {}'.format(ppjson({'SRI anchor: ': san.did, 'Nominal anchor: ': noman.did})))
        assert san.did == noman.did and san.did
        print('\n\n== 2 == SRI, Nominal anchor share common wallet OK')


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_least_role():

    print(Ink.YELLOW('\n\n== Testing least role per anchor class =='))
    least_role = {
        RegistrarAnchor: Role.TRUST_ANCHOR,
        OrgBookAnchor: Role.TRUST_ANCHOR,
        OrgHubAnchor: Role.TRUST_ANCHOR,
        RevRegBuilder: Role.TRUST_ANCHOR,
        ProctorAnchor: Role.TRUST_ANCHOR,
        NominalAnchor: Role.USER,
        TrusteeAnchor: Role.TRUSTEE,
        Verifier: Role.USER
    }

    assert all(k.least_role() == least_role[k] for k in least_role)
    print('\n\n== 1 == Anchor profiles return correct least role OK')


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_did_endpoints():

    print(Ink.YELLOW('\n\n== Testing DID endpoints =='))

    seeds = {
        'sri': 'SRI-Anchor-000000000000000000000',
        'pspc-org-book': 'PSPC-Org-Book-Anchor-00000000000'
    }
    wallets = await get_wallets({k: {'seed': seeds[k]} for k in seeds}, open_all=False)

    # Reset wallet for PSPC Org Book Anchor
    await wallets['pspc-org-book'].open()
    pspcoban = OrgBookAnchor(wallets['pspc-org-book'])
    await pspcoban.open()
    await pspcoban.create_link_secret('SecretLink')
    await pspcoban.reset_wallet(seeds[pspcoban.wallet.name])
    wallets['pspc-org-book'] = pspcoban.wallet  # hot-swap: reset already closed and deleted old one
    await wallets['pspc-org-book'].close()
    await pspcoban.close()

    async with wallets['sri'] as w_sri, (
            wallets['pspc-org-book']) as w_pspc, (
            ProctorAnchor(w_sri, rrbx=False)) as san, (
            OrgBookAnchor(w_pspc)) as pspcoban:

        dids = {
            'san': san.did,
            'pspcoban': pspcoban.did
        }

        print('\n\n== 1 == DIDs: {}'.format(ppjson(dids)))

        try:
            await pspcoban.get_did_endpoint('not-a-did')  # exercise bad DID
            assert False
        except BadIdentifier:
            pass
        try:
            await pspcoban.get_did_endpoint(san.did)
            assert False
        except AbsentRecord:
            pass
        print('\n\n== 2 == PSPC Org Book Anchor correctly fails to get DID endpoint for bad input')

        # Fail to set endpoint on bad DID or no such pairwise
        try:
            await pspcoban.set_did_endpoint('not-a-did', '1.2.3.4:56')  # exercise bad DID
            assert False
        except BadIdentifier:
            pass
        try:
            await pspcoban.set_did_endpoint(san.did, '1.2.3.4:56')  # exercise no such pairwise
            assert False
        except AbsentRecord:
            pass
        print('\n\n== 3 == PSPC Org Book Anchor correctly fails to set DID endpoint for bad input')

        await pspcoban.wallet.write_pairwise(san.did, san.verkey)

        # Fail to get endpoint on pairwise with no endpoint
        try:
            await pspcoban.get_did_endpoint(san.did)
            assert False
        except AbsentRecord:
            pass
        print('\n\n== 4 == PSPC Org Book Anchor correctly fails to get DID endpoint for pairwise with no endpoint set')

        # Set DID endpoint
        endpoint_info = await pspcoban.set_did_endpoint(san.did, '1.2.3.4:56')
        assert await pspcoban.get_did_endpoint(san.did) == endpoint_info
        print('\n\n== 5 == PSPC Org Book Anchor set and got DID endpoint info for SRI Anchor: {}'.format(endpoint_info))

        # Overwrite DID endpoint
        endpoint_info = await pspcoban.set_did_endpoint(san.did, '7.8.9.10:1112')
        assert await pspcoban.get_did_endpoint(san.did) == endpoint_info
        print('\n\n== 6 == PSPC Org Book Anchor set and got DID endpoint info for SRI Anchor: {}'.format(endpoint_info))

        # Get by WQL $like
        records = await pspcoban.wallet.get_pairwise(json.dumps({
            'did_endpoint': {
                '$like': '7.8.9.10:%'
            }
        }))
        print('\n\n== 7 == Got {} record{} from by WQL on $like: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 1
        assert records[san.did].metadata['did_endpoint'] == '7.8.9.10:1112'


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_free_holder_prover(
        pool_ip,
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing Free Holder-Prover (with no public DID on ledger) =='))

    # Set up node pool ledger config and wallets, open pool, init anchors
    p_mgr = NodePoolManager()
    w_mgr = WalletManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)
    p = p_mgr.get(pool_name)

    wallet_data = {
        'trustee-anchor': {'seed': seed_trustee1},
        'bc-proctor': {'seed': 'BC-Proctor-Anchor-00000000000000'},
        'holder-prover': {'seed': 'Simple-Holder-Prover-00000000000', 'link_secret_label': 'hp-secret-sauce'},
        'sri': {'seed': 'SRI-Anchor-000000000000000000000'}
    }

    wallets = await get_wallets(wallet_data, open_all=False)

    # Open pool, init anchors
    async with wallets['trustee-anchor'] as w_trustee, (
            wallets['bc-proctor']) as w_bc, (
            wallets['holder-prover']) as w_hp, (
            wallets['sri']) as w_sri, (
            p_mgr.get(pool_name)) as p, (
            TrusteeAnchor(w_trustee, p)) as tan, (
            ProctorAnchor(w_bc, p)) as bcpan, (  # in this example the BC proctor anchor issues and verifies
            HolderProver(w_hp, p)) as hpan, (
            ProctorAnchor(w_sri, p, rrbx=False)) as san:

        # Publish trustee, issuer anchor particulars to ledger if not yet present
        did2an = {}
        for an in (tan, bcpan, san):
            if not json.loads(await tan.get_nym(an.did)):
                await tan.send_nym(an.did, an.verkey, an.wallet.name, an.least_role())

        nyms = {
            'tan': json.loads(await tan.get_nym()),
            'bcpan': json.loads(await tan.get_nym(bcpan.did)),
            'hpan': json.loads(await tan.get_nym(hpan.did)),
            'san': json.loads(await tan.get_nym(san.did))
        }
        print('\n\n== 1 == Nyms on ledger: {}'.format(ppjson(nyms)))

        # Publish schema to ledger if not yet present; get from ledger
        now = int(time())
        S_ID = {
            'VER-PERSON': schema_id(bcpan.did, 'verified-person', '{}.0'.format(now)),
            'VER-BUS-REL': schema_id(bcpan.did, 'verified-provincial-business-relationship', '{}.0'.format(now)),
            'SRI-AUTHZ': schema_id(san.did, 'sri-authz', '{}.0'.format(now))
        }

        schema_data = {
            S_ID['VER-PERSON']: {
                'name': schema_key(S_ID['VER-PERSON']).name,
                'version': schema_key(S_ID['VER-PERSON']).version,
                'attr_names': [
                    'legalName',
                    'socialInsuranceNumber',
                    'sex',
                    'dateOfBirth',
                    'localityOfBirth'
                ]
            },
            S_ID['VER-BUS-REL']: {
                'name': schema_key(S_ID['VER-BUS-REL']).name,
                'version': schema_key(S_ID['VER-BUS-REL']).version,
                'attr_names': [
                    'businessNumber',
                    'relation',
                    'fromDate',
                    'toDate'
                ]
            },
            S_ID['SRI-AUTHZ']: {
                'name': schema_key(S_ID['SRI-AUTHZ']).name,
                'version': schema_key(S_ID['SRI-AUTHZ']).version,
                'attr_names': [
                    'businessNumber',
                    'year',
                    'limit'
                ]
            }
        }

        cred_data = {
            S_ID['VER-PERSON']: {
                'legalName': 'Bill Lee',
                'socialInsuranceNumber': '123456789',
                'sex': 'M',
                'dateOfBirth': '1970-01-01',
                'localityOfBirth': 'Prince Rupert'
            },
            S_ID['VER-BUS-REL']: {
                'businessNumber': '1337',
                'relation': 'signing officer',
                'fromDate': datetime.date.today().strftime('%Y-%m-%d'),
                'toDate': (datetime.date.today() + datetime.timedelta(days=365)).strftime('%Y-%m-%d')
            }
        }

        # index by transaction number
        seq_no2schema_id = {}

        # index by schema id
        schema_json = {}
        schema = {}
        cred_offer_json = {}
        cred_offer = {}
        cred_def_json = {}
        cred_def = {}
        cd_id = {}
        cred_id = {}
        cred_req_json = {}
        cred_req = {}
        cred_json = {}
        cred_req_metadata_json = {}

        # Publish schemata to ledger
        i = 0
        seq_no = None
        for s_id in schema_data:
            an = san if s_id == S_ID['SRI-AUTHZ'] else bcpan
            s_key = schema_key(s_id)
            await an.send_schema(json.dumps(schema_data[s_id]))
            schema_json[s_id] = await bcpan.get_schema(s_key)
            assert json.loads(schema_json[s_id])  # should exist now

            schema[s_id] = json.loads(schema_json[s_id])
            seq_no2schema_id[schema[s_id]['seqNo']] = s_id
            print('\n\n== 2.{} == Schema [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
            assert schema[s_id]
            i += 1

        # BC Proctor anchor creates, stores, publishes cred definitions to ledger; creates cred offers
        i = 0
        for s_id in schema_data:
            an = san if s_id == S_ID['SRI-AUTHZ'] else bcpan
            s_key = schema_key(s_id)

            await an.send_cred_def(s_id, revo=False, rr_size=None)  # omit revocation for this demo
            cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

            cred_def_json[s_id] = await bcpan.get_cred_def(cd_id[s_id])  # ought to exist now
            cred_def[s_id] = json.loads(cred_def_json[s_id])
            print('\n\n== 3.{}.0 == Cred def [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(json.loads(cred_def_json[s_id]))))
            assert cred_def[s_id].get('schemaId', None) == str(schema[s_id]['seqNo'])

            cred_offer_json[s_id] = await an.create_cred_offer(schema[s_id]['seqNo'])
            cred_offer[s_id] = json.loads(cred_offer_json[s_id])
            print('\n\n== 3.{}.1 == Credential offer (ties issuer to cred def) [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(cred_offer_json[s_id])))
            i += 1

        print(Ink.GREEN('\n\n== Bill applies to BC Proctor for verified person cred =='))

        # Local and pairwise DIDs: Holder-Prover and BC Proctor agents exchange
        didinfo_bcpan = await bcpan.wallet.create_local_did(None, None)
        diddoc = DIDDoc(didinfo_bcpan.did)
        diddoc.set(PublicKey(didinfo_bcpan.did, '1', didinfo_bcpan.verkey))
        print('\n\n== 4 == BC Proctor DID Doc to holder-prover: {}'.format(ppjson(diddoc.to_json())))

        pairwise = {}
        pubkey_bcpan = diddoc.pubkey['did:sov:{}#1'.format(diddoc.did)].value
        pairwise['hpan2bcpan'] = await hpan.wallet.write_pairwise(
            their_did=diddoc.did,
            their_verkey=pubkey_bcpan,
            metadata={'for': 'bcpan'})  # nicety in case of later search
        diddoc = DIDDoc(pairwise['hpan2bcpan'].my_did)
        diddoc.set(PublicKey(pairwise['hpan2bcpan'].my_did, '1', pairwise['hpan2bcpan'].my_verkey))
        print('\n\n== 5 == Holder-prover DID Doc to BC Proctor: {}'.format(ppjson(diddoc.to_json())))

        pairwise['bcpan2hpan'] = await bcpan.wallet.write_pairwise(
            their_did=pairwise['hpan2bcpan'].my_did,
            their_verkey=pairwise['hpan2bcpan'].my_verkey,
            my_did=didinfo_bcpan.did,
            # my_verkey is already in wallet by construction
            metadata={'for': 'hpan'})  # nicety in case of later search
        print('\n\n== 6 == Pairwise relations between Holder-Prover and BC Proctor: {}'.format(
            ppjson({k: pairwise[k].metadata for k in pairwise})))

        # Holder-Prover Verified Person credential request to Province (assume legitimate identity proofing process)
        s_id = S_ID['VER-PERSON']
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await hpan.create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id],
            pairwise['hpan2bcpan'].my_did)
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 7 == Verified person credential request: metadata {}, cred req {}'.format(
            ppjson(cred_req_metadata_json[s_id]),
            ppjson(cred_req_json[s_id])))
        assert json.loads(cred_req_json[s_id])
        assert cred_req[s_id]['prover_did'] == pairwise['bcpan2hpan'].their_did
        assert cred_req[s_id]['prover_did'] == pairwise['hpan2bcpan'].my_did

        # BC Proctor issues verified-person cred
        (cred_json[s_id], _) = await bcpan.create_cred(
            cred_offer_json[s_id],
            cred_req_json[s_id],
            cred_data[s_id])
        assert json.loads(cred_json[s_id])
        print('\n\n== 8 == Issuer created {} cred: {}'.format(s_id, ppjson(cred_json[s_id])))

        # Holder-Prover stores cred
        cred = json.loads(cred_json[s_id])
        cred_id[s_id] = await hpan.store_cred(
            cred_json[s_id],
            cred_req_metadata_json[s_id])
        print('\n\n== 9 == Cred id on {} in wallet: {}'.format(s_id, cred_id[s_id]))
        print(Ink.GREEN('\n\n== Time passes; Bill applies to BC Proctor for verified business relationship cred =='))

        # BC Proctor agent requests proof of identity via verified person, to check for right to verified relation
        proof_req_json = await bcpan.build_proof_req_json({
            cd_id[s_id]: {
                'attrs': [
                    'legalName',
                    'dateOfBirth',
                    'localityOfBirth'
                ]
            }
        })
        proof_req = json.loads(proof_req_json)
        print('\n\n== 10 == Proof req for verified person (BC Proctor asks): {}'.format(ppjson(proof_req_json)))

        # Holder-Prover anchor gets cred-briefs via query, creates proof
        refts = proof_req_attr_referents(proof_req)
        wql = {
            refts[cd_id[s_id]]['legalName']: {
                'attr::legalName::value': cred_data[s_id]['legalName']
            }
        }
        print('\n\n== 11 == WQL to find verified-person cred brief: {}'.format(ppjson(wql)))
        wql_json = json.dumps(wql)
        briefs_q = json.loads(await hpan.get_cred_briefs_by_proof_req_q(proof_req_json, wql_json))
        assert len(briefs_q) == 1  # by construction
        print('\n\n== 12 == Found cred briefs: {}'.format(ppjson(briefs_q)))
        req_creds_q = proof_req_briefs2req_creds(proof_req, briefs_q.values())
        print('\n\n== 13 == Proof req and briefs created req-creds: {}'.format(ppjson(req_creds_q)))
        proof_q = json.loads(await hpan.create_proof(proof_req, briefs_q.values(), req_creds_q))
        print('\n\n== 14 == Proof via query: {}'.format(ppjson(proof_q)))

        # BC Proctor anchor (as Verifier) verifies proof (by query)
        rc_json = await bcpan.verify_proof(proof_req, proof_q)
        print('\n\n== 15 == BC Proctor anchor verifies proof by query as: {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        revealed = revealed_attrs(proof_q)
        print('\n\n== 16 == Revealed attributes from verified-person proof: {}'.format(ppjson(revealed)))
        revealed_vp = revealed[cd_id[s_id]]
        '''
        Looks like {
            'localityofbirth': 'Prince Rupert',
            'dateofbirth': '1970-01-01',
            'legalname': 'Bill Lee'
        }
        '''
        assert all(revealed_vp[canon(attr_name)] == cred_data[s_id][attr_name]
            for attr_name in cred_data[s_id] if canon(attr_name) in revealed_vp)

        # Holder-Prover requests verified business relationship credential
        s_id = S_ID['VER-BUS-REL']
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await hpan.create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id],
            pairwise['hpan2bcpan'].my_did)
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 17 == Verified business relation credential request: metadata {}, cred req {}'.format(
            ppjson(cred_req_metadata_json[s_id]),
            ppjson(cred_req_json[s_id])))
        assert cred_req[s_id]['prover_did'] == pairwise['bcpan2hpan'].their_did
        assert cred_req[s_id]['prover_did'] == pairwise['hpan2bcpan'].my_did

        # BC Proctor anchor (as Issuer) checks DB, issues cred attesting to HolderProver's verified relation to company
        (cred_json[s_id], _) = await bcpan.create_cred(
            cred_offer_json[s_id],
            cred_req_json[s_id],
            cred_data[s_id])
        assert json.loads(cred_json[s_id])
        print('\n\n== 18 == Issuer created {} cred: {}'.format(s_id, ppjson(cred_json[s_id])))

        # Holder-Prover stores cred
        cred = json.loads(cred_json[s_id])
        cred_id[s_id] = await hpan.store_cred(
            cred_json[s_id],
            cred_req_metadata_json[s_id])
        print('\n\n== 19 == Cred id on {} in wallet: {}'.format(s_id, cred_id[s_id]))
        print(Ink.GREEN('\n\n== Time passes; Bill applies to SRI anchor for supplier registration cred =='))

        # Local and pairwise DIDs: Holder-Prover and SRI agents exchange, preparing for presentation of proof to enrol
        didinfo = {}
        pairwise = {}
        didinfo['san'] = await san.wallet.create_local_did(None, None)  # SRI agent sends to Holder-Prover's
        pairwise['hpan2san'] = await hpan.wallet.write_pairwise(
            their_did=didinfo['san'].did,
            their_verkey=didinfo['san'].verkey,
            metadata={'for': 'san'})  # nicety for later search
        pairwise['san2hpan'] = await san.wallet.write_pairwise(
            their_did=pairwise['hpan2san'].my_did,
            their_verkey=pairwise['hpan2san'].my_verkey,
            my_did=didinfo['san'].did,
            metadata={'for': 'hpan'})  # nicety for later search
        print('\n\n== 20 == Pairwise relations between Holder-Prover and SRI agent: {}'.format(
            ppjson({k: pairwise[k].metadata for k in pairwise})))

        # SRI agent requests proof of identity via verified person and verified business relationship
        proof_req_json = await bcpan.build_proof_req_json({
            cd_id[S_ID['VER-PERSON']]: {
                'attrs': [
                    'legalName',
                    'socialInsuranceNumber'
                ]
            },
            cd_id[S_ID['VER-BUS-REL']]: None  # all attrs
        })
        proof_req = json.loads(proof_req_json)
        print('\n\n== 21 == Proof req for verified person and business relation (SRI anchor asks): {}'.format(
            ppjson(proof_req_json)))

        # Holder-Prover anchor gets cred-briefs via query, creates proof
        refts = proof_req_attr_referents(proof_req)
        wql = {
            refts[cd_id[S_ID['VER-PERSON']]]['legalName']: {
                'attr::legalName::value': cred_data[S_ID['VER-PERSON']]['legalName']
            },
            refts[cd_id[S_ID['VER-BUS-REL']]]['businessNumber']: {
                'attr::businessNumber::value': cred_data[S_ID['VER-BUS-REL']]['businessNumber']
            }
        }
        print('\n\n== 22 == WQL to find 2 cred briefs: {}'.format(ppjson(wql)))
        wql_json = json.dumps(wql)
        briefs_q = json.loads(await hpan.get_cred_briefs_by_proof_req_q(proof_req_json, wql_json))
        assert len(briefs_q) == 2  # by construction
        print('\n\n== 23 == Found cred briefs: {}'.format(ppjson(briefs_q)))
        req_creds_q = proof_req_briefs2req_creds(proof_req, briefs_q.values())
        print('\n\n== 24 == Proof req and briefs created req-creds: {}'.format(ppjson(req_creds_q)))
        proof_q = json.loads(await hpan.create_proof(proof_req, briefs_q.values(), req_creds_q))
        print('\n\n== 25 == Multi-cred proof via query: {}'.format(ppjson(proof_q)))

        # SRI anchor (as Verifier) verifies proof (by query)
        rc_json = await bcpan.verify_proof(proof_req, proof_q)
        print('\n\n== 26 == SRI anchor verifies multi-cred proof by query as: {}'.format(ppjson(rc_json)))
        assert json.loads(rc_json)

        revealed = revealed_attrs(proof_q)
        print('\n\n== 27 == Revealed attributes from multi-cred proof: {}'.format(ppjson(revealed)))
        '''
        Looks like {
            "MdANKCkSgQBu8cC2txDXNT:3:CL:32:tag": {
                "relation": "signing officer",
                "fromdate": "2019-07-19",
                "businessnumber": "1337",
                "todate": "2020-07-18"
            },
            "MdANKCkSgQBu8cC2txDXNT:3:CL:31:tag": {
                "socialinsurancenumber": "123456789",
                "legalname": "Bill Lee"
            }
        }
        '''

        # Extract SRI authorization cred data from revealed attrs
        cred_data[S_ID['SRI-AUTHZ']] = {
            'businessNumber': revealed[cd_id[S_ID['VER-BUS-REL']]][canon('businessNumber')],
            'year': revealed[cd_id[S_ID['VER-BUS-REL']]][canon('fromDate')].split('-')[0],
            'limit': 100000
        }

        # Holder-Prover SRI authorization credential request to SRI anchor
        s_id = S_ID['SRI-AUTHZ']
        (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await hpan.create_cred_req(
            cred_offer_json[s_id],
            cd_id[s_id],
            pairwise['hpan2san'].my_did)
        cred_req[s_id] = json.loads(cred_req_json[s_id])
        print('\n\n== 28 == SRI authorization credential request: metadata {}, cred req {}'.format(
            ppjson(cred_req_metadata_json[s_id]),
            ppjson(cred_req_json[s_id])))
        assert json.loads(cred_req_json[s_id])
        assert cred_req[s_id]['prover_did'] == pairwise['san2hpan'].their_did
        assert cred_req[s_id]['prover_did'] == pairwise['hpan2san'].my_did

        # SRI anchor issues verified-person cred
        (cred_json[s_id], _) = await san.create_cred(
            cred_offer_json[s_id],
            cred_req_json[s_id],
            cred_data[s_id])
        assert json.loads(cred_json[s_id])
        print('\n\n== 29 == Issuer created {} cred: {}'.format(s_id, ppjson(cred_json[s_id])))

        # Holder-Prover stores cred
        cred = json.loads(cred_json[s_id])
        cred_id[s_id] = await hpan.store_cred(
            cred_json[s_id],
            cred_req_metadata_json[s_id])
        print('\n\n== 30 == Cred id on {} in wallet: {}'.format(s_id, cred_id[s_id]))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_proof_request_alternatives(
        pool_ip,
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file,
        seed_trustee1):

    print(Ink.YELLOW('\n\n== Testing proof request build and get-cred-briefs alternatives =='))

    # Set up node pool ledger config and wallets, open pool, init anchors
    p_mgr = NodePoolManager()
    w_mgr = WalletManager()
    if pool_name not in await p_mgr.list():
        await p_mgr.add_config(pool_name, pool_genesis_txn_path)
    p = p_mgr.get(pool_name)

    wallet_data = {
        'trustee-anchor': {'seed': seed_trustee1},
        'video-proctor': {'seed': 'Video-Proctor-Anchor-00000000000'},
        'player-1': {'seed': 'Player-One-000000000000000000000', 'link_secret_label': 'hp-secret-skills'}
    }

    wallets = await get_wallets(wallet_data, open_all=False, auto_remove=True)

    # Open pool, init anchors
    async with wallets['trustee-anchor'] as w_trustee, (
            wallets['video-proctor']) as w_vp, (
            wallets['player-1']) as w_hp, (
            p_mgr.get(pool_name)) as p, (
            TrusteeAnchor(w_trustee, p)) as tan, (
            ProctorAnchor(w_vp, p)) as vpan, (  # in this example the BC proctor anchor issues and verifies
            HolderProver(w_hp, p)) as hpan:

        # Publish trustee, issuer anchor particulars to ledger if not yet present
        did2an = {}
        for an in (tan, vpan):
            if not json.loads(await tan.get_nym(an.did)):
                await tan.send_nym(an.did, an.verkey, an.wallet.name, an.least_role())

        nyms = {
            'tan': json.loads(await tan.get_nym()),
            'vpan': json.loads(await tan.get_nym(vpan.did))
        }
        print('\n\n== 1 == Nyms on ledger: {}'.format(ppjson(nyms)))

        # Publish schema to ledger if not yet present; get from ledger
        now = int(time())
        S_ID = {
            'PREFERENCES': schema_id(vpan.did, 'prefs', '{}.0'.format(now)),
            'SCORES': schema_id(vpan.did, 'scores', '{}.0'.format(now))
        }

        schema_data = {
            S_ID['PREFERENCES']: {
                'name': schema_key(S_ID['PREFERENCES']).name,
                'version': schema_key(S_ID['PREFERENCES']).version,
                'attr_names': [
                    'ident',
                    'colour',
                    'drink'
                ]
            },
            S_ID['SCORES']: {
                'name': schema_key(S_ID['SCORES']).name,
                'version': schema_key(S_ID['SCORES']).version,
                'attr_names': [
                    'galaga',
                    'space_invaders',
                    'asteroids',
                    'space_fury'
                ]
            }
        }

        cred_data = {
            S_ID['PREFERENCES']: {
                'ident': 'Wayne',
                'colour': 'purple',
                'drink': 'cola'
            },
            S_ID['SCORES']: {
                'galaga': '123450',
                'space_invaders': '234560',
                'asteroids': '345670',
                'space_fury': '456780'
            }
        }

        # index by transaction number
        seq_no2schema_id = {}

        # index by schema id
        schema_json = {}
        schema = {}
        cred_offer_json = {}
        cred_offer = {}
        cred_def_json = {}
        cred_def = {}
        cd_id = {}
        cred_id = {}
        cred_req_json = {}
        cred_req = {}
        cred_json = {}
        cred_req_metadata_json = {}

        # Publish schemata to ledger
        i = 0
        seq_no = None
        for s_id in schema_data:
            s_key = schema_key(s_id)
            await vpan.send_schema(json.dumps(schema_data[s_id]))
            schema_json[s_id] = await vpan.get_schema(s_key)
            assert json.loads(schema_json[s_id])  # should exist now

            schema[s_id] = json.loads(schema_json[s_id])
            seq_no2schema_id[schema[s_id]['seqNo']] = s_id
            print('\n\n== 2.{} == Schema [{} v{}]: {}'.format(i, s_key.name, s_key.version, ppjson(schema[s_id])))
            assert schema[s_id]
            i += 1

        # BC Proctor anchor creates, stores, publishes cred definitions to ledger; creates cred offers
        i = 0
        for s_id in schema_data:
            s_key = schema_key(s_id)

            await vpan.send_cred_def(s_id, revo=False, rr_size=None)  # omit revocation for this demo
            cd_id[s_id] = cred_def_id(s_key.origin_did, schema[s_id]['seqNo'])

            cred_def_json[s_id] = await vpan.get_cred_def(cd_id[s_id])  # ought to exist now
            cred_def[s_id] = json.loads(cred_def_json[s_id])
            print('\n\n== 3.{}.0 == Cred def [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(json.loads(cred_def_json[s_id]))))
            assert cred_def[s_id].get('schemaId', None) == str(schema[s_id]['seqNo'])

            cred_offer_json[s_id] = await an.create_cred_offer(schema[s_id]['seqNo'])
            cred_offer[s_id] = json.loads(cred_offer_json[s_id])
            print('\n\n== 3.{}.1 == Credential offer (ties issuer to cred def) [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(cred_offer_json[s_id])))
            i += 1

        print(Ink.GREEN('\n\n== Wayne applies to BC Proctor for creds =='))

        # Local and pairwise DIDs: Holder-Prover and BC Proctor agents exchange
        didinfo_vpan = await vpan.wallet.create_local_did(None, None)
        diddoc = DIDDoc(didinfo_vpan.did)
        diddoc.set(PublicKey(didinfo_vpan.did, '1', didinfo_vpan.verkey))
        print('\n\n== 4 == BC Proctor DID Doc to holder-prover: {}'.format(ppjson(diddoc.to_json())))

        pairwise = {}
        pubkey_vpan = diddoc.pubkey['did:sov:{}#1'.format(diddoc.did)].value
        pairwise['hpan2vpan'] = await hpan.wallet.write_pairwise(
            their_did=diddoc.did,
            their_verkey=pubkey_vpan,
            metadata={'for': 'vpan'})  # nicety in case of later search
        diddoc = DIDDoc(pairwise['hpan2vpan'].my_did)
        diddoc.set(PublicKey(pairwise['hpan2vpan'].my_did, '1', pairwise['hpan2vpan'].my_verkey))
        print('\n\n== 5 == Holder-prover DID Doc to BC Proctor: {}'.format(ppjson(diddoc.to_json())))

        pairwise['vpan2hpan'] = await vpan.wallet.write_pairwise(
            their_did=pairwise['hpan2vpan'].my_did,
            their_verkey=pairwise['hpan2vpan'].my_verkey,
            my_did=didinfo_vpan.did,
            # my_verkey is already in wallet by construction
            metadata={'for': 'hpan'})  # nicety in case of later search
        print('\n\n== 6 == Pairwise relations between Holder-Prover and BC Proctor: {}'.format(
            ppjson({k: pairwise[k].metadata for k in pairwise})))

        # Holder-Prover gets and stores credentials
        i = 0
        for key in S_ID:
            s_id = S_ID[key]
            (cred_req_json[s_id], cred_req_metadata_json[s_id]) = await hpan.create_cred_req(
                cred_offer_json[s_id],
                cd_id[s_id],
                pairwise['hpan2vpan'].my_did)
            cred_req[s_id] = json.loads(cred_req_json[s_id])
            print('\n\n== 7.{}.1 == {} credential request: metadata {}, cred req {}'.format(
                i,
                key,
                ppjson(cred_req_metadata_json[s_id]),
                ppjson(cred_req_json[s_id])))
            assert json.loads(cred_req_json[s_id])
            assert cred_req[s_id]['prover_did'] == pairwise['vpan2hpan'].their_did
            assert cred_req[s_id]['prover_did'] == pairwise['hpan2vpan'].my_did

            s_id = S_ID[key]
            (cred_json[s_id], _) = await vpan.create_cred(
                cred_offer_json[s_id],
                cred_req_json[s_id],
                cred_data[s_id])
            assert json.loads(cred_json[s_id])
            print('\n\n== 7.{}.2 == Issuer created {} cred: {}'.format(i, s_id, ppjson(cred_json[s_id])))

            cred = json.loads(cred_json[s_id])
            cred_id[s_id] = await hpan.store_cred(
                cred_json[s_id],
                cred_req_metadata_json[s_id])
            print('\n\n== 7.{}.3 == Cred id on {} in wallet: {}'.format(i, s_id, cred_id[s_id]))
            i += 1

        # BC Proctor agent requests proof: exercise builder
        proof_req_json = await vpan.build_proof_req_x_json(
            req_attrs=[
                {
                    'name':  'drink',
                    'restrictions': [{
                        'cred_def_id': cd_id[S_ID['PREFERENCES']]
                    }]
                },
                {
                    'name': 'colour'  # self-attested
                },
                {
                    'name':  'ident',
                    'restrictions': [{
                        'cred_def_id': cd_id[S_ID['PREFERENCES']]
                    }]
                },
                {
                    'name':  'galaga',
                    'restrictions': [{
                        'cred_def_id': cd_id[S_ID['SCORES']]
                    }]
                }
            ],
            req_preds=[
                {
                    'name': 'space_fury',
                    'p_value': 1000000,
                    # 'p_type': '>=',  implementation fills in
                    'restrictions': [{
                        'cred_def_id': cd_id[S_ID['SCORES']]
                    }]
                }
            ]
        )
        print('\n\n== 8 == Proof req: {}'.format(ppjson(proof_req_json)))

        briefs_q_json = await hpan.get_cred_briefs_by_proof_req_q(proof_req_json)
        print('\n\n== 9 == Cred briefs by proof req and query: {}'.format(ppjson(briefs_q_json)))

        proof_req_json = await vpan.build_proof_req_x_json(
            req_attrs=[
                {
                    'name':  'drink',
                    'restrictions': [{
                        'schema_id': S_ID['PREFERENCES']
                    }]
                },
                {
                    'name': 'colour'  # self-attested
                },
                {
                    'name':  'ident',
                    'restrictions': [{
                        'cred_def_id': cd_id[S_ID['PREFERENCES']]
                    }]
                },
                {
                    'name':  'galaga',
                    'restrictions': [{
                        'schema_issuer_did': vpan.did
                    }]
                }
            ],
            req_preds=[
                {
                    'name': 'space_fury',
                    'p_value': 1000000,
                    # 'p_type': '>=',  implementation fills in
                    'restrictions': [{
                        'issuer_did': vpan.did
                    }]
                }
            ]
        )
        print('\n\n== 10 == Proof req on schema-id restrictions: {}'.format(ppjson(proof_req_json)))

        briefs_json = await hpan.get_cred_briefs_by_proof_req(proof_req_json)
        print('\n\n== 11 == Cred briefs by proof req with schema-id restrictions: {}'.format(ppjson(briefs_json)))
        assert json.loads(briefs_json) == json.loads(briefs_q_json)

        proof_req_json = await vpan.build_proof_req_x_json(
            req_attrs=[
                {
                    'name':  'drink',
                    'restrictions': [
                        {
                            'schema_name': schema_key(S_ID['PREFERENCES']).name,
                            'schema_version': schema_key(S_ID['PREFERENCES']).version,
                            'schema_issuer_did': schema_key(S_ID['PREFERENCES']).origin_did
                        }
                    ]
                },
                {
                    'name': 'colour'  # self-attested
                },
                {
                    'name':  'ident',
                    'restrictions': [
                        {
                            'cred_def_id': cd_id[S_ID['PREFERENCES']]
                        },
                        {
                            'issuer_did': vpan.did,
                            'schema_name': schema_key(S_ID['PREFERENCES']).name,
                        }
                    ]
                },
                {
                    'name':  'galaga',
                    'restrictions': [{
                        'schema_issuer_did': vpan.did
                    }]
                }
            ],
            req_preds=[
                {
                    'name': 'space_fury',
                    'p_value': 1000000,
                    # 'p_type': '>=',  implementation fills in
                    'restrictions': [{
                        'issuer_did': vpan.did
                    }]
                }
            ]
        )
        print('\n\n== 12 == Proof req on complex restrictions: {}'.format(ppjson(proof_req_json)))

        briefs_x_json = await hpan.get_cred_briefs_by_proof_req(proof_req_json)
        print('\n\n== 13 == Cred briefs by proof req with complex restrictions: {}'.format(ppjson(briefs_x_json)))
        assert json.loads(briefs_x_json) == json.loads(briefs_q_json)

        # Exercise restriction logic
        cred_info = {
            'schema_id': S_ID['PREFERENCES'],
            'cred_def_id': cd_id[S_ID['PREFERENCES']]
        }
        assert Restriction.SCHEMA_ID.applies(cred_info, S_ID['PREFERENCES']) 
        assert Restriction.SCHEMA_ISSUER_DID.applies(cred_info, vpan.did)
        assert Restriction.SCHEMA_NAME.applies(cred_info, schema_key(S_ID['PREFERENCES']).name)
        assert Restriction.SCHEMA_VERSION.applies(cred_info, schema_key(S_ID['PREFERENCES']).version)
        assert Restriction.ISSUER_DID.applies(cred_info, vpan.did)
        assert Restriction.CRED_DEF_ID.applies(cred_info, cd_id[S_ID['PREFERENCES']]) 

        assert not Restriction.SCHEMA_ID.applies(cred_info, S_ID['SCORES'])
        assert not Restriction.SCHEMA_ISSUER_DID.applies(cred_info, hpan.did)
        assert not Restriction.SCHEMA_NAME.applies(cred_info, schema_key(S_ID['SCORES']).name)
        assert not Restriction.SCHEMA_VERSION.applies(cred_info, '99.9')
        assert not Restriction.ISSUER_DID.applies(cred_info, hpan.did)
        assert not Restriction.CRED_DEF_ID.applies(cred_info, cd_id[S_ID['SCORES']]) 

        assert Restriction.all_apply_dict(
            cred_info, 
            {
                'schema_issuer_did': schema_key(S_ID['PREFERENCES']).origin_did,
                'schema_name': schema_key(S_ID['PREFERENCES']).name,
                'schema_version': schema_key(S_ID['PREFERENCES']).version,
                'schema_id': S_ID['PREFERENCES'],
                'cred_def_id': cd_id[S_ID['PREFERENCES']],
                'issuer_did': vpan.did
            }
        )

        assert not Restriction.all_apply_dict(
            cred_info, 
            {
                'cred_def_id': cd_id[S_ID['PREFERENCES']],
                'issuer_did': hpan.did
            }
        )

        assert Restriction.any_apply_list(
            cred_info,
            [
                {
                    'schema_issuer_did': schema_key(S_ID['PREFERENCES']).origin_did,
                    'schema_name': schema_key(S_ID['PREFERENCES']).name,
                    'schema_version': schema_key(S_ID['PREFERENCES']).version,
                    'schema_id': S_ID['PREFERENCES'],
                    'cred_def_id': cd_id[S_ID['PREFERENCES']],
                    'issuer_did': vpan.did
                },
                {
                    'cred_def_id': cd_id[S_ID['PREFERENCES']],
                    'issuer_did': hpan.did
                }
            ]
        )

        print('\n\n== 14 == Restriction logic OK')
