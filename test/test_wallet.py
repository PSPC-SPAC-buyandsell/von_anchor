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


from os import unlink
from os.path import join
from pathlib import Path
from time import time
from tempfile import gettempdir

import json
import pytest

from indy import IndyError
from indy.error import ErrorCode

from von_anchor.error import AbsentRecord, BadAccess, BadRecord, BadSearch, ExtantWallet, JSONValidation, WalletState
from von_anchor.frill import Ink, ppjson
from von_anchor.wallet import (
    DIDInfo,
    EndpointInfo,
    KeyInfo,
    PairwiseInfo,
    pairwise_info2tags,
    StorageRecord,
    StorageRecordSearch,
    Wallet,
    WalletManager)


async def get_wallets(wallet_data, open_all, auto_remove=False):
    rv = {}
    w_mgr = WalletManager()
    for name in wallet_data:
        w = None
        creation_data = {'seed', 'did'} & {n for n in wallet_data[name]}  # create for tests when seed or did specifies
        if creation_data:
            config = {
                ('id' if len(wallet_data) > 1 else 'name'): name,  # jerry-rig coverage of 'name'/'id' equivalents
                **{k: wallet_data[name][k] for k in creation_data},
                'auto_remove': auto_remove
            }
            if 'link_secret_label' in wallet_data[name]:
                config['link_secret_label'] = wallet_data[name]['link_secret_label']
            w = await w_mgr.create(
                config,
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
async def test_manager():

    print(Ink.YELLOW('\n\n== Testing Wallet Manager Basics =='))

    w_mgr = WalletManager()
    assert w_mgr.default_storage_type is None
    assert w_mgr.default_freshness_time == 0
    assert w_mgr.default_auto_remove == False
    assert w_mgr.default_auto_create == False
    assert w_mgr.default_access == 'key'

    w = w_mgr.get({'id': 'test', 'auto_remove': True}, access='open-sesame')
    assert w.auto_remove == True
    assert w.name == 'test'
    assert w.storage_type is None
    assert w.access == 'open-sesame'
    assert w.access_creds['key'] == 'open-sesame'

    w_mgr = WalletManager({'key': 'up-down-left-right-a-b-c'})
    assert w_mgr.default_access == 'up-down-left-right-a-b-c'
    w = w_mgr.get({'id': 'test', 'auto_remove': True})
    assert w.access == 'up-down-left-right-a-b-c'
    assert w.access_creds['key'] == 'up-down-left-right-a-b-c'

    print('\n\n== 1 == Wallet manager basics operate OK')


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_wallet(path_home):

    print(Ink.YELLOW('\n\n== Testing Wallet Configuration + Context =='))

    seed = '00000000000000000000000000000000'
    name = 'my-wallet'
    access = 'secret-squirrel'
    path = Path(path_home, 'wallet', name)
    w_mgr = WalletManager()

    # Get VON wallet
    x_wallet =  w_mgr.get({'id': 'no-such-wallet-{}'.format(str(int(time())))})
    assert x_wallet is not None

    # Configuration with auto-remove set
    w_seed = await w_mgr.create({'id': name, 'seed': seed, 'auto_remove': True}, access, replace=True)
    assert path.exists(), 'Wallet path {} not present'.format(path)
    await w_seed.open()
    assert w_seed.did
    assert w_seed.verkey
    await w_seed.close()
    assert not path.exists(), 'Wallet path {} still present'.format(path)
    print('\n\n== 1 == New wallet with auto-remove OK')

    # Configuration with auto-remove set, on DID instead of seed
    w_did = await w_mgr.create({'id': name, 'did': w_seed.did, 'auto_remove': True}, access, replace=True)
    assert path.exists(), 'Wallet path {} not present'.format(path)
    await w_did.open()
    assert w_did.did
    assert w_did.did == w_seed.did
    assert w_did.verkey
    await w_did.close()
    assert not path.exists(), 'Wallet path {} still present'.format(path)
    print('\n\n== 2 == Wallet creation specifies OK by DID instead of seed; auto-remove OK')

    # Configuration with auto-remove set, default DID and seed
    w_dflt = await w_mgr.create({'id': name, 'auto_remove': True}, access, replace=True)
    assert path.exists(), 'Wallet path {} not present'.format(path)
    await w_dflt.open()
    assert w_dflt.did
    assert w_dflt.verkey
    await w_dflt.close()
    assert not path.exists(), 'Wallet path {} still present'.format(path)
    print('\n\n== 3 == Wallet creation specifies OK by default DID and seed; auto-remove OK')

    # Default configuration (auto-remove=False)
    w = await w_mgr.create({'id': name, 'seed': seed}, access)
    assert path.exists(), 'Wallet path {} not present'.format(path)

    await w.open()
    assert w.did
    assert w.verkey
    (w_did, w_verkey) = (w.did, w.verkey)
    await w.close()
    assert path.exists(), 'Wallet path {} not present'.format(path)
    print('\n\n== 4 == New wallet with default config (no auto-remove) OK')

    # Make sure wallet opens from extant file, only on correct access credentials
    try:
        x = await w_mgr.create({'id': name, 'seed': seed})
    except ExtantWallet:
        pass

    try:
        x = w_mgr.get({'id': name})
        async with x:
            assert False
    except BadAccess:
        pass

    try:
        await w_mgr.create({'id': name}, access='incorrect-value', replace=True)
        assert False
    except ExtantWallet:
        pass
    print('\n\n== 5 == Wallet neither opens nor replaces for bad access credentials')

    ww = w_mgr.get({'id': name, 'auto_remove': True}, access)
    async with ww:
        assert ww.did == w_did
        assert ww.verkey == w_verkey
    print('\n\n== 6 == Wallet restores DID and verkey on re-open')

    assert not path.exists(), 'Wallet path {} still present'.format(path)
    print('\n\n== 7 == Re-use extant wallet on good access creds OK, wrong access creds fails as expected')

    # Auto-create, no auto-remove
    w = w_mgr.get({'id': name, 'auto_create': True}, access=access)
    assert not path.exists(), 'Wallet path {} present'.format(path)

    await w.open()
    assert path.exists(), 'Wallet path {} present'.format(path)
    assert w.did
    assert w.verkey
    (w_did, w_verkey) = (w.did, w.verkey)
    await w.close()
    assert path.exists(), 'Wallet path {} not present'.format(path)
    print('\n\n== 8 == Wallet auto_create engages OK')

    await w_mgr.remove(w)
    assert not path.exists(), 'Wallet path {} present'.format(path)
    print('\n\n== 9 == Wallet manager removes wallet OK')

    # Auto-create, auto-remove
    w = w_mgr.get({'id': name, 'auto_create': True, 'auto_remove': True}, access=access)
    assert not path.exists(), 'Wallet path {} present'.format(path)

    async with w:
        assert path.exists(), 'Wallet path {} not present'.format(path)
        assert w.did
        assert w.verkey
    assert not path.exists(), 'Wallet path {} present'.format(path)

    async with w:  # do it again, Feynmann-like wallet creating on every open and deleting on every close
        assert path.exists(), 'Wallet path {} not present'.format(path)
        assert w.did
        assert w.verkey
    assert not path.exists(), 'Wallet path {} present'.format(path)
    print('\n\n== 10 == Wallet auto_create and auto_remove work together')

    # Double-open
    try:
        w = await w_mgr.create({'id': name, 'seed': seed, 'auto_remove': True})
        async with w:
            async with w:
                assert False
    except WalletState:
        pass
    assert not path.exists(), 'Wallet path {} still present'.format(path)
    print('\n\n== 11 == Double-open case encounters error as expected')

    #  Rekey operation tested via anchor, in test_anchors.py


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_local_dids():

    print(Ink.YELLOW('\n\n== Testing local DID operations =='))

    wallets = await get_wallets(
        {
            'multipass': {
                'seed': 'Multi-Pass-000000000000000000000'
            },
        },
        open_all=False,
        auto_remove=True)

    # Open wallet and operate
    async with wallets['multipass'] as w:
        did_info = await w.create_local_did(None, '55GkHamhTU1ZbTbV2ab9DE')
        print('\n\n== 1 == Created local known DID: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 2  # 'since', 'modified'
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

        did_info = await w.create_local_did()
        print('\n\n== 2 == Created random local DID: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 2  # 'since', 'modified'
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

        did_info = await w.create_local_did('Agent-44-00000000000000000000000')
        print('\n\n== 3 == Created local DID on seed: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata)
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

        did_info = await w.create_local_did(metadata={'hello': 'world'})
        print('\n\n== 4 == Created random local DID with metadata: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 3
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

        did_info = await w.create_local_did('Agent-13-00000000000000000000000', metadata={'hello': 'world'})
        print('\n\n== 5 == Created local DID on seed with metadata: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 3
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

        did_info = await w.replace_local_did_metadata(did_info.did, metadata={'no': 'sale'})
        print('\n\n== 6 == Replaced local DID {} metadata'.format(did_info.did))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 3
        assert did_info.metadata['no'] == 'sale'
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_signing_key():

    print(Ink.YELLOW('\n\n== Testing signing key operations =='))

    wallets = await get_wallets(
        {
            'multipass': {
                'seed': 'Multi-Pass-000000000000000000000'
            },
        },
        open_all=False,
        auto_remove=True)

    # Open wallet and operate
    async with wallets['multipass'] as w:
        key_info = await w.create_signing_key('Agent-8-000000000000000000000000')
        print('\n\n== 1 == Created signing key: {}'.format(key_info))
        assert key_info.verkey and not key_info.metadata
        assert key_info == await w.get_signing_key(key_info.verkey)

        key_info = await w.create_signing_key()
        print('\n\n== 2 == Created random signing key: {}'.format(key_info))
        assert key_info.verkey and not key_info.metadata
        assert key_info == await w.get_signing_key(key_info.verkey)

        key_info = await w.create_signing_key(metadata={'hello': 'world'})
        print('\n\n== 3 == Created random signing key with metadata: {}'.format(key_info))
        assert key_info.verkey and len(key_info.metadata) == 1
        assert key_info == await w.get_signing_key(key_info.verkey)

        key_info = await w.create_signing_key('Agent-K13-0000000000000000000000', metadata={'hello': 'world'})
        print('\n\n== 4 == Created signing key on seed with metadata: {}'.format(key_info))
        assert key_info.verkey and len(key_info.metadata) == 1
        assert key_info == await w.get_signing_key(key_info.verkey)

        metadata={'allo': 'tout le monde', 'hola': 'todos'}
        await w.replace_signing_key_metadata(key_info.verkey, metadata=metadata)
        repl = await w.get_signing_key(key_info.verkey)
        print('\n\n== 5 == Replaced signing key {} metadata with: {}'.format(key_info.verkey, repl.metadata))
        assert key_info != repl
        assert repl.metadata == metadata

        try:
            x_key = key_info.verkey.replace(key_info.verkey[0], chr(ord(key_info.verkey[0]) + 1))  # surely absent
            await w.get_signing_key(x_key)
            assert False
        except AbsentRecord:
            pass
        print('\n\n== 6 == Correctly raised absent record on get-key-pair for no such key')

@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_pairwise():

    print(Ink.YELLOW('\n\n== Testing pairwise operations =='))

    wallets = await get_wallets(
        {
            'multipass': {  
                'seed': 'Multi-Pass-000000000000000000000'
            },
            'agent-86': {
                'seed': 'Agent-86-00000000000000000000000'
            },
            'agent-99': {
                'seed': 'Agent-99-00000000000000000000000'
            },
        },
        open_all=False,
        auto_remove=True)

    pairwises = {}  # naive pairwise info, with anchor dids and verkeys
    for name in wallets:
        if name != 'multipass':
            async with wallets[name] as their_wallet:  # engage auto-remove
                pairwises[name] = PairwiseInfo(
                    their_wallet.did,
                    their_wallet.verkey,
                    wallets['multipass'].did,
                    wallets['multipass'].verkey,
                    None)

    assert pairwises['agent-86'] != pairwises['agent-99']
    baseline_meta = {'their_verkey', 'their_did', 'my_verkey', 'my_did'}

    # Open wallets and operate
    async with wallets['multipass'] as w:
        print('\n\n== 1 == Pairwise DIDs: {}'.format(ppjson(pairwises)))

        await w.delete_pairwise(pairwises['agent-86'].their_did)  # not present: silently carries on
        await w.delete_pairwise(pairwises['agent-99'].their_did)  # not present: silently carries on
        assert await w.get_pairwise(pairwises['agent-86'].their_did) == {}

        # Store record for agent 86, 99; get by DID
        metadata = {'epoch': int(time())}  # preparing to exercise metadata int to str
        await w.write_pairwise(
            pairwises['agent-99'].their_did,
            pairwises['agent-99'].their_verkey,
            wallets['multipass'].did,
            metadata)
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 2 == Stored and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta
        assert records[pairwises['agent-86'].their_did].my_did == wallets['multipass'].did
        assert records[pairwises['agent-86'].their_did].my_verkey == wallets['multipass'].verkey

        # Set metadata; get by DID
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 3 == Stored metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch'}

        # Augment metadata; get by DID
        metadata = {'clearance': 'galactic'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 4 == Stored metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch', 'clearance'}

        # Replace metadata on explicit pairwise info; get by DID
        metadata = {'phone': 'shoe'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 5 == Replaced metadata and got {} record{} for agent-86 by explicit pairwise info: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'phone'}

        # Replace metadata on implicit pairwise info; get by DID
        metadata = {'secrecy': 'hover cover'}
        await w.write_pairwise(pairwises['agent-86'].their_did, metadata=metadata, replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 6 == Replaced metadata and got {} record{} for agent-86 by remote DID: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Exercise AbsentRecord on (non-)update of missing pairwise DID
        try:
            x_did = 'X' * 22
            await w.write_pairwise(x_did, metadata=metadata)
            assert False
        except AbsentRecord:
            print('\n\n== 7 == Refused to update missing pairwise DID on as expected')

        try:
            xmeta = {True: True}
            pwise = await w.write_pairwise(pairwises['agent-86'].their_did, metadata=xmeta)
            assert StorageRecord.ok_tags(pwise.metadata)
            print('\n\n== 8 == Coerced metadata {} on write to tags: {}'.format(xmeta, ppjson(pwise.metadata)))
        except BadRecord:
            assert False

        # Update metadata with ~tags, exercise equivalence; get by DID
        metadata = {'~clearance': 'cosmic'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata)  # update metadata should overwrite prior (clearance) attr on ~
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 9 == Updated metadata on ~tags and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert ({k for k in records[pairwises['agent-86'].their_did].metadata} ==
            baseline_meta | {'secrecy', 'clearance', 'True'})

        # Replace metadata on ~tags, exercise equivalence; get by DID
        metadata = {'~secrecy': 'hover cover'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 10 == Replaced metadata on ~tags and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Vacuous storage changing nothing: show intact metadata; get by DID
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 11 == Wrote non-delta and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Clear metadata, show retention of did and verkey base line; get by DID
        metadata = None
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 12 == Cleared metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta

        # Restore epoch to metadata; get all
        metadata = {'epoch': int(time())}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise()
        print('\n\n== 13 == Got {} record{} from get-all: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Get by WQL $neq
        records = await w.get_pairwise(json.dumps({
            'their_verkey': {
                '$neq': pairwises['agent-99'].their_verkey
            }
        }))
        print('\n\n== 14 == Got {} record{} from by WQL on $neq: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 1
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch'}

        # Get by WQL $in
        records = await w.get_pairwise(json.dumps({
            'their_verkey': {
                '$in': [pairwises[name].their_verkey for name in pairwises]
            }
        }))
        print('\n\n== 15 == Got {} record{} from by WQL on $in: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Get by WQL $or
        records = await w.get_pairwise(json.dumps({
            '$or': [
                {
                    'their_verkey': pairwises['agent-86'].their_verkey,
                },
                {
                    'their_did': pairwises['agent-99'].their_did,
                }
            ]
        }))
        print('\n\n== 16 == Got {} record{} from by WQL on $or: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Get by WQL $neq
        records = await w.get_pairwise(json.dumps({
            'their_verkey': {
                '$neq': pairwises['agent-99'].their_verkey
            }
        }))
        print('\n\n== 17 == Got {} record{} from by WQL on $neq: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 1
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch'}

        # Get by WQL $lte
        records = await w.get_pairwise(json.dumps({
            'epoch': {
                '$lte': int(time())
            }
        }))
        print('\n\n== 18 == Got {} record{} from by WQL on $lte: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Get by WQL $like
        records = await w.get_pairwise(json.dumps({
            'their_did': {
                '$like': '{}%'.format(pairwises['agent-86'].their_did)
            }
        }))
        print('\n\n== 19 == Got {} record{} from by WQL on $like: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 1
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch'}

        # Get by WQL equality
        records = await w.get_pairwise(json.dumps({
            'their_did': pairwises['agent-86'].their_did
        }))
        print('\n\n== 20 == Got {} record{} from by WQL on equality: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 1
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch'}

        # Get by nested WQL $or-$like
        records = await w.get_pairwise(json.dumps({
            '$or': [
                {
                    'their_verkey': {
                        '$like': '{}%'.format(pairwises['agent-86'].their_verkey)
                    }
                },
                {
                    'their_verkey': {
                        '$like': '{}%'.format(pairwises['agent-99'].their_verkey)
                    }
                }
            ]
        }))
        print('\n\n== 21 == Got {} record{} from by nested $or-$like WQL: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Get by nested WQL
        records = await w.get_pairwise(json.dumps({
            '$not': {
                'my_did': None
            },
            '$not': {
                'epoch': {
                    '$in': [1, 2, 3, 4, 5]
                }
            },
            'epoch': {
                '$gt': 0,
            },
            '$or': [
                {
                    'their_verkey': {
                        '$like': '{}%'.format(pairwises['agent-86'].their_verkey)
                    }
                },
                {
                    'their_verkey': {
                        '$like': '{}%'.format(pairwises['agent-99'].their_verkey)
                    }
                }
            ]
        }))
        print('\n\n== 22 == Got {} record{} from by nested WQL: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Delete
        await w.delete_pairwise(pairwises['agent-86'].their_did)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 23 == Deleted agent-86 record and checked its absence')
        assert not records

        # Exercise the above writes without specifying local DID; ensure operation creates new local DIDs and verkeys

        metadata = {'epoch': int(time())}  # preparing to exercise metadata int to str
        await w.write_pairwise(
            pairwises['agent-99'].their_did,
            pairwises['agent-99'].their_verkey,
            None,
            metadata)
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 24 == Stored and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta
        p86_my_did = records[pairwises['agent-86'].their_did].my_did
        p86_my_verkey = records[pairwises['agent-86'].their_did].my_verkey
        assert p86_my_did != wallets['multipass'].did
        assert p86_my_verkey != wallets['multipass'].verkey

        # Set metadata; get by DID
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 25 == Stored metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch'}
        assert records[pairwises['agent-86'].their_did].my_did != wallets['multipass'].did
        assert records[pairwises['agent-86'].their_did].my_verkey != wallets['multipass'].verkey
        assert records[pairwises['agent-86'].their_did].my_did != p86_my_did
        assert records[pairwises['agent-86'].their_did].my_verkey != p86_my_verkey

        # Augment metadata; get by DID
        metadata = {'clearance': 'galactic'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 26 == Stored metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch', 'clearance'}

        # Replace metadata; get by DID
        metadata = {'phone': 'shoe'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 27 == Replaced metadata and got {} record{} for agent-86 by explicit pairwise info: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'phone'}

        # Replace metadata on implicit pairwise info; get by DID
        metadata = {'secrecy': 'hover cover'}
        await w.write_pairwise(pairwises['agent-86'].their_did, metadata=metadata, replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 28 == Replaced metadata and got {} record{} for agent-86 by remote DID: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Exercise AbsentRecord on (non-)update of missing pairwise DID
        try:
            x_did = 'X' * 22
            await w.write_pairwise(x_did, metadata=metadata)
            assert False
        except AbsentRecord:
            print('\n\n== 29 == Refused to update missing pairwise DID on as expected')

        # Update metadata with ~tags, exercise equivalence; get by DID
        metadata = {'~clearance': 'cosmic'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata)  # update metadata should overwrite prior (clearance) attr on ~
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 30 == Updated metadata on ~tags and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert ({k for k in records[pairwises['agent-86'].their_did].metadata} ==
            baseline_meta | {'secrecy', 'clearance'})

        # Replace metadata on ~tags, exercise equivalence; get by DID
        metadata = {'~secrecy': 'hover cover'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 31 == Replaced metadata on ~tags and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Vacuous storage changing nothing: show intact metadata; get by DID
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 32 == Wrote non-delta and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Clear metadata, show retention of did and verkey base line; get by DID
        metadata = None
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 33 == Cleared metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta

        # Restore epoch to metadata; get all
        metadata = {'epoch': int(time())}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise()
        print('\n\n== 34 == Got {} record{} from get-all: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Delete
        await w.delete_pairwise(pairwises['agent-86'].their_did)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 35 == Deleted agent-86 record and checked its absence')
        assert not records


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_non_secret_storage_records():

    print(Ink.YELLOW('\n\n== Testing non-secret storage record operations =='))

    wallets = await get_wallets(
        {
            'multipass': {
                'seed': 'Multi-Pass-000000000000000000000'
            }
        },
        open_all=False,
        auto_remove=True)

    # Open wallet and operate
    async with wallets['multipass'] as w:
        await w.delete_non_secret('a-type', 'id0')  # not present: silently carries on
        assert await w.get_non_secret('a-type', 'id0') == {}

        try: # exercise tag value type checking
            StorageRecord('a-type', 'value', {'a_tag': 123}, 'id0')
            assert False
        except BadRecord:
            pass

        # Store non-secret records
        ns = [
            StorageRecord('a-type', 'value 0'),
            StorageRecord('a-type', 'value 1', {'epoch': str(int(time()))}, '1')
        ]
        assert ns[0].id  # exercise default identifier
        assert ns[0] != ns[1]

        await w.write_non_secret(ns[0])
        await w.write_non_secret(ns[1])
        recs = await w.get_non_secret(ns[1].type, ns[1].id)
        print('\n\n== 1 == Stored and got {} record{} for id 1: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert {k for k in recs[ns[1].id].tags} == {'epoch'}

        # Exercise tag type checking
        for tags in [{'price': 4.95}, {'too': {'deep': ''}}, {(0,1): 'key-str'}]:
            try:
                ns[0].tags = tags
                assert False
            except BadRecord:
                pass
        ns[1].tags['score'] = 7
        try:
            await w.write_non_secret(ns[1])
            assert False
        except BadRecord:
            pass
        print('\n\n== 2 == Tags type validation enforces flat {str: str} dict')

        # Augment/override vs. replace metadata
        ns[1].tags = {'score': '7'}
        await w.write_non_secret(ns[1])
        recs = await w.get_non_secret(ns[1].type, ns[1].id)
        assert {k for k in recs[ns[1].id].tags} == {'epoch', 'score'}
        await w.write_non_secret(ns[1], replace_meta = True)
        recs = await w.get_non_secret(ns[1].type, ns[1].id)
        assert {k for k in recs[ns[1].id].tags} == {'score'}
        print('\n\n== 3 == Metadata augment/override vs. replace metadata behaviour OK')

        ns[1].tags['~clear'] = 'text'  # exercise clear/encr tags
        assert {k for k in ns[1].clear_tags} == {'~clear'}
        assert {k for k in ns[1].encr_tags} == {'score'}

        ns[1].value = 'value 0'
        ns[1].tags = None
        await w.write_non_secret(ns[1], replace_meta=True)
        recs = await w.get_non_secret(ns[1].type, ns[1].id)
        assert recs[ns[1].id].tags == None and recs[ns[1].id].value == 'value 0'
        print('\n\n== 4 == Record replacement OK')

        nsb = StorageRecord('b-type', ns[1].value, ns[1].tags, ns[1].id)
        await w.write_non_secret(nsb)
        recs = await w.get_non_secret(nsb.type, nsb.id)
        assert recs[nsb.id].type == 'b-type' and recs[nsb.id].tags == None and recs[nsb.id].value == 'value 0'
        recs = await w.get_non_secret('a-type', nsb.id)
        assert recs[nsb.id].type == 'a-type' and recs[nsb.id].tags == None and recs[nsb.id].value == 'value 0'
        print('\n\n== 5 == Check for record type respect passes OK')
        await w.delete_non_secret('b-type', nsb.id)

        ns = []
        epoch = int(time())
        for i in range(5):
            await w.write_non_secret(StorageRecord(
                'searchable',
                str(i),
                {
                    '~epoch': str(epoch),
                    'encr': str(i)
                },
                str(i)))

        # Get by WQL $neq
        recs = await w.get_non_secret(
            'searchable',
            {
                '~epoch': {
                    '$neq': epoch + 1  # exercise to-str canonicalization
                }
            })
        print('\n\n== 6 == Got {} record{} from by WQL on $neq: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 5

        # Get by WQL $not-$in
        recs = await w.get_non_secret(
            'searchable',
            {
                '$not': {
                    '~epoch': {
                        '$in': [epoch - 1, epoch + 1]
                    }
                }
            })
        print('\n\n== 7 == Got {} record{} from by WQL on $not-$in: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 5

        # Get by WQL $like
        recs = await w.get_non_secret(
            'searchable',
            {
                '~epoch': {
                    '$like': '{}%'.format(epoch)
                }
            })
        print('\n\n== 8 == Got {} record{} from by WQL on $not-$in: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 5

        # Get by WQL equality
        recs = await w.get_non_secret(
            'searchable',
            {
                '~epoch': epoch
            })
        print('\n\n== 9 == Got {} record{} from by WQL on equality: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 5

        # Get by WQL $or
        recs = await w.get_non_secret(
            'searchable',
            {
                '$or': [
                    {
                        '~epoch': epoch
                    },
                    {
                        '~epoch': epoch + 1
                    }
                ]
            })
        print('\n\n== 10 == Got {} record{} from by WQL on equality: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 5

        # Get by WQL $lte
        recs = await w.get_non_secret(
            'searchable',
            {
                '~epoch': {
                    '$lte': epoch
                }
            })
        print('\n\n== 11 == Got {} record{} from by WQL on $lte: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 5

        # Get by WQL $not on encrypted tag values
        recs = await w.get_non_secret(
            'searchable',
            {
                '$not': {
                    'encr': str(0)
                }
            })
        print('\n\n== 12 == Got {} record{} from by WQL on $not for encrypted tag value: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 4

        # Get by WQL equality on encrypted tag values
        recs = await w.get_non_secret(
            'searchable',
            {
                'encr': str(0)
            })
        print('\n\n== 13 == Got {} record{} from by WQL on equality for encrypted tag value: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == 1

        # Exercise WQL search pagination
        cardinality = Wallet.DEFAULT_CHUNK + 16
        nsw = [
            StorageRecord('wql', 'value {}'.format(i), {'~meta': str(i)}, str(i)) for i in range(cardinality)
        ]

        for i in range(cardinality):
            await w.write_non_secret(nsw[i])

        recs = await w.get_non_secret(
            'wql',
            {
                '~meta': {
                    '$gte': 0
                }
            })

        print('\n\n== 14 == Stored and got {} record{} using WQL pagination'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's'))
        assert len(recs) == cardinality
        assert {i for i in range(cardinality)} == {int(k) for k in recs}

        # Exercise limit
        recs = await w.get_non_secret(
            'wql',
            {
                '~meta': {
                    '$gte': 0
                }
            },
            limit=Wallet.DEFAULT_CHUNK)

        print('\n\n== 15 == Stored and got {} record{} using hard limit of {}: {}'.format(
            len(recs or {}),
            '' if len(recs or {}) == 1 else 's',
            Wallet.DEFAULT_CHUNK,
            ppjson({k: vars(recs[k]) for k in recs})))
        assert len(recs) == Wallet.DEFAULT_CHUNK
        assert all(int(k) in range(cardinality) for k in recs)

        # Link secret checks
        await w.create_link_secret('test-secret')
        assert await w.get_link_secret_label() == 'test-secret'
        await w.create_link_secret('test-secret')  # exercise double-write
        assert await w.get_link_secret_label() == 'test-secret'
        await w.create_link_secret('test-another-secret')
        assert await w.get_link_secret_label() == 'test-another-secret'
        print('\n\n== 16 == Link secret writes sync with non-secret label records OK')

        # Storage record search
        S_TYPE = 'searchable'
        NUM_RECS = Wallet.DEFAULT_CHUNK * 2 + 24  # two chunks and some extra
        for i in range(NUM_RECS):
            await w.write_non_secret(StorageRecord(S_TYPE, str(i), {'~value': str(i)}, str(i)))
        storec_search = StorageRecordSearch(
            w,
            S_TYPE,
            {
                '~value': {
                    '$neq': 0 # exercise canonicalization (to string)
                }
            })
        found = []
        async with storec_search:
            while True:
                chunk = await storec_search.fetch()
                if not chunk:
                    break
                found.extend([int(storec.value) for storec in chunk])
        assert not storec_search.opened
        assert sorted(found, key=int) == [i for i in range(NUM_RECS) if i]
        print('\n\n== 17 == Stored and found non-secret {} storage records via batch-wise search'.format(S_TYPE))

        # Exercise double-open exception
        x_search = StorageRecordSearch(w, S_TYPE, {'~value': -1})
        async with x_search:
            try:
                async with x_search:
                    assert False
            except BadSearch:
                pass
        print('\n\n== 18 == Refused to double-open search as expected')

        for i in range(NUM_RECS):
            await w.delete_non_secret(S_TYPE, str(i))
        print('\n\n== 19 == Deleted {} records'.format(S_TYPE))

@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_pack():

    print(Ink.YELLOW('\n\n== Testing packing/unpacking =='))

    wallets = await get_wallets(
        {
            'agent-13': {
                'seed': 'Agent-13-00000000000000000000000'
            },
            'agent-86': {
                'seed': 'Agent-86-00000000000000000000000',
            },
            'agent-99': {
                'seed': 'Agent-99-00000000000000000000000'
            }
        },
        open_all=False,
        auto_remove=True)

    # Open wallets and operate
    async with wallets['agent-13'] as w13, (
            wallets['agent-86']) as w86, (
            wallets['agent-99']) as w99:

        dids = {name: wallets[name].did for name in wallets}
        print('\n\n== 1 == DIDs: {}'.format(ppjson(dids)))

        # Agent 86 packs and unpacks to and from itself anonymously, implicitly and explicitly
        plain = 'Hello World'
        packed = await w86.pack(plain)
        print('\n\n== 2 == Plaintext: {}, packed JWE: {}'.format(plain, packed))
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, None, w86.verkey)
        packed = await w86.pack(plain, w86.verkey)
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, None, w86.verkey)
        packed = await w86.pack(plain, [w86.verkey])
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, None, w86.verkey)
        print('\n\n== 3 == {} packed and unpacked anonymous message: {}'.format(w86.name, unpacked[0]))

        # Agent 86 signs and packs to itself, then unpacks, with anchor verkey and loc did verkey
        packed = await w86.pack(plain, None, w86.verkey)
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, w86.verkey, w86.verkey)
        loc_did_info = await w86.create_local_did('Shoe-Phone-000000000000000000000')
        packed = await w86.pack(plain, None, loc_did_info.verkey)
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, loc_did_info.verkey, w86.verkey)
        print('\n\n== 4 == {} packed and unpacked authenticated message: {}'.format(w86.name, unpacked[0]))

        # Agent 86 signs and packs to agents 13 and 99, fails to unpack
        packed = await w86.pack(plain, [w13.verkey, w99.verkey], loc_did_info.verkey)
        unpacked = await w13.unpack(packed)
        assert unpacked == (plain, loc_did_info.verkey, w13.verkey)
        print('\n\n== 5.0 == {} auth-packed, {} unpacked: {}'.format(w86.name, w13.name, unpacked[0]))
        unpacked = await w99.unpack(packed)
        assert unpacked == (plain, loc_did_info.verkey, w99.verkey)
        print('\n\n== 5.1 == {} auth-packed, {} unpacked: {}'.format(w86.name, w99.name, unpacked[0]))
        try:
            unpacked = await w86.unpack(packed)
            assert False
        except AbsentRecord:
            pass
        print('\n\n== 5.2 == {} correctly failed to unpack ciphertext'.format(w86.name))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_data_structures(path_home):

    print(Ink.YELLOW('\n\n== Testing various record and info types'))

    w_name = 'multipass'
    w_mgr = WalletManager()
    loc_did = '55GkHamhTU1ZbTbV2ab9DE'

    wallets = await get_wallets(
        {
            w_name: {
                'seed': 'Multi-Pass-000000000000000000000',
                'link_secret_label': 'secret'
            },
        },
        open_all=False,
        auto_remove=True)

    # Open wallet and operate, default access
    async with wallets[w_name] as w:
        endpoint = '1.2.3.4:5678'
        meta = {'hello': 'world'}

        # DIDInfo
        did_info = await w.create_local_did(None, loc_did)
        did_info.metadata = {}
        assert bool(did_info.verkey)
        assert did_info.metadata == None
        print('\n\n== 1 == DIDInfo OK')

        # KeyInfo
        key_info = KeyInfo(did_info.verkey)
        assert key_info.metadata == None
        key_info.metadata = meta
        assert key_info.metadata == meta
        print('\n\n== 2 == KeyInfo OK')

        # EndpointInfo
        endpoint_info = EndpointInfo(endpoint, did_info.verkey)
        assert endpoint_info.endpoint == endpoint
        assert endpoint_info.ip_addr == '1.2.3.4'
        assert endpoint_info.port == 5678
        assert endpoint_info.verkey == did_info.verkey

        another_endpoint_info = EndpointInfo('1.2.3.4:56', did_info.verkey)
        assert endpoint_info != another_endpoint_info
        assert repr(endpoint_info) == 'EndpointInfo({}, {})'.format(endpoint, did_info.verkey)
        print('\n\n== 3 == EndpointInfo OK')

        # PairwiseInfo
        pairwise = PairwiseInfo(None, None, None, None)
        assert pairwise.metadata is None
        assert pairwise.their_did is None
        assert pairwise.their_verkey is None
        assert pairwise.my_did is None
        assert pairwise.my_verkey is None
        pairwise.metadata = {'bad': {'metadata': 'too deep'}}
        try:
            pairwise_info2tags(pairwise)
            assert False
        except BadRecord:
            pass
        print('\n\n== 4 == PairwiseInfo OK')

        # StorageRecord
        storec = StorageRecord(None, None)
        assert storec.id  # random UUID
        storec.id = str(1234)
        assert storec.id == str(1234)
        print('\n\n== 5 == StorageRecord OK')
        

@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_export_import(path_home):

    print(Ink.YELLOW('\n\n== Testing export/import =='))

    w_name = 'multipass'
    w_mgr = WalletManager()
    loc_did = '55GkHamhTU1ZbTbV2ab9DE'
    path_export = Path(join(gettempdir(), 'export-multipass'))
    if path_export.exists():
        unlink(str(path_export))

    wallets = await get_wallets(
        {
            w_name: {
                'seed': 'Multi-Pass-000000000000000000000',
                'link_secret_label': 'secret'
            },
        },
        open_all=False,
        auto_remove=True)

    # Open wallet and operate, default access
    async with wallets[w_name] as w:
        did_info = await w.create_local_did(None, loc_did)
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 2  # 'since', 'modified'
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

        label = await w.get_link_secret_label()
        assert label
        print('\n\n== 1 == Created wallet for export with link secret label: {}'.format(label))
        await w_mgr.export_wallet(w, str(path_export))

    assert path_export.exists(), 'Exported wallet path {} not present'.format(path_export)
    print('\n\n== 2 == Exported wallet to path {}'.format(path_export))

    path_import = Path(path_home, 'wallet', w_name)
    assert not path_import.exists()
    await w_mgr.import_wallet({'id': w_name}, str(path_export))
    assert path_import.exists()
    print('\n\n== 3 == Imported wallet from path {}'.format(path_export))

    async with w_mgr.get({'id': w_name}) as w:
        loc = await w.get_local_did(loc_did)
        print('\n\n== 4.1 == Local DID imported OK: {}'.format(loc))
        import_label = await w.get_link_secret_label()
        print('\n\n== 4.2 == Link secret imported on label: {}'.format(label))
        assert import_label == label
        w.auto_remove = True  # no further need for it
    assert not path_import.exists()

    # Export/import on non-default access
    if path_export.exists():
        unlink(str(path_export))
    access = 'secret-squirrel'
    w = await w_mgr.create({'id': w_name, 'link_secret_label': 'secret', 'auto_remove': True}, access)

    try:  # exercise export-closed exception
        await w_mgr.export_wallet(w, str(path_export))
        assert False
    except WalletState:
        pass
    print('\n\n== 5 == Refused to export closed wallet as expected')

    async with w:
        did_info = await w.create_local_did(None, loc_did)
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 2  # 'since', 'modified'
        assert did_info == await w.get_local_did(did_info.did)
        assert did_info == await w.get_local_did(did_info.verkey)

        label = await w.get_link_secret_label()
        assert label
        print('\n\n== 6 == Created wallet for export with link secret label: {}'.format(label))
        await w_mgr.export_wallet(w, str(path_export))

    assert path_export.exists(), 'Exported wallet path {} not present'.format(path_export)
    print('\n\n== 7 == Exported wallet to path {}'.format(path_export))

    path_import = Path(path_home, 'wallet', w_name)
    assert not path_import.exists()

    try:  # exercise no import on bad access
        await w_mgr.import_wallet({'id': w_name}, str(path_export), 'not-{}'.format(access))
        assert False
    except BadAccess:
        pass
    print('\n\n== 8 == Wallet does not import from {} on bad access credential value, as expected'.format(path_export))

    await w_mgr.import_wallet({'id': w_name}, str(path_export), access)
    assert path_import.exists()
    print('\n\n== 9 == Imported wallet from path {}'.format(path_export))

    async with w_mgr.get({'id': w_name, 'auto_remove': True}, access) as w:
        loc = await w.get_local_did(loc_did)
        print('\n\n== 10.1 == Local DID imported OK: {}'.format(loc))
        import_label = await w.get_link_secret_label()
        print('\n\n== 10.2 == Link secret imported on label: {}'.format(label))
        assert import_label == label

    if path_export.exists():
        unlink(str(path_export))
    try:
        await w_mgr.import_wallet({'id': w_name}, str(path_export), access)
        assert False
    except IndyError as x_indy:
        if x_indy.error_code == ErrorCode.CommonIOError:
            pass
        else:
            assert False
    print('\n\n== 11 == Wallet does not import from nonexistent path {} as expected'.format(path_export))


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_reseed_reset(path_home):

    print(Ink.YELLOW('\n\n== Testing wallet reseed-local, reset operations'))

    w_name = 'multipass'
    w_mgr = WalletManager()
    loc_did = '55GkHamhTU1ZbTbV2ab9DE'

    wallets = await get_wallets(
        {
            w_name: {
                'seed': 'Multi-Pass-000000000000000000000',
                'link_secret_label': 'secret'
            },
        },
        open_all=False,
        auto_remove=False)

    try:
        await w_mgr.reseed_local(wallets[w_name])
        assert False
    except WalletState:
        pass
    print('\n\n== 1 == Closed wallet {} reseed fails as expected'.format(w_name))

    try:
        await w_mgr.reset(wallets[w_name])
        assert False
    except WalletState:
        pass
    print('\n\n== 2 == Closed wallet {} reset fails as expected'.format(w_name))

    # Open wallet and operate
    w_reset = None
    async with wallets[w_name] as w:
        await w_mgr.reseed_local(wallets[w_name])
        w_reset = await w_mgr.reset(wallets[w_name])
        await w_reset.close()
    print('\n\n== 3 == Wallet {} reseeds (locally) and resets OK'.format(w_name))

    await w_mgr.remove(w_reset)
    print('\n\n== 4 == Removed wallet {}'.format(w_reset.name))
