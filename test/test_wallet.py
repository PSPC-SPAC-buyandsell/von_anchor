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


from pathlib import Path
from time import time

import json
import pytest

from indy import IndyError
from indy.error import ErrorCode

from von_anchor.error import AbsentRecord, BadRecord, ExtantWallet, JSONValidation, WalletState
from von_anchor.frill import Ink, ppjson
from von_anchor.wallet import NonSecret, PairwiseInfo, Wallet


async def get_wallets(wallet_data, open_all, auto_remove=False):
    rv = {}
    for (name, seed) in wallet_data.items():
        w = Wallet(name, storage_type=None, config={'auto-remove': True} if auto_remove else None)
        try:
            if seed:
                await w.create(seed)
        except ExtantWallet:
            pass
        if open_all:
            await w.open()
        rv[name] = w
    return rv


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_wallet(path_home):

    print(Ink.YELLOW('\n\n== Testing Wallet Configuration + Context =='))

    seed = '00000000000000000000000000000000'
    name = 'my-wallet'
    access_creds = {'key': 'secret-squirrel'}
    path = Path(path_home, 'wallet', name)

    # 1. Configuration with auto-remove set
    w = Wallet(name, None, {'auto-remove': True}, access_creds=access_creds)
    await w.create(seed)
    assert path.exists(), 'Wallet path {} not present'.format(path)
    await w.open()
    assert w.did
    assert w.verkey
    await w.close()
    assert not path.exists(), 'Wallet path {} still present'.format(path)
    print('\n\n== 1 == New wallet with auto-remove OK')

    # 2. Default configuration (auto-remove=False)
    w = Wallet(name, access_creds=access_creds)
    await w.create(seed)
    assert path.exists(), 'Wallet path {} not present'.format(path)

    await w.open()
    assert w.did
    assert w.verkey
    (w_did, w_verkey) = (w.did, w.verkey)
    await w.close()
    assert path.exists(), 'Wallet path {} not present'.format(path)
    print('\n\n== 2 == New wallet with default config (no auto-remove) OK')

    # 3. Make sure wallet opens from extant file, only on correct access credentials
    x = Wallet(name, None, {'auto-remove': True})
    try:
        await x.create(seed)
    except ExtantWallet:
        pass

    try:
        async with x:
            assert False
    except IndyError as x_indy:
        assert x_indy.error_code == ErrorCode.WalletAccessFailed

    ww = Wallet(name, None, {'auto-remove': True}, access_creds=access_creds)
    async with ww:
        assert ww.did == w_did
        assert ww.verkey == w_verkey

    assert not path.exists(), 'Wallet path {} still present'.format(path)
    print('\n\n== 3 == Re-use extant wallet on good access creds OK, wrong access creds fails as expected')

    # 4. Double-open
    try:
        w = await Wallet(name, None, {'auto-remove': True}).create(seed)
        async with w:
            async with w:
                assert False
    except WalletState:
        pass

    assert not path.exists(), 'Wallet path {} still present'.format(path)

    # 5. Bad config
    try:
        Wallet(name, None, {'auto-remove': 'a suffusion of yellow'})
    except JSONValidation:
        pass
    print('\n\n== 4 == Error cases error as expected')

    # X. Rekey operation tested via anchor, in test_anchors.py


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_local_dids():

    print(Ink.YELLOW('\n\n== Testing local DID operations =='))

    wallets = await get_wallets(
        {
            'multipass': 'Multi-Pass-000000000000000000000',
        },
        open_all=False,
        auto_remove=True)

    # Open wallet and operate
    async with wallets['multipass'] as w:
        did_info = await w.create_local_did(None, '55GkHamhTU1ZbTbV2ab9DE')
        print('\n\n == 1 == Created local known DID: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 1  # 'since'
        assert did_info == await w.get_local_did_info(did_info.did)
        assert did_info == await w.get_local_did_info(did_info.verkey)

        did_info = await w.create_local_did()
        print('\n\n == 2 == Created random local DID: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 1
        assert did_info == await w.get_local_did_info(did_info.did)
        assert did_info == await w.get_local_did_info(did_info.verkey)

        did_info = await w.create_local_did('Agent-44-00000000000000000000000')
        print('\n\n == 3 == Created local DID on seed: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata)
        assert did_info == await w.get_local_did_info(did_info.did)
        assert did_info == await w.get_local_did_info(did_info.verkey)

        did_info = await w.create_local_did(metadata={'hello': 'world'})
        print('\n\n == 4 == Created random local DID with metadata: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 2
        assert did_info == await w.get_local_did_info(did_info.did)
        assert did_info == await w.get_local_did_info(did_info.verkey)

        did_info = await w.create_local_did('Agent-13-00000000000000000000000', metadata={'hello': 'world'})
        print('\n\n == 5 == Created local DID on seed with metadata: {}'.format(did_info))
        assert did_info.did and did_info.verkey and len(did_info.metadata) == 2
        assert did_info == await w.get_local_did_info(did_info.did)
        assert did_info == await w.get_local_did_info(did_info.verkey)

@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_pairwise():

    print(Ink.YELLOW('\n\n== Testing pairwise operations =='))

    wallets = await get_wallets(
        {
            'multipass': 'Multi-Pass-000000000000000000000',
            'agent-86': 'Agent-86-00000000000000000000000',
            'agent-99': 'Agent-99-00000000000000000000000',
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

        # Replace metadata; get by DID
        metadata = {'secrecy': 'hover cover'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 5 == Replaced metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Update metadata with ~tags, exercise equivalence; get by DID
        metadata = {'~clearance': 'cosmic'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            wallets['multipass'].did,
            metadata)  # update metadata should overwrite prior (clearance) attr on ~
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 6 == Updated metadata on ~tags and got {} record{} for agent-86: {}'.format(
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
            wallets['multipass'].did,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 7 == Replaced metadata on ~tags and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 8 == Wrote non-delta and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 9 == Cleared metadata and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 10 == Got {} record{} from get-all: {}'.format(
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
        print('\n\n== 11 == Got {} record{} from by WQL on $neq: {}'.format(
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
        print('\n\n== 12 == Got {} record{} from by WQL on $in: {}'.format(
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
        print('\n\n== 13 == Got {} record{} from by WQL on $or: {}'.format(
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

        # Get by WQL $lte
        records = await w.get_pairwise(json.dumps({
            'epoch': {
                '$lte': int(time())
            }
        }))
        print('\n\n== 15 == Got {} record{} from by WQL on $lte: {}'.format(
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
        print('\n\n== 16 == Got {} record{} from by WQL on $like: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 1
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch'}

        # Get by WQL equality
        records = await w.get_pairwise(json.dumps({
            'their_did': pairwises['agent-86'].their_did
        }))
        print('\n\n== 17 == Got {} record{} from by WQL on equality: {}'.format(
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
        print('\n\n== 18 == Got {} record{} from by nested $or-$like WQL: {}'.format(
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
        print('\n\n== 19 == Got {} record{} from by nested WQL: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Delete
        await w.delete_pairwise(pairwises['agent-86'].their_did)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 20 == Deleted agent-86 record and checked its absence')
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
        print('\n\n== 21 == Stored and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 22 == Stored metadata and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 23 == Stored metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'epoch', 'clearance'}

        # Replace metadata; get by DID
        metadata = {'secrecy': 'hover cover'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata,
            replace_meta=True)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 24 == Replaced metadata and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Update metadata with ~tags, exercise equivalence; get by DID
        metadata = {'~clearance': 'cosmic'}
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey,
            None,
            metadata)  # update metadata should overwrite prior (clearance) attr on ~
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 25 == Updated metadata on ~tags and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 26 == Replaced metadata on ~tags and got {} record{} for agent-86: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert {k for k in records[pairwises['agent-86'].their_did].metadata} == baseline_meta | {'secrecy'}

        # Vacuous storage changing nothing: show intact metadata; get by DID
        await w.write_pairwise(
            pairwises['agent-86'].their_did,
            pairwises['agent-86'].their_verkey)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 27 == Wrote non-delta and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 28 == Cleared metadata and got {} record{} for agent-86: {}'.format(
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
        print('\n\n== 29 == Got {} record{} from get-all: {}'.format(
            len(records or {}),
            '' if len(records or {}) == 1 else 's',
            ppjson({k: vars(records[k]) for k in records})))
        assert len(records) == 2
        assert all({k for k in records[pairwises[name].their_did].metadata} ==
            baseline_meta | {'epoch'} for name in pairwises)

        # Delete
        await w.delete_pairwise(pairwises['agent-86'].their_did)
        records = await w.get_pairwise(pairwises['agent-86'].their_did)
        print('\n\n== 30 == Deleted agent-86 record and checked its absence')
        assert not records


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_non_secrets():

    print(Ink.YELLOW('\n\n== Testing non-secrets operations =='))

    wallets = await get_wallets(
        {
            'multipass': 'Multi-Pass-000000000000000000000'
        },
        open_all=False,
        auto_remove=True)

    # Open wallet and operate
    async with wallets['multipass'] as w:
        await w.delete_non_secret('a-type', 'id0')  # not present: silently carries on
        assert await w.get_non_secret('a-type', 'id0') == {}

        try: # exercise tag value type checking
            NonSecret('a-type', 'id0', 'value', {'a_tag': 123})
            assert False
        except BadRecord:
            pass

        # Store non-secret records
        ns = [
            NonSecret('a-type', '0', 'value 0'),
            NonSecret('a-type', '1', 'value 1', {'epoch': str(int(time()))})
        ]
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

        nsb = NonSecret('b-type', ns[1].id, ns[1].value, ns[1].tags)
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
            await w.write_non_secret(NonSecret(
                'searchable',
                str(i),
                str(i),
                {
                    '~epoch': str(epoch),
                    'encr': str(i)
                }))

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


@pytest.mark.skipif(False, reason='short-circuiting')
@pytest.mark.asyncio
async def test_pack():

    print(Ink.YELLOW('\n\n== Testing packing/unpacking =='))

    wallets = await get_wallets(
        {
            'agent-13': 'Agent-13-00000000000000000000000',
            'agent-86': 'Agent-86-00000000000000000000000',
            'agent-99': 'Agent-99-00000000000000000000000'
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
        assert unpacked == (plain, w86.verkey, None)
        packed = await w86.pack(plain, w86.verkey)
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, w86.verkey, None) 
        packed = await w86.pack(plain, [w86.verkey])
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, w86.verkey, None) 
        print('\n\n== 3 == {} packed and unpacked anonymous message: {}'.format(w86.name, unpacked[0]))

        # Agent 86 signs and packs to itself, then unpacks, with anchor verkey and loc did verkey
        packed = await w86.pack(plain, None, w86.verkey)
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, w86.verkey, w86.verkey)
        loc_did_info = await w86.create_local_did('Shoe-Phone-000000000000000000000')
        packed = await w86.pack(plain, None, loc_did_info.verkey)
        unpacked = await w86.unpack(packed)
        assert unpacked == (plain, w86.verkey, loc_did_info.verkey)
        print('\n\n== 4 == {} packed and unpacked authenticated message: {}'.format(w86.name, unpacked[0]))

        # Agent 86 signs and packs to agents 13 and 99, fails to unpack
        packed = await w86.pack(plain, [w13.verkey, w99.verkey], loc_did_info.verkey)
        unpacked = await w13.unpack(packed)
        assert unpacked == (plain, w13.verkey, loc_did_info.verkey)
        print('\n\n== 5.0 == {} auth-packed, {} unpacked: {}'.format(w86.name, w13.name, unpacked[0]))
        unpacked = await w99.unpack(packed)
        assert unpacked == (plain, w99.verkey, loc_did_info.verkey)
        print('\n\n== 5.1 == {} auth-packed, {} unpacked: {}'.format(w86.name, w99.name, unpacked[0]))
        try:
            unpacked = await w86.unpack(packed)
            assert False
        except AbsentRecord:
            pass
        print('\n\n== 5.2 == {} correctly failed to unpack ciphertext'.format(w86.name))
