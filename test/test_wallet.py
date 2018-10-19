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
from pathlib import Path

from von_anchor.error import JSONValidation
from von_anchor.frill import Ink
from von_anchor.wallet import Wallet

import pytest


@pytest.mark.asyncio
async def test_wallet(path_home):

    print(Ink.YELLOW('\n\n== Testing Wallet Configuration + Context =='))

    seed = '00000000000000000000000000000000'
    name = 'my-wallet'
    path = Path(path_home, 'wallet', name)
    path_seed2did = path.with_name('{}.seed2did'.format(path.name))

    # 1. Configuration with auto-remove set
    w = Wallet(seed, name, None, {'auto-remove': True})
    await w.create()
    assert path.exists(), 'Wallet path {} not present'.format(path)
    await w.open()
    assert w.did
    assert w.verkey
    await w.close()
    assert not path.exists(), 'Wallet path {} still present'.format(path)
    assert not path_seed2did.exists(), 'Wallet path {} still present'.format(path_seed2did)
    print('\n\n== 1 == New wallet with auto-remove OK')

    # 2. Default configuration (auto-remove=False)
    w = Wallet(seed, name)
    await w.create()
    assert path.exists(), 'Wallet path {} not present'.format(path)
    assert not path_seed2did.exists(), 'Wallet path {} still present'.format(path_seed2did)

    await w.open()
    assert w.did
    assert w.verkey
    (w_did, w_verkey) = (w.did, w.verkey)
    await w.close()
    assert path.exists(), 'Wallet path {} not present'.format(path)
    assert not path_seed2did.exists(), 'Wallet path {} still present'.format(path_seed2did)
    print('\n\n== 2 == New wallet with default config (no auto-remove) OK')

    # 3. Make sure wallet opens from extant file
    x = Wallet(seed, name, None, {'auto-remove': True})
    await x.create()

    async with x:
        assert x.did == w_did
        assert x.verkey == w_verkey

    assert not path.exists(), 'Wallet path {} still present'.format(path)
    assert not path_seed2did.exists(), 'Wallet path {} still present'.format(path_seed2did)
    print('\n\n== 3 == Re-use extant wallet OK')

    # 4. Double-open
    try:
        async with await Wallet(seed, name, None, {'auto-remove': True}).create() as w:
            async with w:
                assert False
    except IndyError as e:
        assert e.error_code == ErrorCode.WalletAlreadyOpenedError

    assert not path.exists(), 'Wallet path {} still present'.format(path)
    assert not path_seed2did.exists(), 'Wallet path {} still present'.format(path_seed2did)

    # 5. Bad config
    try:
        Wallet(seed, name, None, {'auto-remove': 'a suffusion of yellow'})
    except JSONValidation:
        pass
    print('\n\n== 4 == Error cases error as expected')

    # X. Rekey operation tested via anchor, in test_anchors.py
