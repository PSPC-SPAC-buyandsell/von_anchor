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

import pytest

from indy import IndyError
from indy.error import ErrorCode

from von_anchor.error import ExtantWallet, JSONValidation
from von_anchor.frill import Ink
from von_anchor.wallet import Wallet


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
    except IndyError as x_indy:
        assert x_indy.error_code == ErrorCode.WalletAlreadyOpenedError

    assert not path.exists(), 'Wallet path {} still present'.format(path)

    # 5. Bad config
    try:
        Wallet(name, None, {'auto-remove': 'a suffusion of yellow'})
    except JSONValidation:
        pass
    print('\n\n== 4 == Error cases error as expected')

    # X. Rekey operation tested via anchor, in test_anchors.py
