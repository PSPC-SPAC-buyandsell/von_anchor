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


import pytest

from random import choice
from string import printable
from von_agent.codec import cred_attr_value, encode, decode


@pytest.mark.asyncio
async def test_enco_deco():
    print('\n\n== 0 == Starting encode/decode for string of length up to 1024')
    for printable_len in range(0, 1025):
        raw = ''.join(choice(printable) for _ in range(printable_len))
        print('.', end='' if (printable_len + 1) % 100 else '{}\n'.format(printable_len), flush=True)
        enc = encode(raw)
        dec = decode(enc)
        assert cred_attr_value(raw) == {'raw': str(raw), 'encoded': enc}
        assert raw == dec
    print('\n\n== 1 == Random printable string test passed')

    print('\n\n== 2 == Edge cases - (type) raw -> encoded -> (type) decoded:')
    for raw in (
            None,
            True,
            False,
            -5,
            0,
            1024,
            2**31 - 1,
            2**31,
            2**31 + 1,
            -2**31 - 1,
            -2**31,
            -2**31 + 1,
            0.0,
            '0.0',
            0.1,
            -0.1,
            -19234856120348165921835629183561023142.55,
            19234856120348165921835629183561023142.55,
            'Hello',
            '',
            'Enjoy the process',
            'True',
            'False',
            '1234',
            '-12345',
            [],
            [0,1,2,3]):
        enc = encode(raw)
        dec = decode(enc)
        print('  ({})({}) -> {} -> ({})({})'.format(type(raw).__name__, raw, enc, type(dec).__name__, dec))
        assert cred_attr_value(raw) == {'raw': '' if raw is None else str(raw), 'encoded': enc}
        assert str(raw) == dec if isinstance(raw, list) else raw == dec  # decode(encode) retains scalar types
