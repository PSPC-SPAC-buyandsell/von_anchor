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


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_enco_deco():
    for printable_len in range(0, 1025):
        plain = ''.join(choice(printable) for _ in range(printable_len))
        enc = encode(plain)
        dec = decode(enc)
        assert cred_attr_value(plain) == {'raw': str(plain), 'encoded': enc}
        assert plain == dec

    for plain in (
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
        enc = encode(plain)
        dec = decode(enc)
        assert cred_attr_value(plain) == {'raw': str(plain), 'encoded': enc}
        assert str(plain) == dec if isinstance(plain, list) else plain == dec  # decode(encode) retains scalar types
