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


import re

from math import log
from random import choice
from string import printable
from sys import float_info

import pytest

from von_anchor.indytween import encode, I32_BOUND
from von_anchor.frill import Ink


@pytest.mark.asyncio
async def test_encode():
    print(Ink.YELLOW('\n\n== Testing encode for string of length up to 1024'))

    for printable_len in range(0, 1025):
        orig = ''.join(choice(printable) for _ in range(printable_len))
        print('.', end='' if (printable_len + 1) % 100 else '{}\n'.format(printable_len), flush=True)
        enc = encode(orig)
        assert int(log(max(int(enc), 1))/log(2)) < 256
    print('\n\n== Random printable string test passed')

    print('\n\n== Typical cases - (type) orig -> encoded:')
    for orig in (
            chr(0),
            chr(1),
            chr(2),
            'Alice',
            'Bob',
            'J.R. "Bob" Dobbs',
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
            -1.9234856120348166e+37,
            1.9234856120348166e+37,
            -19234856120348165921835629183561023142.55,
            19234856120348165921835629183561023142.55,
            float_info.max,
            'Hello',
            '',
            'True',
            'False',
            '1234',
            '-12345',
            [],
            [0, 1, 2, 3],
            {'a': 1, 'b': 2, 'c': 3},
            [{}, {'a': [0, 0.1], 'b': [0.0, float_info.min]}, True]):
        enc = encode(orig)
        print('  ({})({}) -> {}'.format(
            type(orig).__name__,
            '0x{:02x}'.format(ord(orig))
                if orig in (chr(0), chr(1), chr(2))
                else "%f" % orig if isinstance(orig, float)
                else orig,
            enc))
        assert isinstance(enc, str)
        assert re.match(r'-?[0-9]+$', enc)
        if int(enc) == orig:
            assert isinstance(orig, int) and (-I32_BOUND <= orig < I32_BOUND)  # includes bools
        else:
            assert not (isinstance(orig, int) and (-I32_BOUND <= orig < I32_BOUND))
