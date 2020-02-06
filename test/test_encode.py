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


@pytest.mark.asyncio
async def test_aries_compliance():
    print(Ink.YELLOW('\n\n== Testing encoding for Aries Interop Profile compliance'))
    values = {
        "address2": {
            "raw": "101 Wilson Lane",
            "encoded": "68086943237164982734333428280784300550565381723532936263016368251445461241953"
        },
        "zip": {
            "raw": "87121",
            "encoded": "87121"
        },
        "city": {
            "raw": "SLC",
            "encoded": "101327353979588246869873249766058188995681113722618593621043638294296500696424"
        },
        "address1": {
            "raw": "101 Tela Lane",
            "encoded": "63690509275174663089934667471948380740244018358024875547775652380902762701972"
        },
        "state": {
            "raw": "UT",
            "encoded": "93856629670657830351991220989031130499313559332549427637940645777813964461231"
        },
        "Empty": {
            "raw": "",
            "encoded": "102987336249554097029535212322581322789799900648198034993379397001115665086549"
        },
        "Null": {
            "raw": None,
            "encoded": "99769404535520360775991420569103450442789945655240760487761322098828903685777"
        },
        "str None": {
            "raw": "None",
            "encoded": "99769404535520360775991420569103450442789945655240760487761322098828903685777"
        },
        "bool True": {
            "raw": True,
            "encoded": "1"
        },
        "bool False": {
            "raw": False,
            "encoded": "0",
        },
        "str True": {
            "raw": "True",
            "encoded": "27471875274925838976481193902417661171675582237244292940724984695988062543640"
        },
        "str False": {
            "raw": "False",
            "encoded": "43710460381310391454089928988014746602980337898724813422905404670995938820350"
        },
        "max i32": {
            "raw": 2147483647,
            "encoded": "2147483647"
        },
        "max i32 + 1": {
            "raw": 2147483648,
            "encoded": "26221484005389514539852548961319751347124425277437769688639924217837557266135"
        },
        "min i32": {
            "raw": -2147483648,
            "encoded": "-2147483648"
        },
        "min i32 - 1": {
            "raw": -2147483649,
            "encoded": "68956915425095939579909400566452872085353864667122112803508671228696852865689"
        },
        "float 0.0": {
            "raw": 0.0,
            "encoded": "62838607218564353630028473473939957328943626306458686867332534889076311281879"
        },
        "str 0.0": {
            "raw": "0.0",
            "encoded": "62838607218564353630028473473939957328943626306458686867332534889076311281879"
        },
        "chr 0": {
            "raw": chr(0),
            "encoded": "49846369543417741186729467304575255505141344055555831574636310663216789168157"
        },
        "chr 1": {
            "raw": chr(1),
            "encoded": "34356466678672179216206944866734405838331831190171667647615530531663699592602"
        },
        "chr 2": {
            "raw": chr(2),
            "encoded": "99398763056634537812744552006896172984671876672520535998211840060697129507206"
        }
    }

    for (tag, attr) in values.items():
        assert encode(attr['raw']) == attr['encoded']
        print('.. OK: {}'.format(tag))
