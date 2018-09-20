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
from sys import float_info

from von_anchor.codec import canon, canon_wql, cred_attr_value, encode, decode, raw
from von_anchor.frill import Ink


@pytest.mark.asyncio
async def test_enco_deco():
    print(Ink.YELLOW('\n\n== Testing encode/decode for string of length up to 1024'))

    for printable_len in range(0, 1025):
        orig = ''.join(choice(printable) for _ in range(printable_len))
        print('.', end='' if (printable_len + 1) % 100 else '{}\n'.format(printable_len), flush=True)
        enc = encode(orig)
        dec = decode(enc)
        assert cred_attr_value(orig) == {'raw': raw(orig), 'encoded': enc}
        assert orig == dec
    print('\n\n== Random printable string test passed')

    print('\n\n== Typical cases - (type) orig -> encoded -> (type) decoded:')
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
            [{}, {'a': [0, 0.1], 'b': [0.0, float_info.min]}, True],
            ):
        enc = encode(orig)
        dec = decode(enc)
        print('  ({})({}) -> {} -> ({})({})'.format(
            type(orig).__name__,
            '0x{:02x}'.format(ord(orig))
                if orig in (chr(0), chr(1), chr(2))
                else "%f" % orig if isinstance(orig, float)
                else orig,
            enc,
            type(dec).__name__,
            '0x{:02x}'.format(ord(dec))
                if dec in (chr(0), chr(1), chr(2))
                else "%f" % dec if isinstance(dec, float)
                else dec))
        assert orig == dec

    for i in range(32):
        orig = ''.join(map(chr, [0] * i))
        enc = encode(orig)
        dec = decode(enc)
        assert cred_attr_value(orig) == {'raw': raw(orig), 'encoded': enc}
        assert orig == dec
    print('Tests OK for (str)(chr(0) multiples)')


@pytest.mark.asyncio
async def test_canon():
    print(Ink.YELLOW('\n\n== Testing Attribute Canonicalization =='))
    assert canon('testAttr') == 'testattr'
    assert canon(' test Attr ') == 'testattr'
    assert canon('testattr') == 'testattr'
    assert canon('testAttrZeroOneTwoThree') == 'testattrzeroonetwothree'
    print('\n\n== Canonicalization for attr values works as expected')


@pytest.mark.asyncio
async def test_canon_wql():
    print(Ink.YELLOW('\n\n== Testing WQL Canonicalization =='))
    invariant = [
        {},
        {
            'attr::test::marker': '1'
        },
        {
            'schema_id': None
        },
        {
            '$or': [
                {'attr::test::value': '0'},
                {'attr::test::value': {'$gt': '10'}},
                {'attr::test::value': {'$lt': '-10'}}
            ]
        },
        {  # and
           'attr::test::marker': '1',
           'attr::test::value': {'$in': ['1', '2', '3', '5', '8', '13']},
           'attr::another::value': {'$like': 'hello%'}
        }
    ]

    assert all(canon_wql(q) == q for q in invariant)
    print('\n\n== Canonicalization for invariant WQL works as expected')

    # simplest case
    q = {'attr::testAttributeName::marker': 1}
    canon_q = canon_wql(q)
    assert all(canon_q[canon(k)] == raw(q[k]) for k in q)

    # and
    q = {
        'attr::testAttributeName::marker': 1,
        'attr::testAttributeName::value': 0
    }
    canon_q = canon_wql(q)
    assert all(canon_q[canon(k)] == raw(q[k]) for k in q)

    # or
    q = {
        '$or': [
            {'attr::testAttributeName::value': '0'},
            {'attr::testAttributeName::value': '1'},
            {'attr::testAttributeName::value': '2'}
        ]
    }
    canon_q = canon_wql(q)
    assert canon_q['$or'] == [
        {'attr::testattributename::value': '0'},
        {'attr::testattributename::value': '1'},
        {'attr::testattributename::value': '2'}
    ]

    # and, not, like
    q = {
        'attr::testAttributeName::value': { 
            '$like': '%'
        },
        '$not': {
            '$or': [
                {'attr::testAttributeName::value': 0},
                {'attr::testAttributeName::value': 1},
                {'attr::testAttributeName::value': {'$gt': 10}},
                {'attr::testAttributeName::value': {'$in': [-3, -7]}},
            ]
        }
    }
    canon_q = canon_wql(q)
    assert canon_q['attr::testattributename::value'] == {'$like': '%'}
    canon_q.pop('attr::testattributename::value')
    assert canon_q['$not']['$or'] == [
        {'attr::testattributename::value': '0'},
        {'attr::testattributename::value': '1'},
        {'attr::testattributename::value': {'$gt': '10'}},
        {'attr::testattributename::value': {'$in': ['-3', '-7']}},
    ]
    canon_q.pop('$not')
    assert not canon_q

    print('\n\n== Canonicalization for non-canonical WQL works as expected')
