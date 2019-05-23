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


import pytest

from von_anchor.canon import canon, canon_cred_wql, canon_non_secret_wql, canon_pairwise_tag, canon_pairwise_wql
from von_anchor.error import BadWalletQuery
from von_anchor.frill import Ink
from von_anchor.indytween import raw


@pytest.mark.asyncio
async def test_canon():
    print(Ink.YELLOW('\n\n== Testing Attribute Canonicalization =='))
    assert canon('testAttr') == 'testattr'
    assert canon(' test Attr ') == 'testattr'
    assert canon('testattr') == 'testattr'
    assert canon('testAttrZeroOneTwoThree') == 'testattrzeroonetwothree'
    assert canon('') == ''
    print('\n\n== Canonicalization for attr values works as expected')


@pytest.mark.asyncio
async def test_canon_cred_wql():

    print(Ink.YELLOW('\n\n== Testing credential WQL canonicalization =='))

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

    assert all(canon_cred_wql(q) == q for q in invariant)
    print('\n\n== Canonicalization for invariant credential WQL works as expected')

    # simplest case
    q = {'attr::testAttributeName::marker': 1}
    canon_q = canon_cred_wql(q)
    assert all(canon_q[canon(k)] == raw(q[k]) for k in q)

    # and
    q = {
        'attr::testAttributeName::marker': 1,
        'attr::testAttributeName::value': 0
    }
    canon_q = canon_cred_wql(q)
    assert all(canon_q[canon(k)] == raw(q[k]) for k in q)

    # or
    q = {
        '$or': [
            {'attr::testAttributeName::value': 0},
            {'attr::testAttributeName::value': 1},
            {'attr::testAttributeName::value': 2}
        ]
    }
    canon_q = canon_cred_wql(q)
    assert canon_q['$or'] == [
        {'attr::testattributename::value': '0'},
        {'attr::testattributename::value': '1'},
        {'attr::testattributename::value': '2'}  # canonicalize tag names
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
    canon_q = canon_cred_wql(q)
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

    # bad 'or'
    q = {
        '$or': {
            'attr::testAttributeName::value': 0,
            'attr::testAttributeName::value': 1
        }
    }
    try:
        canon_q = canon_cred_wql(q)
        assert False
    except BadWalletQuery:
        pass

    print('\n\n== Canonicalization for credential WQL works as expected')


@pytest.mark.asyncio
async def test_canon_non_secret_wql():
    print(Ink.YELLOW('\n\n== Testing non-secret WQL canonicalization =='))
    invariant = [
        {},
        {
            '$or': [
                {'~redness': '0'},
                {'~redness': {'$gte': '204'}}
            ]
        },
        {  # and
            'name': {'$in': ['blue', 'vermilion', 'crimson', 'scarlet', 'claret', 'burgundy']},
            '~hello': {'$like': 'world%'}
        }
    ]

    assert all(canon_non_secret_wql(q) == q for q in invariant)
    print('\n\n== Canonicalization for invariant non-secret WQL works as expected')

    # simplest case
    q = {'item': 1}
    canon_q = canon_non_secret_wql(q)
    assert all(canon_q[k] == raw(q[k]) for k in q)

    # and
    q = {
        'yes': 1,
        'no': 0
    }
    canon_q = canon_non_secret_wql(q)
    assert all(canon_q[k] == raw(q[k]) for k in q)

    # or
    q = {
        '$or': [
            {'YES': '1'},
            {'NO': '0'}
        ]
    }
    canon_q = canon_non_secret_wql(q)
    assert canon_q['$or'] == [
        {'YES': '1'},
        {'NO': '0'}  # do not touch tag names
    ]

    # and, not, like
    q = {
        '~value': {
            '$like': '%'
        },
        '$not': {
            '$or': [
                {'~value': 0},
                {'~value': 1},
                {'~value': {'$gt': 10}},
                {'~value': {'$in': [-3, -7]}},
            ]
        }
    }
    canon_q = canon_non_secret_wql(q)
    assert canon_q['~value'] == {'$like': '%'}
    canon_q.pop('~value')
    assert canon_q['$not']['$or'] == [
        {'~value': '0'},
        {'~value': '1'},
        {'~value': {'$gt': '10'}},
        {'~value': {'$in': ['-3', '-7']}},
    ]
    canon_q.pop('$not')
    assert not canon_q

    # bad 'or'
    q = {
        '$or': {
            '~value': 0,
            '~value': 1
        }
    }
    try:
        canon_q = canon_non_secret_wql(q)
        assert False
    except BadWalletQuery:
        pass

    print('\n\n== Canonicalization for non-secret WQL works as expected')


@pytest.mark.asyncio
async def test_canon_pairwise_wql():
    print(Ink.YELLOW('\n\n== Testing pairwise WQL canonicalization =='))
    invariant = [
        {
            '$or': [
                {'~redness': '0'},
                {'~redness': {'$gte': '204'}}
            ]
        },
        {  # and
            '~name': {'$in': ['blue', 'vermilion', 'crimson', 'scarlet', 'claret', 'burgundy']},
            '~hello': {'$like': 'world%'}
        }
    ]

    assert all(canon_pairwise_wql(q) == q for q in invariant)
    print('\n\n== Canonicalization for invariant pairwise WQL works as expected')

    # empty query
    assert canon_pairwise_wql({}) == {
        '~their_did': {
            '$neq': ''
        }
    }

    # simplest case
    q = {'item': 1}
    canon_q = canon_pairwise_wql(q)
    assert all(canon_q[canon_pairwise_tag(k)] == raw(q[k]) for k in q)

    # and
    q = {
        'yes': 1,
        'no': 0
    }
    canon_q = canon_pairwise_wql(q)
    assert all(canon_q[canon_pairwise_tag(k)] == raw(q[k]) for k in q)

    # or
    q = {
        '$or': [
            {'YES': '1'},
            {'NO': '0'}
        ]
    }
    canon_q = canon_pairwise_wql(q)
    assert canon_q['$or'] == [
        {'~YES': '1'},
        {'~NO': '0'}  # mark for unencrypted storage
    ]

    # and, not, like
    q = {
        '~value': {
            '$like': '%'
        },
        '$not': {
            '$or': [
                {'value': 0},
                {'value': 1},
                {'~value': {'$gt': 10}},
                {'~value': {'$in': [-3, -7]}},
            ]
        }
    }
    canon_q = canon_pairwise_wql(q)
    assert canon_q['~value'] == {'$like': '%'}
    canon_q.pop('~value')
    assert canon_q['$not']['$or'] == [
        {'~value': '0'},
        {'~value': '1'},
        {'~value': {'$gt': '10'}},
        {'~value': {'$in': ['-3', '-7']}},
    ]
    canon_q.pop('$not')
    assert not canon_q

    # bad 'or'
    q = {
        '$or': {
            '~value': 0,
            '~value': 1
        }
    }
    try:
        canon_q = canon_pairwise_wql(q)
        assert False
    except BadWalletQuery:
        pass

    print('\n\n== Canonicalization for pairwise WQL works as expected')
