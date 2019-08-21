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

from von_anchor.frill import Ink
from von_anchor.tails import Tails
from von_anchor.util import (
    ok_cred_def_id,
    ok_did,
    ok_endpoint,
    ok_rev_reg_id,
    ok_role,
    ok_schema_id,
    ok_wallet_reft,
    rev_reg_id2cred_def_id)


@pytest.mark.asyncio
async def test_ids():
    print(Ink.YELLOW('\n\n== Testing Identifier Checks =='))

    assert ok_wallet_reft('49ad0727-8663-45ae-a115-12b09860f9c6')
    assert not ok_wallet_reft('Q4zqM7aXqm7gDQkUVLng9I')
    assert not ok_wallet_reft('49ad0727-45ae-a115-12b09860f9c6')
    print('\n\n== 1 == Wallet referent identifier checks pass OK')

    assert ok_did('Q4zqM7aXqm7gDQkUVLng9h')
    assert not ok_did('Q4zqM7aXqm7gDQkUVLng9I')  # 'I' not a base58 char
    assert not ok_did('Q4zqM7aXqm7gDQkUVLng')  # too short
    print('\n\n== 2 == Distributed identifier checks pass OK')

    for value in (None, 'TRUSTEE', 'STEWARD', 'TRUST_ANCHOR', ''):
        assert ok_role(value)
    for value in (123, 'TRUSTY', 'STEW', 'ANCHOR', ' '):
        assert not ok_role(value)
    print('\n\n== 3 == Role identifier checks pass OK')

    assert Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng9h')
    assert Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng')
    assert not Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9h')
    assert not Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng9hx')
    assert not Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng90')
    print('\n\n== 4 == Tails hash identifier checks pass OK')

    assert ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:3:bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h::bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2::1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0a')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9I:2:bc-reg:1.0')  # I is not in base58
    print('\n\n== 5 == Schema identifier checks pass OK')

    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag')  # protocol >= 1.4
    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:Q4zqM7aXqm7gDQkUVLng9h:2:schema_name:1.0:tag')  # long form
    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag', 'Q4zqM7aXqm7gDQkUVLng9h')  # issuer-did
    assert ok_cred_def_id(
        'Q4zqM7aXqm7gDQkUVLng9h:3:CL:Q999999999999999999999:2:schema_name:1.0:tag',
        'Q4zqM7aXqm7gDQkUVLng9h')  # long form, issuer-did
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag', 'Xxxxxxxxxxxxxxxxxxxxxx')
    assert not ok_cred_def_id(
        'Q4zqM7aXqm7gDQkUVLng9h:3:CL:Q4zqM7aXqm7gDQkUVLng9h:2:schema_name:1.0:tag',
        'Xxxxxxxxxxxxxxxxxxxxxx')  # long form, issuer-did
    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:Q4zqM7aXqm7gDQkUVLng9h:2:schema_name:1.0:tag')  # long form
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:Q4zqM7aXqm7gDQkUVLng9h:schema_name:1.0:tag')  # no :2:
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:QIIIIIIIII7gDQkUVLng9h:schema_name:1.0:tag')  # I not base58
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:QIIIIIIIII7gDQkUVLng9h:schema_name:v1.0:tag')  # bad version
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:4:CL:18:0')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h::CL:18:0')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9I:3:CL:18:tag')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3::18:tag')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:18:tag')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18z:tag')
    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18')  # protocol == 1.3
    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18', 'Q4zqM7aXqm7gDQkUVLng9h')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18', 'Xxxxxxxxxxxxxxxxxxxxxx')
    assert ok_cred_def_id(rev_reg_id2cred_def_id(
        'LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:Q4zqM7aXqm7gDQkUVLng9h:2:schema_name:1.0:tag:CL_ACCUM:1'))
    print('\n\n== 6 == Credential definition identifier checks pass OK')

    assert ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag:CL_ACCUM:1')  # protocol >= 1.4
    assert ok_rev_reg_id(
        'LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag:CL_ACCUM:1',
        'LjgpST2rjsoxYegQDRm7EL')
    assert ok_rev_reg_id(  # long form
        'LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:Q4zqM7aXqm7gDQkUVLng9h:2:schema_name:1.0:tag:CL_ACCUM:1')
    assert not ok_rev_reg_id(
        'LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag:CL_ACCUM:1',
        'Xxxxxxxxxxxxxxxxxxxxxx')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:5:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:4:CL:20:0:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL::CL:20:0:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:NOT_CL:20:tag:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20z:tag:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20::CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag::1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag:CL_ACCUM:')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:tag:CL_ACCUM')
    assert ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:CL_ACCUM:1')  # protocol == 1.3
    assert ok_rev_reg_id(
        'LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:CL_ACCUM:1',
        'LjgpST2rjsoxYegQDRm7EL')
    assert not ok_rev_reg_id(
        'LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:CL_ACCUM:1',
        'Xxxxxxxxxxxxxxxxxxxxxx')
    print('\n\n== 7 == Revocation registry identifier checks pass OK')

    assert ok_endpoint('10.0.0.2:9702')
    assert ok_endpoint('0.0.0.0:0')
    assert not ok_endpoint('canada.gc.ca:8088')
    assert not ok_endpoint(':37')
    assert not ok_endpoint('http://url-wrong')
    assert not ok_endpoint('2.3.4.5')
    assert not ok_endpoint('2.3.4:8080')
    assert not ok_endpoint('1.2.3.4:abc')
    assert not ok_endpoint('1.2.3.4:1234.56')
    print('\n\n== 8 == Endpoint checks pass OK')
