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

from von_anchor.frill import Ink
from von_anchor.tails import Tails
from von_anchor.util import ok_cred_def_id, ok_did, ok_rev_reg_id, ok_schema_id


@pytest.mark.asyncio
async def test_box_ids():
    print(Ink.YELLOW('\n\n== Testing Box Identifier Checks =='))
    
    assert ok_did('Q4zqM7aXqm7gDQkUVLng9h')  # quibble: not technically a box id
    assert not ok_did('Q4zqM7aXqm7gDQkUVLng9I')
    assert not ok_did('Q4zqM7aXqm7gDQkUVLng')

    assert Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng9h')
    assert Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng')
    assert not Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9h')
    assert not Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng9hx')
    assert not Tails.ok_hash('Q4zqM7aXqm7gDQkUVLng9hQ4zqM7aXqm7gDQkUVLng90')

    assert ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:3:bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h::bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:bc-reg:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2::1.0')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0a')
    assert not ok_schema_id('Q4zqM7aXqm7gDQkUVLng9I:2:bc-reg:1.0')  # I is not in base58

    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:0')  # protocol >= 1.4
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:4:CL:18:0')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h::CL:18:0')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9I:3:CL:18:0')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3::18:0')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:18:0')
    assert not ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18z:0')
    assert ok_cred_def_id('Q4zqM7aXqm7gDQkUVLng9h:3:CL:18')  # protocol == 1.3

    assert ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:0:CL_ACCUM:1')  # protocol >= 1.4
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:5:LjgpST2rjsoxYegQDRm7EL:3:CL:20:0:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:4:CL:20:0:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL::CL:20:0:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:NOT_CL:20:0:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20z:0:CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20::CL_ACCUM:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:0::1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:0:1')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:0:CL_ACCUM:')
    assert not ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:0:CL_ACCUM')
    assert ok_rev_reg_id('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:20:CL_ACCUM:1')  # protocol == 1.3
