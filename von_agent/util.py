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

from binascii import hexlify, unhexlify
from copy import deepcopy
from math import ceil, log
from von_agent.schema import SchemaKey, schema_key_for

import json


def ppjson(dumpit):
    """
    JSON pretty printer, whether already json-encoded or not
    """

    return json.dumps(json.loads(dumpit) if isinstance(dumpit, str) else dumpit, indent=4)


def encode(value):
    """
    Encode claim value.
    Operation leaves any (stringified) int32 alone: indy-sdk predicate claims operate on int32
    values properly only when their encoded values match their raw values.

    To disambiguate for decoding, the function adds 2**32 to any non-trivial transform.
    """

    if value is None:
        return '4294967297'  # sentinel 2**32 + 1

    s = str(value)
    try:
        i = int(value)
        if 0 <= i < 2**32:  # it's an i32, leave it (as numeric string)
            return s
    except (ValueError, TypeError):
        pass

    return str(int.from_bytes(hexlify(s.encode()), 'big') + 2**32)


def decode(value: str):
    """
    Decode encoded claim value.

    :param value: numeric string to decode
    """

    assert value.isdigit()

    if 0 <= int(value) < 2**32:  # it's an i32, leave it (as numeric string)
        return value

    i = int(value) - 2**32
    if i == 0:
        return ''  # special case: empty string encodes as 4294967296
    elif i == 1:
        return None  # sentinel 2**32 + 1

    blen = ceil(log(i, 16)/2)
    ibytes = unhexlify(i.to_bytes(blen, 'big'))
    return ibytes.decode()


def claims_for(claims: dict, filt: dict = {}) -> dict:
    """
    Find indy-sdk claims matching input filter from within input claims structure,
    json-loaded as returned via agent get_claims().

    :param claims: claims structure returned by (HolderProver agent) get_claims(), or (equivalently)
        response json structure at ['claims'] to response to POST 'claims-request' message type;
        e.g., {
            "attrs": {
                "attr0_uuid": [
                    {
                        "referent": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "Hello",
                            "attr2": "World"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_key": {
                            "did": "Q4zqM7aXqm7gDQkUVLng9h",
                            "name": "bc-reg",
                            "version": "1.0"
                        },
                        "revoc_reg_seq_no": null
                    },
                    {
                        "referent": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "Nice",
                            "attr2": "Tractor"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_key": {
                            "did": "Q4zqM7aXqm7gDQkUVLng9h",
                            "name": "bc-reg",
                            "version": "1.0"
                        },
                        "revoc_reg_seq_no": null
                    }
                ],
                "attr1_uuid": [
                    {
                        "referent": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "Hello",
                            "attr2": "World"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_key": {
                            "did": "Q4zqM7aXqm7gDQkUVLng9h",
                            "name": "bc-reg",
                            "version": "1.0"
                        },
                        "revoc_reg_seq_no": null
                    },
                    {
                        "referent": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "Nice",
                            "attr2": "Tractor"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_key": {
                            "did": "Q4zqM7aXqm7gDQkUVLng9h",
                            "name": "bc-reg",
                            "version": "1.0"
                        },
                        "revoc_reg_seq_no": null
                    }
                ],
                "attr2_uuid": [
                    {
                        "referent": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "Hello",
                            "attr2": "World"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_key": {
                            "did": "Q4zqM7aXqm7gDQkUVLng9h",
                            "name": "bc-reg",
                            "version": "1.0"
                        },
                        "revoc_reg_seq_no": null
                    },
                    {
                        "referent": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "Nice",
                            "attr2": "Tractor"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_key": {
                            "did": "Q4zqM7aXqm7gDQkUVLng9h",
                            "name": "bc-reg",
                            "version": "1.0"
                        },
                        "revoc_reg_seq_no": null
                    }
                ]
            }
        }
    :param filt: filter for matching attributes and values; dict mapping each SchemaKey to
        dict mapping attributes to values to match (specify empty dict for no filter). E.g.,
        {
            SchemaKey('Q4zqM7aXqm7gDQkUVLng9h', 'bc-reg', '1.0'): {
                'attr0': '1',
                'attr1': 'Nice'
            },
            ...
        ]
    :return: human-legible dict mapping referent to claim attributes for claims matching input filter
    """

    rv = {}
    uuid2claims = claims['attrs']
    for claims in uuid2claims.values():
        for claim in claims:
            if claim['referent'] in rv:
                continue
            if not filt:
                rv[claim['referent']] = claim['attrs']
                continue
            claim_s_key = schema_key_for(claim['schema_key'])
            if claim_s_key in filt:
                if {k: str(filt[claim_s_key][k]) for k in filt[claim_s_key]}.items() <= claim['attrs'].items():
                    rv[claim['referent']] = claim['attrs']

    return rv


def schema_keys_for(claims: dict, referents: list) -> dict:
    """
    Given a claims structure and a list of referents (wallet claim-uuids),
    return dict mapping each referent to its corresponding schema key instance.

    :param claims: claims structure returned by (HolderProver agent) get_claims(), or (equivalently)
        response json structure at ['claims'] to response to POST 'claims-request' message type
    :param referents: list of referents for which to find corresponding schema key
    :return: schema key per referent (empty dict if no such referents present)
    """

    rv = {}
    uuid2claims = claims['attrs']
    for claims in uuid2claims.values():
        for claim in claims:
            referent = claim['referent']
            if (referent not in rv) and (referent in referents):
                rv[referent] = schema_key_for(claim['schema_key'])

    return rv


def prune_claims_json(claims: dict, referents: set) -> str:
    """
    Strip all claims out of the input json structure that do not match any of the input referents.

    :param claims: claims structure returned by (HolderProver agent) get_claims(), or (equivalently)
        response json structure at ['claims'] to response to POST 'claims-request' message type
    :param referents: the set of referents, as specified in claims json structure returned from get_claims(),
        showing up as dict keys that claims_for() returns
    :return: the reduced claims json
    """

    rv = deepcopy(claims)
    for attr_uuid, claims_by_uuid in rv['attrs'].items():
        rv['attrs'][attr_uuid] = [claim for claim in claims_by_uuid if claim['referent'] in referents]

    empties = [attr_uuid for attr_uuid in rv['attrs'] if not rv['attrs'][attr_uuid]]
    for attr_uuid in empties:
        del rv['attrs'][attr_uuid]

    return json.dumps(rv)


def revealed_attrs(proof: dict) -> dict:
    """
    Fetch revealed attributes from input proof and return dict
    mapping referents to dicts mapping attribute names to (decoded) values,
    for processing as further claims downstream.

    :param: indy-sdk proof as dict
    :return: dict mapping referents to dicts mapping revealed attribute names to decoded values
    """

    rv = {}
    for referent in proof['proof']['proofs']:
        revealed = proof['proof']['proofs'][referent]['primary_proof']['eq_proof']['revealed_attrs']
        rv[referent] = {attr: decode(revealed[attr]) for attr in revealed}
    return rv
