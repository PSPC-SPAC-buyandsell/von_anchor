"""
Copyright 2017 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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
from math import ceil, log

import json


def ppjson(dumpit):
    """
    JSON pretty printer, whether already json-encoded or not
    """

    return json.dumps(json.loads(dumpit) if isinstance(dumpit, str) else dumpit, indent=4)


def encode(value):
    """
    Encoder for claim values, returns encoded value.
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
    Decoder for encoded claim values, returns decoded value.

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
    Find indy-sdk claims matching input attribute-value dict from within input claims structure,
    json-loaded as returned via agent get_claims().

    :param claims: claims structure via get_claims();
        e.g., {
            "attrs": {
                "attr0_uuid": [
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "Hello",
                            "attr2": "World"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    },
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "Nice",
                            "attr2": "Tractor"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    }
                ],
                "attr1_uuid": [
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "Hello",
                            "attr2": "World"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    },
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "Nice",
                            "attr2": "Tractor"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    }
                ],
                "attr2_uuid": [
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "Hello",
                            "attr2": "World"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    },
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "Nice",
                            "attr2": "Tractor"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    }
                ]
            }
        }
    :param filt: attributes and values to match from claims structure
    :return: human-legible dict mapping claim uuid to claim attributes for claims matching input filter
    """

    uuid2claims = claims['attrs']
    filt_str = {k: str(filt[k]) for k in filt}
    rv = {}
    for claims in uuid2claims.values():
        for claim in claims:
            if claim['claim_uuid'] not in rv and (filt_str.items() <= claim['attrs'].items()):
                rv[claim['claim_uuid']] = claim['attrs']

    return rv


def prune_claims_json(claim_uuids: set, claims: dict) -> str:
    """
    Strips all claims out of the input json structure that do not match any of the input claim uuids

    :param claim_uuids: the set of claim uuids, as specified in claims json structure returned from get_claims,
        showing up as dict keys that claims_for() returns
    :param claims: claims structure returned by (HolderProver agent) get_claims(), or (equivalently)
        response json structure at ['claims'] to response to POST claims-request message type
    :return: the reduced claims json
    """

    for attr_uuid, claims_by_uuid in claims['attrs'].items():
        claims['attrs'][attr_uuid] = [claim for claim in claims_by_uuid if claim['claim_uuid'] in claim_uuids]

    return json.dumps(claims)


def revealed_attrs(proof: dict) -> dict:
    """
    Fetches revealed attributes from input proof, returns dict mapping attribute names to (decoded) values,
    for processing as further claims downstream

    :param: indy-sdk proof as dict (proving exactly one claim)
    :return: dict mapping revealed attribute names to decoded values
    """

    revealed = proof['proofs'][set(proof['proofs']).pop()]['proof']['primary_proof']['eq_proof']['revealed_attrs']
    rv = {attr: decode(revealed[attr]) for attr in revealed}
    return rv
