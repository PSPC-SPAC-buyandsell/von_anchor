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


import json
import re

from enum import IntEnum
from math import ceil, log
from typing import Any, Union

from von_anchor.error import BadWalletQuery


class Prefix(IntEnum):
    """
    Prefixes for indy encoding to numeric strings. For indy-sdk, 32-bit integers must encode
    to themselves to allow predicates to work.

    A single-digit prefix to identify original type allows the decode to return it, without
    taking the encoding outside the space of numeric strings.
    """

    I32 = 0  # purely a formalism, no prefix for indy (32-bit) int values
    STR = 1
    BOOL = 2
    POSINT = 3
    NEGINT = 4
    FLOAT = 5
    JSON = 9


I32_BOUND = 2**31


def _prefix(orig: Any) -> Prefix:
    """
    Return the prefix for an original value to encode.

    :param orig: input value to encode
    :return: Prefix enum value
    """

    if isinstance(orig, str):
        return Prefix.JSON if orig and all(orig[i] == chr(0) for i in range(len(orig))) else Prefix.STR
    if isinstance(orig, bool):
        return Prefix.BOOL
    if isinstance(orig, int):
        if -I32_BOUND <= orig < I32_BOUND:
            return Prefix.I32
        return Prefix.POSINT if orig >= I32_BOUND else Prefix.NEGINT
    if isinstance(orig, float):
        return Prefix.FLOAT
    return Prefix.JSON


def encode(orig: Any) -> str:
    """
    Encode credential attribute value, leaving any (stringified) int32 alone: indy-sdk predicates
    operate on int32 values properly only when their encoded values match their raw values.

    To disambiguate for decoding, the operation reserves a sentinel for special values and otherwise adds
    2**31 to any non-trivial transform of a non-int32 input, then prepends a digit marking the input type:
      * 1: string (except non-empty string with all characters chr(0))
      * 2: boolean
      * 3: positive non-32-bit integer
      * 4: negative non-32-bit integer
      * 5: floating point
      * 9: other (JSON-encodable) - including non-empty string with all characters chr(0).

    The original value must be JSON-encodable.

    :param orig: original JSON-encodable value to encode
    :return: encoded value
    """

    if orig is None:
        return str(I32_BOUND)  # sentinel

    prefix = '{}'.format(_prefix(orig) or '')  # no prefix for indy 32-bit ints

    if isinstance(orig, bool):
        return '{}{}'.format(
            prefix,
            I32_BOUND + 2 if orig else I32_BOUND + 1)  # python bool('False') = True; just use 2 sentinels

    if isinstance(orig, int):
        return '{}{}'.format(prefix, str(orig) if -I32_BOUND <= orig < I32_BOUND else str(abs(orig)))

    rv = '{}{}'.format(
        prefix,
        str(int.from_bytes(
            orig.encode() if int(prefix) == Prefix.STR else json.dumps(orig).encode(), 'big') + I32_BOUND))

    return rv


def decode(enc_value: str) -> Union[str, None, bool, int, float]:
    """
    Decode encoded credential attribute value.

    :param enc_value: numeric string to decode
    :return: decoded value, stringified if original was neither str, bool, int, nor float
    """

    assert enc_value.isdigit() or enc_value[0] == '-' and enc_value[1:].isdigit()

    if -I32_BOUND <= int(enc_value) < I32_BOUND:  # it's an i32: it is its own encoding
        return int(enc_value)
    if int(enc_value) == I32_BOUND:
        return None  # sentinel

    (prefix, payload) = (int(enc_value[0]), int(enc_value[1:]))
    ival = int(payload) - I32_BOUND

    if prefix == Prefix.STR and ival == 0:
        return ''  # special case: empty string encodes as 2**31
    if prefix == Prefix.BOOL and ival in (1, 2):
        return False if ival == 1 else True # sentinels
    if prefix in (Prefix.POSINT, Prefix.NEGINT):
        return int(payload) if prefix == Prefix.POSINT else -int(payload)

    blen = max(ceil(log(ival, 16)/2), 1)
    ibytes = ival.to_bytes(blen, 'big')

    if prefix == Prefix.FLOAT:
        return float(ibytes.decode())

    return ibytes.decode() if prefix == Prefix.STR else json.loads(ibytes.decode())


def raw(orig: Any) -> dict:
    """
    Stringify input value, empty string for None.

    :param orig: original attribute value of any stringifiable type
    :return: stringified raw value
    """

    return '' if orig is None else str(orig)


def cred_attr_value(orig: Any) -> dict:
    """
    Given a value, return corresponding credential attribute value dict for indy-sdk processing.

    :param orig: original attribute value of any stringifiable type
    :return: dict on 'raw' and 'encoded' keys for indy-sdk processing
    """
    return {'raw': raw(orig), 'encoded': encode(orig)}


def canon(raw_attr_name: str) -> str:
    """
    Canonicalize input attribute name as it appears in proofs and credential offers: strip out
    white space and convert to lower case.

    :param raw_attr_name: attribute name
    :return: canonicalized attribute name
    """

    if raw_attr_name:  # do not dereference None, and '' is already canonical
        return raw_attr_name.replace(' ', '').lower()
    return raw_attr_name


def canon_wql(query: dict) -> dict:
    """
    Canonicalize WQL attribute marker and value keys for input to indy-sdk wallet credential filtration.
    Canonicalize original values to proper indy-sdk raw values as per raw().

    Raise BadWalletQuery for WQL mapping '$or' to non-list.

    :param query: WQL query
    :return canonicalized WQL query dict
    """

    for k in query:
        attr_match = re.match('attr::([^:]+)::(marker|value)$', k)
        if isinstance(query[k], dict):  # only subqueries are dicts: recurse
            query[k] = canon_wql(query[k])
        if k == '$or':
            if not isinstance(query[k], list):
                raise BadWalletQuery('Bad WQL; $or value must be a list in {}'.format(json.dumps(query)))
            query[k] = [canon_wql(subq) for subq in query[k]]
        if attr_match:
            qkey = 'attr::{}::{}'.format(canon(attr_match.group(1)), attr_match.group(2))
            query[qkey] = query.pop(k)
            tag_value = query[qkey]
            if isinstance(tag_value, dict) and len(tag_value) == 1:
                if '$in' in tag_value:
                    tag_value['$in'] = [raw(val) for val in tag_value.pop('$in')]
                else:
                    wql_op = set(tag_value.keys()).pop()  # $neq, $gt, $gte, etc.
                    tag_value[wql_op] = raw(tag_value[wql_op])
            else:  # equality
                query[qkey] = raw(query[qkey])

    return query
