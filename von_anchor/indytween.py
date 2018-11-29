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


from collections import namedtuple
from enum import Enum
from hashlib import sha256
from typing import Any


SchemaKey = namedtuple('SchemaKey', 'origin_did name version')
Relation = namedtuple('Relation', 'fortran wql math yes no')


I32_BOUND = 2**31


def encode(orig: Any) -> str:
    """
    Encode credential attribute value, purely stringifying any int32 and leaving numeric int32 strings alone,
    but mapping any other input to a stringified 256-bit (but not 32-bit) integer. Predicates in indy-sdk operate
    on int32 values properly only when their encoded values match their raw values.

    :param orig: original value to encode
    :return: encoded value
    """

    if isinstance(orig, int) and -I32_BOUND <= orig < I32_BOUND:
        return str(int(orig))  # python bools are ints

    try:
        i32orig = int(str(orig))  # don't encode floats as ints
        if -I32_BOUND <= i32orig < I32_BOUND:
            return str(i32orig)
    except (ValueError, TypeError):
        pass

    rv = int.from_bytes(sha256(raw(orig).encode()).digest(), 'big')
    while -I32_BOUND <= rv < I32_BOUND:
        rv = int.from_bytes(sha256(rv.encode()).digest(), 'big')  # sha256 maps no 32-bit int to another: terminates

    return str(rv)


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


class Predicate(Enum):
    """
    Enum for predicate types that indy-sdk supports.
    """

    LT = Relation(
        'LT',
        '$lt',
        '<',
        lambda x, y: Predicate.to_int(x) < Predicate.to_int(y),
        lambda x, y: Predicate.to_int(x) >= Predicate.to_int(y))
    LE = Relation(
        'LE',
        '$lte',
        '<=',
        lambda x, y: Predicate.to_int(x) <= Predicate.to_int(y),
        lambda x, y: Predicate.to_int(x) > Predicate.to_int(y))
    GE = Relation(
        'GE',
        '$gte',
        '>=',
        lambda x, y: Predicate.to_int(x) >= Predicate.to_int(y),
        lambda x, y: Predicate.to_int(x) < Predicate.to_int(y))
    GT = Relation(
        'GT',
        '$gt',
        '>',
        lambda x, y: Predicate.to_int(x) > Predicate.to_int(y),
        lambda x, y: Predicate.to_int(x) <= Predicate.to_int(y))

    @staticmethod
    def get(relation: str) -> 'Predicate':
        """
        Return enum instance corresponding to input relation string
        """

        for pred in Predicate:
            if relation.upper() in (pred.value.fortran, pred.value.wql.upper(), pred.value.math):
                return pred
        return None

    @staticmethod
    def to_int(value: Any) -> int:
        """
        Cast a value as its equivalent int for indy predicate argument. Raise ValueError for any input but
        int, stringified int, or boolean.

        :param value: value to coerce.
        """

        if isinstance(value, (bool, int)):
            return int(value)
        return int(str(value))  # kick out floats
