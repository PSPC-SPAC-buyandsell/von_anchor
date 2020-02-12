"""
Copyright 2017-2020 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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
from typing import Any, Mapping, Sequence, Union

from von_anchor.canon import raw


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

    return str(int.from_bytes(sha256(raw(orig).encode()).digest(), 'big'))  # OK for indy: sha256 changes all str(i32)s


def cred_attr_value(orig: Any) -> dict:
    """
    Given a value, return corresponding credential attribute value dict for indy-sdk processing.

    :param orig: original attribute value of any stringifiable type
    :return: dict on 'raw' and 'encoded' keys for indy-sdk processing
    """
    return {'raw': raw(orig), 'encoded': encode(orig)}


class Restriction(Enum):
    """
    Enum for restrictions that indy-sdk supports.
    """

    SCHEMA_ID = "schema_id"
    SCHEMA_ISSUER_DID = "schema_issuer_did"
    SCHEMA_NAME = "schema_name"
    SCHEMA_VERSION = "schema_version"
    ISSUER_DID = "issuer_did"
    CRED_DEF_ID = "cred_def_id"

    @staticmethod
    def get(specifier: str) -> 'Restriction':
        """
        Return enum instance corresponding to restriction specifier string.

        :param specifier: specifier in proof request
        :return: corresponding Restriction instance
        """

        return getattr(Restriction, specifier.upper(), None)

    def applies(self, cred_info: Mapping, value: str) -> bool:
        """
        Return whether restriction applies to input cred-info.

        :param cred_info: cred-info to check
        :param value: restriction value to check
        :return: whether cred-info satisfies current restriction
        """

        if not cred_info:
            return True
        if self == Restriction.SCHEMA_ISSUER_DID:
            return cred_info['schema_id'].split(':')[0] == value
        if self == Restriction.SCHEMA_NAME:
            return cred_info['schema_id'].split(':')[2] == value
        if self == Restriction.SCHEMA_VERSION:
            return cred_info['schema_id'].split(':')[3] == value
        if self == Restriction.ISSUER_DID:
            return cred_info['cred_def_id'].split(':')[0] == value
        return cred_info[self.value] == value

    @staticmethod
    def all_apply_dict(cred_info: Mapping, rdict: Mapping[str, str]) -> bool:
        """
        Whether all restrictions specified in dict apply to all input cred-info.

        :param cred_info: cred-info to test
        :param rdict: restriction specification dict
        :return: whether cred-info satisfies all restrictions specified
        """
        return all(Restriction.get(r).applies(cred_info, rdict[r]) for r in rdict or {})

    @staticmethod
    def any_apply_list(cred_info: dict, rdict_list: Sequence[Mapping[str, str]]) -> bool:
        """
        Whether any restriction dict specifiers in list thereof apply to input cred-info.

        :param cred_info: cred-info to test
        :param rdict_list: list of restriction specification dicts
        :return: whether cred-info satisfies any restriction dict in list of restriction dicts
        """
        return any(Restriction.all_apply_dict(cred_info, rdict) for rdict in rdict_list)


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


class Role(Enum):
    """
    Enum for indy roles.
    """

    STEWARD = (2,)
    TRUSTEE = (0,)
    TRUST_ANCHOR = (101,)
    USER = (None, '')  # reading from config, default empty specifier '' or None to USER
    ROLE_REMOVE = ('',)  # but indy-sdk uses '' to identify a role in reset

    @staticmethod
    def get(token: Union[str, int] = None) -> 'Role':
        """
        Return enum instance corresponding to input token.

        :param token: token identifying role to indy-sdk: 'STEWARD', 'TRUSTEE', 'TRUST_ANCHOR', '' or None
        :return: enum instance corresponding to input token
        """

        if token is None:
            return Role.USER

        for role in Role:
            if role == Role.ROLE_REMOVE:
                continue  # ROLE_REMOVE is not a sensible role to parse from any configuration
            if isinstance(token, int) and token in role.value:
                return role
            if str(token).upper() == role.name or token in (str(v) for v in role.value):  # could be numeric string
                return role

        return None

    def to_indy_num_str(self) -> str:
        """
        Return (typically, numeric) string value that indy-sdk associates with role.

        :return: associated string value (None for self-sovereign user
            having no additional write privileges to ledger, '' for role in reset)
        """

        return self.value[0]

    def token(self) -> str:
        """
        Return token identifying role to indy-sdk.

        :return: token: 'STEWARD', 'TRUSTEE', 'TRUST_ANCHOR', or None (for USER)
        """

        return self.value[0] if self in (Role.USER, Role.ROLE_REMOVE) else self.name
