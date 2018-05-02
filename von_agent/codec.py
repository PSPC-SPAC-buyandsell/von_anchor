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

from binascii import hexlify, unhexlify
from math import ceil, log
from typing import Any, Union


def encode(raw: Any) -> str:
    """
    Encode credential attribute value, leaving any (stringified) int32 alone: indy-sdk predicates
    operate on int32 values properly only when their encoded values match their raw values.

    To disambiguate for decoding, the function adds 2**32 to any non-trivial transform.

    :param raw: raw value to encode
    :return: encoded value
    """

    if raw is None:
        return '4294967297'  # sentinel 2**32 + 1

    s = str(raw)
    try:
        i = int(raw)
        if 0 <= i < 2**32:  # it's an i32, leave it (as numeric string)
            return s
    except (ValueError, TypeError):
        pass

    return str(int.from_bytes(hexlify(s.encode()), 'big') + 2**32)


def decode(value: str) -> Union[str, None]:
    """
    Decode encoded credential attribute value.

    :param value: numeric string to decode
    :return: decoded value
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


def cred_attr_value(raw: Any) -> dict:
    """
    Given a raw value, return its (dict) value for use within an indy-sdk credential attribute specification.

    :param raw: raw value
    :return: dict with attribute value for use within indy-sdk credential attribute specification
    """

    return {'raw': str(raw), 'encoded': encode(raw)}


def canon(raw_attr_name: str) -> str:
    """
    Canonicalize input attribute name as it appears in proofs: strip out white space and convert to lower case.

    :param raw_attr_name: attribute name
    :return: canonicalized attribute name
    """

    if raw_attr_name:  # do not dereference None, and '' is already canonical
        return raw_attr_name.replace(' ', '').lower() 
    return raw_attr_name
