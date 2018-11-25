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

from von_anchor.error import BadWalletQuery
from von_anchor.indytween import raw


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
    :return: canonicalized WQL query dict
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
            qkey = 'attr::{}::{}'.format(canon(attr_match.group(1)), canon(attr_match.group(2)))
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
