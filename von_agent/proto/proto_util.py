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

from von_agent.schema import SchemaKey

SCHEMA_KEY_KEYS = ['origin-did', 'name', 'version']
PRED_MATCH_MATCH_KEYS = ['attr', 'pred-type', 'value']


def list_schemata(s_keys: list) -> list:
    """
    Return list of schema key dicts for "schemata" specification in protocol tokens.

    :param s_keys: list of SchemaKey instances
    :return: list of schema key dicts for "schemata" specification in protocol tokens
    """

    return [{k: v for k, v in zip(SCHEMA_KEY_KEYS, list(s_key))} for s_key in s_keys]


def attr_match(s_key: SchemaKey, matches: dict = {}) -> dict:
    """
    Return attr-match list entry for specification in protocol tokens.

    :param s_key: schema key
    :param matches: dict of schema attributes and values to match
    :return: one (dict) entry for "attr-match" list specification in protocol tokens
    """

    return {
        'schema': {k: v for k, v in zip(SCHEMA_KEY_KEYS, list(s_key))},
        'match': matches or {}
    }


def pred_match_match(attr: str, pred_type: str, value: int) -> dict:
    """
    Return (inner) predicate-match entry for its "match" list of predicate match specifications.

    :param attr: attribute name
    :param pred_type: predicate type - specify '>='
    :param value: comparison value
    :return: one (dict) entry for "match" list specification in "predicate-match" protocol tokens
    """

    return {k: v for k, v in zip(PRED_MATCH_MATCH_KEYS, (attr, pred_type, value))}


def pred_match(s_key: SchemaKey, matches: list) -> dict:
    """
    Return predicate-match list entry for specification in protocol tokens.

    :param s_key: schema key
    :param matches: list of dict, each with schema attribute, predicate type, and comparison value
        (as pred_match_match() builds); the protocol demands at least one entry
    :return: one (dict) entry for "predicate-match" list specification in protocol tokens
    """

    return {
        'schema': {k: v for k, v in zip(SCHEMA_KEY_KEYS, list(s_key))},
        'match': matches
    }


def req_attrs(s_key: SchemaKey, attr_names: list = []) -> dict:
    """
    Return requested-attrs (dict) list entry for specification in protocol tokens.

    :param s_key: schema key
    :param attr_names: list of attribute names to match from schema
    :return: one (dict) entry for "requested-attrs" list of dicts within protocol tokens
    """

    return {
        'schema': {k: v for k, v in zip(SCHEMA_KEY_KEYS, list(s_key))},
        'names': attr_names or []
    }
