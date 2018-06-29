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

from collections import namedtuple
from copy import deepcopy
from pprint import pformat
from typing import Any
from von_agent.codec import decode


SchemaKey = namedtuple('SchemaKey', 'origin_did name version')


CD_ID_TAG = '0'


def ppjson(dumpit: Any, elide_to: int = None) -> str:
    """
    JSON pretty printer, whether already json-encoded or not

    :param dumpit: object to pretty-print
    :param elide_to: optional maximum length including ellipses ('...')
    :return: json pretty-print
    """

    if elide_to is not None:
        elide_to = max(elide_to, 3) # make room for ellipses '...'
    try:
        rv = json.dumps(json.loads(dumpit) if isinstance(dumpit, str) else dumpit, indent=4)
    except TypeError:
        rv = '{}'.format(pformat(dumpit, indent=4, width=120))
    return rv if elide_to is None or len(rv) <= elide_to else '{}...'.format(rv[0 : elide_to - 3])


def schema_id(origin_did: str, name: str, version: str) -> str:
    """
    Return schema identifier for input origin DID, schema name, and schema version.

    :param origin_did: DID of schema originator
    :param name: schema name
    :param version: schema version
    :return: schema identifier
    """

    return '{}:2:{}:{}'.format(origin_did, name, version)  # 2 marks indy-sdk schema id


def schema_key(s_id: str) -> SchemaKey:
    """
    Return schema key (namedtuple) convenience for schema identifier components.

    :param s_id: schema identifier
    :return: schema key (namedtuple) object
    """

    s_key = s_id.split(':')
    s_key.pop(1)  # take out indy-sdk schema marker: 2 marks indy-sdk schema id

    return SchemaKey(*s_key)


def cred_def_id(issuer_did: str, schema_seq_no: int) -> str:
    """
    Return credential definition identifier for input issuer DID and schema sequence number.

    :param issuer_did: DID of credential definition issuer
    :param schema_seq_no: schema sequence number
    :return: credential definition identifier
    """

    return '{}:3:CL:{}:{}'.format(issuer_did, schema_seq_no, CD_ID_TAG)  # 3 marks indy-sdk cred def id, CL is sig type


def cred_def_id2seq_no(cd_id: str) -> int:
    """
    Given a credential definition identifier, return its schema sequence number.

    :param cd_id: credential definition identifier
    :return: sequence number
    """

    return int(cd_id.split(':')[-2])  # sequence number is penultimate token


def rev_reg_id(cd_id: str, tag: str) -> str:
    """
    Given a credential definition identifier and a tag, return the corresponding
    revocation registry identifier, repeating the issuer DID from the
    input identifier.

    :param cd_id: credential definition identifier
    :param tag: tag to use
    :return: revocation registry identifier
    """

    return '{}:4:{}:CL_ACCUM:{}'.format(cd_id.split(':', 1)[0], cd_id, tag)  # 4 marks rev reg def id


def rev_reg_id2cred_def_id(rr_id: str) -> str:
    """
    Given a revocation registry identifier, return its corresponding credential definition identifier.

    :param rr_id: revocation registry identifier
    :return: credential definition identifier
    """

    return ':'.join(rr_id.split(':')[2:-2])  # rev reg id comprises (prefixes):<cred_def_id>:(suffixes)


def rev_reg_id2tag(rr_id: str) -> str:
    """
    Given a revocation registry identifier, return its corresponding (stringified int) tag.

    :param rr_id: revocation registry identifier
    :return: tag
    """

    return str(rr_id.split(':')[-1])  # tag is last token


def rev_reg_id2cred_def_id__tag(rr_id: str) -> (str, str):
    """
    Given a revocation registry identifier, return its corresponding credential definition identifier and
    (stringified int) tag.

    :param rr_id: revocation registry identifier
    :return: credential definition identifier and tag
    """

    return (
        ':'.join(rr_id.split(':')[2:-2]),  # rev reg id comprises (prefixes):<cred_def_id>:(suffixes)
        str(rr_id.split(':')[-1])  # tag is last token
    )


def box_ids(creds: dict, cred_ids: list = None) -> dict:
    """
    Given a credentials structure and an optional list of credential identifiers
    (aka wallet cred-ids, referents; specify None to include all), return dict mapping each
    credential identifier to a box ids structure (i.e., a dict specifying its corresponding
    schema identifier, credential definition identifier, and revocation registry identifier,
    the latter being None if cred def does not support revocation).

    :param creds: creds structure returned by (HolderProver agent) get_creds()
    :param cred_ids: list of credential identifiers for which to find corresponding schema identifiers, None for all
    :return: dict mapping each credential identifier to its corresponding box ids (empty dict if
        no matching credential identifiers present)
    """

    rv = {}
    for inner_creds in {**creds.get('attrs', {}), **creds.get('predicates', {})}.values():
        for cred in inner_creds:  # cred is a dict in a list of dicts
            cred_info = cred['cred_info']
            cred_id = cred_info['referent']
            if (cred_id not in rv) and (not cred_ids or cred_id in cred_ids):
                rv[cred_id] = {
                    'schema_id': cred_info['schema_id'],
                    'cred_def_id': cred_info['cred_def_id'],
                    'rev_reg_id': cred_info['rev_reg_id']
                }

    return rv


def prune_creds_json(creds: dict, cred_ids: set) -> str:
    """
    Strip all creds out of the input json structure that do not match any of the input credential identifiers.

    :param creds: creds structure returned by (HolderProver agent) get_creds()
    :param cred_ids: the set of credential identifiers of interest
    :return: the reduced creds json
    """

    rv = deepcopy(creds)
    for key in ('attrs', 'predicates'):
        for attr_uuid, creds_by_uuid in rv[key].items():
            rv[key][attr_uuid] = [cred for cred in creds_by_uuid if cred['cred_info']['referent'] in cred_ids]

        empties = [attr_uuid for attr_uuid in rv[key] if not rv[key][attr_uuid]]
        for attr_uuid in empties:
            del rv[key][attr_uuid]

    return json.dumps(rv)


def creds_display(creds: dict, filt: dict = None, filt_dflt_incl: bool = False) -> dict:
    """
    Find indy-sdk creds matching input filter from within input creds structure,
    json-loaded as returned via HolderProver.get_creds(), and return human-legible summary.

    :param creds: creds structure returned by HolderProver.get_creds(); e.g.,

    ::

        {
            "attrs": {
                "attr0_uuid": [
                    {
                        "interval": null,
                        "cred_info": {
                            "attrs": {
                                "attr0": "2",
                                "attr1": "Hello",
                                "attr2": "World"
                            },
                            "referent": "00000000-0000-0000-0000-000000000000",
                            "schema_id": "Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0",
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:0",
                            "cred_rev_id": null,
                            "rev_reg_id": null
                        }
                    },
                    {
                        "interval": null,
                        "cred_info": {
                            "attrs": {
                                "attr0": "1",
                                "attr1": "Nice",
                                "attr2": "Tractor"
                            },
                            "referent": "00000000-0000-0000-0000-111111111111",
                            "schema_id": "Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0",
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:0",
                            "cred_rev_id": null,
                            "rev_reg_id": null
                        }
                    }
                ],
                "attr1_uuid": [
                    {
                        "interval": null,
                        "cred_info": {
                            "attrs": {
                                "attr0": "2",
                                "attr1": "Hello",
                                "attr2": "World"
                            },
                            "referent": "00000000-0000-0000-0000-000000000000",
                            "schema_id": "Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0",
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:0",
                            "cred_rev_id": null,
                            "rev_reg_id": null
                        }
                    },
                    {
                        "interval": null,
                        "cred_info": {
                            "attrs": {
                                "attr0": "1",
                                "attr1": "Nice",
                                "attr2": "Tractor"
                            },
                            "referent": "00000000-0000-0000-0000-111111111111",
                            "schema_id": "Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0",
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:0",
                            "cred_rev_id": null,
                            "rev_reg_id": null
                        }
                    }
                ],
                "attr2_uuid": [
                    ...
                ]
            }
        }

    :param filt: filter for matching attributes and values; dict (None or empty for no filter, matching all)
        mapping each cred def identifier to dict mapping attributes to values to match; e.g.,

    ::

        {
            'Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:0': {
                'attr0': 1,  # operation stringifies en passant
                'attr1': 'Nice'
            },
            ...
        }

    :param: filt_dflt_incl: whether to include (True) all attributes for schema that filter does not identify
        or to exclude (False) all such attributes
    :return: human-legible dict mapping credential identifiers to human-readable creds synopses -- not proper
        indy-sdk creds structures (each as per HolderProver.get_creds_display_coarse()) -- for creds matching
        input filter
    """

    rv = {}
    if filt is None:
        filt = {}
    for cred_uuid in creds.get('attrs', {}):
        for cred in creds['attrs'][cred_uuid]:  # creds['attrs'][cred_uuid] is a list of dict
            cred_info = cred['cred_info']
            if cred_info['referent'] in rv:
                continue
            cred_cd_id = cred_info['cred_def_id']
            if (not filt) or (filt_dflt_incl and cred_cd_id not in filt):
                rv[cred_info['referent']] = cred_info
                continue
            if filt and cred_cd_id in filt:
                if ({k: str(filt[cred_cd_id][k]) for k in filt[cred_cd_id]}.items() <= cred_info['attrs'].items()):
                    rv[cred_info['referent']] = cred_info

    return rv


def revoc_info(creds: dict, filt: dict = None) -> dict:
    """
    Given a creds structure, return a dict mapping pairs
    (revocation registry identifier, credential revocation identifier)
    to (decoded) attribute name:value dicts.

    If the caller includes a filter of attribute:value pairs, retain only matching attributes.

    :param creds: creds structure returned by HolderProver.get_creds() as above
    :param filt: dict mapping attributes to values of interest; e.g.,

    ::

        {
            'legalName': 'Flan Nebula',
            'effectiveDate': '2018-01-01',
            'endDate': None
        }

    :return: dict mapping (rev_reg_id, cred_rev_id) pairs to decoded attributes
    """

    rv = {}
    for uuid2creds in (creds.get('attrs', {}), creds.get('predicates', {})):
        for inner_creds in uuid2creds.values():
            for cred in inner_creds:
                cred_info = cred['cred_info']
                (rr_id, cr_id) = (cred_info['rev_reg_id'], cred_info['cred_rev_id'])
                if (rr_id, cr_id) in rv or rr_id is None or cr_id is None:
                    continue
                if not filt:
                    rv[(rr_id, cr_id)] = cred_info['attrs']
                    continue
                if ({attr: str(filt[attr]) for attr in filt}.items() <= cred_info['attrs'].items()):
                    rv[(rr_id, cr_id)] = cred_info['attrs']
    return rv


def revealed_attrs(proof: dict) -> dict:
    """
    Fetch revealed attributes from input proof and return dict mapping credential definition identifiers
    to dicts, each dict mapping attribute names to (decoded) values, for processing in further creds downstream.

    :param: indy-sdk proof as dict
    :return: dict mapping cred-ids to dicts, each mapping revealed attribute names to (decoded) values
    """

    rv = {}
    for sub_index in range(len(proof['identifiers'])):
        cd_id = proof['identifiers'][sub_index]['cred_def_id']
        rv[cd_id] = {
            attr: decode(proof['proof']['proofs'][sub_index]['primary_proof']['eq_proof']['revealed_attrs'][attr])
                for attr in proof['proof']['proofs'][sub_index]['primary_proof']['eq_proof']['revealed_attrs']
        }

    return rv
