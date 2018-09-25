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

from copy import deepcopy
from typing import Union

from von_anchor.codec import decode
from von_anchor.nodepool import Protocol
from von_anchor.schema_key import SchemaKey


B58 = '1-9A-HJ-NP-Za-km-z'


def schema_id(origin_did: str, name: str, version: str) -> str:
    """
    Return schema identifier for input origin DID, schema name, and schema version.

    :param origin_did: DID of schema originator
    :param name: schema name
    :param version: schema version
    :return: schema identifier
    """

    return '{}:2:{}:{}'.format(origin_did, name, version)  # 2 marks indy-sdk schema id


def ok_did(token: str) -> bool:
    """
    Whether input token looks like a valid distributed identifier.

    :param token: candidate string
    :return: whether input token looks like a valid schema identifier
    """

    return bool(re.match('[{}]{{21,22}}$'.format(B58), token))


def ok_schema_id(token: str) -> bool:
    """
    Whether input token looks like a valid schema identifier;
    i.e., <issuer-did>:2:<name>:<version>.

    :param token: candidate string
    :return: whether input token looks like a valid schema identifier
    """

    return bool(re.match('[{}]{{21,22}}:2:.+:[0-9.]+$'.format(B58), token))


def schema_key(s_id: str) -> SchemaKey:
    """
    Return schema key (namedtuple) convenience for schema identifier components.

    :param s_id: schema identifier
    :return: schema key (namedtuple) object
    """

    s_key = s_id.split(':')
    s_key.pop(1)  # take out indy-sdk schema marker: 2 marks indy-sdk schema id

    return SchemaKey(*s_key)


def cred_def_id(issuer_did: str, schema_seq_no: int, protocol: Protocol = None) -> str:
    """
    Return credential definition identifier for input issuer DID and schema sequence number.

    Implementation passes to NodePool Protocol.

    :param issuer_did: DID of credential definition issuer
    :param schema_seq_no: schema sequence number
    :param protocol: indy protocol version
    :return: credential definition identifier
    """

    return (protocol or Protocol.DEFAULT).cred_def_id(issuer_did, schema_seq_no)


def ok_cred_def_id(token: str) -> bool:
    """
    Whether input token looks like a valid credential definition identifier; i.e.,
    <issuer-did>:3:CL:<schema-seq-no>:<cred-def-id-tag> for protocol >= 1.4, or
    <issuer-did>:3:CL:<schema-seq-no> for protocol == 1.3.

    :param token: candidate string
    :return: whether input token looks like a valid credential definition identifier
    """

    return bool(re.match('[{}]{{21,22}}:3:CL:[1-9][0-9]*(:.+)?$'.format(B58), token))


def cred_def_id2seq_no(cd_id: str) -> int:
    """
    Given a credential definition identifier, return its schema sequence number.

    :param cd_id: credential definition identifier
    :return: sequence number
    """

    return int(cd_id.split(':')[3])  # sequence number is token at 0-based position 3


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


def ok_rev_reg_id(token: str) -> bool:
    """
    Whether input token looks like a valid revocation registry identifier; i.e.,
    <issuer-did>:4:<issuer-did>:3:CL:<schema-seq-no>:<cred-def-id-tag>:CL_ACCUM:<rev-reg-id-tag> for protocol >= 1.4, or
    <issuer-did>:4:<issuer-did>:3:CL:<schema-seq-no>:CL_ACCUM:<rev-reg-id-tag> for protocol == 1.3.

    :param token: candidate string
    :return: whether input token looks like a valid revocation registry identifier
    """

    return bool(re.match('[{}]{{21,22}}:4:[{}]{{21,22}}:3:CL:[1-9][0-9]*(:.+)?:CL_ACCUM:.+$'.format(B58, B58), token))


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


def rev_reg_id2cred_def_id_tag(rr_id: str) -> (str, str):
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


def box_ids(creds: Union[dict, list], cred_ids: list = None) -> dict:
    """
    Given a credentials structure and an optional list of credential identifiers
    (aka wallet cred-ids, referents; specify None to include all), return dict mapping each
    credential identifier to a box ids structure (i.e., a dict specifying its corresponding
    schema identifier, credential definition identifier, and revocation registry identifier,
    the latter being None if cred def does not support revocation).

    :param creds: indy-sdk creds (dict) structure or human-readable display (list of synopses)
    :param cred_ids: list of credential identifiers for which to find corresponding schema identifiers, None for all
    :return: dict mapping each credential identifier to its corresponding box ids (empty dict if
        no matching credential identifiers present)
    """

    def _update(briefs):
        nonlocal rv, cred_ids

        for brief in briefs:  # cred is a dict in a list of dicts
            cred_info = brief['cred_info']
            cred_id = cred_info['referent']
            if (cred_id not in rv) and (not cred_ids or cred_id in cred_ids):
                rv[cred_id] = {
                    'schema_id': cred_info['schema_id'],
                    'cred_def_id': cred_info['cred_def_id'],
                    'rev_reg_id': cred_info['rev_reg_id']
                }

    rv = {}
    if isinstance(creds, dict):  # it's a proper creds structure
        for briefs in {**creds.get('attrs', {}), **creds.get('predicates', {})}.values():
            _update(briefs)
    else:  # creds is a list of synopses
        _update(creds)

    return rv


def prune_creds_json(creds: dict, cred_ids: set) -> str:
    """
    Strip all creds out of the input json structure that do not match any of the input credential identifiers.

    :param creds: creds structure returned by (HolderProver anchor) get_creds()
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


def proof_req_infos2briefs(proof_req: dict, infos: Union[dict, tuple, list]) -> list:
    """
    Given a proof request and corresponding cred-info(s), return a list of cred-briefs
    (i.e., cred-info plus interval).

    The proof request must have cred def id restrictions on all requested attribute specifications.

    :param proof_req: proof request json
    :param infos: cred-info, or list/tuple thereof; e.g.,

    ::
        [
            {
                'attrs': {
                    'auditDate': '2018-07-30',
                    'greenLevel': 'Silver',
                    'legalName': 'Tart City'
                },
                'cred_rev_id': '48',
                'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:17:0',
                'referent': 'c15674a9-7321-440d-bbed-e1ac9273abd5',
                'rev_reg_id': 'WgWxqztrNooG92RXvxSTWv:4:WgWxqztrNooG92RXvxSTWv:3:CL:17:0:CL_ACCUM:0',
                'schema_id': 'WgWxqztrNooG92RXvxSTWv:2:green:1.0'
            },
            ...
        ]

    :return: list of cred-briefs
    """

    rv = []
    refts = proof_req_attr_referents(proof_req)
    for info in [infos] if isinstance(infos, dict) else infos:
        if info['cred_def_id'] not in refts:
            continue
        brief = {
            'cred_info': info,
            'interval': {}
        }
        fro = None
        to = None
        for uuid in refts[info['cred_def_id']].values():
            interval = proof_req['requested_attributes'][uuid].get('non_revoked', {})
            if 'from' in interval:
                fro = min(fro or interval['from'], interval['from'])
            if 'to' in interval:
                to = max(to or interval['to'], interval['to'])

        if to:
            brief['interval']['to'] = to
        if fro:
            brief['interval']['from'] = fro
        if not brief['interval']:
            brief['interval'] = None

        rv.append(brief)

    return rv

def proof_req_briefs2req_creds(proof_req: dict, briefs: Union[dict, tuple, list]) -> dict:
    """
    Given a proof request and cred-brief(s), return a requested-creds structure.

    The proof request must have cred def id restrictions on all requested attribute specifications.

    :param proof_req_json: proof request json
    :param briefs: credential brief or list/tuple thereof, as indy-sdk wallet credential search returns; e.g.,

    ::
        [
            {
                "cred_info": {
                    "cred_rev_id": "149",
                    "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:15:0",
                    "schema_id": "LjgpST2rjsoxYegQDRm7EL:2:bc-reg:1.0",
                    "rev_reg_id": "LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:15:0:CL_ACCUM:1",
                    "referent": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "attrs": {
                        "busId": "11144444",
                        "endDate": "",
                        "id": "3",
                        "effectiveDate": "2012-12-01",
                        "jurisdictionId": "1",
                        "orgTypeId": "2",
                        "legalName": "Tart City"
                    }
                },
                "interval": {
                    "to": 1532448939,
                    "from": 1234567890
                }
            },
            ...
        ]

    :return: indy-sdk requested credentials json to pass to proof creation request; e.g.,

    ::

        {
            "requested_attributes": {
                "15_endDate_uuid": {
                    "timestamp": 1532444072,
                    "cred_id": "5732809d-b2eb-4eb4-a754-aaa3844b8086",
                    "revealed": true
                },
                "15_id_uuid": {
                    "timestamp": 1532444072,
                    "cred_id": "5732809d-b2eb-4eb4-a754-aaa3844b8086",
                    "revealed": true
                },
                "15_effectiveDate_uuid": {
                    "timestamp": 1532444072,
                    "cred_id": "5732809d-b2eb-4eb4-a754-aaa3844b8086",
                    "revealed": true
                },
                "15_busId_uuid": {
                    "timestamp": 1532444072,
                    "cred_id": "5732809d-b2eb-4eb4-a754-aaa3844b8086",
                    "revealed": true
                },
                "15_orgTypeId_uuid": {
                    "timestamp": 1532444072,
                    "cred_id": "5732809d-b2eb-4eb4-a754-aaa3844b8086",
                    "revealed": true
                },
                "15_jurisdictionId_uuid": {
                    "timestamp": 1532444072,
                    "cred_id": "5732809d-b2eb-4eb4-a754-aaa3844b8086",
                    "revealed": true
                },
                "15_legalName_uuid": {
                    "timestamp": 1532444072,
                    "cred_id": "5732809d-b2eb-4eb4-a754-aaa3844b8086",
                    "revealed": true
                }
            },
            "requested_predicates": {},
            "self_attested_attributes": {}
        }
    """

    rv = {
        'self_attested_attributes': {},
        'requested_attributes': {},
        'requested_predicates': {}
    }

    refts = proof_req_attr_referents(proof_req)
    for brief in [briefs] if isinstance(briefs, dict) else briefs:
        cred_info = brief['cred_info']
        timestamp = (brief['interval'] or {}).get('to', None)
        for attr in brief['cred_info']['attrs']:
            if attr not in refts[cred_info['cred_def_id']]:
                continue
            req_attr = {
                'cred_id': cred_info['referent'],
                'revealed': True,
                'timestamp': timestamp
            }
            if not timestamp:
                req_attr.pop('timestamp')
            rv['requested_attributes'][refts[cred_info['cred_def_id']][attr]] = req_attr

    return rv


def creds_display(creds: dict, filt: dict = None, filt_dflt_incl: bool = False) -> dict:
    """
    Find indy-sdk creds matching input filter from within input creds structure,
    json-loaded as returned via HolderProver.get_creds(), and return human-legible summary.

    :param creds: credentials structure; e.g.,

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


def proof_req2wql_all(proof_req: dict, except_cd_ids: list = None) -> dict:
    """
    Given a proof request and a list of cred def ids to omit, return an extra WQL query dict
    that will find all corresponding credentials in search.

    The proof request must have cred def id restrictions on all requested attribute specifications.
    At present, the utility does not support predicates.

    :param proof_req: proof request
    :return: extra WQL dict to fetch all corresponding credentials in search.
    """

    rv = {}
    refts = proof_req_attr_referents(proof_req)
    for cd_id in [k for k in refts if k not in (except_cd_ids or [])]:
        rv[set(refts[cd_id].values()).pop()] = {"cred_def_id": cd_id}

    return rv


def proof_req_attr_referents(proof_req: dict) -> dict:
    """
    Given a proof request with all requested attributes having cred def id restrictions,
    return its attribute referents by cred def id and attribute.

    The returned structure can be useful in populating the extra WQL query parameter
    in the credential search API.

    :param proof_req: proof request with all requested attribute specifications having cred def id restriction; e.g.,

    ::

        {
            "name": "proof_req",
            "version": "0.0",
            "requested_attributes": {
                "18_greenLevel_uuid": {
                    "restrictions": [
                        {
                            "cred_def_id": "WgWxqztrNooG92RXvxSTWv:3:CL:18:0"
                        }
                    ],
                    "name": "greenLevel",
                    "non_revoked": {
                        "to": 1532367957,
                        "from": 1532367957
                    }
                },
                "18_legalName_uuid": {
                    "restrictions": [
                        {
                            "cred_def_id": "WgWxqztrNooG92RXvxSTWv:3:CL:18:0"
                        }
                    ],
                    "name": "legalName",
                    "non_revoked": {
                        "to": 1532367957,
                        "from": 1532367957
                    }
                },
                "15_id_uuid": {  # this specification will not show up in response: no cred def id restriction :-(
                    "name": "id",
                    "non_revoked": {
                        "to": 1532367957,
                        "from": 1532367957
                    }
                }
            }
        }

    :return: nested dict mapping cred def id to name to proof request referent; e.g.,

    ::

        {
            'WgWxqztrNooG92RXvxSTWv:3:CL:18:0': {
                'legalName': '18_legalName_uuid'
                'greenLevel': '18_greenLevel_uuid'
            }
        }
    """

    rv = {}
    for uuid, spec in proof_req['requested_attributes'].items():
        cd_id = None
        for restriction in spec.get('restrictions', []):
            cd_id = restriction.get('cred_def_id', None)
            if cd_id:
                break
        if not cd_id:
            continue
        if cd_id not in rv:  # cd_id of None is not OK
            rv[cd_id] = {}
        rv[cd_id][spec['name']] = uuid

    return rv


def revoc_info(creds: Union[dict, list], filt: dict = None) -> dict:
    """
    Given a creds structure or a list of cred-briefs, return a dict mapping pairs
    (revocation registry identifier, credential revocation identifier)
    to (decoded) attribute name:value dicts.

    If the caller includes a filter of attribute:value pairs, retain only matching attributes.

    :param creds: creds structure or list of briefs
    :param filt: dict mapping attributes to values of interest; e.g.,

    ::

        {
            'legalName': 'Flan Nebula',
            'effectiveDate': '2018-01-01',
            'endDate': None
        }

    :return: dict mapping (rev_reg_id, cred_rev_id) pairs to decoded attributes
    """

    def _add(briefs):
        nonlocal rv, filt
        for brief in briefs:
            cred_info = brief['cred_info']
            (rr_id, cr_id) = (cred_info['rev_reg_id'], cred_info['cred_rev_id'])
            if (rr_id, cr_id) in rv or rr_id is None or cr_id is None:
                continue
            if not filt:
                rv[(rr_id, cr_id)] = cred_info['attrs']
                continue
            if ({attr: str(filt[attr]) for attr in filt}.items() <= cred_info['attrs'].items()):
                rv[(rr_id, cr_id)] = cred_info['attrs']

    rv = {}
    if isinstance(creds, dict):
        for uuid2creds in (creds.get('attrs', {}), creds.get('predicates', {})):
            for briefs in uuid2creds.values():
                _add(briefs)
    else:
        _add(creds)

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
