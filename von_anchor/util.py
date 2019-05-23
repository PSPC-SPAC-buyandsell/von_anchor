"""
Copyright 2017-2019 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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
from typing import Sequence, Union

from base58 import alphabet, b58decode

from von_anchor.error import BadIdentifier
from von_anchor.nodepool import Protocol
from von_anchor.indytween import Role, Predicate, SchemaKey


B58 = alphabet if isinstance(alphabet, str) else alphabet.decode('ascii')


def schema_id(origin_did: str, name: str, version: str) -> str:
    """
    Return schema identifier for input origin DID, schema name, and schema version.

    :param origin_did: DID of schema originator
    :param name: schema name
    :param version: schema version
    :return: schema identifier
    """

    return '{}:2:{}:{}'.format(origin_did, name, version)  # 2 marks indy-sdk schema id


def ok_wallet_reft(token: str) -> bool:
    """
    Whether input token looks like a valid wallet credential identifier
    (aka wallet referent, wallet cred id, wallet cred uuid).

    :param token: candidate string
    :return: whether input token looks like a valid wallet credential identifier
    """

    return bool(re.match(r'[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$', token or ''))


def ok_role(token: str) -> bool:
    """
    Whether input role is valid to mark indy anchor role on ledger.

    :param token: candidate string
    :return: whether input token looks like a valid indy anchor role
    """

    return Role.get(token) is not None


def ok_endpoint(token: str) -> bool:
    """
    Whether input token looks like a valid indy endpoint (<ip-address>:<port>).

    :param token: candidate string
    :return: whether input token looks like a valid indy endpoint
    """

    return bool(re.match(
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]+$',
        token or ''))


def ok_did(token: str) -> bool:
    """
    Whether input token looks like a valid distributed identifier.

    :param token: candidate string
    :return: whether input token looks like a valid schema identifier
    """

    try:
        return len(b58decode(token)) == 16 if token else False
    except ValueError:
        return False


def ok_schema_id(token: str) -> bool:
    """
    Whether input token looks like a valid schema identifier;
    i.e., <issuer-did>:2:<name>:<version>.

    :param token: candidate string
    :return: whether input token looks like a valid schema identifier
    """

    return bool(re.match('[{}]{{21,22}}:2:.+:[0-9.]+$'.format(B58), token or ''))


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


def ok_cred_def_id(token: str, issuer_did: str = None) -> bool:
    """
    Whether input token looks like a valid credential definition identifier from input issuer DID (default any); i.e.,
    <issuer-did>:3:CL:<schema-seq-no>:<cred-def-id-tag> for protocol >= 1.4, or
    <issuer-did>:3:CL:<schema-seq-no> for protocol == 1.3.

    :param token: candidate string
    :param issuer_did: issuer DID to match, if specified
    :return: whether input token looks like a valid credential definition identifier
    """

    cd_id_m = re.match('([{}]{{21,22}}):3:CL:[1-9][0-9]*(:.+)?$'.format(B58), token or '')
    return bool(cd_id_m) and ((not issuer_did) or cd_id_m.group(1) == issuer_did)


def cred_def_id2seq_no(cd_id: str) -> int:
    """
    Given a credential definition identifier, return its schema sequence number.
    Raise BadIdentifier on input that is not a credential definition identifier.

    :param cd_id: credential definition identifier
    :return: sequence number
    """

    if ok_cred_def_id(cd_id):
        return int(cd_id.split(':')[3])  # sequence number is token at 0-based position 3
    raise BadIdentifier('Bad credential definition identifier {}'.format(cd_id))


def rev_reg_id(cd_id: str, tag: Union[str, int]) -> str:
    """
    Given a credential definition identifier and a tag, return the corresponding
    revocation registry identifier, repeating the issuer DID from the
    input identifier.

    :param cd_id: credential definition identifier
    :param tag: tag to use
    :return: revocation registry identifier
    """

    return '{}:4:{}:CL_ACCUM:{}'.format(cd_id.split(":", 1)[0], cd_id, tag)  # 4 marks rev reg def id


def ok_rev_reg_id(token: str, issuer_did: str = None) -> bool:
    """
    Whether input token looks like a valid revocation registry identifier from input issuer DID (default any); i.e.,
    <issuer-did>:4:<issuer-did>:3:CL:<schema-seq-no>:<cred-def-id-tag>:CL_ACCUM:<rev-reg-id-tag> for protocol >= 1.4, or
    <issuer-did>:4:<issuer-did>:3:CL:<schema-seq-no>:CL_ACCUM:<rev-reg-id-tag> for protocol == 1.3.

    :param token: candidate string
    :param issuer_did: issuer DID to match, if specified
    :return: whether input token looks like a valid revocation registry identifier
    """

    rr_id_m = re.match(
        '([{0}]{{21,22}}):4:([{0}]{{21,22}}):3:CL:[1-9][0-9]*(:.+)?:CL_ACCUM:.+$'.format(B58),
        token or '')
    return bool(rr_id_m) and ((not issuer_did) or (rr_id_m.group(1) == issuer_did and rr_id_m.group(2) == issuer_did))


def rev_reg_id2cred_def_id(rr_id: str) -> str:
    """
    Given a revocation registry identifier, return its corresponding credential definition identifier.
    Raise BadIdentifier if input is not a revocation registry identifier.

    :param rr_id: revocation registry identifier
    :return: credential definition identifier
    """

    if ok_rev_reg_id(rr_id):
        return ':'.join(rr_id.split(':')[2:-2])  # rev reg id comprises (prefixes):<cred_def_id>:(suffixes)
    raise BadIdentifier('Bad revocation registry identifier {}'.format(rr_id))


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
    (stringified int) tag. Raise BadIdentifier if input is not a revocation registry identifier.

    :param rr_id: revocation registry identifier
    :return: credential definition identifier and tag
    """

    if ok_rev_reg_id(rr_id):
        return (
            ':'.join(rr_id.split(':')[2:-2]),  # rev reg id comprises (prefixes):<cred_def_id>:(suffixes)
            str(rr_id.split(':')[-1])  # tag is last token
        )
    raise BadIdentifier('Bad revocation registry identifier {}'.format(rr_id))


def iter_briefs(briefs: Union[dict, Sequence[dict]]) -> tuple:
    """
    Given a cred-brief/cred-info, an sequence thereof, or cred-brief-dict
    (as HolderProver.get_cred_briefs_by_proof_req_q() returns), return tuple with
    all contained cred-briefs.

    :param briefs: cred-brief/cred-info, sequence thereof, or cred-brief-dict
    :return: tuple of cred-briefs
    """

    if isinstance(briefs, dict):
        if all(ok_wallet_reft(k) for k in briefs):
            return tuple(briefs.values())
        return (briefs,)
    return tuple(briefs)


def box_ids(briefs: Union[dict, Sequence[dict]], cred_ids: Union[Sequence[str], str] = None) -> dict:
    """
    Given one or more cred-briefs/cred-infos, and an optional sequence of credential identifiers
    (aka wallet cred ids, referents; specify None to include all), return dict mapping each
    credential identifier to a box ids structure (i.e., a dict specifying its corresponding
    schema identifier, credential definition identifier, and revocation registry identifier,
    the latter being None if cred def does not support revocation).

    :param briefs: cred-brief/cred-info, sequence thereof, or cred-brief-dict
    :param cred_ids: credential identifier or sequence thereof for which to find corresponding
        schema identifiers, None for all
    :return: dict mapping each credential identifier to its corresponding box ids (empty dict if
        no matching credential identifiers present)
    """

    rv = {}
    for brief in iter_briefs(briefs):
        cred_info = brief.get('cred_info', {}) or brief  # briefs could be cred-infos or cred-briefs
        cred_id = cred_info['referent']
        if ((cred_id not in rv) and (not cred_ids or cred_id in [cred_ids, [cred_ids]][isinstance(cred_ids, str)])):
            rv[cred_id] = {
                'schema_id': cred_info['schema_id'],
                'cred_def_id': cred_info['cred_def_id'],
                'rev_reg_id': cred_info['rev_reg_id']
            }

    return rv


def prune_creds_json(creds: dict, cred_ids: set) -> str:
    """
    Strip all creds out of the input json structure that do not match any of the input credential identifiers.

    :param creds: indy-sdk creds structure
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


def proof_req_infos2briefs(proof_req: dict, infos: Union[dict, Sequence[dict]]) -> list:
    """
    Given a proof request and corresponding cred-info(s), return a list of cred-briefs
    (i.e., cred-info plus interval).

    The proof request must have cred def id restrictions on all requested attribute specifications.

    :param proof_req: proof request
    :param infos: cred-info or sequence thereof; e.g.,

    ::

        [
            {
                'attrs': {
                    'auditDate': '2018-07-30',
                    'greenLevel': 'Silver',
                    'legalName': 'Tart City'
                },
                'cred_rev_id': '48',
                'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:17:tag',
                'referent': 'c15674a9-7321-440d-bbed-e1ac9273abd5',
                'rev_reg_id': 'WgWxqztrNooG92RXvxSTWv:4:WgWxqztrNooG92RXvxSTWv:3:CL:17:tag:CL_ACCUM:0',
                'schema_id': 'WgWxqztrNooG92RXvxSTWv:2:green:1.0'
            },
            ...
        ]

    :return: list of cred-briefs
    """

    rv = []
    refts = proof_req_attr_referents(proof_req)
    for info in iter_briefs(infos):
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

def proof_req_briefs2req_creds(proof_req: dict, briefs: Union[dict, Sequence[dict]]) -> dict:
    """
    Given a proof request and cred-brief(s), return a requested-creds structure.

    The proof request must have cred def id restrictions on all requested attribute specifications.

    :param proof_req: proof request
    :param briefs: credential brief, sequence thereof (as indy-sdk wallet credential search returns),
        or cred-brief-dict (as HolderProver.get_cred_briefs_for_proof_req_q() returns); e.g.,

    ::

        [
            {
                "cred_info": {
                    "cred_rev_id": "149",
                    "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:15:tag",
                    "schema_id": "LjgpST2rjsoxYegQDRm7EL:2:bc-reg:1.0",
                    "rev_reg_id": "LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:15:tag:CL_ACCUM:1",
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

    :return: indy-sdk requested creds json to pass to proof creation request; e.g.,

    ::

        {
            "requested_attributes": {
                "15_endDate_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "revealed": true
                },
                "15_id_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "revealed": true
                },
                "15_effectiveDate_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "revealed": true
                },
                "15_busId_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "revealed": true
                },
                "15_orgTypeId_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "revealed": false
                },
                "15_jurisdictionId_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "revealed": true
                },
                "15_legalName_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                    "revealed": true
                }
            },
            "requested_predicates": {
                "15_orgTypeId_GE_uuid": {
                    "timestamp": 1532448939,
                    "cred_id": "43f8dc18-ac00-4b72-8a96-56f47dba77ca",
                }
            },
            "self_attested_attributes": {}
        }

    """

    rv = {
        'self_attested_attributes': {},
        'requested_attributes': {},
        'requested_predicates': {}
    }

    attr_refts = proof_req_attr_referents(proof_req)
    pred_refts = proof_req_pred_referents(proof_req)
    for brief in iter_briefs(briefs):
        cred_info = brief['cred_info']
        timestamp = (brief['interval'] or {}).get('to', None)
        for attr in cred_info['attrs']:
            if attr in attr_refts.get(cred_info['cred_def_id'], {}):
                req_attr = {
                    'cred_id': cred_info['referent'],
                    'revealed': attr not in pred_refts.get(cred_info['cred_def_id'], {}),
                    'timestamp': timestamp
                }
                if not timestamp:
                    req_attr.pop('timestamp')
                rv['requested_attributes'][attr_refts[cred_info['cred_def_id']][attr]] = req_attr
            if attr in pred_refts.get(cred_info['cred_def_id'], {}):
                for uuid in pred_refts[cred_info['cred_def_id']][attr]:
                    req_pred = {
                        'cred_id': cred_info['referent'],
                        'timestamp': timestamp
                    }
                    if not timestamp:
                        req_pred.pop('timestamp')
                    rv['requested_predicates'][uuid] = req_pred
    return rv


def creds_display(creds: Union[dict, Sequence[dict]], filt: dict = None, filt_dflt_incl: bool = False) -> dict:
    """
    Find indy-sdk creds matching input filter from within input creds structure,
    sequence of cred-briefs/cred-infos, or cred-brief-dict.  Return human-legible summary.

    :param creds: creds structure, cred-brief/cred-info or sequence thereof,
        or cred-brief-dict; e.g., creds

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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag",
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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag",
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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag",
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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag",
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
            'Q4zqM7aXqm7gDQkUVLng9h:3:CL:18:tag': {
                'attr0': 1,  # operation stringifies en passant
                'attr1': 'Nice'
            },
            ...
        }

    :param filt_dflt_incl: whether to include (True) all attributes for schema that filter does not identify
        or to exclude (False) all such attributes
    :return: human-legible dict mapping credential identifiers to human-readable credential briefs
        (not proper indy-sdk creds structures) for creds matching input filter
    """

    def _add(briefs):
        nonlocal rv, filt
        for brief in briefs:
            cred_info = brief.get('cred_info', {}) or brief  # briefs could be cred-infos or cred-briefs
            if cred_info['referent'] in rv:
                continue
            cred_cd_id = cred_info['cred_def_id']
            if (not filt) or (filt_dflt_incl and cred_cd_id not in filt):
                rv[cred_info['referent']] = cred_info
                continue
            if filt and cred_cd_id in filt:
                if ({k: str(filt[cred_cd_id][k]) for k in filt[cred_cd_id]}.items() <= cred_info['attrs'].items()):
                    rv[cred_info['referent']] = cred_info

    rv = {}
    if filt is None:
        filt = {}
    if isinstance(creds, dict):
        if all(ok_wallet_reft(k) for k in creds):
            _add(creds.values())
        else:
            for uuid2briefs in (creds.get('attrs', {}), creds.get('predicates', {})):
                for briefs in uuid2briefs.values():
                    _add(briefs)
    else:
        _add(creds)
    return rv


def proof_req2wql_all(proof_req: dict, x_cd_ids: Union[str, Sequence[str]] = None) -> dict:
    """
    Given a proof request and a list of cred def ids to omit, return an extra WQL query dict
    that will find all corresponding credentials in search.

    The proof request must have cred def id restrictions on all requested attribute specifications.
    At present, the utility does not support predicates.

    :param proof_req: proof request
    :param x_cd_ids: cred def identifier or sequence thereof to omit
    :return: extra WQL dict to fetch all corresponding credentials in search.
    """

    rv = {}
    attr_refts = proof_req_attr_referents(proof_req)
    for cd_id in [k for k in attr_refts if k not in ([x_cd_ids] if isinstance(x_cd_ids, str) else x_cd_ids or [])]:
        rv[set(attr_refts[cd_id].values()).pop()] = {"cred_def_id": cd_id}

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
            'name": 'proof_req',
            'version': '0.0',
            'requested_attributes': {
                '18_greenLevel_uuid': {
                    'restrictions': [
                        {
                            'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:18:tag'
                        }
                    ],
                    'name': 'greenLevel',
                    'non_revoked': {
                        'to': 1532367957,
                        'from': 1532367957
                    }
                },
                '18_legalName_uuid': {
                    'restrictions': [
                        {
                            'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:18:tag'
                        }
                    ],
                    'name': 'legalName',
                    'non_revoked': {
                        'to': 1532367957,
                        'from': 1532367957
                    }
                },
                '15_id_uuid': {  # this specification will not show up in response: no cred def id restriction :-(
                    'name': 'id',
                    'non_revoked': {
                        'to': 1532367957,
                        'from': 1532367957
                    }
                }
            }
            'requested_predicates': {
            }
        }

    :return: nested dict mapping cred def id to name to proof request referent; e.g.,

    ::

        {
            'WgWxqztrNooG92RXvxSTWv:3:CL:18:tag': {
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


def proof_req_pred_referents(proof_req: dict) -> dict:
    """
    Given a proof request with all requested predicates having cred def id restrictions,
    return its predicate referents by cred def id and attribute, mapping a predicate and a limit.

    The returned structure can be useful in downstream processing to filter cred-infos for predicates.

    :param proof_req: proof request with all requested predicate specifications having cred def id restriction; e.g.,

    ::

        {
            'name': 'proof_req',
            'version': '0.0',
            'requested_attributes': {
                ...
            }
            'requested_predicates': {
                '194_highscore_GE_uuid': {
                    'name': 'highscore',
                    'p_type': '>=',
                    'p_value': '100000',
                    'restrictions': [
                        {
                            'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:194:tag'
                        }
                    ],
                    'non_revoked': {
                        ...
                    }
                },
                '194_level_GE_uuid': {
                    'name': 'level',
                    'p_type': '>=',
                    'p_value': '10',
                    'restrictions': [
                        {
                            'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:194:tag'
                        }
                    ],
                    'non_revoked': {
                        ...
                    }
                },
                '194_attempts_LE_uuid': {
                    'name': 'attempts',
                    'p_type': '<=',
                    'p_value': '3',
                    'restrictions': [
                        {
                            'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:194:tag'
                        }
                    ],
                    'non_revoked': {
                        ...
                    }
                },
                '198_employees_LT_uuid': {
                    'name': 'employees',
                    'p_type': '<',
                    'p_value': '100',
                    'restrictions': [
                        {
                            'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:198:tag'
                        }
                    ],
                    'non_revoked': {
                        ...
                    }
                },
                '198_employees_GE_uuid': {
                    'name': 'employees',
                    'p_type': '>=',
                    'p_value': '50',
                    'restrictions': [
                        {
                            'cred_def_id': 'WgWxqztrNooG92RXvxSTWv:3:CL:198:tag'
                        }
                    ],
                    'non_revoked': {
                        ...
                    }
                },
            }
        }

    :return: nested dict mapping cred def id to name to proof request referent to predicate and limit; e.g.,

    ::

        {
            'WgWxqztrNooG92RXvxSTWv:3:CL:194:tag': {
                'highscore': {
                    '194_level_GE_uuid': ['>=', 100000]
                },
                'level': {
                    '194_level_GE_uuid': ['>=', 10]
                },
                'attempts': {
                    '194_attempts_LE_uuid': ['<=', 3]
                }
            },
            'WgWxqztrNooG92RXvxSTWv:3:CL:198:tag': {
                'employees': {  # may have many preds per attr, but always 1 uuid and 1 relation per pred
                    '198_LT_employees_uuid': ['<=', 100]
                    '198_GE_employees_uuid': ['>=', 50]
                }
            }
        }

    """

    rv = {}
    for uuid, spec in proof_req['requested_predicates'].items():
        cd_id = None
        for restriction in spec.get('restrictions', []):
            cd_id = restriction.get('cred_def_id', None)
            if cd_id:
                break
        if not cd_id:
            continue
        if cd_id not in rv:  # cd_id of None is not OK
            rv[cd_id] = {}
        if spec['name'] not in rv[cd_id]:
            rv[cd_id][spec['name']] = {}
        rv[cd_id][spec['name']][uuid] = [spec['p_type'], Predicate.to_int(spec['p_value'])]

    return rv


def revoc_info(briefs: Union[dict, Sequence[dict]], filt: dict = None) -> dict:
    """
    Given a cred-brief, cred-info or sequence of either, return a dict mapping pairs
    (revocation registry identifier, credential revocation identifier)
    to attribute name: (raw) value dicts.

    If the caller includes a filter of attribute:value pairs, retain only matching attributes.

    :param briefs: cred-brief/cred-info, or sequence thereof
    :param filt: dict mapping attributes to values of interest; e.g.,

    ::

        {
            'legalName': 'Flan Nebula',
            'effectiveDate': '2018-01-01',
            'endDate': None
        }

    :return: dict mapping (rev_reg_id, cred_rev_id) pairs to (raw) attributes; e.g.,

    ::

        {
            ('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:17:tag:CL_ACCUM:1', '2'): {
                'busId': '11121398',
                'effectiveDate': '2010-10-10',
                'endDate': '',
                'id': '1',
                'jurisdictionId': '1',
                'legalName': 'The Original House of Pies',
                'orgTypeId': '2'},
            ('LjgpST2rjsoxYegQDRm7EL:4:LjgpST2rjsoxYegQDRm7EL:3:CL:17:tag:CL_ACCUM:1', '3'): {
                'busId': '11133333',
                'effectiveDate': '2011-10-01',
                'endDate': '',
                'id': '2',
                'jurisdictionId': '1',
                'legalName': 'Planet Cake',
                'orgTypeId': '1'}
        }

    """

    rv = {}
    for brief in iter_briefs(briefs):
        cred_info = brief.get('cred_info', {}) or brief  # briefs could be cred-infos or cred-briefs
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
    to dicts, each dict mapping attribute names to (raw) values, for processing in further creds downstream.

    :param proof: indy-sdk proof as dict
    :return: dict mapping cred-ids to dicts, each mapping revealed attribute names to (raw) values
    """

    rv = {}
    for sub_index in range(len(proof['identifiers'])):
        cd_id = proof['identifiers'][sub_index]['cred_def_id']
        rv[cd_id] = ({  # uses von_anchor convention for uuid (referent) construction: will break on foreign anchor's
            '_'.join(uuid.split('_')[1:-1]): proof['requested_proof']['revealed_attrs'][uuid]['raw']
            for uuid in proof['requested_proof']['revealed_attrs']
            if proof['requested_proof']['revealed_attrs'][uuid]['sub_proof_index'] == sub_index})

    return rv
