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
from collections import namedtuple
from copy import deepcopy
from pprint import pformat
from math import ceil, log
from von_agent.codec import decode


SchemaKey = namedtuple('SchemaKey', 'origin_did name version')

def ppjson(dumpit, elide = None):
    """
    JSON pretty printer, whether already json-encoded or not
    """

    if elide is not None:
        elide = max(elide - 3, 0) # make room for ellipses '...'
    try:
        rv = json.dumps(json.loads(dumpit) if isinstance(dumpit, str) else dumpit, indent=4)
    except:
        rv = '{}'.format(pformat(dumpit, indent=4, width=120))
    return rv if elide is None else '{}...'.format(rv[0 : elide])

def schema_id(origin_did: str, name: str, version: str) -> str:
    """
    Return schema identifier for input origin DID, schema name, and schema version.

    :param origin_did: DID of schema originator
    :param name: schema name
    :param version: schema version
    :return: schema identifier
    """

    return '{}:2:{}:{}'.format(origin_did, name, version)  # 2 marks indy-sdk schema id


def schema_key(schema_id: str) -> SchemaKey:
    """
    Return schema key (namedtuple) convenience for schema identifier components.

    :param schema_id: schema identifier
    :return: schema key (namedtuple) object
    """

    s_key = schema_id.split(':')
    s_key.pop(1)  # take out indy-sdk schema marker

    return SchemaKey(*s_key)


def cred_def_id(issuer_did: str, schema_seq_no: int) -> str:
    """
    Return credential definition identifier for input issuer DID and schema sequence number.

    :param issuer_did: DID of credential definition issuer
    :param schema_seq_no: schema sequence number
    :return: credential definition identifier
    """

    return '{}:3:CL:{}'.format(issuer_did, schema_seq_no)  # 3 marks indy-sdk cred def id, CL denotes sig type


def rev_reg_id(cred_def_id: str, tag: str) -> str:
    """
    Given a credential definition identifier and a tag, return the corresponding
    revocation registry identifier, repeating the issuer DID from the
    input identifier.

    :param cred_def_did: credential definition identifier
    :param tag: tag to use
    :return: revocation registry identifier
    """

    return '{}:4:{}:CL_ACCUM:{}'.format(cred_def_id.split(':', 1)[0], cred_def_id, tag)  # 4 marks rev reg def id


def rev_reg_id2cred_def_id(rev_reg_id: str) -> str:
    """
    Given a revocation registry identifier, return its corresponding credential definition identifier.

    :param rev_reg_id: revocation registry identifier
    :return: credential definition identifier
    """

    return ':'.join(rev_reg_id.split(':')[2:-2])  # rev_reg_id comprises prefixes:<cred_def_id>:suffixes


def rev_reg_id2tag(rev_reg_id: str) -> str:
    """
    Given a revocation registry identifier, return its corresponding (stringified int) tag.

    :param rev_reg_id: revocation registry identifier
    :return: tag
    """

    return str(rev_reg_id.split(':')[-1])  # tag is last token


def rev_reg_id2cred_def_id__tag(rev_reg_id: str) -> str:
    """
    Given a revocation registry identifier, return its corresponding credential definition identifier and
    (stringified int) tag.

    :param rev_reg_id: revocation registry identifier
    :return: credential definition identifier and tag
    """

    return (':'.join(rev_reg_id.split(':')[2:-2]),  # rev_reg_id comprises prefixes:<cred_def_id>:suffixes
        str(rev_reg_id.split(':')[-1]))  # tag is last token


def schema_ids_for(creds: dict, cred_ids: list) -> dict:
    """
    Given a credentials structure and a list of credential identifiers (aka wallet cred-ids, referents),
    return dict mapping each credential identifier to its corresponding schema identifier (string).

    :param creds: creds structure returned by (HolderProver agent) get_creds()
    :param cred_ids: list of credential identifiers for which to find corresponding schema identifiers
    :return: dict mapping each credential identifier to its corresponding schema identifier
        (empty dict if no such credential identifiers present)
    """

    rv = {}
    for uuid2creds in (creds['attrs'], creds['predicates']):
        for inner_creds in uuid2creds.values():
            for cred in inner_creds:  # it's a list of dicts, each dict a cred
                cred_id = cred['cred_info']['referent']
                if (cred_id not in rv) and (cred_id in cred_ids):
                    rv[cred_id] = cred['cred_info']['schema_id']

    return rv


def prune_creds_json(creds: dict, cred_ids: set) -> str:
    """
    Strip all claims out of the input json structure that do not match any of the input credential identifiers.

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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18",
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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18",
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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18",
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
                            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:18",
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
    :param filt: filter for matching attributes and values; dict (None or empty for no filter)
        mapping each schema identifier to dict mapping attributes to values to match; e.g.,
        ::
        {
            'Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0': {
                'attr0': '1',
                'attr1': 'Nice'
            },
            ...
        }
    :param: filt_dflt_incl: whether to include (True) all attributes for schema that filter does not identify
        or to exclude (False) all such attributes
    :return: human-legible dict mapping credential identifiers to human-readable creds structures
        (each as per HolderProver.get_creds_coarse()) for creds matching input filter
    """

    rv = {}
    if filt is None:
        filt = {}
    for uuid2creds in (creds['attrs'], creds['predicates']):
        for inner_creds in uuid2creds.values():
            for cred in inner_creds:
                cred_info = cred['cred_info']
                if cred_info['referent'] in rv:
                    continue
                cred_s_id = cred_info['schema_id']
                if (not filt) or (filt_dflt_incl and cred_s_id not in filt):
                    rv[cred_info['referent']] = cred_info
                    continue
                if filt and cred_s_id in filt:
                    if ({k: str(filt[cred_s_id][k]) for k in filt[cred_s_id]}.items() <= cred_info['attrs'].items()):
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
    for uuid2creds in (creds['attrs'], creds['predicates']):
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
    :return: dict mapping cred-ids to dicts mapping revealed attribute names to (decoded) values
    """

    rv = {}
    for sub_index in range(len(proof['identifiers'])):
        cd_id = proof['identifiers'][sub_index]['cred_def_id']
        rv[cd_id] = {
            attr: decode(proof['proof']['proofs'][sub_index]['primary_proof']['eq_proof']['revealed_attrs'][attr])
                for attr in proof['proof']['proofs'][sub_index]['primary_proof']['eq_proof']['revealed_attrs']
        }

    return rv
