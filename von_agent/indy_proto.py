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

from time import time


def proof_req_all_attrs_json(s_id2schema: dict, non_revoked_to: int = None) -> str:
    """
    Return proof request json on all attributes (and no predicates) of specified
    schemata, with non-revocation interval to specification (or None).

    Note that this heuristic is subject to improvement to accommodate a mixed bag of
    cred_defs, some with revocation support and some without.

    :param s_id2schema: dict mapping schema ids to their respective schemata as they
        appear on the ledger; e.g.,
        ::
        {
            '4QxzWk3ajdnEA37NdNU5Kt:2:gvt:1.0': {
                "seqNo": 13,
                "name": "gvt",
                "id": "4QxzWk3ajdnEA37NdNU5Kt:2:gvt:1.0",
                "version": "1.0",
                "ver": "1.0",
                "attrNames": [
                    "height",
                    "sex",
                    "age",
                    "name"
                ]
            }
            '4QxzWk3ajdnEA37NdNU5Kt:2:drinks:1.1': {
                "seqNo": 15,
                "name": "drinks",
                "id": "4QxzWk3ajdnEA37NdNU5Kt:2:drinks:1.1",
                "version": "1.1",
                "ver": "1.0",
                "attrNames": [
                    "favouriteDrink",
                    "secondFavouriteDrink"
                ]
            }
        }
    :param non_revoked_to: (epoch seconds) end of non-revocation interval;
        specify None for cred defs not supporting revocation.
    :return: proof req json on all attributes of all input schema, no predicates.
    """

    proof_req = {
        'nonce': str(int(time())),
        'name': 'proof_req',
        'version': '0.0',
        'requested_attributes': {
            '{}_{}_uuid'.format(s_id2schema[s_id]['seqNo'], attr): {
                'name': attr,
                'restrictions': [{
                    'schema_id': s_id
                }]
            } for s_id in s_id2schema for attr in s_id2schema[s_id]['attrNames']
        },
        'requested_predicates': {},
    }

    if non_revoked_to is not None:
        proof_req['non_revoked'] = {
            'to': non_revoked_to
        }

    return json.dumps(proof_req)


def req_creds_all_json(creds: dict) -> str:
    """
    Return requested credentials json on all attributes (and no predicates)
    of specified creds structure.

    The heuristic assumes that the structure has exactly one credential
    per credential definition (i.e., it passes Claims Focus test for proof creation).

    :param creds: indy-sdk creds structure
    :return: requested_credentials structure for use in proof creation
    """

    req_creds = {
        'self_attested_attributes': {},
        'requested_attributes': {},
        'requested_predicates': {}
    }
    for attr_uuid in creds['attrs']:
        if 'interval' in creds['attrs'][attr_uuid][0]:
            req_creds['requested_attributes'] = {
                'cred_id': creds['attrs'][attr_uuid][0]['cred_info']['referent'],
                'revealed': True,
                'timestamp': creds['attrs'][attr_uuid][0]['interval']['to']
            }
        else:
            req_creds['requested_attributes'] = {
                'cred_id': creds['attrs'][attr_uuid][0]['cred_info']['referent'],
                'revealed': True
            }

    return json.dumps(req_creds)
