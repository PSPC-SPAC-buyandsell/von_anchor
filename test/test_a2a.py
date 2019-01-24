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
import pytest

from von_anchor.a2a import PublicKeyType, PublicKey, DIDDoc
from von_anchor.error import BadIdentifier
from von_anchor.frill import Ink, ppjson


@pytest.mark.asyncio
async def test_a2a():
    print(Ink.YELLOW('\n\n== Testing DID Doc wranglers =='))

    did_doc0 = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'routing',
                'type': 'RsaVerificationKey2018',
                'owner': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC X...'
            },
            {
                'id': '4',
                'type': 'RsaVerificationKey2018',
                'owner': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC 9...'},
            {
                'id': '6',
                'type': 'RsaVerificationKey2018',
                'owner': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC A...'
            }
        ],
        'authentication': [
            {
                'type': 'RsaSignatureAuthentication2018',
                'publicKey': 'did:sov:LjgpST2rjsoxYegQDRm7EL#4'
            }
        ],
        'service': [
            {
                'type': 'Agency',
                'serviceEndpoint': 'did:sov:Q4zqM7aXqm7gDQkUVLng9h'
            }
        ]
    }
    did_doc0_json = json.dumps(did_doc0)
    did_doc1 = DIDDoc.from_json(did_doc0_json)
    did_doc1_json = did_doc1.to_json()
    assert json.loads(did_doc0_json) == json.loads(did_doc1_json)
    print('\n\n== 1 == DID Doc from JSON and back again: {}'.format(ppjson(did_doc1_json)))
