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

from von_anchor.a2a.diddoc import DIDDoc
from von_anchor.error import BadIdentifier
from von_anchor.frill import Ink, ppjson


@pytest.mark.asyncio
async def test_a2a():
    print(Ink.YELLOW('\n\n== Testing DID Doc wranglers =='))

    # One authn key by reference
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'routing',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC X...'
            },
            {
                'id': '4',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC 9...'
            },
            {
                'id': '6',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
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
                'id': '0',
                'type': 'Agency',
                'serviceEndpoint': 'did:sov:Q4zqM7aXqm7gDQkUVLng9h'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.verkeys) == len(dd_in['publicKey'])
    assert len(dd.authnkeys) == len(dd_in['authentication'])

    dd_out = dd.serialize()
    print('\n\n== 1 == DID Doc on referenced authn keys from dict and back again: {}'.format(ppjson(dd_out)))

    # One authn key embedded, all possible refs canonical
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'routing',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC X...'
            },
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL#4',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC 9...'
            }
        ],
        'authentication': [
            {
                'type': 'RsaSignatureAuthentication2018',
                'publicKey': 'did:sov:LjgpST2rjsoxYegQDRm7EL#4'
            },
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL#6',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC A...'
            }
        ],
        'service': [
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL;0',
                'type': 'Agency',
                'serviceEndpoint': 'https://www.von.ca'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.verkeys) == len(dd_in['publicKey']) + 1
    assert len(dd.authnkeys) == len(dd_in['authentication'])

    dd_out = dd.serialize()
    print('\n\n== 2 == DID Doc on refs canonical where possible from dict and back again: {}'.format(ppjson(dd_out)))

    # All references canonical where possible
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'routing',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC X...'
            },
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL#4',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC 9...'
            }
        ],
        'authentication': [
            {
                'type': 'RsaSignatureAuthentication2018',
                'publicKey': 'did:sov:LjgpST2rjsoxYegQDRm7EL#4'
            },
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL#6',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC A...'
            }
        ],
        'service': [
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL;0',
                'type': 'Agency',
                'serviceEndpoint': 'https://www.von.ca'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.verkeys) == len(dd_in['publicKey']) + 1
    assert len(dd.authnkeys) == len(dd_in['authentication'])

    dd_out = dd.serialize()
    print('\n\n== 3 == DID Doc on refs canonical where possible from dict and back again: {}'.format(ppjson(dd_out)))

    # Minimal as per indy-agent test suite circa 2019-02
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'publicKey': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL#keys-1',
                'type': 'Ed25519VerificationKey2018',
                'controller': 'LjgpST2rjsoxYegQDRm7EL',
                'publicKeyBase58': '~XXXXXXXXXXXXXXXXXX'
            }
        ],
        'service': [
            {
                'type': 'IndyAgent',
                'recipientKeys': ['~XXXXXXXXXXXXXXXX'],
                'serviceEndpoint': 'www.von.ca'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.verkeys) == len(dd_in['publicKey'])
    assert len(dd.authnkeys) == 0

    dd_out = dd.serialize()
    print('\n\n== 4 == DID Doc miminal style from dict and back again: {}'.format(
        ppjson(dd_out)))
