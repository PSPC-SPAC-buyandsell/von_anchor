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
from von_anchor.error import AbsentDIDDocItem
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
                'id': '3',
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
    assert len(dd.pubkey) == len(dd_in['publicKey'])
    assert len(dd.authnkey) == len(dd_in['authentication'])

    dd_out = dd.serialize()
    print('\n\n== 1 == DID Doc on abbreviated identifiers: {}'.format(ppjson(dd_out)))

    # One authn key embedded, all possible refs canonical
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': '3',
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
    assert len(dd.pubkey) == len(dd_in['publicKey']) + 1
    assert len(dd.authnkey) == len(dd_in['authentication'])

    dd_out = dd.serialize()
    print('\n\n== 2 == DID Doc on mixed reference styles, embedded and ref style authn keys: {}'.format(ppjson(dd_out)))

    # All references canonical where possible; one authn key embedded and one by reference
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL#3',
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
                'type': 'DidMessaging',
                'serviceEndpoint': 'https://www.von.ca'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.pubkey) == len(dd_in['publicKey']) + 1
    assert len(dd.authnkey) == len(dd_in['authentication'])

    dd_out = dd.serialize()
    print('\n\n== 3 == DID Doc on canonical refs: {}'.format(ppjson(dd_out)))

    # Minimal as per indy-agent test suite without explicit identifiers
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'publicKey': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL#keys-1',
                'type': 'Ed25519VerificationKey2018',
                'controller': 'LjgpST2rjsoxYegQDRm7EL',
                'publicKeyBase58': '~XXXXXXXXXXXXXXXX'
            }
        ],
        'service': [
            {
                'type': 'DidMessaging',
                'recipientKeys': ['~XXXXXXXXXXXXXXXX'],
                'serviceEndpoint': 'https://www.von.ca'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.pubkey) == len(dd_in['publicKey'])
    assert len(dd.authnkey) == 0

    dd_out = dd.serialize()
    print('\n\n== 4 == DID Doc miminal style, implcit DID document identifier: {}'.format(
        ppjson(dd_out)))

    # Minimal + ids as per indy-agent test suite with explicit identifiers; novel service recipient key on raw base58
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL#keys-1',
                'type': 'Ed25519VerificationKey2018',
                'controller': 'LjgpST2rjsoxYegQDRm7EL',
                'publicKeyBase58': '~XXXXXXXXXXXXXXXX'
            }
        ],
        'service': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL;indy',
                'type': 'DidMessaging',
                'priority': 1,
                'recipientKeys': ['~YYYYYYYYYYYYYYYY'],
                'serviceEndpoint': 'https://www.von.ca'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.pubkey) == 1 + len(dd_in['publicKey'])
    assert len(dd.authnkey) == 0

    dd_out = dd.serialize()
    print('\n\n== 5 == DID Doc miminal style plus explicit idents and novel raw base58 service recip key: {}'.format(
        ppjson(dd_out)))

    # Minimal + ids as per indy-agent test suite with explicit identifiers; novel service recipient key on raw base58
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL#keys-1',
                'type': 'Ed25519VerificationKey2018',
                'controller': 'LjgpST2rjsoxYegQDRm7EL',
                'publicKeyBase58': '~XXXXXXXXXXXXXXXX'
            },
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL#keys-2',
                'type': 'Ed25519VerificationKey2018',
                'controller': 'LjgpST2rjsoxYegQDRm7EL',
                'publicKeyBase58': '~YYYYYYYYYYYYYYYY'
            },
            {
                'id': 'did:sov:LjgpST2rjsoxYegQDRm7EL#keys-3',
                'type': 'RsaVerificationKey2018',
                'controller': 'did:sov:LjgpST2rjsoxYegQDRm7EL',
                'publicKeyPem': '-----BEGIN PUBLIC A...'
            }
        ],
        'service': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL;indy',
                'type': 'DidMessaging',
                'priority': 0,
                'recipientKeys': ['~ZZZZZZZZZZZZZZZZ'],
                'serviceEndpoint': 'did:sov:LjgpST2rjsoxYegQDRm7EL;1'
            },
            {
                'id': '1',
                'type': 'one',
                'priority': 1,
                'recipientKeys': [
                    '~XXXXXXXXXXXXXXXX',
                    'did:sov:LjgpST2rjsoxYegQDRm7EL#keys-1'
                ],
                'routingKeys': [
                    'did:sov:LjgpST2rjsoxYegQDRm7EL#keys-3'
                ],
                'serviceEndpoint': 'LjgpST2rjsoxYegQDRm7EL;2'
            },
            {
                'id': '2',
                'type': 'two',
                'priority': 2,
                'recipientKeys': [
                    '~XXXXXXXXXXXXXXXX',
                    'did:sov:LjgpST2rjsoxYegQDRm7EL#keys-1'
                ],
                'routingKeys': [
                    'did:sov:LjgpST2rjsoxYegQDRm7EL#keys-3'
                ],
                'serviceEndpoint': 'https://www.two.ca/two'
            }
        ]
    }

    dd = DIDDoc.deserialize(dd_in)
    assert len(dd.pubkey) == 1 + len(dd_in['publicKey'])
    assert len(dd.authnkey) == 0
    assert {s.priority for s in dd.service.values()} == {0, 1, 2}
    assert len(dd.service) == 3

    dd_out = dd.serialize()
    print('\n\n== 6 == DID Doc on mixed service routing and recipient keys: {}'.format(
        ppjson(dd_out)))

    # Exercise missing service recipient key
    dd_in = {
        '@context': 'https://w3id.org/did/v1',
        'id': 'LjgpST2rjsoxYegQDRm7EL',
        'publicKey': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL#keys-1',
                'type': 'Ed25519VerificationKey2018',
                'controller': 'LjgpST2rjsoxYegQDRm7EL',
                'publicKeyBase58': '~XXXXXXXXXXXXXXXX'
            }
        ],
        'service': [
            {
                'id': 'LjgpST2rjsoxYegQDRm7EL;indy',
                'type': 'DidMessaging',
                'priority': 1,
                'recipientKeys': [
                    'did:sov:LjgpST2rjsoxYegQDRm7EL#keys-3'
                ],
                'serviceEndpoint': 'https://www.von.ca'
            }
        ]
    }

    try:
        dd = DIDDoc.deserialize(dd_in)
        assert False
    except AbsentDIDDocItem:
        pass
    print('\n\n== 7 == DID Doc on underspecified service key fails as expected')
