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

from collections import namedtuple
from enum import Enum
from typing import Iterable, Union

from von_anchor.error import BadIdentifier
from von_anchor.util import did2uri, ok_did, uri2did


DIDPair = namedtuple('DIDPair', 'did verkey')
LinkedDataKeySpec = namedtuple('LinkedDataKeySpec', 'ver_type authn_type specifier')


class PublicKeyType(Enum):
    """
    Class encapsulating indy-node transaction particulars by protocol version.
    """

    RSA_SIG_2018 = LinkedDataKeySpec(
        'RsaVerificationKey2018',
        'RsaSignatureAuthentication2018',
        'publicKeyPem')
    ED25519_SIG_2018 = LinkedDataKeySpec(
        'Ed25519VerificationKey2018',
        'Ed25519SignatureAuthentication2018',
        'publicKeyBase58')
    EDDSA_SA_SIG_SECP256K1 = LinkedDataKeySpec(
        'Ed25519VerificationKey2018',
        'Ed25519SignatureAuthenticationKey2018',
        'publicKeyHex')

    @staticmethod
    def get(value: str) -> 'Protocol':
        """
        Return enum instance corresponding to input version value ('RsaVerificationKey2018' etc.)
        """

        for pktype in PublicKeyType:
            if value in (pktype.ver_type, pktype.authn_type):
                return pktype
        return None

    @property
    def ver_type(self) -> str:
        """
        Return verification type identifier in public key specification.

        :return verification type
        """

        return self.value.ver_type

    @property
    def authn_type(self) -> str:
        """
        Return authentication type identifier in public key specification.

        :return authentication type
        """

        return self.value.authn_type

    @property
    def specifier(self) -> str:
        """
        Return value specifier in public key specification.
        """

        return self.value.specifier

    def specification(self, value: str) -> str:
        """
        Return specifier and input value for use in public key specification.
        """

        return {self.value.specifier: value}


class PublicKey:
    """
    Public key specification to embed in DIDDoc.
    """

    ID_ROUTING = 'routing'

    def __init__(self, ident: str, pk_type: PublicKeyType, owner_did: str, value: str, is_authn: bool = False) -> None:
        """
        Retain key specification particulars. Raise BadIdentifier on bad input owner DID.

        :param ident: identifier for public key
        :param pk_type: public key type (enum)
        :param owner_did: owner DID, as a raw base58 (sovrin) value
        :param value: key content, encoded as key specification requires
        :param is_authn: mark key as having DID authentication privilege
        """

        if not ok_did(owner_did):
            raise BadIdentifier('Bad owner DID: {}'.format(owner_did))

        self._id = ident
        self._type = pk_type
        self._owner_did = owner_did
        self._value = value
        self._is_authn = is_authn

    @property
    def id(self) -> str:
        """
        Return public key identifier.

        :return: public key identifier
        """

        return self._id

    @property
    def type(self) -> str:
        """
        Return public key type.

        :return: public key type
        """

        return self._type

    @property
    def value(self) -> str:
        """
        Return public key value.

        :return: public key value
        """

        return self._value

    @property
    def owner(self) -> str:
        """
        Return owner DID.

        :return: owner DID
        """

        return self._owner_did

    @property
    def is_authn(self) -> str:
        """
        Return public key identifier.

        :return: whether public key is marked as having DID authentication privilege
        """

        return self._is_authn

    def to_dict(self):
        """
        Return dict representation of public key to embed in DID document.
        """

        return {
            'id': self._id,
            'type': str(self.type.ver_type),
            'owner': did2uri(self.owner),
            **self.type.specification(self.value)
        }


class DIDDoc:
    """
    DID document, grouping a DID with verification keys and endpoints.
    """

    CONTEXT = 'https://w3id.org/did/v1'

    def __init__(self, did: str = None) -> None:
        """
        Initializer. Retain DID ('id' in DIDDoc context); initialize verification keys and endpoints to empty lists.
        Raise BadIdentifier for bad input DID.

        :param did: DID for current DIDdoc
        """

        if did and not ok_did(did):
            raise BadIdentifier('Bad DID: {}'.format(did))

        self._did = did
        self._verkeys = []
        self._endpoints = []

    @property
    def did(self) -> str:
        """
        Accessor for DID.
        """

        return self._did

    @did.setter
    def did(self, value: str) -> None:
        """
        Set DID ('id' in DIDDoc context). Raise BadIdentifier for bad input DID.

        :param value: DID
        """

        if value and not ok_did(value):
            raise BadIdentifier('Bad DID: {}'.format(value))
        self._did = value

    @property
    def verkeys(self) -> str:
        """
        Accessor for verification keys.
        """

        return self._verkeys

    @verkeys.setter
    def verkeys(self, value: Union[Iterable, PublicKey] = None) -> None:
        """
        Set verication keys.

        :param value: verification key or keys (specify None to clear)
        """

        if value:
            self._verkeys = [value] if isinstance(value, PublicKey) else list(value)
        else:
            self._verkeys = []

    @property
    def endpoints(self) -> str:
        """
        Accessor for endpoints.
        """

        return self._endpoints

    @endpoints.setter
    def endpoints(self, value: Union[Iterable, str] = None) -> None:
        """
        Set endpoints.

        :param value: endpoint or endpoints (specify None to clear)
        """

        if value:
            self._endpoints = [value] if isinstance(value, str) else list(value)
        else:
            self._endpoints = []

    def to_json(self) -> str:
        """
        Dump current object as json (JSON-LD).

        :return: json representation of current DIDDoc
        """

        return json.dumps({
            '@context': DIDDoc.CONTEXT,
            'id': did2uri(self.did),
            'publicKey': [verkey.to_dict() for verkey in self.verkeys],
            'authentication': [{
                'type': verkey.type.authn_type,
                'publicKey': '{}#{}'.format(did2uri(self.did), verkey.id)
            } for verkey in self.verkeys if verkey.is_authn],
            'service': [{
                'type': 'Agency',
                'serviceEndpoint': did2uri(endpoint) if ok_did(endpoint) else endpoint
            } for endpoint in self.endpoints]
        })

    @staticmethod
    def from_json(did_doc_json: str) -> 'DIDDoc':
        """
        Construct DIDDoc object from json representation.

        :param did_doc_json: DIDDoc json reprentation.
        :return: DIDDoc from input json.
        """

        did_doc = json.loads(did_doc_json)
        rv = DIDDoc(uri2did(did_doc['id']))

        verkeys = []
        for pubkey in did_doc['publicKey']:
            pubkey_type = PublicKeyType.get(pubkey['type'])
            owner_did = uri2did(pubkey['owner'])
            value = pubkey[pubkey_type.specifier]
            is_authn = any(ak.get('publicKey', '').split('#')[-1] == pubkey['id'] for ak in did_doc['authentication'])
            verkeys.append(PublicKey(pubkey['id'], pubkey_type, owner_did, value, is_authn))
        rv.verkeys = verkeys

        endpoints = []
        for service in did_doc['service']:
            serviceEndpoint = service['serviceEndpoint']
            endpoints.append(uri2did(serviceEndpoint) if ok_did(serviceEndpoint) else serviceEndpoint)
        rv.endpoints = endpoints

        return rv

    def __str__(self) -> str:
        """
        Return string representation for abbreviated display.

        :return: string representation
        """

        return 'DIDDoc({})'.format(self.did)
