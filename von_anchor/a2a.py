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
from typing import Iterable, List, Union
from urllib.parse import urlparse

from von_anchor.error import BadIdentifier
from von_anchor.util import ok_did


DIDPair = namedtuple('DIDPair', 'did verkey')
LinkedDataKeySpec = namedtuple('LinkedDataKeySpec', 'ver_type authn_type specifier')


def resource(ref: str, delimiter: str = None) -> str:
    """
    Given a (URI) reference, return up to its delimiter (exclusively), or all of it if there is none.

    :param ref: reference
    :param delimiter: delimiter character (default None maps to '#', or ';' introduces identifiers)
    """

    return ref.split(delimiter if delimiter else '#')[0]


def canon_did(uri: str) -> str:
    """
    Convert a URI into a DID if need be, left-stripping 'did:sov:' if present.
    Return input if already a DID. Raise BadIdentifier for invalid input.

    :param uri: input URI or DID
    :return: corresponding DID
    """

    if ok_did(uri):
        return uri

    if uri.startswith('did:sov:'):
        rv = uri[8:]
        if ok_did(rv):
            return rv
    raise BadIdentifier('Bad specification {} does not correspond to a sovrin DID'.format(uri))


def canon_ref(did: str, ref: str, delimiter: str = None):
    """
    Given a reference in a DID document, return it in its canonical form of a URI.

    :param did: DID acting as the identifier of the DID document
    :param ref: reference to canonicalize, either a DID or a fragment pointing to a location in the DID doc
    :param delimiter: delimiter character marking fragment ('#', to which default None maps) or
        introducing identifier (';') against DID resource
    """

    if not ok_did(did):
        raise BadIdentifier('Bad DID {} cannot act as DID document identifier'.format(did))

    if ok_did(ref):  # e.g., LjgpST2rjsoxYegQDRm7EL
        return 'did:sov:{}'.format(did)

    if ref.startswith('did:sov:'):  # e.g., did:sov:LjgpST2rjsoxYegQDRm7EL, did:sov:LjgpST2rjsoxYegQDRm7EL#3
        rv = ref[8:]
        if ok_did(resource(rv, delimiter)):
            return ref
        raise BadIdentifier('Bad URI {} does not correspond to a sovrin DID'.format(ref))

    if urlparse(ref).scheme:  # e.g., https://example.com/messages/8377464
        return ref

    if ref == PublicKey.ID_ROUTING:  # e.g., routing
        return ref

    return 'did:sov:{}{}{}'.format(did, delimiter if delimiter else '#', ref)  # e.g., 3


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
    Public key specification to embed in DID document. Retains DIDs as raw values
    (orientated toward indy-facing operations), everything else as URIs
    (oriented toward W3C-facing operations).
    """

    ID_ROUTING = 'routing'

    def __init__(
            self,
            did: str,
            ident: str,
            pk_type: PublicKeyType,
            controller: str,
            value: str,
            authn: bool = False) -> None:
        """
        Retain key specification particulars. Raise BadIdentifier on any bad input DID.

        :param did: DID of DID document embedding public key
        :param ident: identifier for public key
        :param pk_type: public key type (enum)
        :param controller: controller DID
        :param value: key content, encoded as key specification requires
        :param authn: whether key as has DID authentication privilege
        """

        self._did = canon_did(did)
        self._id = canon_ref(self._did, ident)
        self._type = pk_type
        self._controller = canon_did(controller)
        self._value = value
        self._authn = authn

    @property
    def did(self) -> str:
        """
        Return DID.

        :return: DID
        """

        return self._did

    @property
    def id(self) -> str:
        """
        Return public key identifier.

        :return: public key identifier
        """

        return self._id

    @property
    def type(self) -> PublicKeyType:
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
    def controller(self) -> str:
        """
        Return controller DID.

        :return: controller DID
        """

        return self._controller

    @property
    def authn(self) -> bool:
        """
        Return whether public key is marked as having DID authentication privilege.

        :return: whether public key is marked as having DID authentication privilege
        """

        return self._authn

    @authn.setter
    def authn(self, value: bool) -> None:
        """
        Set or clear authentication marker.

        :param value: authentication marker
        """

        self._authn = value


    def to_dict(self):
        """
        Return dict representation of public key to embed in DID document.
        """

        return {
            'id': self.id,
            'type': str(self.type.ver_type),
            'controller': canon_ref(self.did, self.controller),
            **self.type.specification(self.value)
        }


class Service:
    """
    Service specification to embed in DID document. Retains DIDs as raw values
    (orientated toward indy-facing operations), everything else as URIs
    (oriented toward W3C-facing operations).
    """

    def __init__(self, did: str, ident: str, s_type: str, endpoint: str):
        """
        Retain service specification particulars. Raise BadIdentifier on bad input controller DID.

        :param did: DID of DID document embedding public key, specified raw (operation converts to URI)
        :param ident: identifier for public key
        :param s_type: service type
        :param endpoint: service endpoint
        """

        self._did = canon_did(did)
        self._id = canon_ref(self._did, ident, ';')
        self._type = s_type
        self._endpoint = canon_ref(self._did, endpoint)

    @property
    def did(self) -> str:
        """
        Return DID.

        :return: DID
        """

        return self._did

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
        Return service type.

        :return: service type
        """

        return self._type

    @property
    def endpoint(self) -> str:
        """
        Return endpoint value.

        :return: endpoint value
        """

        return self._endpoint

    def to_dict(self):
        """
        Return dict representation of service to embed in DID document.
        """

        return {
            'id': self.id,
            'type': self.type,
            'serviceEndpoint': self.endpoint
        }


class DIDDoc:
    """
    DID document, grouping a DID with verification keys and services.
    Retains DIDs as raw values (orientated toward indy-facing operations),
    everything else as URIs (oriented toward W3C-facing operations).
    """

    CONTEXT = 'https://w3id.org/did/v1'

    def __init__(self, did: str = None) -> None:
        """
        Initializer. Retain DID ('id' in DIDDoc context); initialize verification keys and services to empty lists.
        Raise BadIdentifier for bad input DID.

        :param did: DID for current DIDdoc
        """

        self._did = canon_did(did) if did else None  # allow specification post-hoc
        self._verkeys = []
        self._services = []

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

        self._did = canon_did(value) if value else None

    @property
    def verkeys(self) -> List:
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
    def authnkeys(self) -> List:
        """
        Accessor for verification keys marked as authentication keys.
        """

        return [k for k in self._verkeys if k.authn]

    @property
    def services(self) -> List:
        """
        Accessor for services.
        """

        return self._services

    @services.setter
    def services(self, value: Union[Iterable, Service] = None) -> None:
        """
        Set services.

        :param value: service or services (specify None to clear)
        """

        if value:
            self._services = [value] if isinstance(value, Service) else list(value)
        else:
            self._services = []

    def to_json(self) -> str:
        """
        Dump current object as json (JSON-LD).

        :return: json representation of current DIDDoc
        """

        return json.dumps({
            '@context': DIDDoc.CONTEXT,
            'id': canon_ref(self.did, self.did),
            'publicKey': [verkey.to_dict() for verkey in self.verkeys],
            'authentication': [{
                'type': verkey.type.authn_type,
                'publicKey': canon_ref(self.did, verkey.id)
            } for verkey in self.verkeys if verkey.authn],
            'service': [service.to_dict() for service in self.services]
        })

    @staticmethod
    def from_json(did_doc_json: str) -> 'DIDDoc':
        """
        Construct DIDDoc object from json representation.

        :param did_doc_json: DIDDoc json reprentation.
        :return: DIDDoc from input json.
        """

        did_doc = json.loads(did_doc_json)
        rv = DIDDoc(did_doc['id'])

        verkeys = []
        for pubkey in did_doc['publicKey']:  # include public keys and authentication keys by reference
            pubkey_type = PublicKeyType.get(pubkey['type'])
            controller = canon_did(pubkey['controller'])
            value = pubkey[pubkey_type.specifier]
            authn = any(
                canon_ref(rv.did, ak.get('publicKey', '')) == canon_ref(rv.did, pubkey['id'])
                for ak in did_doc['authentication'] if isinstance(ak.get('publicKey', None), str))
            verkeys.append(PublicKey(rv.did, pubkey['id'], pubkey_type, controller, value, authn))

        for akey in did_doc['authentication']:  # include embedded authentication keys
            pk_ref = akey.get('publicKey', None)
            if pk_ref:
                pass  # got it already with public keys
            else:
                pubkey_type = PublicKeyType.get(akey['type'])
                controller = canon_did(akey['controller'])
                value = akey[pubkey_type.specifier]
                verkeys.append(PublicKey(rv.did, akey['id'], pubkey_type, controller, value, True))
        rv.verkeys = verkeys

        rv.services = [Service(
            rv.did,
            service['id'],
            service['type'],
            service['serviceEndpoint']) for service in did_doc['service']]

        return rv

    def __str__(self) -> str:
        """
        Return string representation for abbreviated display.

        :return: string representation
        """

        return 'DIDDoc({})'.format(self.did)
