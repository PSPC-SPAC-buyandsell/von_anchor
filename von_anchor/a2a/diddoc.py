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

from typing import Iterable, List, Union

from von_anchor.a2a.docutil import canon_did, canon_ref
from von_anchor.a2a.publickey import PublicKey, PublicKeyType
from von_anchor.a2a.service import Service


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

    def serialize(self) -> str:
        """
        Dump current object to a JSON-compatible dictionary.

        :return: dict representation of current DIDDoc
        """

        return {
            '@context': DIDDoc.CONTEXT,
            'id': canon_ref(self.did, self.did),
            'publicKey': [verkey.to_dict() for verkey in self.verkeys],
            'authentication': [{
                'type': verkey.type.authn_type,
                'publicKey': canon_ref(self.did, verkey.id)
            } for verkey in self.verkeys if verkey.authn],
            'service': [service.to_dict() for service in self.services]
        }

    def to_json(self) -> str:
        """
        Dump current object as json (JSON-LD).

        :return json representation of current DIDDoc
        """

        return json.dumps(self.serialize())

    @classmethod
    def deserialize(cls, did_doc: dict) -> 'DIDDoc':
        """
        Construct DIDDoc object from dict representation.

        :param did_doc: DIDDoc dict reprentation.
        :return: DIDDoc from input json.
        """

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

    @classmethod
    def from_json(cls, did_doc_json: str) -> 'DIDDoc':
        """
        Construct DIDDoc object from json representation.

        :param did_doc_json: DIDDoc json reprentation.
        :return: DIDDoc from input json.
        """

        return cls.deserialize(json.loads(did_doc_json))

    def __str__(self) -> str:
        """
        Return string representation for abbreviated display.

        :return: string representation
        """

        return 'DIDDoc({})'.format(self.did)
