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


from von_anchor.a2a.docutil import canon_did, canon_ref


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
