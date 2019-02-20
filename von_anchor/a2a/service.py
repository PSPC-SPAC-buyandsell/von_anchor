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


from typing import List, Sequence, Union

from von_anchor.a2a.docutil import canon_did, canon_ref


class Service:
    """
    Service specification to embed in DID document. Retains DIDs as raw values
    (orientated toward indy-facing operations), everything else as URIs
    (oriented toward W3C-facing operations).
    """

    def __init__(
            self, did: str,
            ident: str,
            typ: str,
            recip_keys: Union[Sequence, str],
            rtg_keys: Union[Sequence, str],
            endpoint: str):
        """
        Retain service specification particulars. Raise BadIdentifier on bad input controller DID.

        :param did: DID of DID document embedding public key, specified raw (operation converts to URI)
        :param ident: identifier for public key
        :param typ: service type
        :param recip_keys: recipient key or keys
        :param rtg_keys: routing key or keys
        :param endpoint: service endpoint
        """

        self._did = canon_did(did)
        self._id = canon_ref(self._did, ident, ';')
        self._type = typ
        self._recip_keys = [recip_keys] if isinstance(recip_keys, str) else list(recip_keys) if recip_keys else None
        self._routing_keys = [rtg_keys] if isinstance(rtg_keys, str) else list(rtg_keys) if rtg_keys else None
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
    def recip_keys(self) -> List[str]:
        """
        Return recipient keys.

        :return: recip keys
        """

        return self._recip_keys

    @property
    def routing_keys(self) -> List[str]:
        """
        Return routing keys.

        :return: routing keys
        """

        return self._routing_keys

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

        rv = {
            'id': self.id,
            'type': self.type,
        }
        if self.recip_keys:
            rv['recipientKeys'] = self.recip_keys
        if self.routing_keys:
            rv['routingKeys'] = self.routing_keys
        rv['serviceEndpoint'] = self.endpoint

        return rv
