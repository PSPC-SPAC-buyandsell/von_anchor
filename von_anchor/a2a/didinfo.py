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


class DIDInfo:
    """
    Bundle for DID, verification key, and metadata.
    """

    def __init__(self, did: str, verkey: str, metadata: dict = None) -> None:
        """
        Initialize DID, verification key, metadata.

        :param did: DID to store
        :param verkey: verification key to store
        :param metadata: metadata associated with current DID
        """

        self._did = did
        self._verkey = verkey
        self._metadata = metadata

    @property
    def did(self) -> str:
        """
        Accessor for DID

        :return: DID
        """

        return self._did

    @property
    def verkey(self) -> str:
        """
        Accessor for verification key

        :return: verification key
        """

        return self._verkey

    @property
    def metadata(self) -> dict:
        """
        Accessor for metadata

        :return: metadata
        """

        return self._metadata

    @metadata.setter
    def metadata(self, value: dict) -> None:
        """
        Accessor for metadata

        :param value: metadata dict
        """

        self._metadata = value

    def __eq__(self, other: 'DIDInfo') -> bool:
        """
        Equivalence operator. Two DIDInfos are equivalent when their attributes are.

        :param other: DIDInfo to test for equivalence
        :return: whether DIDInfos are equivalent
        """

        return self.did == other.did and self.verkey == other.verkey and self.metadata == other.metadata

    def __repr__(self) -> str:
        """
        Return representation.

        :return: string representation evaluating to construction call
        """

        return 'DIDInfo({}, {}, {})'.format(self.did, self.verkey, self.metadata)
