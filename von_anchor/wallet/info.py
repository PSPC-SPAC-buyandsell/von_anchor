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


from von_anchor.canon import raw, canon_pairwise_tag
from von_anchor.error import BadRecord
from von_anchor.wallet.record import StorageRecord


class KeyInfo:
    """
    Bundle for verification key and metadata.
    """

    def __init__(self, verkey: str, metadata: dict = None) -> None:
        """
        Initialize verification key, metadata.

        :param verkey: verification key to store
        :param metadata: metadata associated with current DID
        """

        self._verkey = verkey
        self._metadata = metadata or {}  # store trivial metadata as empty (for iteration), return as None

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

        return self._metadata or None  # store trivial metadata as empty (for iteration), return as None

    @metadata.setter
    def metadata(self, value: dict) -> None:
        """
        Accessor for metadata

        :param value: metadata dict
        """

        self._metadata = value or {}  # store trivial metadata as empty (for iteration), return as None

    def __eq__(self, other: 'KeyInfo') -> bool:
        """
        Equivalence operator. Two KeyInfos are equivalent when their attributes are.

        :param other: KeyInfo to test for equivalence
        :return: whether KeyInfos are equivalent
        """

        return self.verkey == other.verkey and self.metadata == other.metadata

    def __repr__(self) -> str:
        """
        Return representation.

        :return: string representation evaluating to construction call
        """

        return 'KeyInfo({}, {})'.format(self.verkey, self.metadata)

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
        self._metadata = metadata or {}  # store trivial metadata as empty (for iteration), return as None

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

        return self._metadata or None  # store trivial metadata as empty (for iteration), return as None

    @metadata.setter
    def metadata(self, value: dict) -> None:
        """
        Accessor for metadata

        :param value: metadata dict
        """

        self._metadata = value or {}  # store trivial metadata as empty (for iteration), return as None

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


class EndpointInfo:
    """
    Bundle for endpoint and (transport) verification key.
    """

    def __init__(self, endpoint: str, verkey: str) -> None:
        """
        Initialize endpoint, verification key.

        :param endpoint: endpoint to store ('<ip-address>:<port>')
        :param verkey: verification key to store
        """

        self._endpoint = endpoint
        self._verkey = verkey

    @property
    def endpoint(self) -> str:
        """
        Accessor for endpoint

        :return: endpoint
        """

        return self._endpoint

    @property
    def ip_addr(self) -> str:
        """
        Accessor for endpoint IP address

        :return: endpoint IP address
        """

        return self._endpoint.split(':')[0]

    @property
    def port(self) -> int:
        """
        Accessor for endpoint port

        :return: endpoint port
        """

        return int(self._endpoint.split(':')[-1])

    @property
    def verkey(self) -> str:
        """
        Accessor for verification key

        :return: verification key
        """

        return self._verkey

    def __eq__(self, other: 'EndpointInfo') -> bool:
        """
        Equivalence operator. Two EndpointInfos are equivalent when their attributes are.

        :param other: EndpointInfo to test for equivalence
        :return: whether EndpointInfos are equivalent
        """

        return self.endpoint == other.endpoint and self.verkey == other.verkey

    def __repr__(self) -> str:
        """
        Return representation.

        :return: string representation evaluating to construction call
        """

        return 'EndpointInfo({}, {})'.format(self.endpoint, self.verkey)


class PairwiseInfo:
    """
    Bundle for pairwise DID relation: DIDs, verification keys, and metadata.
    """

    def __init__(self, their_did: str, their_verkey: str, my_did: str, my_verkey: str, metadata: dict = None) -> None:
        """
        Initialize DIDs, verification keys, metadata.

        :param their_did: remote DID to store
        :param their_verkey: remote verification key to store
        :param my_did: local DID to store
        :param my_verkey: local verification key to store
        :param metadata: metadata associated with pairwise DID relationship
        """

        self._their_did = their_did
        self._their_verkey = their_verkey
        self._my_did = my_did
        self._my_verkey = my_verkey
        self._metadata = metadata

    @property
    def their_did(self) -> str:
        """
        Accessor for remote DID

        :return: remote DID
        """

        return self._their_did

    @property
    def their_verkey(self) -> str:
        """
        Accessor for remote verification key

        :return: remote verification key
        """

        return self._their_verkey

    @property
    def my_did(self) -> str:
        """
        Accessor for local DID

        :return: local DID
        """

        return self._my_did

    @property
    def my_verkey(self) -> str:
        """
        Accessor for local verification key

        :return: local verification key
        """

        return self._my_verkey

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

    def __eq__(self, other: 'PairwiseInfo') -> bool:
        """
        Equivalence operator. Two PairwiseInfos are equivalent when their attributes are.

        :param other: PairwiseInfo to test for equivalence
        :return: whether PairwiseInfos are equivalent
        """

        return (
            self.their_did == other.their_did and
            self.their_verkey == other.their_verkey and
            self.my_did == other.my_did and
            self.my_verkey == other.my_verkey and
            self.metadata == other.metadata)

    def __repr__(self) -> str:
        """
        Return representation.

        :return: string representation evaluating to construction call
        """

        return 'PairwiseInfo({}, {}, {}, {}, {})'.format(
            self.their_did,
            self.their_verkey,
            self.my_did,
            self.my_verkey,
            self.metadata)


def pairwise_info2tags(pairwise: PairwiseInfo) -> dict:
    """
    Given pairwise info with metadata mapping tags to values, return corresponding
    indy-sdk non_secrets record tags dict to store same in wallet (via non_secrets)
    unencrypted (for WQL search options).  Canonicalize metadata values to strings via
    raw() for WQL fitness.

    Raise BadRecord if metadata does not coerce into non_secrets API tags spec of {str:str}.

    :param pairwise: pairwise info with metadata dict mapping tags to values
    :return: corresponding non_secrets tags dict marked for unencrypted storage
    """

    rv = {
        canon_pairwise_tag(tag): raw(pairwise.metadata[tag]) for tag in pairwise.metadata or {}
    }
    rv['~their_did'] = pairwise.their_did
    rv['~their_verkey'] = pairwise.their_verkey
    rv['~my_did'] = pairwise.my_did
    rv['~my_verkey'] = pairwise.my_verkey

    if not StorageRecord.ok_tags(rv):
        raise BadRecord('Pairwise metadata {} must map strings to strings'.format(rv))

    return rv


def storage_record2pairwise_info(storec: StorageRecord) -> PairwiseInfo:
    """
    Given indy-sdk non_secrets implementation of pairwise storage record dict, return corresponding PairwiseInfo.

    :param storec: (non-secret) storage record to convert to PairwiseInfo
    :return: PairwiseInfo on record DIDs, verkeys, metadata
    """

    return PairwiseInfo(
        storec.id,  # = their did
        storec.value,  # = their verkey
        storec.tags['~my_did'],
        storec.tags['~my_verkey'],
        {
            tag[tag.startswith('~'):]: storec.tags[tag] for tag in (storec.tags or {})  # strip any leading '~'
        })
