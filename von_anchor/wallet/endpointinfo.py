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
