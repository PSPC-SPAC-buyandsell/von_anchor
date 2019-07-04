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

from von_anchor.indytween import SchemaKey


ProtocolMap = namedtuple('ProtocolMap', 'name indy')


class Protocol(Enum):
    """
    Class encapsulating indy-node transaction particulars by protocol version.
    """

    V1_3 = ProtocolMap('1.3', 1)
    V1_4 = ProtocolMap('1.4', 2)
    V1_5 = ProtocolMap('1.5', 2)
    V1_6 = ProtocolMap('1.6', 2)
    V1_7 = ProtocolMap('1.7', 2)
    V1_8 = ProtocolMap('1.8', 2)
    V1_9 = ProtocolMap('1.9', 2)
    V1_10 = ProtocolMap('1.10', 2)
    DEFAULT = ProtocolMap('1.10', 2)

    @staticmethod
    def get(version: str) -> 'Protocol':
        """
        Return enum instance corresponding to input version value ('1.6' etc.)
        """

        return Protocol.V1_3 if version == Protocol.V1_3.value.name else Protocol.DEFAULT

    def __str__(self) -> str:
        return self.name

    def indy(self) -> int:
        """
        Return indy integer mapping for protocol.

        :return: indy integer mapping for protocol
        """

        return self.value.indy

    def cd_id_tag(self, for_box_id: bool = False) -> str:
        """
        Return (place-holder) credential definition identifier tag for current version of node protocol.
        At present, von_anchor always uses the tag of 'tag' if the protocol calls for one.

        :param for_box_id: whether to prefix a colon, if current protocol uses one, in constructing
            a cred def id or rev reg id.
        :return: cred def id tag
        """

        if for_box_id:
            return '' if self == Protocol.V1_3 else ':tag'
        return 'tag'

    def cred_def_id(self, issuer_did: str, schema_seq_no: int) -> str:
        """
        Return credential definition identifier for input issuer DID and schema sequence number.

        :param issuer_did: DID of credential definition issuer
        :param schema_seq_no: schema sequence number
        :return: credential definition identifier
        """

        return '{}:3:CL:{}{}'.format(  # 3 marks indy cred def id, CL is sig type
            issuer_did,
            schema_seq_no,
            self.cd_id_tag(True))

    def txn_data2schema_key(self, txn: dict) -> SchemaKey:
        """
        Return schema key from ledger transaction data.

        :param txn: get-schema transaction (by sequence number)
        :return: schema key identified
        """

        rv = None
        if self == Protocol.V1_3:
            rv = SchemaKey(txn['identifier'], txn['data']['name'], txn['data']['version'])
        else:
            txn_txn = txn.get('txn', None) or txn  # may have already run this txn through txn2data() below
            rv = SchemaKey(
                txn_txn['metadata']['from'],
                txn_txn['data']['data']['name'],
                txn_txn['data']['data']['version'])

        return rv

    def txn2data(self, txn: dict) -> str:
        """
        Given ledger transaction, return its data json.

        :param txn: transaction as dict
        :return: transaction data json
        """

        rv_json = json.dumps({})
        if self == Protocol.V1_3:
            rv_json = json.dumps(txn['result'].get('data', {}))
        else:
            rv_json = json.dumps((txn['result'].get('data', {}) or {}).get('txn', {}))  # "data": null for no such txn

        return rv_json

    def txn2epoch(self, txn: dict) -> int:
        """
        Given ledger transaction, return its epoch time.

        :param txn: transaction as dict
        :return: transaction time
        """

        rv = None
        if self == Protocol.V1_3:
            rv = txn['result']['txnTime']
        else:
            rv = txn['result']['txnMetadata']['txnTime']

        return rv
