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


import logging

from uuid import uuid4

from von_anchor.error import BadRecord


TYPE_LINK_SECRET_LABEL = 'link_secret_label'
TYPE_PAIRWISE = 'pairwise'

LOGGER = logging.getLogger(__name__)


class StorageRecord:
    """
    Non-secret wallet record.
    """

    def __init__(self, typ: str, value: str, tags: dict = None, ident: str = None) -> None:
        """
        Initialize non-secret record. Raise BadRecord if input tags are not legitimate indy non-secret record tags.

        :param typ: record type - (typ, ident) identifies a non-secret record in the wallet
        :param value: record value
        :param tags: record tags (metadata) dict
        :param ident: record identifier - (typ, ident) identifies a non-secret record in the wallet
        """

        self._type = typ
        self._id = ident or uuid4().hex
        self._value = value

        if not StorageRecord.ok_tags(tags):
            LOGGER.debug('StorageRecord.__init__ <!< Tags %s must map strings to strings', tags)
            raise BadRecord('Tags {} must map strings to strings'.format(tags))

        self._tags = tags or {}  # store trivial tags as empty (for iteration), return as None

    @staticmethod
    def ok_tags(tags: dict) -> bool:
        """
        Whether input tags dict is OK as an indy-sdk tags structure (depth=1, string values).
        """

        if not tags:
            return True
        depth = 0
        queue = [(i, depth+1) for i in tags.values() if isinstance(i, dict)]
        max_depth = 0
        while queue and max_depth < 2:
            sub, depth = queue.pop()
            max_depth = max(max_depth, depth)
            queue = queue + [(i, depth+1) for i in sub.values() if isinstance(i, dict)]

        return max_depth < 2 and all(isinstance(k, str) and isinstance(tags[k], str) for k in tags)

    @property
    def type(self) -> str:
        """
        Accessor for record type.

        :return: type
        """

        return self._type

    @property
    def id(self) -> str:
        """
        Accessor for record identifier.

        :return: record identifier
        """

        return self._id

    @id.setter
    def id(self, val: str) -> None:
        """
        Accessor for record identifier.

        :param val: identifier value
        """

        self._id = val

    @property
    def value(self) -> str:
        """
        Accessor for record value.

        :return: record value
        """

        return self._value

    @value.setter
    def value(self, val: str) -> None:
        """
        Accessor for record value.

        :param val: record value
        """

        self._value = val

    @property
    def tags(self) -> dict:
        """
        Accessor for record tags (metadata).

        :return: record tags
        """

        return self._tags or None  # store trivial tags as empty (for iteration), return as None

    @tags.setter
    def tags(self, val: str) -> None:
        """
        Accessor for record tags (metadata).

        :param val: record tags
        """

        if not StorageRecord.ok_tags(val):
            LOGGER.debug('StorageRecord.__init__ <!< Tags %s must map strings to strings', val)
            raise BadRecord('Tags {} must map strings to strings'.format(val))

        self._tags = val or {}

    @property
    def clear_tags(self) -> dict:
        """
        Accessor for record tags (metadata) stored in the clear.

        :return: record tags stored in the clear
        """

        return {t: self.tags[t] for t in (self.tags or {}) if t.startswith('~')} or None

    @property
    def encr_tags(self) -> dict:
        """
        Accessor for record tags (metadata) stored encrypted.

        :return: record tags stored encrypted
        """

        return {t: self._tags[t] for t in self.tags or {} if not t.startswith('~')} or None

    def __eq__(self, other: 'DIDInfo') -> bool:
        """
        Equivalence operator. Two instances are equivalent when their attributes are.

        :param other: instance to test for equivalence
        :return: whether instances are equivalent
        """

        return self.type == other.type and self.id == other.id and self.value == other.value and self.tags == other.tags

    def __repr__(self) -> str:
        """
        Return representation.

        :return: string representation evaluating to construction call
        """

        return 'StorageRecord({}, {}, {}, {})'.format(self.type, self.id, self.value, self.tags)
