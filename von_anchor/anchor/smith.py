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

from indy import ledger

from von_anchor.anchor.base import BaseAnchor
from von_anchor.error import BadIdentifier
from von_anchor.indytween import Role
from von_anchor.util import ok_did


LOGGER = logging.getLogger(__name__)


class AnchorSmith(BaseAnchor):
    """
    Mixin for (trustee) anchor to write anchors onto the distributed ledger.
    """

    @staticmethod
    def least_role() -> Role:
        """
        Return the TRUSTEE indy-sdk role for an anchor acting in an AnchorSmith capacity.

        :return: TRUSTEE role
        """

        LOGGER.debug('AnchorSmith.least_role >>>')

        rv = Role.TRUSTEE

        LOGGER.debug('AnchorSmith.least_role <<< %s', rv)
        return rv

    async def send_nym(self, did: str, verkey: str = None, alias: str = None, role: Role = None) -> None:
        """
        Send input anchor's cryptonym (including DID, verification key, plus optional alias and role)
        to the distributed ledger.

        Raise BadLedgerTxn on failure, BadIdentifier for bad DID, or BadRole for bad role.

        :param did: anchor DID to send to ledger
        :param verkey: optional anchor verification key
        :param alias: optional alias
        :param role: anchor role on the ledger (default value of USER)
        """

        LOGGER.debug(
            'AnchorSmith.send_nym >>> did: %s, verkey: %s, alias: %s, role: %s', did, verkey, alias, role)

        if not ok_did(did):
            LOGGER.debug('AnchorSmith.send_nym <!< Bad DID %s', did)
            raise BadIdentifier('Bad DID {}'.format(did))

        req_json = await ledger.build_nym_request(self.did, did, verkey, alias, (role or Role.USER).token())
        await self._sign_submit(req_json)

        LOGGER.debug('AnchorSmith.send_nym <<<')
