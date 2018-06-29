"""
Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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
from von_agent.agent.base import _BaseAgent


LOGGER = logging.getLogger(__name__)


class AgentRegistrar(_BaseAgent):
    """
    Mixin for (trust anchor) agent to register agents onto the distributed ledger
    """

    @staticmethod
    def role() -> str:
        """
        Return the indy-sdk role for an agent in building its nym for the trust anchor to send to the ledger.

        :param agent: agent instance
        :return: role string
        """

        LOGGER.debug('AgentRegistrar.role >>>')

        rv = 'TRUSTEE'
        LOGGER.debug('AgentRegistrar.role <<< %s', rv)
        return rv

    async def send_nym(self, did: str, verkey: str, alias: str = None, role: str = None) -> None:
        """
        Send input agent's cryptonym (including DID, verification key, plus optional alias and role)
        to the distributed ledger.

        Raise BadLedgerTxn on failure.

        :param did: agent DID to send to ledger
        :param verkey: agent verification key
        :param alias: optional alias
        :param role: agent role on the ledger; specify one of 'TRUSTEE', 'STEWARD', 'TRUST_ANCHOR',
            or else '' to reset role
        """

        LOGGER.debug(
            'AgentRegistrar.send_nym >>> did: %s, verkey: %s, alias: %s, role: %s', did, verkey, alias, role or '')

        req_json = await ledger.build_nym_request(self.did, did, verkey, alias, role or '')
        await self._sign_submit(req_json)

        LOGGER.debug('AgentRegistrar.send_nym <<<')
