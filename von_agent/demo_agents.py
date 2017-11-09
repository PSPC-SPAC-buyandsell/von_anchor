"""
Copyright 2017 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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

from requests import post

from .agents import AgentRegistrar, Origin, Verifier, Issuer, HolderProver

import json
import logging


class TrustAnchorAgent(AgentRegistrar, Origin):
    """
    Trust anchor register agents and schemata & claim defs onto the distributed ledger
    """

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('TrustAnchorAgent.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = TrustAnchorAgent._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('TrustAnchorAgent.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        # token-type/proxy
        logger.debug('TrustAnchorAgent.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class SRIAgent(Verifier, Issuer, HolderProver):
    """
    SRI agent is:
        * a Verifier for:
            * Org Book proofs of BC Registrar
            * its own proofs of its own SRI registration claims
        * an Issuer and HolderProver of its own SRI registration claims
        * a Prover for its own SRI registration claims.
    """

    async def reset_wallet(self) -> int:
        """
        Method for SRIAgent to close and delete wallet, then create and open a new one. Delegates to
        HolderProver.reset_wallet() to create wallet and reset master secret, then resets claim_def for
        SRIAgent's Issuer nature.
        Useful for demo purpose so as not to have to shut down and restart the HolderProver from django.
        Precursor to revocation, and issuer/filter-specifiable claim deletion.

        :return: wallet num
        """

        logger = logging.getLogger(__name__)
        logger.debug('SRIAgent.reset_wallet: >>>')

        await HolderProver.reset_wallet(self)
        schema_json = await self._schema_info({})
        await self.send_claim_def(schema_json)  # allow for new claim creation

        rv = self.wallet.num
        logger.debug('SRIAgent.reset_wallet: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('SRIAgent.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = SRIAgent._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('SRIAgent.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        # token-type/proxy
        logger.debug('SRIAgent.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class BCRegistrarAgent(Issuer):
    """
    BC registrar agent is an Issuer of BC registrar claims
    """

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('BCRegistrarAgent.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = SRIAgent._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('BCRegistrarAgent.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        # token-type/proxy
        logger.debug('BCRegistrarAgent.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class OrgBookAgent(HolderProver):
    """
    The Org Book  agent is a HolderProver of BC registrar claims
    """

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('OrgBookAgent.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = OrgBookAgent._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('OrgBookAgent.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        # token-type/proxy
        logger.debug('OrgBookAgent.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))
