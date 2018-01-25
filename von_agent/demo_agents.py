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

        # Try dispatching to each ancestor from BaseListeningAgent first
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


class SRIAgent(Verifier, Issuer):
    """
    SRI agent is:
        * a Verifier for:
            * BC Org Book proofs of BC Registrar
            * PSPC Org Book proofs of its own SRI registration claims
        * an Issuer of its own SRI registration claims
    """

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('SRIAgent.process_post: >>> form: {}'.format(form))

        # Try dispatching to each ancestor from BaseListeningAgent first
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

        # Try dispatching to each ancestor from BaseListeningAgent first
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
    The BC Org Book agent is a HolderProver of BC registrar claims.
    The PSPC Org Book agent is a HolderProver of SRI agent claims.
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

        # Try dispatching to each ancestor from BaseListeningAgent first
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
