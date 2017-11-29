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

from indy import anoncreds, ledger
from re import match
from requests import post
from time import time
from typing import Set

from .wallet import Wallet
from .nodepool import NodePool
from .util import encode, decode, prune_claims_json, ppjson

import json
import logging


class BaseAgent:
    """
    Base class for agent
    """

    def __init__(self, pool: NodePool, seed: str, wallet_base_name: str, wallet_cfg_json: str) -> None:
        """
        Initializer for agent. Does not open its wallet, only retains input parameters.

        :param pool: node pool on which agent operates
        :param seed: seed to bootstrap agent
        :param wallet_base_name: (base) name of wallet that agent uses
        :param wallet_cfg_json: wallet configuration json, None for default
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.__init__: >>> pool {}, seed [SEED], wallet_base_name {}, wallet_cfg_json {}'.format(
            pool,
            wallet_base_name,
            wallet_cfg_json))

        self._pool = pool

        self._wallet = Wallet(pool.name, seed, wallet_base_name, 0, wallet_cfg_json)

        logger.debug('BaseAgent.__init__: <<<')

    @property
    def pool(self) -> NodePool:
        """
        Accessor for node pool

        :return: node pool
        """

        return self._pool

    @property
    def wallet(self) -> 'Wallet':
        """
        Accessor for wallet

        :return: wallet
        """

        return self._wallet

    @property
    def did(self) -> str:
        """
        Accessor for agent DID

        :return: agent DID
        """

        return self.wallet.did

    @property
    def verkey(self) -> str:
        """
        Accessor for agent verification key

        :return: agent verification key
        """

        return self.wallet.verkey

    async def __aenter__(self) -> 'BaseAgent':
        """
        Context manager entry. Opens wallet and stores agent DID in it.
        For use in monolithic call opening, using, and closing the agent.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.__aenter__: >>>')

        rv = await self.open()

        logger.debug('BaseAgent.__aenter__: <<<')
        return rv

    async def open(self) -> 'BaseAgent':
        """
        Explicit entry. Opens wallet and stores agent DID in it.
        For use when keeping agent open across multiple calls.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.open: >>>')

        await self.wallet.open()

        logger.debug('BaseAgent.open: <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Closes and deletes wallet.
        For use in monolithic call opening, using, and closing the agent.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.__aexit__: >>> exc_type: {}, exc: {}, traceback: {}'.format(exc_type, exc, traceback))

        await self.close()
        logger.debug('BaseAgent.__exit__: <<<')

    async def close(self) -> None:
        """
        Explicit exit. Closes and deletes wallet.
        For use when keeping agent open across multiple calls.
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.close: >>>')

        await self.wallet.close()

        logger.debug('BaseAgent.close: <<<')

    async def get_nym(self, did: str) -> str:
        """
        Get cryptonym (including current verification key) for input (agent) DID from ledger.

        :param did: DID of cryptonym to fetch
        :return: cryptonym json
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.get_nym: >>> did: {}'.format(did))

        get_nym_req = await ledger.build_get_nym_request(
            self.did,
            did)
        resp_json = await ledger.submit_request(self.pool.handle, get_nym_req)
        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json is None:
            return json.dumps({})

        rv = data_json
        logger.debug('BaseAgent.get_nym: <<< {}'.format(rv))
        return rv

    async def get_schema(self, issuer_did: str, name: str, version: str) -> str:
        """
        Method for Issuer/Verifier/HolderProver to get schema from ledger by issuer, name, and version;
        empty production {} for none, IndyError with error_code = ErrorCode.LedgerInvalidTransaction
        for bad request.

        :param issuer_did: DID of schema issuer
        :param name: schema name
        :param version: schema version string

        :return: schema json as retrieved from ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.get_schema: >>> issuer_did: {}, name: {}, version: {}'.format(
            issuer_did,
            name,
            version))

        req_json = await ledger.build_get_schema_request(
            self.did,
            issuer_did,
            json.dumps({'name': name, 'version': version}))
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        resp = json.loads(resp_json)

        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if (not data_json) or ('attr_names' not in data_json):
            return json.dumps({})  # not present, give back an empty production

        rv = json.dumps(resp['result'])
        logger.debug('BaseAgent.get_schema: <<< {}'.format(rv))
        return rv

    async def get_endpoint(self, did: str) -> str:
        """
        Get endpoint for agent having input DID

        :param did: DID for agent whose endpoint to find
        :return: json endpoint data for agent having input DID
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseAgent.get_endpoint: >>> did: {}'.format(did))

        req_json = await ledger.build_get_attrib_request(
            self.did,
            did,
            'endpoint')
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json is None:
            return json.dumps({})
        endpoint = json.loads(data_json)['endpoint']

        rv = json.dumps(endpoint)
        logger.debug('BaseAgent.get_endpoint: <<< {}'.format(rv))
        return rv

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}({}, [SEED], {}, {})'.format(
            self.__class__.__name__,
            repr(self.pool),
            self.wallet.base_name,
            self.wallet.cfg_json)

    def __str__(self) -> str:
        """
        Return informal string identifying current object.

        :return: string identifying current object
        """

        return '{}({})'.format(self.__class__.__name__, self.wallet.base_name)


class BaseListeningAgent(BaseAgent):
    """
    Class for agent that listens and responds to other agents. Note that a service wrapper will
    listen for requests, parse requests, dispatch to agents, and return content to callers;
    the current design calls not to use indy-sdk for direct agent-to-agent communication.

    The BaseListeningAgent differs from the BaseAgent in that it stores endpoint information
    to put on the ledger, and it receives and responds to requests from the (django application)
    service wrapper API.
    """

    def __init__(self,
            pool: NodePool,
            seed: str,
            wallet_base_name: str,
            wallet_cfg_json: str,
            host: str,
            port: int,
            agent_api_path: str = '') -> None:
        """
        Initializer for agent. Does not open its wallet, only retains input parameters.

        :pool: node pool on which agent operates
        :seed: seed to bootstrap agent
        :wallet_base_name: (base) name of wallet that agent uses
        :wallet_cfg_json: wallet configuration json, None for default
        :host: agent IP address
        :port: agent port
        :agent_api_path: URL path to agent API, for use in proxying to further agents
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent.__init__: >>> ' +
            'pool: {}, ' +
            'seed: [SEED], ' +
            'wallet_base_name: {}, ' +
            'wallet_cfg_json: {}, ' +
            'host: {}, ' +
            'port: {}, ' +
            'agent_api_path: {}'.format(pool, wallet_base_name, wallet_cfg_json, host, port, agent_api_path))

        super().__init__(pool, seed, wallet_base_name, wallet_cfg_json)
        self._host = host
        self._port = port
        self._agent_api_path = agent_api_path
        self._schema_cache = None

        logger.debug('BaseListeningAgent.__init__: <<<')

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def agent_api_path(self):
        return self._agent_api_path

    @property
    def schema_cache(self):
        return self._schema_cache

    def _vet_keys(must: Set[str], have: Set[str], hint: str = '') -> None:
        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent._vet_keys: >>> must: {}, have: {}, hint: {}'.format(must, have, hint))

        if not must.issubset(have):
            x = ValueError('Bad token:{} missing keys {}'.format(' ' + hint, must - have))
            logger.error(x)
            raise x

        logger.debug('BaseListeningAgent._vet_keys: <<<')

    async def send_endpoint(self) -> str:
        """
        Sends agent endpoint attribute to ledger. Returns endpoint json as written
        (the process of writing the attribute to the ledger does not add any additional content).

        :return: endpoint attibute entry json with host and port
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent.send_endpoint: >>>')

        raw_json = json.dumps({
            'endpoint': {
                'host': str(self.host),
                'port': self.port
            }
        })
        req_json = await ledger.build_attrib_request(self.did, self.did, None, raw_json, None)

        rv = await ledger.sign_and_submit_request(self.pool.handle, self.wallet.handle, self.did, req_json)
        logger.debug('BaseListeningAgent.send_endpoint: <<< {}'.format(rv))
        return rv

    async def get_claim_def(self, schema_seq_no: int, issuer_did: str) -> str:
        """
        Method to get claim definition from ledger by its parent schema and issuer DID;
        empty production {} for none, IndyError with error_code = ErrorCode.LedgerInvalidTransaction
        for bad request.

        :param schema_seq_no: schema sequence number on the ledger
        :param issuer_did: (claim def) issuer DID
        :return: claim definition json as retrieved from ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent.get_claim_def: >>> schema_seq_no: {}, issuer_did: {}'.format(
            schema_seq_no,
            issuer_did))

        req_json = await ledger.build_get_claim_def_txn(
            self.did,
            schema_seq_no,
            'CL',
            issuer_did)

        resp_json = await ledger.submit_request(self.pool.handle, req_json)

        resp = json.loads(resp_json)
        data_json = (json.loads(resp_json))['result']['data']
        if data_json is None:
            return json.dumps({})  # not present, give back an empty production

        if resp['result']['data']['revocation'] is not None:
            resp['result']['data']['revocation'] = None  #TODO: support revocation

        rv = json.dumps(resp['result'])
        logger.debug('BaseListeningAgent.get_claim_def: <<< {}'.format(rv))
        return rv

    async def get_schema(self, issuer_did: str, name: str, version: str) -> str:
        """
        Method to get schema from ledger by issuer, name, and version; empty production {} for none,
        IndyError with error_code = ErrorCode.LedgerInvalidTransaction
        for bad request.

        BaseListenerAgent.get_schema() caches schema for future calls before returning.

        :param issuer_did: DID of schema issuer
        :param name: schema name
        :param version: schema version string
        :return: schema json as retrieved from ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent.get_schema: >>> issuer_did: {}, name: {}, version: {}'.format(
            issuer_did,
            name,
            version))

        schema_json = await super().get_schema(issuer_did, name, version)
        schema = json.loads(schema_json)

        if schema:
            self._schema_cache = {
                'issuer-did': issuer_did,
                'name': name,
                'version': version,
                'seq_no': schema['seqNo'],
                'json': schema_json
            }

        rv = schema_json
        logger.debug('BaseListeningAgent.get_schema: <<< {}'.format(rv))
        return rv

    async def _schema_info(self, form_data: dict) -> str:
        """
        Gets schema json for use in indy-sdk structures, reading it from cached property
        or from the ledger if specified in form data.

        :param form_data: form['data'] of request form
        :return: schema json as it appears on the ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent._schema_info: >>> form_data: {}'.format(form_data))

        if 'schema' in form_data:
            self.__class__._vet_keys(
                {'issuer-did', 'name', 'version'},
                set(form_data['schema'].keys()),
                hint='schema')
            schema_json = await self.get_schema(
                form_data['schema']['issuer-did'], 
                form_data['schema']['name'],
                form_data['schema']['version'])
        elif self.schema_cache is not None:
            schema_json = self.schema_cache['json']
        else:
            x = ValueError('Schema neither loaded nor specified')
            logger.error(x)
            raise x

        rv = schema_json
        logger.debug('BaseListeningAgent._schema_info: <<< {}'.format(rv))
        return rv

    async def _response_from_proxy(self, form: dict, proxy_marker_attr: str) -> 'Response':
        """
        Get the response from the proxy, if the request form content identifies to do so

        :param form: request form on which to operate
        :param proxy_marker_attr: attribute in dict at form['data'] identifying intent to proxy
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent._response_from_proxy: >>> form: {}, proxy_marker_attr: {}'.format(
            form,
            proxy_marker_attr))

        if (proxy_marker_attr in form['data']) and (form['data'][proxy_marker_attr] != self.did):
            endpoint = json.loads(await self.get_endpoint(form['data'][proxy_marker_attr]))
            form['data'].pop(proxy_marker_attr)
            r = post(
                'http://{}:{}/{}/{}'.format(
                    endpoint['host'],
                    endpoint['port'],
                    self.agent_api_path,
                    form['type']),
                json=form)  # requests module json-encodes
            r.raise_for_status()

            rv = json.dumps(r.json())  # requests module json-decodes
            logger.debug('BaseListeningAgent._response_from_proxy: <<< {}'.format(rv))
            return rv

        logger.debug('BaseListeningAgent._response_from_proxy: <<<')
        return None

    @classmethod
    def _mro_dispatch(cls):
        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent._mro_dispatch: >>> cls.__name__: {}'.format(cls.__name__))

        rv = [c for c in cls.__mro__
            if issubclass(c, BaseListeningAgent) and issubclass(cls, c) and c != cls]
        rv.reverse()

        logger.debug('BaseListeningAgent._mro_dispatch: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent.process_post: >>> form: : {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        if form['type'] == 'agent-nym-lookup':  # local only, no use case for proxying
            # get agent nym from ledger (if present)
            self.__class__._vet_keys(
                {'agent-nym',},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'did'},
                set(form['data']['agent-nym'].keys()),
                hint='agent-nym')

            rv = await self.get_nym(form['data']['agent-nym']['did'])
            logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'agent-endpoint-lookup':  # local only, no use case for proxying
            # get agent endpoint from ledger (if present)
            self.__class__._vet_keys(
                {'agent-endpoint'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'did'},
                set(form['data']['agent-endpoint'].keys()),
                hint='agent-endpoint')

            rv = await self.get_endpoint(form['data']['agent-endpoint']['did'])
            logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'agent-endpoint-send':
            # send to agent endpoint to ledger

            resp_proxy_json = await self._response_from_proxy(form, 'proxy-did')
            if resp_proxy_json != None:
                return resp_proxy_json  # it's proxied

            resp_json = await self.send_endpoint()
            rv = json.dumps({})
            logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'schema-lookup':  # local only, no use case for proxying
            # init schema from ledger
            self.__class__._vet_keys(
                {'schema'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'issuer-did', 'name', 'version'},
                set(form['data']['schema'].keys()),
                hint='schema')
            schema_json = await self.get_schema(
                form['data']['schema']['issuer-did'], 
                form['data']['schema']['name'],
                form['data']['schema']['version'])
            schema = json.loads(schema_json)

            if not schema:
                rv = schema_json
                logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
                return rv

            rv = schema_json
            logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] in ('claim-request', 'proof-request'):
            self.__class__._vet_keys(
                {'claim-filter'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'attr-match', 'predicate-match'},
                set(form['data']['claim-filter'].keys()),
                hint='claim-filter')
            # TODO: predicates

            resp_proxy_json = await self._response_from_proxy(form, 'proxy-did')
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
                return rv

            # it's local: base listening agent doesn't do this work
            logger.debug('BaseListeningAgent.process_post: <!< not this form type: {}'.format(form['type']))
            raise NotImplementedError(
                '{} does not respond locally to token type {}'.format(self.__class__.__name__, form['type']))

        elif form['type'] == 'proof-request-by-claim-uuid':
            self.__class__._vet_keys({'claim-uuid'}, set(form['data'].keys()), hint='data')

            resp_proxy_json = await self._response_from_proxy(form, 'proxy-did')
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
                return rv

            # it's local: base listening agent doesn't do this work
            logger.debug('BaseListeningAgent.process_post: <!< not this form type: {}'.format(form['type']))
            raise NotImplementedError(
                '{} does not respond locally to token type {}'.format(self.__class__.__name__, form['type']))

        elif form['type'] == 'verification-request':
            self.__class__._vet_keys({'proof-req', 'proof'}, set(form['data'].keys()), hint='data')

            resp_proxy_json = await self._response_from_proxy(form, 'proxy-did')
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
                return rv

            # it's local: base listening agent doesn't do this work
            logger.debug('BaseListeningAgent.process_post: <!< not this form type: {}'.format(form['type']))
            raise NotImplementedError(
                '{} does not respond locally to token type {}'.format(self.__class__.__name__, form['type']))

        elif form['type'] == 'claim-hello':
            resp_proxy_json = await self._response_from_proxy(form, 'proxy-did')
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
                return rv

            # it's local: base listening agent doesn't do this work
            logger.debug('BaseListeningAgent.process_post: <!< not this form type: {}'.format(form['type']))
            raise NotImplementedError(
                '{} does not respond locally to token type {}'.format(self.__class__.__name__, form['type']))

        elif form['type'] == 'claim-store':
            self.__class__._vet_keys({'claim'}, set(form['data'].keys()), hint='data')

            resp_proxy_json = await self._response_from_proxy(form, 'proxy-did')
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('BaseListeningAgent.process_post: <<< {}'.format(rv))
                return rv

            # it's local: base listening agent doesn't do this work
            logger.debug('BaseListeningAgent.process_post: <!< not this form type: {}'.format(form['type']))
            raise NotImplementedError(
                '{} does not respond locally to token type {}'.format(self.__class__.__name__, form['type']))

        # unknown token type
        logger.debug('BaseListeningAgent.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))

    async def process_get_txn(self, txn: int) -> str:
        """
        Takes a request to find a transaction on the distributed ledger by its sequence number.

        :param txn: transaction number
        :return: json sequence number of transaction, null for no match
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent.process_get_txn: >>> txn: {}'.format(txn))

        req_json = await ledger.build_get_txn_request(self.did, txn)
        resp = json.loads(await ledger.submit_request(self.pool.handle, req_json))

        rv = json.dumps(resp['result']['data'] or {})
        logger.debug('BaseListeningAgent.process_get_txn: <<< {}'.format(rv))
        return rv

    async def process_get_did(self) -> str:
        """
        Takes a request to get current agent's DID, returns json accordingly.

        :return: json DID
        """

        logger = logging.getLogger(__name__)
        logger.debug('BaseListeningAgent.process_get_did: >>>')

        rv = json.dumps(self.did or '{}')
        logger.debug('BaseListeningAgent.process_get_did: <<< {}'.format(rv))
        return rv

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}({}, [SEED], {}, {}, {}, {})'.format(
            self.__class__.__name__,
            repr(self.pool),
            self.wallet.base_name,
            self.wallet.cfg_json,
            self.host,
            self.port)


class AgentRegistrar(BaseListeningAgent):
    """
    Mixin for (trust anchor) agent to register agents onto the distributed ledger
    """

    async def send_nym(self, did: str, verkey: str) -> None:
        """
        Method for trust anchor to send input agent's cryptonym (including DID and current verification key) to ledger.

        :param did: agent DID to send to ledger
        :param verkey: agent verification key
        """

        logger = logging.getLogger(__name__)
        logger.debug('AgentRegistrar.send_nym: >>> did: {}, verkey: {}'.format(did, verkey))

        req_json = await ledger.build_nym_request(
            self.did,
            did,
            verkey,
            None,
            None)
        await ledger.sign_and_submit_request(
            self.pool.handle,
            self.wallet.handle,
            self.did,
            req_json)

        logger.debug('AgentRegistrar.send_nym: <<<')

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('AgentRegistrar.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = AgentRegistrar._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('AgentRegistrar.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        if form['type'] == 'agent-nym-send':
            # write agent nym to ledger
            self.__class__._vet_keys(
                {'agent-nym',},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'did', 'verkey'},
                set(form['data']['agent-nym'].keys()),
                hint='agent-nym')

            # base listening agent code handles all proxied requests: it's local, carry on
            await self.send_nym(form['data']['agent-nym']['did'], form['data']['agent-nym']['verkey'])
            rv = json.dumps({})
            logger.debug('AgentRegistrar.process_post: <<< {}'.format(rv))
            return rv

        # token-type/proxy
        logger.debug('AgentRegistrar.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class Origin(BaseListeningAgent):
    """
    Mixin for agent to send schemata and claim definitions to the distributed ledger
    """

    async def send_schema(self, schema_data_json: str) -> str:
        """
        Method for schema originator to send schema to ledger, then retrieve it as written
        (and completed through the write process to the ledger) and return it.

        :param schema_data_json: schema data json with name, version, attribute names;
            e.g.,: {
                'name': 'my-schema',
                'version': '1.234',
                'attr_names': ['favourite_drink', 'height', 'last_visit_date']
            }
        :return: schema json as written to ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('Origin.send_schema: >>> schema_data_json: {}'.format(schema_data_json))

        req_json = await ledger.build_schema_request(self.did, schema_data_json)
        resp_json = await ledger.sign_and_submit_request(self.pool.handle, self.wallet.handle, self.did, req_json)
        resp = (json.loads(resp_json))['result']

        rv = await self.get_schema(resp['identifier'], resp['data']['name'], resp['data']['version'])
        logger.debug('Origin.send_schema: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('Origin.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = Origin._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('Origin.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        if form['type'] == 'schema-send':
            # write schema to ledger
            self.__class__._vet_keys(
                {'schema', 'attr-names'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'issuer-did', 'name', 'version'},
                set(form['data']['schema'].keys()),
                hint='schema')

            schema_json = await self.send_schema(json.dumps({
                'name': form['data']['schema']['name'],
                'version': form['data']['schema']['version'],
                'attr_names': form['data']['attr-names']
            }))
            schema = json.loads(schema_json)

            rv = await self.get_schema(
                self.schema_cache['issuer-did'],
                self.schema_cache['name'],
                self.schema_cache['version'])  # pick up ledger contributions
            logger.debug('Origin.process_post: <<< {}'.format(rv))
            return rv

        # token-type
        logger.debug('Origin.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))

class Issuer(BaseListeningAgent):
    """
    Mixin for agent acting in role of Issuer
    """

    async def send_claim_def(self, schema_json: str) -> str:
        """
        Method for Issuer to create a claim definition, store it in its wallet, and send it to the ledger.

        :param schema_json: schema as it appears on ledger via get_schema()
        :return: json claim definition as it appears on ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.send_claim_def: >>> schema_json: {}'.format(schema_json))

        schema = json.loads(schema_json)
        claim_def_json = await anoncreds.issuer_create_and_store_claim_def(
            self.wallet.handle,
            self.did,  # issuer DID
            schema_json,
            'CL',
            False)

        req_json = await ledger.build_claim_def_txn(
            self.did,
            schema['seqNo'],
            'CL',
            json.dumps(json.loads(claim_def_json)['data']))
        resp_json = await ledger.sign_and_submit_request(
            self.pool.handle,
            self.wallet.handle,
            self.did,
            req_json)
        data = (json.loads(resp_json))['result']['data']

        if data is None:
            rv = json.dumps({})
        else:
            rv = json.dumps(data)
        logger.debug('Issuer.send_claim_def: <<< {}'.format(rv))
        return rv

    async def create_claim(self, claim_req_json: str, claim: dict) -> (str, str):
        """
        Method for Issuer to create claim out of claim request and dict of key:[value, encoding] entries
        for revealed attributes.

        :param claim_req_json: claim request as created by HolderProver
        :param claim: claim dict mapping each revealed attribute to its [value, encoding];
            e.g., {
                'favourite_drink': ['martini', '1103189706537168622028552856221241'],
                'height': ['180', '180'],
                'last_visit_date': ['2017-12-31', '292278025700124567977725373155106423905275032369']
            }
        :return: revocation registry update json, newly issued claim json
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.create_claim: >>> claim_req_json: {}, claim: {}'.format(claim_req_json, claim))

        rv = await anoncreds.issuer_create_claim(
            self.wallet.handle,
            claim_req_json,
            json.dumps(claim),
            -1)
        logger.debug('Issuer.create_claim: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = Issuer._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('Issuer.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        if form['type'] == 'claim-def-send':
            # create claim def, store in wallet, send to ledger

            # it's local, carry on (no use case for proxying)
            schema_json = await self._schema_info(form['data'])
            await self.send_claim_def(schema_json)
            rv = json.dumps({})
            logger.debug('Issuer.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claim-create':
            self.__class__._vet_keys({'claim-req', 'claim-attrs'}, set(form['data'].keys()), hint='data')

            # it's local, carry on (no use case for proxying)
            _, rv = await self.create_claim(
                json.dumps(form['data']['claim-req']),
                {k:
                    [
                        str(form['data']['claim-attrs'][k]),
                        encode(form['data']['claim-attrs'][k])
                    ] for k in form['data']['claim-attrs']
                })
            logger.debug('Issuer.process_post: <<< {}'.format(rv))
            return rv  # TODO: support revocation -- this return value will change

        # token-type
        logger.debug('Issuer.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class HolderProver(BaseListeningAgent):
    """
    Mixin for agent acting in the role of w3c Holder and indy-sdk Prover. A Holder holds claims,
    and a Prover produces proof for claims.
    """

    def __init__(self,
            pool: NodePool,
            seed: str,
            wallet_base_name: str,
            wallet_cfg_json: str,
            host: str,
            port: int,
            agent_api_path: str = '') -> None:
        """
        Initializer for agent. Does not open its wallet, only retains input parameters.

        :pool: node pool on which agent operates
        :seed: seed to bootstrap agent
        :wallet_base_name: (base) name of wallet that agent uses
        :wallet_cfg_json: wallet configuration json, None for default
        :host: agent IP address
        :port: agent port
        :agent_api_path: URL path to agent API, for use in proxying to further agents
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.__init__: >>> ' +
            'pool: {}, ' +
            'seed: [SEED], ' +
            'wallet_base_name: {}, ' +
            'wallet_cfg_json: {}, ' +
            'host: {}, ' +
            'port: {}, ' +
            'agent_api_path: {}'.format(pool, wallet_base_name, wallet_cfg_json, host, port, agent_api_path))

        super().__init__(pool, seed, wallet_base_name, wallet_cfg_json, host, port, agent_api_path)
        self._master_secret = None
        self._claim_req_json = None  # FIXME: support multiple schema, use dict: txn_no -> claim_req_json

        logger.debug('HolderProver.__init__: <<<')

    @property
    def claim_req_json(self) -> str:
        """
        Accessor for (HolderProver) agent claim request json as stored in wallet

        :return: agent claim request json as stored in wallet
        """

        return self._claim_req_json

    async def create_master_secret(self, master_secret: str) -> None:
        """
        Method for HolderProver to create a master secret used in proofs.

        :param master_secret: label for master secret; indy-sdk uses label to generate master secret
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_master_secret: >>> master_secret {}'.format(master_secret))

        await anoncreds.prover_create_master_secret(self.wallet.handle, master_secret)
        self._master_secret = master_secret
        logger.debug('HolderProver.create_master_secret: <<<')

    async def store_claim_offer(self, issuer_did: str, schema_seq_no: int) -> None:
        """
        Method for HolderProver to store a claim offer in its wallet.
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.store_claim_offer: >>> issuer_did: {}, schema_seq_no: {}'.format(
            issuer_did,
            schema_seq_no))

        await anoncreds.prover_store_claim_offer(
            self.wallet.handle,
            json.dumps({
                'issuer_did': issuer_did,
                'schema_seq_no': schema_seq_no
            }))

        logger.debug('HolderProver.store_claim_offer: <<<')


    async def store_claim_req(self, issuer_did: str, claim_def_json: str) -> str:
        """
        Method for HolderProver to create a claim request and store it in its wallet.

        :param issuer_did: claim issuer DID
        :param claim_def_json: claim definition json as retrieved from ledger via get_claim_def()
        :return: claim request json as stored in wallet
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.store_claim_req: >>> issuer_did: {}, claim_def_json: {}'.format(
            issuer_did,
            claim_def_json))

        if self._master_secret is None:
            x = ValueError('Master secret is not set')
            logger.error(x)
            raise x

        rv = await anoncreds.prover_create_and_store_claim_req(
            self.wallet.handle,
            self.did,
            json.dumps({
                'issuer_did': issuer_did,
                'schema_seq_no': json.loads(claim_def_json)['ref']  # = schema seq no
            }),
            claim_def_json,
            self._master_secret);

        self._claim_req_json = rv
        logger.debug('HolderProver.store_claim_req: <<< {}'.format(rv))
        return rv

    async def store_claim(self, claim_json: str) -> None:
        """
        Method for HolderProver to store claim in wallet.

        :param claim_json: json claim as HolderProver created
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.store_claim: >>> claim_json: {}'.format(claim_json))

        await anoncreds.prover_store_claim(self.wallet.handle, claim_json)
        logger.debug('HolderProver.store_claim: <<<')

    async def create_proof(self,
            proof_req_json: str,
            schema: dict,
            claim_def: dict,
            requested_claims: dict = None) -> str:
        """
        Method for HolderProver to create proof.

        :param proof_req_json: proof request json as Verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates.
            E.g., {
                'nonce': '12345',  # for Verifier info, not HolderProver matching
                'name': 'proof-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'schema_seq_no': 57,
                        'name': 'favourite_drink'
                    },
                    'attr2_uuid': {
                        'schema_seq_no': 57,
                        'name': 'height'
                    },
                    'attr3_uuid': {
                        'schema_seq_no': 57,
                        'name': 'last_visit_date'
                    },
                },
                'requested_predicates': {
                    'predicate1_uuid': {
                        'attr_name': 'age',
                        'p_type': 'GE',
                        'value': 19
                    }
                }
            }
        :param schema: schema used in proof, as retrieved from ledger (multiple schemata not supported yet)
        :param claim_def: claim definition as retrieved from ledger
        :param requested_claims: data structure with self-attested attribute info, requested attribute info
            and requested predicate info, assembled from get_claims() and filtered for
            content of interest.
            E.g., {
                'self_attested_attributes': {},
                'requested_attrs': {
                    'attr0_uuid': ['claim::31291362-9b75-4353-a948-a7d02d0e7a00', True],
                    'attr1_uuid': ['claim::97977381-ca99-3817-8f22-a07cd3550287', True]
                },
                'requested_predicates': {
                    'predicate0_uuid': claim::31219731-9783-a772-bc98-12369780831f'
                }
            }
        :return: proof json
        """

        logger = logging.getLogger(__name__)
        logger.debug(
            'HolderProver.create_proof: >>> proof_req_json: {}, schema: {}, claim_def: {}, requested_claims: {}'.format(
                proof_req_json,
                schema,
                claim_def,
                requested_claims))

        if self._master_secret is None:
            x = ValueError('Master secret is not set')
            logger.error(x)
            raise x

        # TODO: support multiple schemata? Tricky.

        rv = await anoncreds.prover_create_proof(
            self.wallet.handle,
            proof_req_json,
            json.dumps(requested_claims),
            json.dumps({  # schemas_json
                claim_uuid[0]: schema
                    for claim_uuid in requested_claims['requested_attrs'].values()
            }),
            self._master_secret,
            json.dumps({  # claim_defs_json
                claim_uuid[0]: claim_def
                    for claim_uuid in requested_claims['requested_attrs'].values()
            }),
            json.dumps({})  # revoc_regs_json
        )
        logger.debug('HolderProver.create_proof: <<< {}'.format(rv))
        return rv

    async def get_claims(self, proof_req_json: str, filt: dict = None) -> (Set[str], str):
        """
        Method for HolderProver to get claims (from wallet) corresponding to proof request

        :param proof_req: proof request json as Verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates
            E.g., {
                'nonce': '12345',  # for Verifier info, not HolderProver matching
                'name': 'proof-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'schema_seq_no': 57,
                        'name': 'favourite_drink'
                    },
                    'attr2_uuid': {
                        'schema_seq_no': 57,
                        'name': 'height'
                    },
                    'attr3_uuid': {
                        'schema_seq_no': 57,
                        'name': 'last_visit_date'
                    },
                },
                'requested_predicates': {
                    'predicate1_uuid': {
                        'attr_name': 'age',
                        'p_type': 'GE',
                        'value': 19
                    }
                }
            }
        :param filt: dict with stringified values to match in revealed attributes
            (default None for no filter);
            e.g., {
                'height': '175',
                'name': 'Alex'
            }
        :return: tuple with (set of claim uuids, json with claims for input proof request)
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_claims: >>> proof_req_json: {}, filt: {}'.format(proof_req_json, filt))

        claims_for_proof_json = await anoncreds.prover_get_claims_for_proof_req(self.wallet.handle, proof_req_json)
        claims_for_proof = json.loads(claims_for_proof_json)
        claim_uuids = set()
        # retain only claim(s) of interest: find corresponding claim uuid(s)
        for attr_uuid in claims_for_proof['attrs']:
            for candidate in claims_for_proof['attrs'][attr_uuid]:
                if filt is None:
                    claim_uuids.add(candidate['claim_uuid'])
                else:
                    if filt.items() <= candidate['attrs'].items():
                        claim_uuids.add(candidate['claim_uuid'])
        if filt is not None:
            claims_for_proof = json.loads(prune_claims_json(claim_uuids, claims_for_proof))

        rv = (claim_uuids, json.dumps(claims_for_proof))
        logger.debug('HolderProver.get_claims: <<< {}'.format(rv))
        return rv

    async def get_claim_by_claim_uuid(self, schema_json: str, claim_uuid: str) -> str:
        """
        Method for HolderProver to get claim (from wallet) by claim-uuid

        :param schema_json: schema json
        :param claim-uuid: claim uuid
        :return: json with claim for input claim uuid
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_claim_by_claim_uuid: >>> schema_json: {}, claim_uuid: {}'.format(
            schema_json,
            claim_uuid))

        schema = json.loads(schema_json)
        claim_req_json = json.dumps({
                'nonce': str(int(time() * 1000)),
                'name': 'claim-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': {
                    '{}_uuid'.format(attr): {
                        'schema_seq_no': schema['seqNo'],
                        'name': attr
                    } for attr in schema['data']['attr_names']
                },
                'requested_predicates': {
                }
            })

        claims_for_proof_json = await anoncreds.prover_get_claims_for_proof_req(self.wallet.handle, claim_req_json)

        # retain only claim of interest: find corresponding claim uuid
        rv = prune_claims_json({claim_uuid}, json.loads(claims_for_proof_json))
        logger.debug('HolderProver.get_claim_by_claim_uuid: <<< {}'.format(rv))
        return rv

    async def reset_wallet(self) -> int:
        """
        Method for HolderProver to close and delete wallet, then create and open a new one.
        Useful for demo purpose so as not to have to shut down and restart the HolderProver from django.
        Precursor to revocation, and issuer/filter-specifiable claim deletion.

        :return: wallet num
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.reset_wallet: >>>')

        if self._master_secret is None:
            x = ValueError('Master secret is not set')
            logger.error(x)
            raise x

        _seed = self.wallet._seed
        base_name = self.wallet.base_name
        num = self.wallet.num
        cfg_json = self.wallet.cfg_json
        await self.wallet.close()
        self._wallet = Wallet(self.pool.name, _seed, base_name, num + 1, cfg_json)
        await self.wallet.open()

        await self.create_master_secret(self._master_secret)  # carry over master secret to new wallet

        rv = self.wallet.num
        logger.debug('HolderProver.reset_wallet: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = HolderProver._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('HolderProver.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        if form['type'] == 'master-secret-set':
            # it's local, carry on (no use case for proxying)
            self.__class__._vet_keys({'label'}, set(form['data'].keys()), hint='data')
            await self.create_master_secret(form['data']['label'])

            rv = json.dumps({})
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claim-hello':
            # base listening agent code handles all proxied requests: it's local, carry on
            self.__class__._vet_keys({'issuer-did'}, set(form['data'].keys()), hint='data')
            schema_json = await self._schema_info(form['data'])
            schema = json.loads(schema_json)
            await self.store_claim_offer(form['data']['issuer-did'], schema['seqNo'])
            claim_def_json = await self.get_claim_def(schema['seqNo'], form['data']['issuer-did'])
            await self.store_claim_req(form['data']['issuer-did'], claim_def_json)

            rv = self.claim_req_json
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] in ('claim-request', 'proof-request'):
            self.__class__._vet_keys(
                {'claim-filter'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'attr-match', 'predicate-match'},
                set(form['data']['claim-filter'].keys()),
                hint='claim-filter')
            # TODO: predicates

            # base listening agent code handles all proxied requests: it's local, carry on
            schema = json.loads(await self._schema_info(form['data']))
            find_req = {
                'nonce': str(int(time() * 1000)),
                'name': 'find_req_0', # informational only
                'version': '1.0',  # informational only
                'requested_attrs': {
                    '{}_uuid'.format(attr): {
                        'schema_seq_no': schema['seqNo'],
                        'name': attr
                    } for attr in schema['data']['attr_names']
                    # } for attr in form['data']['claim-filter']['attr-match'] or schema['data']['attr_names']
                },
                'requested_predicates': {
                    # TODO: predicates
                }
            }
            filt = {
                #k: encode(form['data']['claim-filter']['attr-match'][k])
                k: str(form['data']['claim-filter']['attr-match'][k])
                    for k in form['data']['claim-filter']['attr-match']
            } if form['data']['claim-filter']['attr-match'] else None
            (claim_uuids, claims_found_json) = await self.get_claims(json.dumps(find_req), filt)
            claims_found = json.loads(claims_found_json)

            if form['type'] == 'claim-request':
                rv = json.dumps({
                    'proof-req': find_req,
                    'claims': claims_found
                })
                logger.debug('HolderProver.process_post: <<< {}'.format(rv))
                return rv

            # FIXME: what if there are multiple matching claims to prove? How to encode requested attrs/preds?
            claim_uuid = claim_uuids.pop()  # pick one
            requested_claims = {
                'self_attested_attributes': {},
                'requested_attrs': {
                    attr: [claim_uuid, True]
                        for attr in find_req['requested_attrs'] if attr in claims_found['attrs']
                },
                'requested_predicates': {
                    pred: claim_uuid
                        for pred in find_req['requested_predicates']
                }
            }

            proof_json = await self.create_proof(
                json.dumps(find_req),
                schema,
                json.loads(await self.get_claim_def(
                    schema['seqNo'],
                    claims_found['attrs'][set([*claims_found['attrs']]).pop()][0]['issuer_did'])),
                requested_claims)

            rv = json.dumps({
                'proof-req': find_req,
                'proof': json.loads(proof_json)
            })
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'proof-request-by-claim-uuid':
            self.__class__._vet_keys({'claim-uuid'}, set(form['data'].keys()), hint='data')

            # base listening agent code handles all proxied requests: it's local, carry on
            schema_json = await self._schema_info(form['data'])
            claim_json = await self.get_claim_by_claim_uuid(schema_json, form['data']['claim-uuid'])
            claim = json.loads(claim_json)
            if all(not claim['attrs'][attr] for attr in claim['attrs']):
                x = ValueError('No claim has claim-uuid {}'.format(form['data']['claim-uuid']))
                logger.error(x)
                raise x

            schema = json.loads(schema_json)
            proof_req = {
                'nonce': str(int(time() * 1000)),
                'name': 'proof_req_0', # informational only
                'version': '1.0',  # informational only
                'requested_attrs': {
                    '{}_uuid'.format(attr): {
                        'schema_seq_no': schema['seqNo'],
                        'name': attr
                    } for attr in schema['data']['attr_names']
                },
                'requested_predicates': {
                    # TODO: predicates
                }
            }

            claim_uuid = form['data']['claim-uuid']
            requested_claims = {
                'self_attested_attributes': {},
                'requested_attrs': {
                    attr: [claim_uuid, True]
                        for attr in proof_req['requested_attrs'] if attr in claim['attrs']
                },
                'requested_predicates': {
                }
            }

            proof_json = await self.create_proof(
                json.dumps(proof_req),
                schema,
                json.loads(await self.get_claim_def(
                    schema['seqNo'],
                    claim['attrs'][set([*claim['attrs']]).pop()][0]['issuer_did'])),
                requested_claims)

            rv = json.dumps({
                'proof-req': proof_req,
                'proof': json.loads(proof_json)
            })
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claim-store':
            self.__class__._vet_keys({'claim'}, set(form['data'].keys()), hint='data')

            # base listening agent code handles all proxied requests: it's local, carry on
            await self.store_claim(json.dumps(form['data']['claim']))

            rv = json.dumps({})
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claims-reset':
            # it's local, carry on (no use case for proxying)
            await self.reset_wallet()

            rv = json.dumps({})
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        # token-type
        logger.debug('HolderProver.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class Verifier(BaseListeningAgent):
    """
    Mixin for agent acting in the role of Verifier.
    """

    async def verify_proof(self, proof_req_json: str, proof: dict, schema: dict, claim_def: dict) -> str:
        """
        Method for Verifier to verify proof.

        :param proof_req_json: proof request json as Verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates
            E.g., {
                'nonce': '12345',  # for Verifier info, not HolderProver matching
                'name': 'proof-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'schema_seq_no': 57,
                        'name': 'favourite_drink'
                    },
                    'attr2_uuid': {
                        'schema_seq_no': 57,
                        'name': 'height'
                    },
                    'attr3_uuid': {
                        'schema_seq_no': 57,
                        'name': 'last_visit_date'
                    },
                },
                'requested_predicates': {
                    'predicate1_uuid': {
                        'attr_name': 'age',
                        'p_type': 'GE',
                        'value': 19
                    }
                }
            }
        :param proof: proof as HolderProver creates
        :param schema: schema used in proof, as retrieved from ledger (multiple schemata not supported yet)
        :param claim_def: claim definition as retrieved from ledger
        :return: json encoded True if proof is valid; False if not
        """

        logger = logging.getLogger(__name__)
        logger.debug('Verifier.verify_proof: >>> proof_req_json: {}, proof: {}, schema: {}, claim_def: {}'.format(
            proof_req_json,
            proof,
            schema,
            claim_def))

        rv = json.dumps(
            await anoncreds.verifier_verify_proof(
                proof_req_json,
                json.dumps(proof),
                json.dumps({  # schemas_json
                    claim_uuid: schema for claim_uuid in proof['proofs']
                }),
                json.dumps({  # claim_defs_json
                    claim_uuid: claim_def for claim_uuid in proof['proofs']
                }),
                json.dumps({})  # revoc_regs_json
            )
        )
        logger.debug('Verifier.verify_proof: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.process_post: >>> form: {}'.format(form))

        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        # Try each responder code base from BaseListeningAgent up before trying locally
        mro = Verifier._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('Verifier.process_post: <<< {}'.format(rv))
                return rv
            except NotImplementedError:
                pass

        if form['type'] == 'verification-request':
            self.__class__._vet_keys({'proof-req', 'proof'}, set(form['data'].keys()), hint='data')

            # base listening agent code handles all proxied requests: it's local, carry on
            schema_json = await self._schema_info(form['data'])
            a_claim = form['data']['proof']['proofs'][set([*form['data']['proof']['proofs']]).pop()]

            rv = await self.verify_proof(
                json.dumps(form['data']['proof-req']),
                form['data']['proof'],
                json.loads(schema_json),
                json.loads(await self.get_claim_def(
                    a_claim['schema_seq_no'],
                    a_claim['issuer_did'])))
            logger.debug('Verifier.process_post: <<< {}'.format(rv))
            return rv

        # token-type
        logger.debug('Verifier.process_post: <!< not this form type: {}'.format(form['type']))
        raise NotImplementedError('{} does not support token type {}'.format(self.__class__.__name__, form['type']))
