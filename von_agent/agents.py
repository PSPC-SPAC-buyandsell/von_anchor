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

from indy import anoncreds, ledger
from indy.error import IndyError, ErrorCode
from requests import post, HTTPError
from time import time
from typing import Set, Union

from von_agent.error import AbsentAttribute, AbsentMasterSecret, ClaimsFocus, ProxyHop, TokenType
from von_agent.nodepool import NodePool
from von_agent.proto.validate import validate as validate_form
from von_agent.schema import SchemaKey, SchemaStore, schema_key_for
from von_agent.util import encode, decode, prune_claims_json, ppjson
from von_agent.validate_config import CONFIG_JSON_SCHEMA, validate_config
from von_agent.wallet import Wallet

import asyncio
import json
import logging
import re


class _AgentCore:
    """
    Base class for agent implementing low-level functionality.
    """

    def __init__(self, pool: NodePool, wallet: Wallet) -> None:
        """
        Initializer for agent. Retain input parameters; do not open wallet.

        :param pool: node pool on which agent operates
        :param wallet: wallet for agent use
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.__init__: >>> pool: {}, wallet: {}'.format(pool, wallet))

        self._pool = pool
        self._wallet = wallet
        self._schema_store = SchemaStore()

        logger.debug('_AgentCore.__init__: <<<')

    @property
    def pool(self) -> NodePool:
        """
        Accessor for node pool.

        :return: node pool
        """

        return self._pool

    @property
    def wallet(self) -> 'Wallet':
        """
        Accessor for wallet.

        :return: wallet
        """

        return self._wallet

    @property
    def did(self) -> str:
        """
        Accessor for agent DID.

        :return: agent DID
        """

        return self.wallet.did

    @property
    def verkey(self) -> str:
        """
        Accessor for agent verification key.

        :return: agent verification key
        """

        return self.wallet.verkey

    async def __aenter__(self) -> '_AgentCore':
        """
        Context manager entry. Open wallet and store agent DID in it.
        For use in monolithic call opening, using, and closing the agent.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.__aenter__: >>>')

        rv = await self.open()

        logger.debug('_AgentCore.__aenter__: <<<')
        return rv

    async def open(self) -> '_AgentCore':
        """
        Explicit entry. Open wallet and store agent DID in it.
        For use when keeping agent open across multiple calls.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.open: >>>')

        await self.wallet.open()

        logger.debug('_AgentCore.open: <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Close wallet.
        For use in monolithic call opening, using, and closing the agent.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.__aexit__: >>> exc_type: {}, exc: {}, traceback: {}'.format(exc_type, exc, traceback))

        await self.close()
        logger.debug('_AgentCore.__exit__: <<<')

    async def close(self) -> None:
        """
        Explicit exit. Close wallet.
        For use when keeping agent open across multiple calls.
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.close: >>>')

        await self.wallet.close()

        logger.debug('_AgentCore.close: <<<')

    async def get_nym(self, did: str) -> str:
        """
        Get json cryptonym (including current verification key) for input (agent) DID from ledger.

        :param did: DID of cryptonym to fetch
        :return: cryptonym json
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.get_nym: >>> did: {}'.format(did))

        rv = json.dumps({})
        get_nym_req = await ledger.build_get_nym_request(
            self.did,
            did)
        resp_json = await ledger.submit_request(self.pool.handle, get_nym_req)
        await asyncio.sleep(0)

        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json:
            rv = data_json

        logger.debug('_AgentCore.get_nym: <<< {}'.format(rv))
        return rv

    async def get_schema(self, index: Union[SchemaKey, int]) -> str:
        """
        Get schema from ledger by origin DID, name, and version; return empty production {} for none.

        The operation retrieves the schema from the agent's schema store if it has it, and caches it
        en passant if it does not (and if there is a corresponding schema on the ledger).

        :param index: schema key (origin DID, name, version) or sequence number
        :return: schema json as retrieved from ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.get_schema: >>> index: {}'.format(index))

        rv = json.dumps({})

        if isinstance(index, SchemaKey):
            if self._schema_store.contains(index):
                rv = json.dumps(self._schema_store[index])
            else:
                req_json = await ledger.build_get_schema_request(
                    self.did,
                    index.origin_did,
                    json.dumps({'name': index.name, 'version': index.version}))
                resp_json = await ledger.submit_request(self.pool.handle, req_json)
                await asyncio.sleep(0)

                resp = json.loads(resp_json)
                if ('op' in resp) and (resp['op'] == 'REQNACK'):
                    logger.error('_AgentCore.get_schema: {}'.format(resp['reason']))
                else:
                    schema = resp['result']
                    data_json = schema['data']  # response result data is double-encoded on the ledger
                    if data_json and 'attr_names' in data_json:
                        self._schema_store[index] = schema
                        rv = json.dumps(schema)
                    else:
                        logger.info('_AgentCore.get_schema: ledger query returned response with no data')

        elif isinstance(index, int):
            if self._schema_store.contains(index):
                rv = json.dumps(self._schema_store[index])
            else:
                req_json = await ledger.build_get_txn_request(self.did, index)
                resp = json.loads(await ledger.submit_request(self.pool.handle, req_json))
                await asyncio.sleep(0)

                if ('op' in resp) and (resp['op'] == 'REQNACK'):
                    logger.error('_AgentCore.get_schema: {}'.format(resp['reason']))
                elif resp['result']['data'] and (resp['result']['data']['type'] == '101'):  # type '101' == schema
                    # getting it as a transaction misses the 'dest' field: look it up from schema key data
                    rv = await self.get_schema(SchemaKey(
                        resp['result']['data']['identifier'],
                        resp['result']['data']['data']['name'],
                        resp['result']['data']['data']['version']))

        logger.debug('_AgentCore.get_schema: <<< {}'.format(rv))
        return rv

    async def get_endpoint(self, did: str) -> str:
        """
        Get json endpoint for agent having input DID.

        :param did: DID for agent whose endpoint to find
        :return: json endpoint object (one 'endpoint' attribute and value) for agent having input DID;
            empty production for none
        """

        logger = logging.getLogger(__name__)
        logger.debug('_AgentCore.get_endpoint: >>> did: {}'.format(did))

        rv = json.dumps({})
        req_json = await ledger.build_get_attrib_request(
            self.did,
            did,
            'endpoint',
            None,
            None)
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        await asyncio.sleep(0)

        resp = json.loads(resp_json)
        if ('op' in resp) and (resp['op'] == 'REQNACK'):
            logger.error('_AgentCore.get_endpoint: {}'.format(resp['reason']))
        else:
            data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
            if data_json:
                rv = json.dumps(json.loads(data_json)['endpoint'])
            else:
                logger.info('_AgentCore.get_endpoint: ledger query returned response with no data')

        logger.debug('_AgentCore.get_endpoint: <<< {}'.format(rv))
        return rv

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}({}, {})'.format(self.__class__.__name__, repr(self.pool), self.wallet)

    def __str__(self) -> str:
        """
        Return informal string identifying current object.

        :return: string identifying current object
        """

        return '{}({})'.format(self.__class__.__name__, self.wallet)


class _BaseAgent(_AgentCore):
    """
    Class for agent that listens and responds to other agents. Note that a service wrapper will
    listen for requests, parse requests, dispatch to agents, and return content to callers;
    the current design calls not to use indy-sdk for direct agent-to-agent communication.

    The _BaseAgent builds on the _AgentCore in that it stores configuration information (e.g., endpoint data),
    and it receives and responds to (json) VON protocol messages (via a VON connector).
    """

    def __init__(self, pool: NodePool, wallet: Wallet, cfg: dict = None) -> None:
        """
        Initializer for agent. Retain input parameters; do not open wallet.

        :param pool: node pool on which agent operates
        :param wallet: wallet for agent use
        :param cfg: configuration, None for default with no endpoint and proxy-relay=False;
            e.g., {
                'endpoint': 'http://127.0.0.1:8808/api/v0',
                'proxy-relay': True
            }
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.__init__: >>> pool: {}, wallet: {}, cfg: {}'.format(pool, wallet, cfg))

        super().__init__(pool, wallet)

        self._cfg = cfg or {}
        validate_config('agent', self._cfg)

        logger.debug('_BaseAgent.__init__: <<<')

    @property
    def cfg(self):
        return self._cfg

    async def send_endpoint(self) -> str:
        """
        Send agent endpoint attribute to ledger. Return endpoint json as written to the ledger.

        Raise AbsentAttribute if no such endpoint.

        :return: endpoint attibute entry json (at present, 'http://<host>:<port>/<base-api-path>' or none)
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.send_endpoint: >>>')

        if 'endpoint' in self.cfg:
            raw_json = json.dumps({
                'endpoint': {
                    'endpoint': self.cfg['endpoint']
                }  # indy-sdk needs value itself to be a dict; {'endpoint': '...'} is no good
            })
            req_json = await ledger.build_attrib_request(self.did, self.did, None, raw_json, None)
            resp_json = await ledger.sign_and_submit_request(self.pool.handle, self.wallet.handle, self.did, req_json)
            await asyncio.sleep(0)
            resp = json.loads(resp_json)
            if ('op' in resp) and (resp['op'] == 'REQNACK'):
                logger.error('_BaseAgent.send_endpoint: {}'.format(resp['reason']))
        else:
            logger.debug('_BaseAgent.send_endpoint: <!< no endpoint configured')
            raise AbsentAttribute('Cannot send agent endpoint to ledger: no such endpoint in configuration')

        rv = await self.get_endpoint(self.did)
        logger.debug('_BaseAgent.send_endpoint: <<< {}'.format(rv))
        return rv

    async def get_claim_def(self, schema_seq_no: int, issuer_did: str) -> str:
        """
        Get claim definition from ledger by its parent schema and issuer DID; return
        empty production {} for none, IndyError with error_code = ErrorCode.LedgerInvalidTransaction
        for bad request.

        :param schema_seq_no: schema sequence number on the ledger
        :param issuer_did: (claim def) issuer DID
        :return: claim definition json as retrieved from ledger
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.get_claim_def: >>> schema_seq_no: {}, issuer_did: {}'.format(
            schema_seq_no,
            issuer_did))

        rv = json.dumps({})
        req_json = await ledger.build_get_claim_def_txn(
            self.did,
            schema_seq_no,
            'CL',
            issuer_did)

        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        await asyncio.sleep(0)

        resp = json.loads(resp_json)
        if ('op' in resp) and (resp['op'] == 'REQNACK'):
            logger.error('_BaseAgent.get_claim_def: {}'.format(resp['reason']))
        elif 'result' in resp and 'data' in resp['result'] and resp['result']['data']:
            data = resp['result']['data']
            if 'revocation' in data and data['revocation'] is not None:
                resp['result']['data']['revocation'] = None  #TODO: support revocation
            rv = json.dumps(resp['result'])
        else:
            logger.info('_BaseAgent.get_claim_def: ledger query returned response with no data')

        logger.debug('_BaseAgent.get_claim_def: <<< {}'.format(rv))
        return rv

    async def _response_from_proxy(self, form: dict) -> 'Response':
        """
        Get the response from the proxy, if the request form content identifies to do so.

        Raise ProxyHop if no agent found for specified DID, or endpoint specifies non-supported protocol (e.g., xmpp)

        :param form: request form on which to operate
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent._response_from_proxy: >>> form: {}'.format(form))

        rv = None
        if (self.cfg.get('proxy-relay', False)) and ('proxy-did' in form['data']):
            proxy_did = form['data'].pop('proxy-did')
            if (proxy_did != self.did):
                endpoint = json.loads(await self.get_endpoint(proxy_did))
                if (('endpoint' not in endpoint) or
                    not re.match(
                        CONFIG_JSON_SCHEMA['agent']['properties']['endpoint']['pattern'],
                        endpoint['endpoint'],
                        re.IGNORECASE)):
                    logger.debug('_BaseAgent._response_from_proxy: <!< no agent found for DID {}'.format(proxy_did))
                    raise ProxyHop('No agent on the ledger has DID {}'.format(proxy_did))
                if re.match('^http[s]?://.*', endpoint['endpoint'], re.IGNORECASE):
                    r = post(
                        '{}/{}'.format(endpoint['endpoint'], form['type']),
                        json=form)  # requests module json-encodes
                    if not r.ok:
                        logger.debug('_BaseAgent._response_from_proxy: <!< proxy got HTTP {}'.format(r.status_code))
                        raise HTTPError(r.status_code, r.reason)
                else:
                    logger.debug('_BaseAgent._response_from_proxy: <!< cannot resolve proxy hop')
                    raise ProxyHop(
                        'No proxy strategy implemented for target agent endpoint {}'.format(endpoint['endpoint']))
                rv = json.dumps(r.json())  # requests module json-decodes

        logger.debug('_BaseAgent._response_from_proxy: <<< {}'.format(rv))
        return rv

    @classmethod
    def _mro_dispatch(cls):
        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent._mro_dispatch: >>> cls.__name__: {}'.format(cls.__name__))

        rv = [c for c in cls.__mro__
            if issubclass(c, _BaseAgent) and issubclass(cls, c) and c != cls]
        rv.reverse()

        logger.debug('_BaseAgent._mro_dispatch: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Take a request from service wrapper POST, validate form via JSON schema, and dispatch
        the applicable agent action.  Return (json) response arising from processing.

        Raise:
            * JSONValidation on token validation exception,
            * TokenType on demurral for descendant class processing,
            * ProxyRelayConfig for attempt to proxy via agent not so configured
            * ProxyHop if unable to proxy otherwise OK message token.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.process_post: >>> form: {}'.format(form))

        validate_form(form, self.cfg.get('proxy-relay', False))

        if form['type'] == 'agent-nym-lookup':
            resp_proxy_json = await self._response_from_proxy(form)
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
                return rv

            rv = await self.get_nym(form['data']['agent-nym']['did'])
            logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'agent-endpoint-lookup':
            resp_proxy_json = await self._response_from_proxy(form)
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
                return rv

            rv = await self.get_endpoint(form['data']['agent-endpoint']['did'])
            logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'agent-endpoint-send':
            resp_proxy_json = await self._response_from_proxy(form)
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
                return rv

            resp_json = await self.send_endpoint()
            rv = json.dumps({})
            logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'schema-lookup':
            resp_proxy_json = await self._response_from_proxy(form)
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
                return rv

            s_key = schema_key_for(form['data']['schema'])
            schema_json = await self.get_schema(s_key)
            schema = json.loads(schema_json)
            if not schema:
                rv = schema_json
                logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
                return rv

            rv = schema_json
            logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] in (
                'agent-nym-send',
                'schema-send',
                'claim-def-send',
                'claim-offer-create',
                'claim-offer-store',
                'claim-create',
                'claim-store',
                'claim-request',
                'proof-request',
                'proof-request-by-referent',
                'verification-request'):  # do not proxy: master-secret-set, claims-reset
            resp_proxy_json = await self._response_from_proxy(form)
            if resp_proxy_json != None:
                rv = resp_proxy_json  # it's proxied
                logger.debug('_BaseAgent.process_post: <<< {}'.format(rv))
                return rv

            # base listening agent doesn't do this work
            logger.debug('_BaseAgent.process_post: <!< not this form type: {}'.format(form['type']))
            raise TokenType('{} does not respond to token type {}'.format(self.__class__.__name__, form['type']))

        logger.debug('_BaseAgent.process_post: <!< not this form type: {}'.format(form['type']))
        raise TokenType('{} does not support token type {}'.format(self.__class__.__name__, form['type']))

    async def process_get_txn(self, txn: int) -> str:
        """
        Take a request to find a transaction on the distributed ledger by its sequence number.

        :param txn: transaction number
        :return: json sequence number of transaction, null for no match
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.process_get_txn: >>> txn: {}'.format(txn))

        rv = json.dumps({})
        req_json = await ledger.build_get_txn_request(self.did, txn)
        resp = json.loads(await ledger.submit_request(self.pool.handle, req_json))
        await asyncio.sleep(0)

        if ('op' in resp) and (resp['op'] == 'REQNACK'):
            logger.error('_BaseAgent.process_get_txn: {}'.format(resp['reason']))
        else:
            rv = json.dumps(resp['result']['data'] or {})

        logger.debug('_BaseAgent.process_get_txn: <<< {}'.format(rv))
        return rv

    async def process_get_did(self) -> str:
        """
        Take a request to get current agent's DID, return json accordingly.

        :return: json DID
        """

        logger = logging.getLogger(__name__)
        logger.debug('_BaseAgent.process_get_did: >>>')

        rv = json.dumps(self.did or {})
        logger.debug('_BaseAgent.process_get_did: <<< {}'.format(rv))
        return rv

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return '{}({}, {}, {})'.format(self.__class__.__name__, repr(self.pool), self.wallet, self.cfg)

    def __str__(self) -> str:
        """
        Return informal string identifying current object.

        :return: string identifying current object
        """

        return '{}({}, {})'.format(self.__class__.__name__, self.wallet, self.cfg)


class AgentRegistrar(_BaseAgent):
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
        await asyncio.sleep(0)

        logger.debug('AgentRegistrar.send_nym: <<<')

    async def process_post(self, form: dict) -> str:
        """
        Take a request from service wrapper POST and dispatch the applicable agent action.
        Return (json) response arising from processing.

        Raise TokenType on demurral.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('AgentRegistrar.process_post: >>> form: {}'.format(form))

        # Try dispatching to each ancestor from _BaseAgent first
        mro = AgentRegistrar._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('AgentRegistrar.process_post: <<< {}'.format(rv))
                return rv
            except TokenType:
                pass

        if form['type'] == 'agent-nym-send':
            # base listening agent code handles all proxied requests: it's agent-local, carry on
            await self.send_nym(form['data']['agent-nym']['did'], form['data']['agent-nym']['verkey'])
            rv = json.dumps({})
            logger.debug('AgentRegistrar.process_post: <<< {}'.format(rv))
            return rv

        logger.debug('AgentRegistrar.process_post: <!< not this form type: {}'.format(form['type']))
        raise TokenType('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class Origin(_BaseAgent):
    """
    Mixin for agent to send schemata and claim definitions to the distributed ledger
    """

    async def send_schema(self, schema_data_json: str) -> str:
        """
        Send schema to ledger, then retrieve it as written to the ledger and return it.

        :param schema_data_json: schema data json with name, version, attribute names; e.g.,:
            {
                'name': 'my-schema',
                'version': '1.234',
                'attr_names': ['favourite_drink', 'height', 'last_visit_date']
            }
        :return: schema json as written to ledger, empty production for None
        """

        logger = logging.getLogger(__name__)
        logger.debug('Origin.send_schema: >>> schema_data_json: {}'.format(schema_data_json))

        rv = json.dumps({})

        schema_data = json.loads(schema_data_json)
        if (json.loads(await self.get_schema(SchemaKey(self.did, schema_data['name'], schema_data['version'])))):
            logger.error('Schema {} version {} already exists on ledger for origin-did {}: not sending'.format(
                schema_data['name'],
                schema_data['version'],
                self.did))

        else:
            req_json = await ledger.build_schema_request(self.did, schema_data_json)
            resp_json = await ledger.sign_and_submit_request(self.pool.handle, self.wallet.handle, self.did, req_json)
            await asyncio.sleep(0)

            resp = json.loads(resp_json)
            if ('op' in resp) and (resp['op'] == 'REQNACK'):
                logger.error('_BaseAgent.send_schema: {}'.format(resp['reason']))
            else:
                resp_result = (json.loads(resp_json))['result']
                rv = await self.get_schema(SchemaKey(
                    resp_result['identifier'],
                    resp_result['data']['name'],
                    resp_result['data']['version']))  # adds to store

        logger.debug('Origin.send_schema: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Take a request from service wrapper POST and dispatch the applicable agent action.
        Return (json) response arising from processing.

        Raise TokenType on demurral.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('Origin.process_post: >>> form: {}'.format(form))

        # Try dispatching to each ancestor from _BaseAgent first
        mro = Origin._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('Origin.process_post: <<< {}'.format(rv))
                return rv
            except TokenType:
                pass

        if form['type'] == 'schema-send':
            rv = await self.send_schema(json.dumps({
                'name': form['data']['schema']['name'],
                'version': form['data']['schema']['version'],
                'attr_names': form['data']['attr-names']
            }))

            logger.debug('Origin.process_post: <<< {}'.format(rv))
            return rv

        logger.debug('Origin.process_post: <!< not this form type: {}'.format(form['type']))
        raise TokenType('{} does not support token type {}'.format(self.__class__.__name__, form['type']))

class Issuer(Origin):
    """
    Mixin for agent acting in role of Issuer. Any issuer may originate its own schema.
    """

    async def send_claim_def(self, schema_json: str) -> str:
        """
        Create a claim definition as Issuer, store it in its wallet, and send it to the ledger.

        Raise any IndyError causing failure to store claim def.

        :param schema_json: schema as it appears on ledger via get_schema()
        :return: json claim definition as it appears on ledger, empty production for None
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.send_claim_def: >>> schema_json: {}'.format(schema_json))

        schema = json.loads(schema_json)
        rv = await self.get_claim_def(schema['seqNo'], schema['identifier'])
        if json.loads(rv):
            # TODO: revocation support will definitely change this check
            logger.info(
                'Claim def on schema {} version {} already exists on ledger; Issuer not sending another'.format(
                    schema['data']['name'],
                    schema['data']['version']))

        try:
            claim_def_json = await anoncreds.issuer_create_and_store_claim_def(
                self.wallet.handle,
                self.did,  # issuer DID
                schema_json,
                'CL',
                False)
        except IndyError as e:
            # TODO: revocation support may change this check
            if e.error_code == ErrorCode.AnoncredsClaimDefAlreadyExistsError:
                if json.loads(rv):
                    logger.info('Issuer wallet reusing existing claim def on schema {} version {}'.format(
                        schema['data']['name'],
                        schema['data']['version']))
                else:
                    logger.warn(
                        'Issuer wallet has claim def on schema {} version {} not on ledger: resetting wallet'.format(
                            schema['data']['name'],
                            schema['data']['version']))
                    seed = self.wallet._seed
                    wallet_name = self.wallet.name
                    wallet_cfg = self.wallet.cfg
                    await self.wallet.close()
                    await self.wallet.remove()
                    self._wallet = Wallet(self.pool.name, seed, wallet_name, wallet_cfg)
                    await self.wallet.open()

                    return await self.send_claim_def(schema_json)
            else:
                logger.debug(
                    'Issuer.send_claim_def: <!< cannot store claim def in wallet {}: indy error code {}'.format(
                        self.name,
                        self.e.error_code))
                raise

        if not json.loads(rv):  # checking the ledger returned no claim def: send it
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
            await asyncio.sleep(0)

            resp = json.loads(resp_json)
            if ('op' in resp) and (resp['op'] == 'REQNACK'):
                logger.error('Issuer.send_claim_def: {}'.format(resp['reason']))
            else:
                data = resp['result']['data']
                if data:
                    rv = json.dumps(data)
                else:
                    logger.info('Issuer.send_claim_def: ledger query returned response with no data')

        logger.debug('Issuer.send_claim_def: <<< {}'.format(rv))
        return rv

    async def create_claim_offer(self, schema_json: str, holder_prover_did: str) -> str:
        """
        Create claim offer as Issuer for given schema and agent on specified DID.

        :param schema_json: schema as it appears on ledger via get_schema()
        :return: json claim offer for use in storing claims at HolderProver.
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.create_claim_offer: >>> schema_json: {}, holder_prover_did: {}'.format(
            schema_json,
            holder_prover_did))

        rv = await anoncreds.issuer_create_claim_offer(
            self.wallet.handle,
            schema_json,
            self.did,
            holder_prover_did)

        logger.debug('Issuer.create_claim_offer: <<< {}'.format(rv))
        return rv

    async def create_claim(self, claim_req_json: str, claim: dict) -> (str, str):
        """
        Create claim as Issuer out of claim request and dict of key:[value, encoding] entries
        for revealed attributes.

        :param claim_req_json: claim request as created by HolderProver
        :param claim: claim dict mapping each revealed attribute to its [value, encoding]; e.g.,
            {
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
        Take a request from service wrapper POST and dispatch the applicable agent action.
        Return (json) response arising from processing.

        Raise TokenType on demurral.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('Issuer.process_post: >>> form: {}'.format(form))

        # Try dispatching to each ancestor from _BaseAgent first
        mro = Issuer._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('Issuer.process_post: <<< {}'.format(rv))
                return rv
            except TokenType:
                pass

        if form['type'] == 'claim-def-send':
            schema_json = await self.get_schema(schema_key_for(form['data']['schema']))
            await self.send_claim_def(schema_json)
            rv = json.dumps({})
            logger.debug('Issuer.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claim-offer-create':
            schema_json = await self.get_schema(schema_key_for(form['data']['schema']))
            rv = await self.create_claim_offer(schema_json, form['data']['holder-did'])  # claim offer json
            logger.debug('Issuer.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claim-create':
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

        logger.debug('Issuer.process_post: <!< not this form type: {}'.format(form['type']))
        raise TokenType('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class HolderProver(_BaseAgent):
    """
    Mixin for agent acting in the role of w3c Holder and indy-sdk Prover. A Holder holds claims,
    and a Prover produces proof for claims.
    """

    def __init__(self, pool: NodePool, wallet: Wallet, cfg: dict = None) -> None:
        """
        Initializer for HolderProver agent. Retain input parameters; do not open wallet.

        :param pool: node pool on which agent operates
        :param wallet: wallet for agent use
        :param cfg: configuration, None for default with no endpoint and proxy-relay=False;
            e.g., {
                'endpoint': 'http://127.0.0.1:8808/api/v0',
                'proxy-relay': True
            }
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.__init__: >>> pool: {}, wallet: {}, cfg: {}'.format(pool, wallet, cfg))

        super().__init__(pool, wallet, cfg)
        self._master_secret = None

        logger.debug('HolderProver.__init__: <<<')

    async def create_master_secret(self, master_secret: str) -> None:
        """
        Create master secret used in proofs by HolderProver.

        Raise any IndyError causing failure to set master secret in wallet.

        :param master_secret: label for master secret; indy-sdk uses label to generate master secret
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_master_secret: >>> master_secret: {}'.format(master_secret))

        try:
            await anoncreds.prover_create_master_secret(self.wallet.handle, master_secret)
        except IndyError as e:
            if e.error_code == ErrorCode.AnoncredsMasterSecretDuplicateNameError:
                logger.info('HolderProver did not create master secret - it already exists')
            else:
                logger.debug(   
                    'HolderProver.create_master_secret: <<<  cannot create master secret {}, indy error code {}'.format(
                        self.name,
                        self.e.error_code))
                raise

        self._master_secret = master_secret
        logger.debug('HolderProver.create_master_secret: <<<')

    async def store_claim_req(self, claim_offer_json: str, claim_def_json: str) -> str:
        """
        Store claim offer and create claim request as HolderProver and store in wallet.

        Raise AbsentMasterSecret if master secret not set.

        :param claim_offer_json: claim offer json
        :param claim_def_json: claim definition json as retrieved from ledger via get_claim_def()
        :return: claim request json as stored in wallet
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.store_claim_req: >>> claim_offer_json: {}, claim_def_json: {}'.format(
            claim_offer_json,
            claim_def_json))

        if self._master_secret is None:
            logger.debug('HolderProver.store_claim_req: <!< master secret not set')
            raise AbsentMasterSecret('Master secret is not set')

        await anoncreds.prover_store_claim_offer(
            self.wallet.handle,
            claim_offer_json)

        schema_seq_no = json.loads(claim_def_json)['ref']  # = schema seq no in claim def
        await self.get_schema(schema_seq_no)  # update schema store if need be
        s_key = self._schema_store.schema_key_for(schema_seq_no)
        rv = await anoncreds.prover_create_and_store_claim_req(
            self.wallet.handle,
            self.did,
            claim_offer_json,
            claim_def_json,
            self._master_secret)

        logger.debug('HolderProver.store_claim_req: <<< {}'.format(rv))
        return rv

    async def store_claim(self, claim_json: str) -> None:
        """
        Store claim in wallet as HolderProver.

        :param claim_json: json claim as HolderProver created
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.store_claim: >>> claim_json: {}'.format(claim_json))

        await anoncreds.prover_store_claim(
            self.wallet.handle,
            claim_json,
            None)  # rev_reg_json - TODO: revocation
        logger.debug('HolderProver.store_claim: <<<')

    async def create_proof(self, proof_req: dict, claims: dict, requested_claims: dict = None) -> str:
        """
        Create proof as HolderProver.

        Raise:
            * AbsentMasterSecret if master secret not set
            * ClaimsFocus on attempt to create proof on no claims or multiple claims for a claim definition.

        :param proof_req: proof request as Verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates. E.g.,
            {
                'nonce': '12345',  # for Verifier info, not HolderProver matching
                'name': 'proof-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'name': 'favourite_drink',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'Vx4E82R17q...',
                                    'name': 'friendlies',
                                    'version': '1.0'
                                }
                            }
                        ]
                    },
                    'attr2_uuid': {
                        'name': 'height',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'R17v42T4pk...',
                                    'name': 'patient-records',
                                    'version': '2.1'
                                }
                            }
                        ]
                    },
                    'attr3_uuid': {
                        'name': 'last_visit_date',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'R17v42T4pk...',
                                    'name': 'patient-records',
                                    'version': '2.1'
                                }
                            }
                        ]
                    },
                },
                'requested_predicates': {
                    'predicate0_uuid': {
                        'attr_name': 'age',
                        'p_type': '>=',
                        'value': 18,
                        'restrictions': [
                            'schema_key': {
                                'did': 'R17v42T4pk...',
                                'name': 'patient-records',
                                'version': '2.1'
                            }
                        ]
                    }
                }
            }
        :param claims: claims to prove
        :param requested_claims: data structure with self-attested attribute info, requested attribute info
            and requested predicate info, assembled from get_claims() and filtered for
            content of interest. E.g.,
            {
                'self_attested_attributes': {},
                'requested_attrs': {
                    'attr0_uuid': ['claim::31291362-9b75-4353-a948-a7d02d0e7a00', True],
                    'attr1_uuid': ['claim::97977381-ca99-3817-8f22-a07cd3550287', True]
                },
                'requested_predicates': {
                    'predicate0_uuid': 'claim::31219731-9783-a772-bc98-12369780831f'
                }
            }
        :return: proof json
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.create_proof: >>> proof_req: {}, claims: {}, requested_claims: {}'.format(
                proof_req,
                claims,
                requested_claims))

        if self._master_secret is None:
            logger.debug('HolderProver.create_proof: <!< master secret not set')
            raise AbsentMasterSecret('Master secret is not set')

        x_uuids = [attr_uuid for attr_uuid in claims['attrs'] if len(claims['attrs'][attr_uuid]) != 1]
        if x_uuids:
            logger.debug('HolderProver.create_proof: <!< claims specification out of focus (non-uniqueness)')
            raise ClaimsFocus('Proof request requires unique claims per attribute; violators: {}'.format(x_uuids))

        referent2schema = {}
        referent2claim_def = {}
        for attr_uuid in claims['attrs']:
            s_key = schema_key_for(claims['attrs'][attr_uuid][0]['schema_key'])
            schema = json.loads(await self.get_schema(s_key))  # make sure it's in the schema store
            referent2schema[claims['attrs'][attr_uuid][0]['referent']] = schema
            referent2claim_def[claims['attrs'][attr_uuid][0]['referent']] = (
                json.loads(await self.get_claim_def(
                    schema['seqNo'],
                    claims['attrs'][attr_uuid][0]['issuer_did'])))

        rv = await anoncreds.prover_create_proof(
            self.wallet.handle,
            json.dumps(proof_req),
            json.dumps(requested_claims),
            json.dumps(referent2schema),
            self._master_secret,
            json.dumps(referent2claim_def),
            json.dumps({}))  # revoc_regs_json
        logger.debug('HolderProver.create_proof: <<< {}'.format(rv))
        return rv

    async def get_claims(self, proof_req_json: str, filt: dict = {}) -> (Set[str], str):
        """
        Get claims from HolderProver wallet corresponding to proof request and filter criteria; return referents
        and proof json or empty set and empty production for no such claim.

        :param proof_req_json: proof request json as Verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates. E.g.,
            {
                'nonce': '12345',  # for Verifier info, not HolderProver matching
                'name': 'proof-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'name': 'favourite_drink',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'Vx4E82R17q...',
                                    'name': 'friendlies',
                                    'version': '1.0'
                                }
                            }
                        ]
                    },
                    'attr2_uuid': {
                        'name': 'height',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'R17v42T4pk...',
                                    'name': 'patient-records',
                                    'version': '2.1'
                                }
                            }
                        ]
                    },
                    'attr3_uuid': {
                        'name': 'last_visit_date',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'R17v42T4pk...',
                                    'name': 'patient-records',
                                    'version': '2.1'
                                }
                            }
                        ]
                    },
                },
                'requested_predicates': {
                    'predicate0_uuid': {
                        'attr_name': 'age',
                        'p_type': '>=',
                        'value': 18,
                        'restrictions': [
                            'schema_key': {
                                'did': 'R17v42T4pk...',
                                'name': 'patient-records',
                                'version': '2.1'
                            }
                        ]
                    }
                }
            }
        :param filt: filter for matching attribute-value pairs and predicates; dict mapping each SchemaKey to
            dict mapping attributes to values to match or compare (specify empty dict for no filter). E.g.,
            {
                SchemaKey('Vx4E82R17q...', 'friendlies', '1.0'): {
                    'attr-match': {
                        'name': 'Alex',
                        'sex': 'M',
                        'favouriteDrink': None
                    },
                    'pred-match': [
                        {
                            'attr' : 'favouriteNumber',
                            'pred-type': '>=',
                            'value': 10
                        },
                        {
                            'attr' : 'score',
                            'pred-type': '>=',
                            'value': 100
                        },
                    ]
                },
                SchemaKey('R17v42T4pk...', 'tombstone', '2.1'): {
                    'attr-match': {
                        'height': 175,
                        'birthdate': '1975-11-15'
                    }
                },
                ...
            }
        :return: tuple with (set of referents, claims json for input proof request); empty set and production
            for no such claim
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_claims: >>> proof_req_json: {}, filt: {}'.format(proof_req_json, filt))

        rv = None
        claims_json = await anoncreds.prover_get_claims_for_proof_req(self.wallet.handle, proof_req_json)
        claims = json.loads(claims_json)
        referents = set()

        # retain only claim(s) of interest: find corresponding referent(s)

        if filt:
            for s_key in filt:
                schema = json.loads(await self.get_schema(s_key))
                if not schema:
                    logger.warn('HolderProver.get_claims: ignoring filter criterion, no schema on {}'.format(s_key))
                    filt.pop(s_key)

        for attr_uuid in claims['attrs']:
            for candidate in claims['attrs'][attr_uuid]:
                if filt:
                    add_me = True
                    claim_s_key = schema_key_for(candidate['schema_key'])
                    if claim_s_key in filt and 'attr-match' in filt[claim_s_key]:
                        if not {k: str(filt[claim_s_key]['attr-match'][k])
                                for k in filt[claim_s_key]['attr-match']}.items() <= candidate['attrs'].items():
                            continue
                    if claim_s_key in filt and 'pred-match' in filt[claim_s_key]:
                        try:
                            if any((pred_match['attr'] not in candidate['attrs']) or
                                (int(candidate['attrs'][pred_match['attr']]) < pred_match['value'])
                                    for pred_match in filt[claim_s_key]['pred-match']):
                                continue
                        except ValueError:
                            # int conversion failed - reject candidate
                            continue
                    referents.add(candidate['referent'])
                else:
                    referents.add(candidate['referent'])

        if filt:
            claims = json.loads(prune_claims_json(claims, referents))

        rv = (referents, json.dumps(claims))
        logger.debug('HolderProver.get_claims: <<< {}'.format(rv))
        return rv

    async def get_claim_by_referent(self, referents: set, requested_attrs: dict) -> str:
        """
        Get claim structure from HolderProver wallet by referents.

        :param referents: set of referents of interest
        :param requested_attrs: requested attrs dict mapping uuid to schema sequence number and attribute name for
            each requested attribute; e.g.,
            {
                'attr1_uuid': {
                    'schema_seq_no': 57,
                    'name': 'favourite_drink'
                },
                'attr2_uuid': {
                    'schema_seq_no': 54,
                    'name': 'height'
                },
            }
        :return: json with claim(s) for input referent(s)
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.get_claim_by_referent: >>> referents: {}, requested_attrs: {}'.format(
            referents,
            requested_attrs))

        claim_req_json = json.dumps({
                'nonce': str(int(time() * 1000)),
                'name': 'claim-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': requested_attrs,
                'requested_predicates': {}
            })

        claims_json = await anoncreds.prover_get_claims_for_proof_req(self.wallet.handle, claim_req_json)

        # retain only claims of interest: find corresponding referents
        rv = prune_claims_json(json.loads(claims_json), referents)
        logger.debug('HolderProver.get_claim_by_referent: <<< {}'.format(rv))
        return rv

    async def reset_wallet(self) -> str:
        """
        Close and delete HolderProver wallet, then create and open a replacement.
        Precursor to revocation, and issuer/filter-specifiable claim deletion.

        Raise AbsentMasterSecret if master secret not set.

        :return: wallet name
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.reset_wallet: >>>')

        if self._master_secret is None:
            logger.debug('HolderProver.reset_wallet: <!< master secret not set')
            raise AbsentMasterSecret('Master secret is not set')

        seed = self.wallet._seed
        wallet_name = self.wallet.name
        wallet_cfg = self.wallet.cfg
        await self.wallet.close()
        await self.wallet.remove()
        self._wallet = Wallet(self.pool.name, seed, wallet_name, wallet_cfg)
        await self.wallet.open()

        await self.create_master_secret(self._master_secret)  # carry over master secret to new wallet

        rv = self.wallet.name
        logger.debug('HolderProver.reset_wallet: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Take a request from service wrapper POST and dispatch the applicable agent action.
        Return (json) response arising from processing.

        Raise:
            * TokenType on demurral
            * ClaimsFocus on attempt to create proof on no claims or multiple claims for a claim definition.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.process_post: >>> form: {}'.format(form))

        # Try dispatching to each ancestor from _BaseAgent first
        mro = HolderProver._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('HolderProver.process_post: <<< {}'.format(rv))
                return rv
            except TokenType:
                pass

        if form['type'] == 'master-secret-set':
            # it's agent-local, carry on (no use case for proxying)
            await self.create_master_secret(form['data']['label'])

            rv = json.dumps({})
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claim-offer-store':
            # base listening agent code handles all proxied requests: it's agent-local, carry on
            s_key = schema_key_for(form['data']['claim-offer']['schema_key'])
            issuer_did = form['data']['claim-offer']['issuer_did']
            schema_json = await self.get_schema(s_key)
            schema = json.loads(schema_json)
            claim_def_json = await self.get_claim_def(schema['seqNo'], issuer_did)
            rv = await self.store_claim_req(json.dumps(form['data']['claim-offer']), claim_def_json)

            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] in ('claim-request', 'proof-request'):
            # base listening agent code handles all proxied requests: it's agent-local, carry on
            form_schema_keys = []
            for form_s_key_spec in (form['data']['schemata'] +
                    [attr_matcher['schema'] for attr_matcher in form['data']['claim-filter']['attr-match']] +
                    [pred_matcher['schema'] for pred_matcher in form['data']['claim-filter']['pred-match']] +
                    [r_attr['schema'] for r_attr in form['data']['requested-attrs']]):
                s_key = schema_key_for(form_s_key_spec)
                await self.get_schema(s_key)  # add to store en passant
                form_schema_keys.append(s_key)

            req_preds = {}  # do preds first: there may be defaulting req-attrs to compute, avoid collision with preds
            for pred_match in form['data']['claim-filter']['pred-match']:
                s_key = schema_key_for(pred_match['schema'])
                seq_no = self._schema_store[s_key]['seqNo']
                for pred_match_match in pred_match['match']:
                    req_preds['{}_{}_uuid'.format(seq_no, pred_match_match['attr'])] = {
                        'attr_name': pred_match_match['attr'],
                        'p_type': pred_match_match['pred-type'],
                        'value': pred_match_match['value'],
                        'restrictions': [{
                            'schema_key': {
                                'did': s_key.origin_did,
                                'name': s_key.name,
                                'version': s_key.version
                            }
                        }]
                    }

            req_attrs = {}
            if form['data']['requested-attrs']:
                for req_attr in form['data']['requested-attrs']:
                    s_key = schema_key_for(req_attr['schema'])
                    schema = self._schema_store[s_key]
                    for name in req_attr['names'] or schema['data']['attr_names']:
                        if all(name != req_pred['attr_name'] or
                            s_key != schema_key_for(req_pred['restrictions'][0]['schema_key'])
                                for req_pred in req_preds.values()):
                            req_attrs['{}_{}_uuid'.format(schema['seqNo'], name)] = {
                                'name': name,
                                'restrictions': [{
                                    'schema_key': {
                                        'did': s_key.origin_did,
                                        'name': s_key.name,
                                        'version': s_key.version
                                    }
                                }]
                            }
            else:
                for s_key in form_schema_keys:
                    schema = self._schema_store[s_key]
                    for attr_name in schema['data']['attr_names']:
                        if all(attr_name != req_pred['attr_name'] or
                            s_key != schema_key_for(req_pred['restrictions'][0]['schema_key'])
                                for req_pred in req_preds.values()):
                            req_attrs['{}_{}_uuid'.format(schema['seqNo'], attr_name)] = {
                                'name': attr_name,
                                'restrictions': [{
                                    'schema_key': {
                                        'did': s_key.origin_did,
                                        'name': s_key.name,
                                        'version': s_key.version
                                    }
                                }]
                            }

            find_req = {
                'nonce': str(int(time() * 1000)),
                'name': 'find_req_0', # informational only
                'version': '1.0',  # informational only
                'requested_attrs': req_attrs,
                'requested_predicates': req_preds
            }

            filt = {
                schema_key_for(attr_match['schema']): {'attr-match': attr_match['match']}
                    for attr_match in form['data']['claim-filter']['attr-match']
            }
            for pred_match in form['data']['claim-filter']['pred-match']:
                s_key = schema_key_for(pred_match['schema'])
                if s_key not in filt:
                    filt[s_key] = {}
                filt[s_key]['pred-match'] = pred_match['match']

            (referents, claims_found_json) = await self.get_claims(
                json.dumps(find_req),
                filt)
            claims_found = json.loads(claims_found_json)
            if form['type'] == 'claim-request':
                rv = json.dumps({
                    'proof-req': find_req,
                    'claims': claims_found
                })
                logger.debug('HolderProver.process_post: <<< {}'.format(rv))
                return rv

            # forbid multiple matching claims for any claim-def in a proof
            x_uuids = [attr_uuid for attr_uuid in claims_found['attrs'] if len(claims_found['attrs'][attr_uuid]) != 1]
            if x_uuids:
                logger.debug('HolderProver.process_post: <!< claims specification out of focus (non-uniqueness)')
                raise ClaimsFocus('Proof request requires unique claims per attribute; violators: {}'.format(x_uuids))

            requested_claims = {
                'self_attested_attributes': {},
                'requested_attrs': {
                    attr_uuid: [claims_found['attrs'][attr_uuid][0]['referent'], True]
                        for attr_uuid in claims_found['attrs']
                },
                'requested_predicates': {
                    pred_uuid: claims_found['predicates'][pred_uuid][0]['referent']
                        for pred_uuid in claims_found['predicates']
                }
            }

            proof_json = await self.create_proof(
                find_req,
                claims_found,
                requested_claims)

            rv = json.dumps({
                'proof-req': find_req,
                'proof': json.loads(proof_json)
            })
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'proof-request-by-referent':
            # base listening agent code handles all proxied requests: it's agent-local, carry on
            form_schema_keys = []
            for form_s_key_spec in (form['data']['schemata'] +
                    [r_attr['schema'] for r_attr in form['data']['requested-attrs']]):
                s_key = schema_key_for(form_s_key_spec)
                await self.get_schema(s_key)  # add to store en passant
                form_schema_keys.append(s_key)

            req_attrs = {}
            if form['data']['requested-attrs']:
                for req_attr in form['data']['requested-attrs']:
                    s_key = schema_key_for(req_attr['schema'])
                    schema = self._schema_store[s_key]
                    for name in req_attr['names'] or schema['data']['attr_names']:
                        req_attrs['{}_{}_uuid'.format(schema['seqNo'], name)] = {
                            'name': name,
                            'restrictions': [{
                                'schema_key': {
                                    'did': s_key.origin_did,
                                    'name': s_key.name,
                                    'version': s_key.version
                                }
                            }]
                        }
            else:
                for s_key in form_schema_keys:
                    schema = self._schema_store[s_key]
                    for attr_name in schema['data']['attr_names']:
                        req_attrs['{}_{}_uuid'.format(schema['seqNo'], attr_name)] = {
                            'name': attr_name,
                            'restrictions': [{
                                'schema_key': {
                                    'did': s_key.origin_did,
                                    'name': s_key.name,
                                    'version': s_key.version
                                }
                            }]
                        }

            claims_found_json = await self.get_claim_by_referent(
                {referent for referent in form['data']['referents']},
                req_attrs)
            claims_found = json.loads(claims_found_json)

            # kick out early if no matching claims
            if (not claims_found['attrs']) and (not claims_found['predicates']):
                logger.debug('HolderProver.process_post: <!< claims specification out of focus (no matching claims)')
                raise ClaimsFocus('No such referent claim: {}'.format(form['data']['referents']))

            # forbid multiple matching claims for any claim-def in a proof
            x_referents = [attr_uuid for attr_uuid in claims_found['attrs']
                if len(claims_found['attrs'][attr_uuid]) != 1]
            if x_referents:
                logger.debug('HolderProver.process_post: <!< claims specification out of focus (too many claims)')
                raise ClaimsFocus(  
                    'Proof request requires unique claims per attribute; violators: {}'.format(x_referents))

            proof_req = {
                'nonce': str(int(time() * 1000)),
                'name': 'proof_req_0', # informational only
                'version': '1.0',  # informational only
                'requested_attrs': req_attrs,
                'requested_predicates': {}
            }

            referents = form['data']['referents']
            requested_claims = {
                'self_attested_attributes': {},
                'requested_attrs': {
                    attr_uuid: [claims_found['attrs'][attr_uuid][0]['referent'], True]
                        for attr_uuid in claims_found['attrs']
                },
                'requested_predicates': {}
            }

            proof_json = await self.create_proof(
                proof_req,
                claims_found,
                requested_claims)

            rv = json.dumps({
                'proof-req': proof_req,
                'proof': json.loads(proof_json)
            })
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claim-store':
            # base listening agent code handles all proxied requests: it's agent-local, carry on
            await self.store_claim(json.dumps(form['data']['claim']))

            rv = json.dumps({})
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        elif form['type'] == 'claims-reset':
            # it's agent-local, carry on (no use case for proxying)
            await self.reset_wallet()

            rv = json.dumps({})
            logger.debug('HolderProver.process_post: <<< {}'.format(rv))
            return rv

        logger.debug('HolderProver.process_post: <!< not this form type: {}'.format(form['type']))
        raise TokenType('{} does not support token type {}'.format(self.__class__.__name__, form['type']))


class Verifier(_BaseAgent):
    """
    Mixin for agent acting in the role of Verifier.
    """

    async def verify_proof(self, proof_req: dict, proof: dict) -> str:
        """
        Verify proof as Verifier.

        :param proof_req: proof request as Verifier creates - has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates; e.g.,
            {
                'nonce': '12345',  # for Verifier info, not HolderProver matching
                'name': 'proof-request',  # for Verifier info, not HolderProver matching
                'version': '1.0',  # for Verifier info, not HolderProver matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'name': 'favourite_drink',
                        'restrictions' [
                                {
                                'schema_key': {
                                    'did': 'Vx4E82R17q...',
                                    'name': 'friendlies',
                                    'version': '1.0'
                                }
                            }
                        ]
                    },
                    'attr2_uuid': {
                        'name': 'height',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'R17v42T4pk...',
                                    'name': 'patient-records',
                                    'version': '2.1'
                                }
                            }
                        ]
                    },
                    'attr3_uuid': {
                        'name': 'last_visit_date',
                        'restrictions' [
                            {
                                'schema_key': {
                                    'did': 'R17v42T4pk...',
                                    'name': 'patient-records',
                                    'version': '2.1'
                                }
                            }
                        ]
                    },
                },
                'requested_predicates': {
                    'predicate0_uuid': {
                        'attr_name': 'age',
                        'p_type': '>=',
                        'value': 18,
                        'restrictions': [
                            'schema_key': {
                                'did': 'R17v42T4pk...',
                                'name': 'patient-records',
                                'version': '2.1'
                            }
                        ]
                    }
                }
            }
        :param proof: proof as HolderProver creates
        :return: json encoded True if proof is valid; False if not
        """

        logger = logging.getLogger(__name__)
        logger.debug('Verifier.verify_proof: >>> proof_req: {}, proof: {}'.format(
            proof_req,
            proof))

        claims = proof['identifiers']
        uuid2schema = {}
        uuid2claim_def = {}
        for claim_uuid in claims:
            claim_s_key = schema_key_for(claims[claim_uuid]['schema_key'])
            schema = json.loads(await self.get_schema(claim_s_key))
            uuid2schema[claim_uuid] = schema
            uuid2claim_def[claim_uuid] = json.loads(await self.get_claim_def(
                schema['seqNo'],
                claims[claim_uuid]['issuer_did']))

        rv = json.dumps(await anoncreds.verifier_verify_proof(
            json.dumps(proof_req),
            json.dumps(proof),
            json.dumps(uuid2schema),
            json.dumps(uuid2claim_def),
            json.dumps({})))  # revoc_regs_json

        logger.debug('Verifier.verify_proof: <<< {}'.format(rv))
        return rv

    async def process_post(self, form: dict) -> str:
        """
        Take a request from service wrapper POST and dispatch the applicable agent action.
        Return (json) response arising from processing.

        Raise TokenType on demurral.

        :param form: request form on which to operate
        :return: json response
        """

        logger = logging.getLogger(__name__)
        logger.debug('HolderProver.process_post: >>> form: {}'.format(form))

        # Try dispatching to each ancestor from _BaseAgent first
        mro = Verifier._mro_dispatch()
        for ResponderClass in mro:
            try:
                rv = await ResponderClass.process_post(self, form)
                logger.debug('Verifier.process_post: <<< {}'.format(rv))
                return rv
            except TokenType:
                pass

        if form['type'] == 'verification-request':
            # base listening agent code handles all proxied requests: it's agent-local, carry on
            rv = await self.verify_proof(
                form['data']['proof-req'],
                form['data']['proof'])
            logger.debug('Verifier.process_post: <<< {}'.format(rv))
            return rv

        logger.debug('Verifier.process_post: <!< not this form type: {}'.format(form['type']))
        raise TokenType('{} does not support token type {}'.format(self.__class__.__name__, form['type']))
