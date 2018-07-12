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


import json
import logging

from indy import anoncreds, ledger
from von_anchor.anchor.base import _BaseAnchor
from von_anchor.cache import SCHEMA_CACHE
from von_anchor.error import AbsentSchema
from von_anchor.util import schema_id, schema_key


LOGGER = logging.getLogger(__name__)


class Origin(_BaseAnchor):
    """
    Mixin for anchor to send schemata to the distributed ledger.
    """

    async def send_schema(self, schema_data_json: str) -> str:
        """
        Send schema to ledger, then retrieve it as written to the ledger and return it.
        If schema already exists on ledger, log error and return schema.

        :param schema_data_json: schema data json with name, version, attribute names; e.g.,

        ::

            {
                'name': 'my-schema',
                'version': '1.234',
                'attr_names': ['favourite_drink', 'height', 'last_visit_date']
            }

        :return: schema json as written to ledger (or existed a priori)
        """

        LOGGER.debug('Origin.send_schema >>> schema_data_json: %s', schema_data_json)

        schema_data = json.loads(schema_data_json)
        s_key = schema_key(schema_id(self.did, schema_data['name'], schema_data['version']))
        with SCHEMA_CACHE.lock:
            try:
                rv_json = await self.get_schema(s_key)
                LOGGER.error(
                    'Schema %s version %s already exists on ledger for origin-did %s: not sending',
                    schema_data['name'],
                    schema_data['version'],
                    self.did)
            except AbsentSchema:  # OK - about to create and send it
                (_, schema_json) = await anoncreds.issuer_create_schema(
                    self.did,
                    schema_data['name'],
                    schema_data['version'],
                    json.dumps(schema_data['attr_names']))
                req_json = await ledger.build_schema_request(self.did, schema_json)
                resp_json = await self._sign_submit(req_json)
                resp = json.loads(resp_json)
                resp_result_txn = resp['result']['txn']
                rv_json = await self.get_schema(schema_key(schema_id(
                    resp_result_txn['metadata']['from'],
                    resp_result_txn['data']['data']['name'],
                    resp_result_txn['data']['data']['version'])))  # add to cache en passant

        LOGGER.debug('Origin.send_schema <<< %s', rv_json)
        return rv_json
