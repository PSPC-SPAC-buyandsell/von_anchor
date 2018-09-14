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

from asyncio import sleep

from indy import anoncreds, ledger
from von_anchor.anchor.base import _BaseAnchor
from von_anchor.cache import SCHEMA_CACHE
from von_anchor.error import AbsentSchema, BadLedgerTxn
from von_anchor.util import schema_id, schema_key

LOGGER = logging.getLogger(__name__)


class Origin(_BaseAnchor):
    """
    Mixin for anchor to send schemata to the distributed ledger.
    """

    async def send_schema(self, schema_data_json: str) -> str:
        """
        Send schema to ledger, then retrieve it as written to the ledger and return it.
        Raise BadLedgerTxn on failure.

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
        s_id = schema_id(self.did, schema_data['name'], schema_data['version'])
        s_key = schema_key(s_id)
        rv_json = None
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
                await self._sign_submit(req_json)

                for _ in range(16):  # reasonable timeout
                    try:
                        rv_json = await self.get_schema(s_key)  # adds to cache
                        break
                    except AbsentSchema:
                        await sleep(1)
                        LOGGER.info('Sent schema %s to ledger, waiting 1s for its appearance', s_id)

                if not rv_json:
                    LOGGER.debug('Origin.send_schema <!< timed out waiting on sent schema %s', s_id)
                    raise BadLedgerTxn('Timed out waiting on sent schema {}'.format(s_id))

        LOGGER.debug('Origin.send_schema <<< %s', rv_json)
        return rv_json
