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

from os import makedirs
from os.path import expanduser, join
from time import time

from indy import anoncreds, ledger
from indy.error import IndyError
from von_agent.agent.base import _BaseAgent
from von_agent.cache import Caches, CRED_DEF_CACHE, REVO_CACHE, SCHEMA_CACHE
from von_agent.error import AbsentRevReg, AbsentSchema, BadRevStateTime, ClosedPool
from von_agent.nodepool import NodePool
from von_agent.validate_config import validate_config
from von_agent.wallet import Wallet


LOGGER = logging.getLogger(__name__)


class Verifier(_BaseAgent):
    """
    Mixin for agent acting in the role of Verifier. Verifier agents verify proofs.
    """

    def __init__(self, wallet: Wallet, pool: NodePool, cfg: dict = None) -> None:
        """
        Initializer for Verifier agent. Retain input parameters; do not open wallet.

        :param wallet: wallet for agent use
        :param pool: pool for agent use
        :param cfg: configuration dict for cache archive behaviour; e.g.,

        ::

            {
                'parse-cache-on-open': True,
                'archive-on-close': {
                    'schema_id': [
                        'R17v42T4pk...:2:tombstone:1.2',
                        '9cHbp54C8n...:2:business:2.0',
                        'Pcq76cx6jE...:2:birth_cert:1.0',
                        ...
                    ],
                    'cred_def_id': [
                        'R17v42T4pk...:3:CL:19:0',
                        '9cHbp54C8n...:3:CL:37:0',
                        'Pcq76cx6jE...:3:CL:51:0',
                        ...
                    ]
                    'rev_reg_id': [
                        'R17v42T4pk...:4:R17v42T4pk...:3:CL:19:0:CL_ACCUM:0',
                        'R17v42T4pk...:4:R17v42T4pk...:3:CL:19:0:CL_ACCUM:1',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:0:CL_ACCUM:0',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:0:CL_ACCUM:1',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:0:CL_ACCUM:2',
                        ...
                    ]
                }
            }

        """

        LOGGER.debug('Verifier.__init__ >>> wallet: %s, pool: %s, cfg: %s', wallet, pool, cfg)

        super().__init__(wallet, pool)

        self._cfg = cfg or {}
        validate_config('verifier', self._cfg)

        self._dir_cache = join(expanduser('~'), '.indy_client', 'wallet', self.wallet.name, 'cache')
        makedirs(self._dir_cache, exist_ok=True)

        LOGGER.debug('HolderProver.__init__ <<<')

    @property
    def cfg(self) -> dict:
        """
        Accessor for configuration dict

        :return: verifier config dict
        """

        return self._cfg

    @cfg.setter
    def cfg(self, value: dict) -> None:
        """
        Set configuration dict

        :param value: configuration dict
        """

        self._cfg = value or {}
        validate_config('verifier', self._cfg)

    @property
    def dir_cache(self) -> str:
        """
        Accessor for cache archive directory

        :return: verifier cache archive directory
        """

        return self._dir_cache

    async def _build_rr_state_json(self, rr_id: str, timestamp: int) -> (str, int):
        """
        Build rev reg state json at a given requested timestamp.

        Return delta json and its transaction time on the distributed ledger,
        with upper bound at input timestamp of interest.

        Raise AbsentRevReg if no revocation registry exists on input rev reg id,
        or BadRevStateTime if requested timestamp predates revocation registry creation.

        :param rr_id: rev reg id
        :param timestamp: timestamp of interest (epoch seconds)
        :return: rev reg delta json and ledger timestamp (epoch seconds)
        """

        LOGGER.debug('_Verifier._build_rr_state_json >>> rr_id: %s, timestamp: %s', rr_id, timestamp)

        rr_json = None
        ledger_timestamp = None

        get_rr_req_json = await ledger.build_get_revoc_reg_request(self.did, rr_id, timestamp)
        resp_json = await self._submit(get_rr_req_json)
        resp = json.loads(resp_json)
        if resp.get('result', {}).get('data', None) and resp['result']['data'].get('value', None):
            # timestamp at or beyond rev reg creation, carry on
            try:
                (_, rr_json, ledger_timestamp) = await ledger.parse_get_revoc_reg_response(resp_json)
            except IndyError:  # ledger replied, but there is no such rev reg available
                LOGGER.debug('Verifier._build_rr_state_json: <!< no rev reg exists on %s', rr_id)
                raise AbsentRevReg('No rev reg exists on {}'.format(rr_id))
        else:
            LOGGER.debug(
                '_Verifier._build_rr_state_json: <!< Rev reg %s created after asked-for time %s',
                rr_id,
                timestamp)
            raise BadRevStateTime('Rev reg {} created after asked-for time {}'.format(rr_id, timestamp))

        rv = (rr_json, ledger_timestamp)
        LOGGER.debug('_Verifier._build_rr_state_json <<< %s', rv)
        return rv

    async def load_cache(self, archive: bool = False) -> int:
        """
        Load caches and archive enough to go offline and be able to verify proof
        on content marked of interest in configuration.

        Return timestamp (epoch seconds) of cache load event, also used as subdirectory
        for cache archives.

        :param archive: whether to archive caches to disk
        :return: cache load event timestamp (epoch seconds)
        """

        LOGGER.debug('Verifier.load_cache >>> archive: %s', archive)

        rv = int(time())
        for s_id in self.cfg.get('archive-on-close', {}).get('schema_id', {}):
            with SCHEMA_CACHE.lock:
                await self.get_schema(s_id)
        for cd_id in self.cfg.get('archive-on-close', {}).get('cred_def_id', {}):
            with CRED_DEF_CACHE.lock:
                await self.get_cred_def(cd_id)
        for rr_id in self.cfg.get('archive-on-close', {}).get('rev_reg_id', {}):
            await self._get_rev_reg_def(rr_id)
            with REVO_CACHE.lock:
                revo_cache_entry = REVO_CACHE.get(rr_id, None)
                if revo_cache_entry:
                    try:
                        await revo_cache_entry.get_state_json(self._build_rr_state_json, rv, rv)
                    except ClosedPool:
                        LOGGER.warning(
                            'Verifier %s is offline from pool %s, cannot update revo cache reg state for %s to %s',
                            self.wallet.name,
                            self.pool.name,
                            rr_id,
                            rv)

        if archive:
            Caches.archive(self.dir_cache)
        LOGGER.debug('Verifier.load_cache <<< %s', rv)
        return rv

    async def open(self) -> 'HolderProver':
        """
        Explicit entry. Perform ancestor opening operations,
        then parse cache from archive if so configured, and
        synchronize revocation registry to tails tree content.

        :return: current object
        """

        LOGGER.debug('Verifier.open >>>')

        await super().open()
        if self.cfg.get('parse-cache-on-open', False):
            Caches.parse(self.dir_cache)

        LOGGER.debug('Verifier.open <<<')
        return self

    async def close(self) -> None:
        """
        Explicit exit. If so configured, populate cache to prove for any creds on schemata,
        cred defs, and rev regs marked of interest in configuration at initialization,
        archive cache, and purge prior cache archives.

        :return: current object
        """

        LOGGER.debug('Verifier.close >>>')

        if self.cfg.get('archive-on-close', {}):
            await self.load_cache(True)
            Caches.purge_archives(self.dir_cache, True)

        await super().close()

        LOGGER.debug('Verifier.close <<<')

    async def verify_proof(self, proof_req: dict, proof: dict) -> str:
        """
        Verify proof as Verifier. Raise AbsentRevReg if a proof cites a revocation registry
        that does not exist on the distributed ledger.

        :param proof_req: proof request as Verifier creates, as per proof_req_json above
        :param proof: proof as HolderProver creates
        :return: json encoded True if proof is valid; False if not
        """

        LOGGER.debug('Verifier.verify_proof >>> proof_req: %s, proof: %s', proof_req, proof)

        s_id2schema = {}
        cd_id2cred_def = {}
        rr_id2rr_def = {}
        rr_id2rr = {}
        proof_ids = proof['identifiers']

        for proof_id in proof_ids:
            # schema
            s_id = proof_id['schema_id']
            if s_id not in s_id2schema:
                schema = json.loads(await self.get_schema(s_id))  # add to cache en passant
                if not schema:
                    LOGGER.debug(
                        'Verifier.verify_proof: <!< absent schema %s, proof req may be for another ledger',
                        s_id)
                    raise AbsentSchema(
                        'Absent schema {}, proof req may be for another ledger'.format(s_id))
                s_id2schema[s_id] = schema

            # cred def
            cd_id = proof_id['cred_def_id']
            if cd_id not in cd_id2cred_def:
                cred_def = json.loads(await self.get_cred_def(cd_id))  # add to cache en passant
                cd_id2cred_def[cd_id] = cred_def

            # rev reg def
            rr_id = proof_id['rev_reg_id']
            if not rr_id:
                continue

            rr_def_json = await self._get_rev_reg_def(rr_id)
            rr_id2rr_def[rr_id] = json.loads(rr_def_json)

            # timestamp
            timestamp = proof_id['timestamp']
            with REVO_CACHE.lock:
                revo_cache_entry = REVO_CACHE.get(rr_id, None)
                (rr_json, _) = await revo_cache_entry.get_state_json(self._build_rr_state_json, timestamp, timestamp)
                if rr_id not in rr_id2rr:
                    rr_id2rr[rr_id] = {}
                rr_id2rr[rr_id][timestamp] = json.loads(rr_json)

        rv = json.dumps(await anoncreds.verifier_verify_proof(
            json.dumps(proof_req),
            json.dumps(proof),
            json.dumps(s_id2schema),
            json.dumps(cd_id2cred_def),
            json.dumps(rr_id2rr_def),
            json.dumps(rr_id2rr)))

        LOGGER.debug('Verifier.verify_proof <<< %s', rv)
        return rv
