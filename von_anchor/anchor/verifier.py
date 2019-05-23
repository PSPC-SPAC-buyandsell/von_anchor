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


import json
import logging

from os import makedirs
from os.path import expanduser, join
from time import time

from indy import anoncreds, ledger
from indy.error import IndyError

from von_anchor.anchor.base import BaseAnchor
from von_anchor.cache import ArchivableCaches, CRED_DEF_CACHE, REVO_CACHE, SCHEMA_CACHE
from von_anchor.canon import canon
from von_anchor.error import (
    AbsentPool,
    AbsentRevReg,
    AbsentSchema,
    BadIdentifier,
    BadRevStateTime,
    ClosedPool)
from von_anchor.indytween import encode, Predicate, Role
from von_anchor.nodepool import NodePool
from von_anchor.util import cred_def_id2seq_no, ok_cred_def_id, ok_rev_reg_id, ok_schema_id
from von_anchor.validcfg import validate_config
from von_anchor.wallet import Wallet


LOGGER = logging.getLogger(__name__)


class Verifier(BaseAnchor):
    """
    Mixin for anchor acting in the capacity of Verifier. Verifier anchors verify proofs.
    """

    def __init__(self, wallet: Wallet, pool: NodePool = None, **kwargs) -> None:
        """
        Initializer for Verifier anchor. Retain input parameters; do not open wallet.

        :param wallet: wallet for anchor use
        :param pool: pool for anchor use
        :param config: configuration dict for cache archive behaviour; e.g.,

        ::

            {
                'parse-caches-on-open': True,
                'archive-verifier-caches-on-close': {
                    'schema_id': [
                        'R17v42T4pk...:2:tombstone:1.2',
                        '9cHbp54C8n...:2:business:2.0',
                        'Pcq76cx6jE...:2:birth_cert:1.0',
                        ...
                    ],
                    'cred_def_id': [
                        'R17v42T4pk...:3:CL:19:tag',
                        '9cHbp54C8n...:3:CL:37:tag',
                        'Pcq76cx6jE...:3:CL:51:tag',
                        ...
                    ]
                    'rev_reg_id': [
                        'R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:0',
                        'R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:1',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:0',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:1',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:2',
                        ...
                    ]
                }
            }

        """

        LOGGER.debug('Verifier.__init__ >>> wallet: %s, pool: %s, kwargs: %s', wallet, pool, kwargs)

        super().__init__(wallet, pool, **kwargs)

        self._config = kwargs.get('config', {})
        validate_config('verifier', self._config)

        self._dir_cache = join(expanduser('~'), '.indy_client', 'cache', self.name)
        makedirs(self._dir_cache, exist_ok=True)

        LOGGER.debug('Verifier.__init__ <<<')

    @staticmethod
    def least_role() -> Role:
        """
        Return the indy-sdk USER (null) role for a verifier, which does not need write access.

        :return: USER role
        """

        LOGGER.debug('AnchorSmith.least_role >>>')

        rv = Role.USER

        LOGGER.debug('AnchorSmith.least_role <<< %s', rv)
        return rv

    @property
    def config(self) -> dict:
        """
        Accessor for configuration dict

        :return: verifier config dict
        """

        return self._config

    @config.setter
    def config(self, value: dict) -> None:
        """
        Set configuration dict

        :param value: configuration dict
        """

        validate_config('verifier', value or {})
        self._config = value or {}

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

        Return rev reg state json and its transaction time on the distributed ledger,
        with upper bound at input timestamp of interest.

        Raise AbsentRevReg if no revocation registry exists on input rev reg id,
        or BadRevStateTime if requested timestamp predates revocation registry creation.

        :param rr_id: rev reg id
        :param timestamp: timestamp of interest (epoch seconds)
        :return: rev reg state json and ledger timestamp (epoch seconds)
        """

        LOGGER.debug('_Verifier._build_rr_state_json >>> rr_id: %s, timestamp: %s', rr_id, timestamp)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Verifier._build_rr_state_json <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

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
                LOGGER.debug('Verifier._build_rr_state_json <!< no rev reg exists on %s', rr_id)
                raise AbsentRevReg('No rev reg exists on {}'.format(rr_id))
        else:
            LOGGER.debug(
                '_Verifier._build_rr_state_json <!< Rev reg %s created after asked-for time %s',
                rr_id,
                timestamp)
            raise BadRevStateTime('Rev reg {} created after asked-for time {}'.format(rr_id, timestamp))

        rv = (rr_json, ledger_timestamp)
        LOGGER.debug('_Verifier._build_rr_state_json <<< %s', rv)
        return rv

    async def build_proof_req_json(self, cd_id2spec: dict) -> str:
        """
        Build and return indy-sdk proof request for input attributes and non-revocation intervals by cred def id.

        :param cd_id2spec: dict mapping cred def ids to:

            - (optionally) 'attrs': lists of names of attributes of interest (omit for all, empty list or None for none)
            - (optionally) '>=': (pred) inclusive int lower-bounds of interest (omit, empty list, or None for none)
            - (optionally) '>': (pred) exclusive int lower-bounds of interest (omit, empty list, or None for none)
            - (optionally) '<=': (pred) inclusive int upper-bounds of interest (omit, empty list, or None for none)
            - (optionally) '<': (pred) exclusive int upper-bounds of interest (omit, empty list, or None for none)
            - (optionally), 'interval': either
                - (2-tuple) pair of epoch second counts marking 'from' and 'to' timestamps, or
                - | single epoch second count to set 'from' and 'to' the same; default
                  | (now, now) for cred defs supporting revocation or None otherwise; e.g.,

        ::

            {
                'Vx4E82R17q...:3:CL:16:tag': {
                    'attrs': [  # request attrs 'name' and 'favouriteDrink' from this cred def's schema
                        'name',
                        'favouriteDrink'
                    ],
                    '>=': {  # request predicate score>=80 from this cred def
                        'score': 80
                    }
                    '<=': {  # request ranking <=10 from this cred def
                        'ranking': 10
                    }
                    'interval': 1528116008  # same instant for all attrs and preds of corresponding schema
                },
                'R17v42T4pk...:3:CL:19:tag': None,  # request all attrs, no preds, default intervals on all attrs
                'e3vc5K168n...:3:CL:23:tag': {},  # request all attrs, no preds, default intervals on all attrs
                'Z9ccax812j...:3:CL:27:tag': {  # request all attrs, no preds, this interval on all attrs
                    'interval': (1528112408, 1528116008)
                },
                '9cHbp54C8n...:3:CL:37:tag': {  # request no attrs and some predicates; specify interval
                    'attrs': [],  # or equivalently, 'attrs': None
                    '>=': {
                        'employees': '50'  # nicety: implementation converts to int for caller
                    },
                    '>=': {
                        'revenue': '10000000'  # nicety: implementation converts to int for caller
                        'ebidta': 0
                    }
                    'interval': (1528029608, 1528116008)
                },
                '6caBcmLi33...:3:CL:41:tag': {  # all attrs, one pred, default intervals to now on attrs & pred
                    '>': {
                        'regEpoch': 1514782800
                    }
                },
                ...
            }

        :return: indy-sdk proof request json
        """

        LOGGER.debug('Verifier.build_proof_req_json >>> cd_id2spec: %s', cd_id2spec)

        cd_id2schema = {}
        now = int(time())
        rv = {
            'nonce': str(int(time())),
            'name': 'proof_req',
            'version': '0.0',
            'requested_attributes': {},
            'requested_predicates': {}
        }

        for cd_id in cd_id2spec:
            if not ok_cred_def_id(cd_id):
                LOGGER.debug('Verifier.build_proof_req_json <!< Bad cred def id %s', cd_id)
                raise BadIdentifier('Bad cred def id {}'.format(cd_id))

            interval = None
            cred_def = json.loads(await self.get_cred_def(cd_id))
            seq_no = cred_def_id2seq_no(cd_id)
            cd_id2schema[cd_id] = json.loads(await self.get_schema(seq_no))

            if 'revocation' in cred_def['value']:
                fro_to = cd_id2spec[cd_id].get('interval', (now, now)) if cd_id2spec[cd_id] else (now, now)
                interval = {
                    'from': fro_to if isinstance(fro_to, int) else min(fro_to),
                    'to': fro_to if isinstance(fro_to, int) else max(fro_to)
                }

            for attr in (cd_id2spec[cd_id].get('attrs', cd_id2schema[cd_id]['attrNames']) or []
                    if cd_id2spec[cd_id] else cd_id2schema[cd_id]['attrNames']):
                attr_uuid = '{}_{}_uuid'.format(seq_no, canon(attr))
                rv['requested_attributes'][attr_uuid] = {
                    'name': attr,
                    'restrictions': [{
                        'cred_def_id': cd_id
                    }]
                }
                if interval:
                    rv['requested_attributes'][attr_uuid]['non_revoked'] = interval

            for pred in Predicate:
                for attr in (cd_id2spec[cd_id].get(pred.value.math, {}) or {} if cd_id2spec[cd_id] else {}):
                    pred_uuid = '{}_{}_{}_uuid'.format(seq_no, canon(attr), pred.value.fortran)
                    try:
                        rv['requested_predicates'][pred_uuid] = {
                            'name': attr,
                            'p_type': pred.value.math,
                            'p_value': Predicate.to_int(cd_id2spec[cd_id][pred.value.math][attr]),
                            'restrictions': [{
                                'cred_def_id': cd_id
                            }]
                        }
                    except ValueError:
                        LOGGER.info(
                            'cannot build %s predicate on non-int bound %s for %s',
                            pred.value.fortran,
                            cd_id2spec[cd_id][pred.value.math][attr],
                            attr)
                        continue  # int conversion failed - reject candidate
                    if interval:
                        rv['requested_predicates'][pred_uuid]['non_revoked'] = interval

        LOGGER.debug('Verifier.build_proof_req_json <<< %s', json.dumps(rv))
        return json.dumps(rv)

    async def load_cache_for_verification(self, archive: bool = False) -> int:
        """
        Load schema, cred def, revocation caches; optionally archive enough to go
        offline and be able to verify proof on content marked of interest in configuration.

        Return timestamp (epoch seconds) of cache load event, also used as subdirectory
        for cache archives.

        :param archive: True to archive now or False to demur (subclasses may still
            need to augment archivable caches further)
        :return: cache load event timestamp (epoch seconds)
        """

        LOGGER.debug('Verifier.load_cache_for_verification >>> archive: %s', archive)

        rv = int(time())
        for s_id in self.config.get('archive-verifier-caches-on-close', {}).get('schema_id', {}):
            if ok_schema_id(s_id):
                with SCHEMA_CACHE.lock:
                    await self.get_schema(s_id)
            else:
                LOGGER.info('Not archiving schema for specified bad id %s', s_id)
        for cd_id in self.config.get('archive-verifier-caches-on-close', {}).get('cred_def_id', {}):
            if ok_cred_def_id(cd_id):
                with CRED_DEF_CACHE.lock:
                    await self.get_cred_def(cd_id)
            else:
                LOGGER.info('Not archiving cred def for specified bad id %s', cd_id)
        for rr_id in self.config.get('archive-verifier-caches-on-close', {}).get('rev_reg_id', {}):
            if ok_rev_reg_id(rr_id):
                await self.get_rev_reg_def(rr_id)
                with REVO_CACHE.lock:
                    revo_cache_entry = REVO_CACHE.get(rr_id, None)
                    if revo_cache_entry:
                        try:
                            await revo_cache_entry.get_state_json(self._build_rr_state_json, rv, rv)
                        except ClosedPool:
                            LOGGER.warning(
                                'Verifier %s is offline from pool %s, cannot update revo cache reg state for %s to %s',
                                self.name,
                                self.pool.name,
                                rr_id,
                                rv)
                        except AbsentPool:
                            LOGGER.warning(
                                'Verifier %s has no pool, cannot update revo cache reg state for %s to %s',
                                self.name,
                                rr_id,
                                rv)
            else:
                LOGGER.info('Not archiving rev reg for specified bad id %s', rr_id)

        if archive:
            ArchivableCaches.archive(self.dir_cache)
        LOGGER.debug('Verifier.load_cache_for_verification <<< %s', rv)
        return rv

    async def open(self) -> 'Verifier':
        """
        Explicit entry. Perform ancestor opening operations,
        then parse cache from archive if so configured, and
        synchronize revocation registry to tails tree content.

        :return: current object
        """

        LOGGER.debug('Verifier.open >>>')

        await super().open()
        if self.config.get('parse-caches-on-open', False):
            ArchivableCaches.parse(self.dir_cache)

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

        if self.config.get('archive-verifier-caches-on-close', {}):
            await self.load_cache_for_verification(True)
            ArchivableCaches.purge_archives(self.dir_cache, True)

        await BaseAnchor.close(self)

        LOGGER.debug('Verifier.close <<<')

    @staticmethod
    def check_encoding(proof_req: dict, proof: dict) -> bool:
        """
        Return whether the proof's raw values correspond to their encodings
        as cross-referenced against proof request.

        :param proof request: proof request
        :param proof: corresponding proof to check
        :return: True if OK, False for encoding mismatch
        """

        LOGGER.debug('Verifier.check_encoding <<< proof_req: %s, proof: %s', proof_req, proof)

        cd_id2proof_id = {}  # invert proof['identifiers'] per cd_id
        p_preds = {}  # cd_id and attr to bound
        for idx in range(len(proof['identifiers'])):
            cd_id = proof['identifiers'][idx]['cred_def_id']
            cd_id2proof_id[cd_id] = idx  # since at most 1 cred per cred def
            p_preds[cd_id] = {
                ge_proof['predicate']['attr_name']: ge_proof['predicate']['value']
                for ge_proof in proof['proof']['proofs'][idx]['primary_proof']['ge_proofs']
            }

        for (uuid, req_attr) in proof_req['requested_attributes'].items():  # proof req xref proof per revealed attr
            canon_attr = canon(req_attr['name'])
            proof_ident_idx = cd_id2proof_id[req_attr['restrictions'][0]['cred_def_id']]
            enco = proof['proof']['proofs'][proof_ident_idx]['primary_proof']['eq_proof']['revealed_attrs'].get(
                canon_attr)
            if not enco:
                continue  # requested but declined from revelation in proof: must appear in a predicate
            if enco != proof['requested_proof']['revealed_attrs'][uuid]['encoded']:
                LOGGER.debug('Verifier.check_proof_encoding <<< False')
                return False
            if enco != encode(proof['requested_proof']['revealed_attrs'][uuid]['raw']):
                LOGGER.debug('Verifier.check_proof_encoding <<< False')
                return False

        for (uuid, req_pred) in proof_req['requested_predicates'].items():  # proof req xref proof per pred
            canon_attr = canon(req_pred['name'])
            if p_preds[req_pred['restrictions'][0]['cred_def_id']].get(canon_attr) != req_pred['p_value']:
                LOGGER.debug('Verifier.check_proof_encoding <<< False')
                return False

        LOGGER.debug('Verifier.check_proof_encoding <<< True')
        return True

    async def verify_proof(self, proof_req: dict, proof: dict) -> str:
        """
        Verify proof as Verifier. Raise AbsentRevReg if a proof cites a revocation registry
        that does not exist on the distributed ledger.

        :param proof_req: proof request as Verifier creates, as per proof_req_json above
        :param proof: proof as HolderProver creates
        :return: json encoded True if proof is valid; False if not
        """

        LOGGER.debug('Verifier.verify_proof >>> proof_req: %s, proof: %s', proof_req, proof)

        if not Verifier.check_encoding(proof_req, proof):
            LOGGER.info(
                'Proof encoding does not cross-reference with proof request %s: failing verification',
                proof_req.get('nonce', '(missing nonce)'))
            LOGGER.debug('Verifier.verify_proof <<< "False"')
            return json.dumps(False)

        async def _set_schema(s_id: str) -> None:
            nonlocal s_id2schema
            if not ok_schema_id(s_id):
                LOGGER.debug('Verifier.verify_proof <!< Bad schema id %s', s_id)
                raise BadIdentifier('Bad schema id {}'.format(s_id))
            if s_id not in s_id2schema:
                schema = json.loads(await self.get_schema(s_id))  # add to cache en passant
                if not schema:
                    LOGGER.debug(
                        'Verifier.verify_proof <!< absent schema %s, proof req may be for another ledger',
                        s_id)
                    raise AbsentSchema('Absent schema {}, proof req may be for another ledger'.format(s_id))
                s_id2schema[s_id] = schema

        async def _set_cred_def(cd_id: str) -> None:
            nonlocal cd_id2cred_def
            if not ok_cred_def_id(cd_id):
                LOGGER.debug('Verifier.verify_proof <!< Bad cred def id %s', cd_id)
                raise BadIdentifier('Bad cred def id {}'.format(cd_id))
            if cd_id not in cd_id2cred_def:
                cd_id2cred_def[cd_id] = json.loads(await self.get_cred_def(cd_id))  # add to cache en passant

        async def _set_rev_reg_def(rr_id: str) -> bool:
            """
            Return true to continue to timestamp setting, false to short-circuit
            """
            nonlocal rr_id2rr_def
            if not rr_id:
                return False
            if not ok_rev_reg_id(rr_id):
                LOGGER.debug('Verifier.verify_proof <!< Bad rev reg id %s', rr_id)
                raise BadIdentifier('Bad rev reg id {}'.format(rr_id))
            if rr_id not in rr_id2rr_def:
                rr_id2rr_def[rr_id] = json.loads(await self.get_rev_reg_def(rr_id))
            return True

        async def _set_timestamp(rr_id: str, timestamp: int) -> None:
            nonlocal rr_id2rr
            with REVO_CACHE.lock:
                revo_cache_entry = REVO_CACHE.get(rr_id, None)
                (rr_json, _) = await revo_cache_entry.get_state_json(self._build_rr_state_json, timestamp, timestamp)
                if rr_id not in rr_id2rr:
                    rr_id2rr[rr_id] = {}
                rr_id2rr[rr_id][timestamp] = json.loads(rr_json)

        s_id2schema = {}
        cd_id2cred_def = {}
        rr_id2rr_def = {}
        rr_id2rr = {}
        proof_ids = proof['identifiers']

        for proof_id in proof_ids:
            await _set_schema(proof_id['schema_id'])
            await _set_cred_def(proof_id['cred_def_id'])
            rr_id = proof_id['rev_reg_id']
            if await _set_rev_reg_def(rr_id):
                await _set_timestamp(rr_id, proof_id['timestamp'])

        rv = json.dumps(await anoncreds.verifier_verify_proof(
            json.dumps(proof_req),
            json.dumps(proof),
            json.dumps(s_id2schema),
            json.dumps(cd_id2cred_def),
            json.dumps(rr_id2rr_def),
            json.dumps(rr_id2rr)))

        LOGGER.debug('Verifier.verify_proof <<< %s', rv)
        return rv
