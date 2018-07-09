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
from os.path import basename, expanduser, isfile, join
from time import time
from typing import Set

from indy import anoncreds, ledger
from indy.error import IndyError, ErrorCode
from von_agent.agent.base import _BaseAgent
from von_agent.cache import Caches, RevoCacheEntry, CRED_DEF_CACHE, REVO_CACHE, SCHEMA_CACHE
from von_agent.error import (
    AbsentCredDef,
    AbsentInterval,
    AbsentLinkSecret,
    AbsentRevReg,
    AbsentSchema,
    AbsentTails,
    BadRevStateTime,
    ClosedPool,
    CredentialFocus)
from von_agent.nodepool import NodePool
from von_agent.tails import Tails
from von_agent.util import cred_def_id2seq_no, prune_creds_json, rev_reg_id2cred_def_id__tag
from von_agent.validate_config import validate_config
from von_agent.wallet import Wallet


LOGGER = logging.getLogger(__name__)


class HolderProver(_BaseAgent):
    """
    Mixin for agent acting in the role of w3c Holder and indy-sdk Prover.  A Holder holds
    credentials; a Prover produces proof of credentials. Revocation support requires
    the holder-prover agent to manage tails files.
    """

    def __init__(self, wallet: Wallet, pool: NodePool, cfg: dict = None) -> None:
        """
        Initializer for HolderProver agent. Retain input parameters; do not open wallet nor tails writer.

        :param wallet: wallet for agent use
        :param pool: pool for agent use
        :param cfg: configuration dict for cache archive behaviour; e.g.,

        ::

            {
                'parse-cache-on-open': True
                'archive-cache-on-close': True,
            }

        """

        LOGGER.debug('HolderProver.__init__ >>> wallet: %s, pool: %s, cfg: %s', wallet, pool, cfg)

        super().__init__(wallet, pool)
        self._link_secret = None

        self._dir_tails = join(expanduser('~'), '.indy_client', 'tails')
        makedirs(self._dir_tails, exist_ok=True)

        self._cfg = cfg or {}
        validate_config('holder-prover', self._cfg)

        self._dir_cache = join(expanduser('~'), '.indy_client', 'wallet', self.wallet.name, 'cache')
        makedirs(self._dir_cache, exist_ok=True)

        LOGGER.debug('HolderProver.__init__ <<<')

    def _assert_link_secret(self, action: str):
        """
        Raise AbsentLinkSecret if link secret is not set.

        :param action: action requiring link secret
        """

        if self._link_secret is None:
            LOGGER.debug('HolderProver._assert_link_secret: action %s requires link secret but it is not set', action)
            raise AbsentLinkSecret('Action {} requires link secret but it is not set'.format(action))

    @property
    def cfg(self) -> dict:
        """
        Accessor for configuration dict

        :return: holder-prover config dict
        """

        return self._cfg

    @cfg.setter
    def cfg(self, value: dict) -> None:
        """
        Set configuration dict

        :param value: configuration dict
        """

        self._cfg = value or {}
        validate_config('holder-prover', self._cfg)

    @property
    def dir_cache(self) -> str:
        """
        Accessor for cache archive directory

        :return: holder-prover cache archive directory
        """

        return self._dir_cache

    async def _sync_revoc(self, rr_id: str) -> None:
        """
        Pick up tails file reader handle for input revocation registry identifier.  If no symbolic
        link is present, get the revocation registry definition to retrieve its tails file hash,
        then find the tails file and link it.

        Raise AbsentTails for missing corresponding tails file.

        :param rr_id: revocation registry identifier
        """

        LOGGER.debug('HolderProver._sync_revoc >>> rr_id: %s', rr_id)

        (cd_id, tag) = rev_reg_id2cred_def_id__tag(rr_id)

        try:
            json.loads(await self.get_cred_def(cd_id))
        except AbsentCredDef:
            LOGGER.debug(
                'HolderProver._sync_revoc: <!< corrupt tails tree %s may be for another ledger', self._dir_tails)
            raise AbsentCredDef('Corrupt tails tree {} may be for another ledger'.format(self._dir_tails))
        except ClosedPool:
            pass  # carry on, may be OK from cache only

        with REVO_CACHE.lock:
            revo_cache_entry = REVO_CACHE.get(rr_id, None)
            tails = revo_cache_entry.tails if revo_cache_entry else None
            if tails is None:  #  it's not yet set in cache
                try:
                    tails = await Tails(self._dir_tails, cd_id, tag).open()
                except AbsentTails:  # get hash from ledger and check for tails file
                    rrdef = json.loads(await self._get_rev_reg_def(rr_id))
                    tails_hash = rrdef['value']['tailsHash']
                    path_tails = join(Tails.dir(self._dir_tails, rr_id), tails_hash)
                    if not isfile(path_tails):
                        LOGGER.debug('HolderProver._sync_revoc: <!< No tails file present at %s', path_tails)
                        raise AbsentTails('No tails file present at {}'.format(path_tails))
                    Tails.associate(self._dir_tails, rr_id, tails_hash)
                    tails = await Tails(self._dir_tails, cd_id, tag).open()  # OK now since tails file present

                if revo_cache_entry is None:
                    REVO_CACHE[rr_id] = RevoCacheEntry(None, tails)
                else:
                    REVO_CACHE[rr_id].tails = tails

        LOGGER.debug('HolderProver._sync_revoc <<<')

    async def _build_rr_delta_json(self, rr_id: str, to: int, fro: int = None, fro_delta: dict = None) -> (str, int):
        """
        Build rev reg delta json, potentially starting from existing (earlier) delta.

        Return delta json and its timestamp on the distributed ledger.

        Raise AbsentRevReg for no such revocation registry, or BadRevStateTime for a requested delta to
        a time preceding revocation registry creation.

        :param rr_id: rev reg id
        :param to: time (epoch seconds) of interest; upper-bounds returned timestamp
        :param fro: optional prior time of known delta json
        :param fro_delta: optional known delta as of time fro
        :return: rev reg delta json and ledger timestamp (epoch seconds)
        """

        LOGGER.debug(
            '_HolderProver._build_rr_delta_json >>> rr_id: %s, to: %s, fro: %s, fro_delta: %s',
            rr_id,
            to,
            fro,
            fro_delta)

        rr_delta_json = None
        ledger_timestamp = None

        get_rr_delta_req_json = await ledger.build_get_revoc_reg_delta_request(self.did, rr_id, fro, to)
        resp_json = await self._submit(get_rr_delta_req_json)
        resp = json.loads(resp_json)
        if resp.get('result', {}).get('data', None) and resp['result']['data'].get('value', None):
            # delta is to some time at or beyond rev reg creation, carry on
            try:
                (_, rr_delta_json, ledger_timestamp) = await ledger.parse_get_revoc_reg_delta_response(resp_json)
            except IndyError:  # ledger replied, but there is no such rev reg
                LOGGER.debug('_HolderProver._build_rr_delta_json: <!< no rev reg exists on %s', rr_id)
                raise AbsentRevReg('No rev reg exists on {}'.format(rr_id))
        else:
            LOGGER.debug(
                '_HolderProver._build_rr_delta_json: <!< Rev reg %s created after asked-for time %s',
                rr_id,
                to)
            raise BadRevStateTime('Rev reg {} created after asked-for time {}'.format(rr_id, to))

        if fro and fro_delta:
            rr_delta_json = await anoncreds.issuer_merge_revocation_registry_deltas(
                json.dumps(fro_delta),
                rr_delta_json)

        rv = (rr_delta_json, ledger_timestamp)
        LOGGER.debug('_HolderProver._build_rr_delta_json <<< %s', rv)
        return rv

    async def build_proof_req_json(self, cd_id2spec: dict, cache_only: bool = False) -> str:
        """
        Build and return indy-sdk proof request for input attributes and timestamps by cred def id.

        Raise AbsentInterval if caller specifies cache_only and default non-revocation intervals, but
        revocation cache does not have delta frames for any revocation registries on a specified cred def.

        :param cd_id2spec: dict mapping cred def ids to:
            - (optionally) 'attrs': lists of names of attributes of interest (omit for all, empty list or None for none)
            - (optionally) 'minima': (pred) integer lower-bounds of interest (omit, empty list, or None for none)
            - (optionally), 'interval': (2-tuple) pair of epoch second counts marking 'from' and 'to' timestamps,
                or single epoch second count to set 'from' and 'to' the same: default (now, now) if cache_only
                is clear, or latest values from cache if cache_only is set.
            e.g.,

        ::

            {
                'Vx4E82R17q...:3:CL:16:0': {
                    'attrs': [  # request attrs 'name' and 'favouriteDrink' from this cred def's schema
                        'name',
                        'favouriteDrink'
                    ],
                    'minima': {  # request predicate score>=80 from this cred def
                        'score': 80
                    }
                    'interval': 1528116008  # same instant for all attrs and preds of corresponding schema
                },
                'R17v42T4pk...:3:CL:19:0': None,  # request all attrs, no preds, default intervals on all attrs
                'e3vc5K168n...:3:CL:23:0': {},  # request all attrs, no preds, default intervals on all attrs
                'Z9ccax812j...:3:CL:27:0': {  # request all attrs, no preds, this interval on all attrs
                    'interval': (1528112408, 1528116008)
                },
                '9cHbp54C8n...:3:CL:37:0': {  # request no attrs, one pred, specify interval on pred
                    'attrs': [],  # or equivalently, 'attrs': None
                    'minima': {
                        'employees': '50'  # nicety: implementation converts to int for caller
                    },
                    'interval': (1528029608, 1528116008)
                },
                '6caBcmLi33...:3:CL:41:0': {  # all attrs, one pred, default intervals to now on attrs & pred
                    'minima': {
                        'regEpoch': 1514782800
                    }
                }
                ...
            }

        :param cache_only: (True) take default intervals (per cred def id) from latest cached deltas, or
            (default False) use current time
        :return: indy-sdk proof request json
        """

        LOGGER.debug('HolderProver.build_proof_req_json >>> cd_id2spec: %s, cache_only: %s', cd_id2spec, cache_only)

        cd_id2schema = {}
        now = int(time())
        proof_req = {
            'nonce': str(int(time())),
            'name': 'proof_req',
            'version': '0.0',
            'requested_attributes': {},
            'requested_predicates': {}
        }

        for cd_id in cd_id2spec:
            interval = None
            cred_def = json.loads(await self.get_cred_def(cd_id))
            seq_no = cred_def_id2seq_no(cd_id)
            cd_id2schema[cd_id] = json.loads(await self.get_schema(seq_no))

            if 'revocation' in cred_def['value']:
                if cache_only and not (cd_id2spec.get(cd_id, {}) or {}).get('interval', None):
                    with REVO_CACHE.lock:
                        (fro, to) = REVO_CACHE.dflt_interval(cd_id)
                        if not (fro and to):
                            LOGGER.debug(
                                'HolderProver.build_proof_req_json: <!< no cached delta for non-revoc interval on %s',
                                cd_id)
                            raise AbsentInterval('No cached delta for non-revoc interval on {}'.format(cd_id))
                        interval = {
                            'from': fro,
                            'to': to
                        }
                else:
                    fro_to = cd_id2spec[cd_id].get('interval', (now, now)) if cd_id2spec[cd_id] else (now, now)
                    interval = {
                        'from': fro_to if isinstance(fro_to, int) else min(fro_to),
                        'to': fro_to if isinstance(fro_to, int) else max(fro_to)
                    }

            for attr in (cd_id2spec[cd_id].get('attrs', cd_id2schema[cd_id]['attrNames']) or []
                    if cd_id2spec[cd_id] else cd_id2schema[cd_id]['attrNames']):
                attr_uuid = '{}_{}_uuid'.format(seq_no, attr)
                proof_req['requested_attributes'][attr_uuid] = {
                    'name': attr,
                    'restrictions': [{
                        'cred_def_id': cd_id
                    }]
                }
                if interval:
                    proof_req['requested_attributes'][attr_uuid]['non_revoked'] = interval

            for attr in (cd_id2spec[cd_id].get('minima', {}) or {} if cd_id2spec[cd_id] else {}):
                pred_uuid = '{}_{}_uuid'.format(seq_no, attr)
                try:
                    proof_req['requested_predicates'][pred_uuid] = {
                        'name': attr,
                        'p_type': '>=',
                        'p_value': int(cd_id2spec[cd_id]['minima'][attr]),
                        'restrictions': [{
                            'cred_def_id': cd_id
                        }]
                    }
                except ValueError:
                    LOGGER.info(
                        'cannot build predicate on non-int minimum %s for %s',
                        cd_id2spec[cd_id]['minima'][attr],
                        attr)
                    continue  # int conversion failed - reject candidate
                if interval:
                    proof_req['requested_predicates'][pred_uuid]['non_revoked'] = interval

        rv_json = json.dumps(proof_req)
        LOGGER.debug('HolderProver.build_proof_req_json <<< %s', rv_json)
        return rv_json

    async def build_req_creds_json(self, creds: dict, filt: dict = None, filt_dflt_incl: bool = False) -> str:
        """
        Build and return indy-sdk requested credentials json from input indy-sdk creds structure
        through specified filter.

        :param creds: indy-sdk creds structure
        :param filt: filter  mapping cred def ids to:
            - (optionally) 'attr-match': dict mapping attributes to values (omit, empty dict, or None to match all);
            - (optionally) 'minima': (pred) integer lower-bounds of interest (omit, empty dict, or None to match all);
            omit parameter or specify empty dict or None for no filter, matching all; e.g.,

        ::

            {
                'Vx4E82R17q...:3:CL:16:0': {
                    'attr-match': {
                        'name': 'Alex',
                        'sex': 'M',
                        'favouriteDrink': None
                    },
                    'minima': {  # if both attr-match and minima present, combined conjunctively (i.e., via AND)
                        'favouriteNumber' : 10,
                        'score': 100  # if more than one minimum present, combined conjunctively (i.e., via AND)
                    }
                },
                'R17v42T4pk...:3:CL:19:0': {
                    'attr-match': {
                        'height': 175,
                        'birthdate': '1975-11-15'  # combined conjunctively (i.e., via AND)
                    }
                },
                'Z9ccax812j...:3:CL:27:0': {
                    'attr-match': {}  # match all attributes on this cred def
                },
                '9cHbp54C8n...:3:CL:37:0': {
                    'minima': {  # request all attributes on this cred def, request preds specifying employees>=50
                        'employees' : 50,
                    }
                }
                ...
            }

        :param filt_dflt_incl: whether to request (True) all creds by attribute/predicate
            that filter does not identify by cred def, or (False) to exclude them. Note that
            if the filter is None or {}, this parameter is unnecessary - it applies to a filter,
            not a non-filter.
        :return: indy_sdk requested_credentials json for use in proof creation
        """

        LOGGER.debug('HolderProver.build_req_creds_json >>> creds: %s, filt: %s', creds, filt)

        req_creds = {
            'self_attested_attributes': {},
            'requested_attributes': {},
            'requested_predicates': {}
        }

        def _add_cred(cred, uuid, key):
            nonlocal req_creds
            req_creds[key][uuid] = {
                'cred_id': cred['cred_info']['referent'],
                'revealed': True
            }
            if cred.get('interval', None):
                req_creds[key][uuid]['timestamp'] = cred['interval']['to']
            if key == 'requested_attributes':
                req_creds[key][uuid]['revealed'] = True

        if filt:
            for cd_id in filt:
                try:
                    json.loads(await self.get_cred_def(cd_id))
                except AbsentCredDef:
                    LOGGER.warning(
                        'HolderProver.build_req_creds_json: ignoring filter criterion, no cred def on %s', cd_id)
                    filt.pop(cd_id)

        for attr_uuid in creds.get('attrs', {}):
            for cred in creds['attrs'][attr_uuid]:
                if attr_uuid in req_creds['requested_attributes']:
                    continue
                cred_info = cred['cred_info']
                cred_cd_id = cred_info['cred_def_id']

                if filt:
                    if cred_cd_id not in filt:
                        if filt_dflt_incl:
                            _add_cred(cred, attr_uuid, 'requested_attributes')
                        continue
                    if cred_cd_id in filt and 'attr-match' in (filt[cred_cd_id] or {}):  # maybe filt[cred_cd_id]: None
                        if not {k: str(filt[cred_cd_id].get('attr-match', {})[k])
                                for k in filt[cred_cd_id].get('attr-match', {})}.items() <= cred_info['attrs'].items():
                            continue
                    _add_cred(cred, attr_uuid, 'requested_attributes')
                else:
                    _add_cred(cred, attr_uuid, 'requested_attributes')

        for pred_uuid in creds.get('predicates', {}):
            for cred in creds['predicates'][pred_uuid]:
                if pred_uuid in req_creds['requested_predicates']:
                    continue
                cred_info = cred['cred_info']
                cred_cd_id = cred_info['cred_def_id']

                if filt:
                    if cred_cd_id not in filt:
                        if filt_dflt_incl:
                            _add_cred(cred, pred_uuid, 'requested_predicates')
                        continue
                    if cred_cd_id in filt and 'minima' in (filt[cred_cd_id] or {}):  # maybe filt[cred_cd_id]: None
                        minima = filt[cred_cd_id].get('minima', {})
                        try:
                            if any((attr not in cred_info['attrs'])
                                or (int(cred_info['attrs'][attr]) < int(minima[attr]))
                                    for attr in minima):
                                continue
                        except ValueError:
                            continue  # int conversion failed - reject candidate
                    _add_cred(cred, pred_uuid, 'requested_predicates')
                else:
                    _add_cred(cred, pred_uuid, 'requested_predicates')

        rv_json = json.dumps(req_creds)
        LOGGER.debug('HolderProver.build_req_creds_json <<< %s', rv_json)
        return rv_json

    def dir_tails(self, rr_id: str) -> str:
        """
        Return path to the correct directory for the tails file on input revocation registry identifier.

        :param rr_id: revocation registry identifier of interest
        :return: path to tails dir for input revocation registry identifier
        """

        return Tails.dir(self._dir_tails, rr_id)

    async def open(self) -> 'HolderProver':
        """
        Explicit entry. Perform ancestor opening operations,
        then parse cache from archive if so configured, and
        synchronize revocation registry to tails tree content.

        :return: current object
        """

        LOGGER.debug('HolderProver.open >>>')

        await super().open()
        if self.cfg.get('parse-cache-on-open', False):
            Caches.parse(self.dir_cache)

        for path_rr_id in Tails.links(self._dir_tails):
            await self._sync_revoc(basename(path_rr_id))

        LOGGER.debug('HolderProver.open <<<')
        return self

    async def close(self) -> None:
        """
        Explicit exit. If so configured, populate cache to prove all creds in
        wallet offline if need be, archive cache, and purge prior cache archives.

        :return: current object
        """

        LOGGER.debug('HolderProver.close >>>')

        if self.cfg.get('archive-cache-on-close', False):
            await self.load_cache(True)
            Caches.purge_archives(self.dir_cache, True)

        await super().close()
        for path_rr_id in Tails.links(self._dir_tails):
            rr_id = basename(path_rr_id)
            try:
                await self._sync_revoc(rr_id)
            except ClosedPool:
                LOGGER.warning('HolderProver sync-revoc on close required ledger for %s but pool was closed', rr_id)

        LOGGER.debug('HolderProver.close <<<')

    def rev_regs(self) -> list:
        """
        Return list of revocation registry identifiers for which HolderProver has tails files.

        :return: list of revocation registry identifiers for which HolderProver has tails files
        """

        LOGGER.debug('HolderProver.rev_regs >>>')

        rv = [basename(f) for f in Tails.links(self._dir_tails)]
        LOGGER.debug('HolderProver.rev_regs <<< %s', rv)
        return rv

    async def create_link_secret(self, link_secret: str) -> None:
        """
        Create link secret (a.k.a. master secret) used in proofs by HolderProver.

        Raise any IndyError causing failure to set link secret in wallet.

        :param link_secret: label for link secret; indy-sdk uses label to generate link secret
        """

        LOGGER.debug('HolderProver.create_link_secret >>> link_secret: %s', link_secret)

        try:
            await anoncreds.prover_create_master_secret(self.wallet.handle, link_secret)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.AnoncredsMasterSecretDuplicateNameError:
                LOGGER.info('HolderProver did not create link secret - it already exists')
            else:
                LOGGER.debug(
                    'HolderProver.create_link_secret: <!< cannot create link secret %s, indy error code %s',
                    self.wallet.name,
                    x_indy.error_code)
                raise

        self._link_secret = link_secret
        LOGGER.debug('HolderProver.create_link_secret <<<')

    async def create_cred_req(self, cred_offer_json: str, cd_id: str) -> (str, str):
        """
        Create credential request as HolderProver and store in wallet; return credential json and metadata json.

        Raise AbsentLinkSecret if link secret not set.

        :param cred_offer_json: credential offer json
        :param cd_id: credential definition identifier
        :return: cred request json and corresponding metadata json as created and stored in wallet
        """

        LOGGER.debug('HolderProver.create_cred_req >>> cred_offer_json: %s, cd_id: %s', cred_offer_json, cd_id)

        self._assert_link_secret('create_cred_req')

        # Check that ledger has schema on ledger where cred def expects - in case of pool reset with extant wallet
        cred_def_json = await self.get_cred_def(cd_id)
        schema_seq_no = int(json.loads(cred_def_json)['schemaId'])
        schema_json = await self.get_schema(schema_seq_no)
        schema = json.loads(schema_json)
        if not schema:
            LOGGER.debug(
                'HolderProver.create_cred_req: <!< absent schema@#%s, cred req may be for another ledger',
                schema_seq_no)
            raise AbsentSchema('Absent schema@#{}, cred req may be for another ledger'.format(schema_seq_no))
        (cred_req_json, cred_req_metadata_json) = await anoncreds.prover_create_credential_req(
            self.wallet.handle,
            self.did,
            cred_offer_json,
            cred_def_json,
            self._link_secret)
        rv = (cred_req_json, cred_req_metadata_json)

        LOGGER.debug('HolderProver.create_cred_req <<< %s', rv)
        return rv

    async def store_cred(self, cred_json: str, cred_req_metadata_json) -> str:
        """
        Store cred in wallet as HolderProver, return its credential identifier as created in wallet.

        Raise AbsentTails if tails file not available for revocation registry for input credential.

        :param cred_json: credential json as HolderProver created
        :param cred_req_metadata_json: credential request metadata as HolderProver created via create_cred_req()
        :return: credential identifier within wallet
        """

        LOGGER.debug(
            'HolderProver.store_cred >>> cred_json: %s, cred_req_metadata_json: %s',
            cred_json,
            cred_req_metadata_json)

        cred = json.loads(cred_json)
        cred_def_json = await self.get_cred_def(cred['cred_def_id'])
        rr_id = cred['rev_reg_id']
        rrdef_json = None
        if rr_id:
            await self._sync_revoc(rr_id)
            rrdef_json = await self._get_rev_reg_def(rr_id)

        rv = await anoncreds.prover_store_credential(
            self.wallet.handle,
            None,  # cred_id, let indy-sdk generate random uuid
            cred_req_metadata_json,
            cred_json,
            cred_def_json,
            rrdef_json)

        LOGGER.debug('HolderProver.store_cred <<< %s', rv)
        return rv

    async def load_cache(self, archive: bool = False) -> int:
        """
        Load caches and archive enough to go offline and be able to generate proof
        on all credentials in wallet.

        Return timestamp (epoch seconds) of cache load event, also used as subdirectory
        for cache archives.

        :return: cache load event timestamp (epoch seconds)
        """

        LOGGER.debug('HolderProver.load_cache >>> archive: %s', archive)

        rv = int(time())
        box_ids = json.loads(await self.get_box_ids_json())
        for s_id in box_ids['schema_id']:
            with SCHEMA_CACHE.lock:
                await self.get_schema(s_id)
        for cd_id in box_ids['cred_def_id']:
            with CRED_DEF_CACHE.lock:
                await self.get_cred_def(cd_id)
        for rr_id in box_ids['rev_reg_id']:
            await self._get_rev_reg_def(rr_id)
            with REVO_CACHE.lock:
                revo_cache_entry = REVO_CACHE.get(rr_id, None)
                if revo_cache_entry:
                    try:
                        await revo_cache_entry.get_delta_json(self._build_rr_delta_json, rv, rv)
                    except ClosedPool:
                        LOGGER.warning(
                            'Holder-Prover %s is offline from pool %s, cannot update revo cache reg delta for %s to %s',
                            self.wallet.name,
                            self.pool.name,
                            rr_id,
                            rv)

        if archive:
            Caches.archive(self.dir_cache)
        LOGGER.debug('HolderProver.load_cache <<< %s', rv)
        return rv

    async def get_box_ids_json(self) -> str:
        """
        Return json object on lists of all unique box identifiers for credentials in wallet:
        schema identifiers, credential definition identifiers, and revocation registry identifiers; e.g.,

        ::

        {
            "schema_id": [
                "R17v42T4pk...:2:tombstone:1.2",
                "9cHbp54C8n...:2:business:2.0",
                ...
            ],
            "cred_def_id": [
                "R17v42T4pk...:3:CL:19:0",
                "9cHbp54C8n...:3:CL:37:0",
                ...
            ]
            "rev_reg_id": [
                "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:0:CL_ACCUM:0",
                "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:0:CL_ACCUM:1",
                "9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:0:CL_ACCUM:0",
                "9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:0:CL_ACCUM:1",
                "9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:0:CL_ACCUM:2",
                ...
            ]
        }

        :return: tuple of sets for schema ids, cred def ids, rev reg ids
        """

        LOGGER.debug('HolderProver.get_box_ids_json >>>')

        s_ids = set()
        cd_ids = set()
        rr_ids = set()
        for cred in json.loads(await self.get_creds_display_coarse()):
            s_ids.add(cred['schema_id'])
            cd_ids.add(cred['cred_def_id'])
            if cred['rev_reg_id']:
                rr_ids.add(cred['rev_reg_id'])

        rv = json.dumps({
            'schema_id': list(s_ids),
            'cred_def_id': list(cd_ids),
            'rev_reg_id': list(rr_ids)
        })
        LOGGER.debug('HolderProver.get_box_ids_json <<< %s', rv)
        return rv

    async def get_creds_display_coarse(self, filt: dict = None) -> str:
        """
        Return human-readable credentials from wallet by input filter for
        schema identifier and/or credential definition identifier components;
        return all credentials for no filter.

        :param filt: indy-sdk filter for credentials; i.e.,

        ::

            {
                "schema_id": string,  # optional
                "schema_issuer_did": string,  # optional
                "schema_name": string,  # optional
                "schema_version": string,  # optional
                "issuer_did": string,  # optional
                "cred_def_id": string  # optional
            }

        :return: credentials json list; i.e.,

        ::

            [{
                "referent": string,  # credential identifier in the wallet
                "attrs": {
                    "attr1" : {"raw": "value1", "encoded": "value1_as_int" },
                    "attr2" : {"raw": "value2", "encoded": "value2_as_int" },
                    ...
                }
                "schema_id": string,
                "cred_def_id": string,
                "rev_reg_id": Optional<string>,
                "cred_rev_id": Optional<string>
            }]

        """

        LOGGER.debug('HolderProver.get_creds_display_coarse >>> filt: %s', filt)

        rv_json = await anoncreds.prover_get_credentials(self.wallet.handle, json.dumps(filt or {}))
        LOGGER.debug('HolderProver.get_creds_display_coarse <<< %s', rv_json)
        return rv_json

    async def get_creds(self, proof_req_json: str, filt: dict = None, filt_dflt_incl: bool = False) -> (Set[str], str):
        """
        Get credentials from HolderProver wallet corresponding to proof request and
        filter criteria; return credential identifiers from wallet and credentials json.
        Return empty set and empty production for no such credentials.

        :param proof_req_json: proof request json as Verifier creates; has entries for proof request's
            nonce, name, and version; plus credential's requested attributes, requested predicates. I.e.,

        ::

            {
                'nonce': string,  # indy-sdk makes no semantic specification on this value
                'name': string,  # indy-sdk makes no semantic specification on this value
                'version': numeric-string,  # indy-sdk makes no semantic specification on this value
                'requested_attributes': {
                    '<attr_uuid>': {  # aka attr_referent, a proof-request local identifier
                        'name': string,  # attribute name (matches case- and space-insensitively)
                        'restrictions' [  # optional
                            {
                                "schema_id": string,  # optional
                                "schema_issuer_did": string,  # optional
                                "schema_name": string,  # optional
                                "schema_version": string,  # optional
                                "issuer_did": string,  # optional
                                "cred_def_id": string  # optional
                            },
                            {
                                ...  # if more than one restriction given, combined disjunctively (i.e., via OR)
                            }
                        ],
                        'non_revoked': {  # optional - indy-sdk ignores when getting creds from wallet
                            'from': int,  # optional, epoch seconds
                            'to': int  # optional, epoch seconds
                        }
                    },
                    ...
                },
                'requested_predicates': {
                    '<pred_uuid>': {  # aka predicate_referent, a proof-request local predicate identifier
                        'name': string,  # attribute name (matches case- and space-insensitively)
                        'p_type': '>=',
                        'p_value': int,  # predicate value
                        'restrictions': [  # optional
                            {
                                "schema_id": string,  # optional
                                "schema_issuer_did": string,  # optional
                                "schema_name": string,  # optional
                                "schema_version": string,  # optional
                                "issuer_did": string,  # optional
                                "cred_def_id": string  # optional
                            },
                            {
                                ...  # if more than one restriction given, combined disjunctively (i.e., via OR)
                            }
                        ],
                        'non_revoked': {  # optional - indy-sdk ignores when getting creds from wallet
                            'from': int,  # optional, epoch seconds
                            'to': int  # optional, epoch seconds
                        }
                    },
                    ...
                },
                'non_revoked': {  # optional - indy-sdk ignores when getting creds from wallet
                    'from': Optional<int>,
                    'to': Optional<int>
                }
            }

        :param filt: filter for matching attribute-value pairs and predicates; dict mapping each
            cred def id to dict (specify empty dict or none for no filter, matching all)
            mapping attributes to values to match or compare. E.g.,

        ::

            {
                'Vx4E82R17q...:3:CL:16:0': {
                    'attr-match': {
                        'name': 'Alex',
                        'sex': 'M',
                        'favouriteDrink': None
                    },
                    'minima': {  # if both attr-match and minima present, combined conjunctively (i.e., via AND)
                        'favouriteNumber' : 10,
                        'score': '100'  # nicety: implementation converts to int for caller
                    },
                },
                'R17v42T4pk...:3:CL:19:0': {
                    'attr-match': {
                        'height': 175,
                        'birthdate': '1975-11-15'  # combined conjunctively (i.e., via AND)
                    }
                },
                'Z9ccax812j...:3:CL:27:0': {
                    'attr-match': {}  # match all attributes on this cred def
                }
                ...
            }

        :param filt_dflt_incl: whether to include (True) all credentials from wallet that filter does not
            identify by cred def, or to exclude (False) all such credentials
        :return: tuple with (set of referents, creds json for input proof request);
            empty set and empty production for no such credential
        """

        LOGGER.debug('HolderProver.get_creds >>> proof_req_json: %s, filt: %s', proof_req_json, filt)

        if filt is None:
            filt = {}
        rv = None
        creds_json = await anoncreds.prover_get_credentials_for_proof_req(self.wallet.handle, proof_req_json)
        creds = json.loads(creds_json)
        cred_ids = set()

        if filt:
            for cd_id in filt:
                try:
                    json.loads(await self.get_cred_def(cd_id))
                except AbsentCredDef:
                    LOGGER.warning('HolderProver.get_creds: ignoring filter criterion, no cred def on %s', cd_id)
                    filt.pop(cd_id)

        for inner_creds in {**creds['attrs'], **creds['predicates']}.values():
            for cred in inner_creds:  # cred is a dict in a list of dicts
                cred_info = cred['cred_info']
                if filt:
                    cred_cd_id = cred_info['cred_def_id']
                    if cred_cd_id not in filt:
                        if filt_dflt_incl:
                            cred_ids.add(cred_info['referent'])
                        continue
                    if 'attr-match' in (filt[cred_cd_id] or {}):  # maybe filt[cred_cd_id]: None
                        if not {k: str(filt[cred_cd_id].get('attr-match', {})[k])
                                for k in filt[cred_cd_id].get('attr-match', {})}.items() <= cred_info['attrs'].items():
                            continue
                    if 'minima' in (filt[cred_cd_id] or {}):  # maybe filt[cred_cd_id]: None
                        minima = filt[cred_cd_id].get('minima', {})
                        try:
                            if any((attr not in cred_info['attrs'])
                                or (int(cred_info['attrs'][attr]) < int(minima[attr]))
                                    for attr in minima):
                                continue
                        except ValueError:
                            continue  # int conversion failed - reject candidate
                    cred_ids.add(cred_info['referent'])
                else:
                    cred_ids.add(cred_info['referent'])

        if filt:
            creds = json.loads(prune_creds_json(creds, cred_ids))

        rv = (cred_ids, json.dumps(creds))
        LOGGER.debug('HolderProver.get_creds <<< %s', rv)
        return rv

    async def get_creds_by_id(self, proof_req_json: str, cred_ids: set) -> str:
        """
        Get creds structure from HolderProver wallet by credential identifiers.

        :param proof_req_json: proof request as per get_creds() above
        :param cred_ids: set of credential identifiers of interest
        :return: json with cred(s) for input credential identifier(s)
        """

        LOGGER.debug('HolderProver.get_creds_by_id >>> proof_req_json: %s, cred_ids: %s', proof_req_json, cred_ids)

        creds_json = await anoncreds.prover_get_credentials_for_proof_req(self.wallet.handle, proof_req_json)

        # retain only creds of interest: find corresponding referents
        rv_json = prune_creds_json(json.loads(creds_json), cred_ids)
        LOGGER.debug('HolderProver.get_cred_by_referent <<< %s', rv_json)
        return rv_json

    async def create_proof(self, proof_req: dict, creds: dict, requested_creds: dict) -> str:
        """
        Create proof as HolderProver.

        Raise:
            * AbsentLinkSecret if link secret not set
            * CredentialFocus on attempt to create proof on no creds or multiple creds for a credential definition
            * AbsentTails if missing required tails file
            * BadRevStateTime if a timestamp for a revocation registry state in the proof request
              occurs before revocation registry creation
            * IndyError for any other indy-sdk error.
            * AbsentInterval if creds missing non-revocation interval, but cred def supports revocation

        :param proof_req: proof request as per get_creds() above
        :param creds: credentials to prove
        :param requested_creds: data structure with self-attested attribute info, requested attribute info
            and requested predicate info, assembled from get_creds() and filtered for content of interest. I.e.,

        ::

            {
                'self_attested_attributes': {},
                'requested_attributes': {
                    'attr0_uuid': {
                        'cred_id': string,
                        'timestamp': integer,  # for revocation state
                        'revealed': bool
                    },
                    ...
                },
                'requested_predicates': {
                    'predicate0_uuid': {
                        'cred_id': string,
                        'timestamp': integer  # for revocation state
                    }
                }
            }

        :return: proof json
        """

        LOGGER.debug(
            'HolderProver.create_proof >>> proof_req: %s, creds: %s, requested_creds: %s',
            proof_req,
            creds,
            requested_creds)

        self._assert_link_secret('create_proof')

        x_uuids = [attr_uuid for attr_uuid in creds['attrs'] if len(creds['attrs'][attr_uuid]) != 1]
        if x_uuids:
            LOGGER.debug('HolderProver.create_proof: <!< creds specification out of focus (non-uniqueness)')
            raise CredentialFocus('Proof request requires unique cred per attribute; violators: {}'.format(x_uuids))

        s_id2schema = {}  # schema identifier to schema
        cd_id2cred_def = {}  # credential definition identifier to credential definition
        rr_id2timestamp = {}  # revocation registry of interest to timestamp of interest (or None)
        rr_id2cr_id = {}  # revocation registry of interest to credential revocation identifier
        for referents in {**creds['attrs'], **creds['predicates']}.values():
            interval = referents[0].get('interval', None)
            cred_info = referents[0]['cred_info']
            s_id = cred_info['schema_id']
            if s_id not in s_id2schema:
                schema = json.loads(await self.get_schema(s_id))  # add to cache en passant
                if not schema:
                    LOGGER.debug(
                        'HolderProver.create_proof: <!< absent schema %s, proof req may be for another ledger',
                        s_id)
                    raise AbsentSchema(
                        'Absent schema {}, proof req may be for another ledger'.format(s_id))
                s_id2schema[s_id] = schema

            cd_id = cred_info['cred_def_id']
            if cd_id not in cd_id2cred_def:
                cred_def = json.loads(await self.get_cred_def(cd_id))  # add to cache en passant
                cd_id2cred_def[cd_id] = cred_def

            rr_id = cred_info['rev_reg_id']
            if rr_id:
                await self._sync_revoc(rr_id)  # link tails file to its rr_id if it's new
                if interval:
                    if rr_id not in rr_id2timestamp:
                        if interval['to'] > int(time()):
                            LOGGER.debug(
                                'HolderProver.create_proof: <!< interval to %s for rev reg %s is in the future',
                                interval['to'],
                                rr_id)
                            raise BadRevStateTime('Revocation registry {} timestamp {} is in the future'.format(
                                rr_id,
                                interval['to']))
                        rr_id2timestamp[rr_id] = interval['to']
                elif 'revocation' in cd_id2cred_def[cd_id]['value']:
                    LOGGER.debug(
                        'HolderProver.create_proof: <!< creds on cred def id %s missing non-revocation interval',
                        cd_id)
                    raise AbsentInterval('Creds on cred def id {} missing non-revocation interval'.format(cd_id))
                if rr_id in rr_id2cr_id:
                    continue
                rr_id2cr_id[rr_id] = cred_info['cred_rev_id']

        rr_id2rev_state = {}  # revocation registry identifier to its state
        with REVO_CACHE.lock:
            for rr_id in rr_id2timestamp:
                revo_cache_entry = REVO_CACHE.get(rr_id, None)
                tails = revo_cache_entry.tails if revo_cache_entry else None
                if tails is None:  # missing tails file
                    LOGGER.debug('HolderProver.create_proof: <!< missing tails file for rev reg id %s', rr_id)
                    raise AbsentTails('Missing tails file for rev reg id {}'.format(rr_id))
                rr_def_json = await self._get_rev_reg_def(rr_id)
                (rr_delta_json, ledger_timestamp) = await revo_cache_entry.get_delta_json(
                    self._build_rr_delta_json,
                    rr_id2timestamp[rr_id],
                    rr_id2timestamp[rr_id])
                rr_state_json = await anoncreds.create_revocation_state(
                    tails.reader_handle,
                    rr_def_json,
                    rr_delta_json,
                    ledger_timestamp,
                    rr_id2cr_id[rr_id])
                rr_id2rev_state[rr_id] = {
                    rr_id2timestamp[rr_id]: json.loads(rr_state_json)
                }

        rv = await anoncreds.prover_create_proof(
            self.wallet.handle,
            json.dumps(proof_req),
            json.dumps(requested_creds),
            self._link_secret,
            json.dumps(s_id2schema),
            json.dumps(cd_id2cred_def),
            json.dumps(rr_id2rev_state))
        LOGGER.debug('HolderProver.create_proof <<< %s', rv)
        return rv

    async def reset_wallet(self) -> str:
        """
        Close and delete HolderProver wallet, then create and open a replacement on prior link secret.
        Note that this operation effectively destroys private keys for credential definitions. Its
        intended use is primarily for testing and demonstration.

        Raise AbsentLinkSecret if link secret not set.

        :return: wallet name
        """

        LOGGER.debug('HolderProver.reset_wallet >>>')

        self._assert_link_secret('reset_wallet')

        seed = self.wallet._seed
        wallet_name = self.wallet.name
        wallet_cfg = self.wallet.cfg
        wallet_xtype = self.wallet.xtype
        wallet_access_creds = self.wallet.access_creds

        await self.wallet.close()
        await self.wallet.remove()
        self.wallet = await Wallet(
            seed,
            wallet_name,
            wallet_xtype,
            wallet_cfg,
            wallet_access_creds).create()
        await self.wallet.open()

        await self.create_link_secret(self._link_secret)  # carry over link secret to new wallet

        rv = self.wallet.name
        LOGGER.debug('HolderProver.reset_wallet <<< %s', rv)
        return rv
