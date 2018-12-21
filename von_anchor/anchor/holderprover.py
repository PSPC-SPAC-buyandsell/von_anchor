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

from collections.abc import Iterable
from os import listdir, makedirs
from os.path import basename, expanduser, isdir, isfile, join
from time import time
from typing import Union

from indy import anoncreds, ledger
from indy.error import IndyError, ErrorCode

from von_anchor.anchor.base import BaseAnchor
from von_anchor.cache import Caches, RevoCacheEntry, CRED_DEF_CACHE, REVO_CACHE, SCHEMA_CACHE
from von_anchor.canon import canon_wql
from von_anchor.error import (
    AbsentCred,
    AbsentCredDef,
    AbsentInterval,
    AbsentLinkSecret,
    AbsentRevReg,
    AbsentSchema,
    AbsentTails,
    BadIdentifier,
    BadRevStateTime,
    CacheIndex,
    ClosedPool,
    CredentialFocus)
from von_anchor.indytween import Predicate
from von_anchor.nodepool import NodePool
from von_anchor.tails import Tails
from von_anchor.util import (
    cred_def_id2seq_no,
    iter_briefs,
    ok_cred_def_id,
    ok_rev_reg_id,
    ok_schema_id,
    proof_req_pred_referents,
    rev_reg_id2cred_def_id_tag)
from von_anchor.validcfg import validate_config
from von_anchor.wallet import Wallet


LOGGER = logging.getLogger(__name__)


class HolderProver(BaseAnchor):
    """
    Mixin for anchor acting in the role of w3c Holder and indy-sdk Prover.  A Holder holds
    credentials; a Prover produces proof of credentials. Revocation support requires
    the holder-prover anchor to manage tails files.
    """

    def __init__(self, wallet: Wallet, pool: NodePool, **kwargs) -> None:
        """
        Initializer for HolderProver anchor. Retain input parameters; do not open wallet nor tails writer.

        :param wallet: wallet for anchor use
        :param pool: pool for anchor use
        :param cfg: configuration dict for cache archive behaviour; e.g.,

        ::

            {
                'parse-caches-on-open': True,
                'archive-holder-prover-caches-on-close': True
            }

        """

        LOGGER.debug('HolderProver.__init__ >>> wallet: %s, pool: %s, kwargs: %s', wallet, pool, kwargs)

        super().__init__(wallet, pool, **kwargs)
        self._link_secret = None

        self._dir_tails = join(expanduser('~'), '.indy_client', 'tails')
        makedirs(self._dir_tails, exist_ok=True)

        self._cfg = kwargs.get('cfg', {})
        validate_config('holder-prover', self._cfg)

        self._dir_cache = join(expanduser('~'), '.indy_client', 'cache', self.wallet.name)
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

    async def _sync_revoc_for_proof(self, rr_id: str) -> None:
        """
        Pick up tails file reader handle for input revocation registry identifier.  If no symbolic
        link is present, get the revocation registry definition to retrieve its tails file hash,
        then find the tails file and link it.

        Raise AbsentTails for missing corresponding tails file.

        :param rr_id: revocation registry identifier
        """

        LOGGER.debug('HolderProver._sync_revoc_for_proof >>> rr_id: %s', rr_id)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('HolderProver._sync_revoc_for_proof <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        (cd_id, tag) = rev_reg_id2cred_def_id_tag(rr_id)

        try:
            json.loads(await self.get_cred_def(cd_id))
        except AbsentCredDef:
            LOGGER.debug(
                'HolderProver._sync_revoc_for_proof <!< corrupt tails tree %s may be for another ledger',
                self._dir_tails)
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
                    rr_def = json.loads(await self._get_rev_reg_def(rr_id))
                    tails_hash = rr_def['value']['tailsHash']
                    path_tails = join(Tails.dir(self._dir_tails, rr_id), tails_hash)
                    if not isfile(path_tails):
                        LOGGER.debug('HolderProver._sync_revoc_for_proof <!< No tails file present at %s', path_tails)
                        raise AbsentTails('No tails file present at {}'.format(path_tails))
                    Tails.associate(self._dir_tails, rr_id, tails_hash)
                    tails = await Tails(self._dir_tails, cd_id, tag).open()  # OK now since tails file present

                if revo_cache_entry is None:
                    REVO_CACHE[rr_id] = RevoCacheEntry(None, tails)
                else:
                    REVO_CACHE[rr_id].tails = tails

        LOGGER.debug('HolderProver._sync_revoc_for_proof <<<')

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

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('HolderProver._build_rr_delta_json <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

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
                LOGGER.debug('_HolderProver._build_rr_delta_json <!< no rev reg exists on %s', rr_id)
                raise AbsentRevReg('No rev reg exists on {}'.format(rr_id))
        else:
            LOGGER.debug(
                '_HolderProver._build_rr_delta_json <!< Rev reg %s created after asked-for time %s',
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

    def dir_tails(self, rr_id: str) -> str:
        """
        Return path to the correct directory for the tails file on input revocation registry identifier.

        :param rr_id: revocation registry identifier of interest
        :return: path to tails dir for input revocation registry identifier
        """

        LOGGER.debug('HolderProver.dir_tails >>>')

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('HolderProver.dir_tails <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        rv = Tails.dir(self._dir_tails, rr_id)
        LOGGER.debug('HolderProver.dir_tails <<< %s', rv)
        return rv

    async def open(self) -> 'HolderProver':
        """
        Explicit entry. Perform ancestor opening operations,
        then parse cache from archive if so configured, and
        synchronize revocation registry to tails tree content.

        :return: current object
        """

        LOGGER.debug('HolderProver.open >>>')

        await super().open()
        if self.cfg.get('parse-caches-on-open', False):
            Caches.parse(self.dir_cache)

        for path_rr_id in Tails.links(self._dir_tails):
            await self._sync_revoc_for_proof(basename(path_rr_id))

        LOGGER.debug('HolderProver.open <<<')
        return self

    async def close(self) -> None:
        """
        Explicit exit. If so configured, populate cache to prove all creds in
        wallet offline if need be, archive cache, and purge prior cache archives.

        :return: current object
        """

        LOGGER.debug('HolderProver.close >>>')

        if self.cfg.get('archive-holder-prover-caches-on-close', False):
            await self.load_cache_for_proof(True)
            Caches.purge_archives(self.dir_cache, True)

        await BaseAnchor.close(self)
        for path_rr_id in Tails.links(self._dir_tails):
            rr_id = basename(path_rr_id)
            try:
                await self._sync_revoc_for_proof(rr_id)
            except ClosedPool:
                LOGGER.warning('HolderProver sync-revoc on close required ledger for %s but pool was closed', rr_id)

        LOGGER.debug('HolderProver.close <<<')

    async def rev_regs(self) -> list:
        """
        Return list of revocation registry identifiers for which HolderProver has associated tails files.
        The operation creates associations for any (newly copied, via service wrapper API) tails files without.

        :return: list of revocation registry identifiers for which HolderProver has associated tails files
        """

        LOGGER.debug('HolderProver.rev_regs >>>')

        for path_rr_id in Tails.links(self._dir_tails):
            await self._sync_revoc_for_proof(basename(path_rr_id))

        rv = [basename(f) for f in Tails.links(self._dir_tails)]
        LOGGER.debug('HolderProver.rev_regs <<< %s', rv)
        return rv

    async def offline_intervals(self, cd_ids: Union[Iterable, str]) -> dict:
        """
        Return default non-revocation intervals for input cred def ids, based on content of revocation cache,
        for augmentation into specification for Verifier.build_proof_req_json. Note that the close() call
        to set the anchor off-line extends all revocation cache registry delta entries to its time of execution:
        in this case, the intervals will all be single timestamps rather than (to, fro) pairs.

        Raise CacheIndex if proof request cites credential definition without corresponding
        content in cred def cache or revocation cache.

        :param cd_ids: credential definition identifier or iterable collection thereof
        :return: dict mapping revocable cred def ids to interval specifications to augment into cd_id2spec
            parameter for Verifier.build_proof_req_json(), and non-revocable cred def ids to empty dict; e.g.,

        ::

            {
                'Vx4E82R17q...:3:CL:16:tag': {
                    'interval': (1528111730, 1528115832)
                },
                'R17v42T4pk...:3:CL:19:tag': {},
                'Z9ccax812j...:3:CL:27:tag': {
                    'interval': (1528112408, 1528116008)
                },
                '9cHbp54C8n...:3:CL:37:tag': {
                    'interval': 1528116426
                },
                '6caBcmLi33...:tag:CL:41:tag': {},
                ...
            }
        """

        LOGGER.debug('HolderProver.offline_intervals >>> cd_ids: %s', cd_ids)

        rv = {}
        for cd_id in [cd_ids] if isinstance(cd_ids, str) else cd_ids:
            if not ok_cred_def_id(cd_id):
                LOGGER.debug('HolderProver.offline_intervals <!< Bad cred def id %s', cd_id)
                raise BadIdentifier('Bad cred def id {}'.format(cd_id))

            try:
                cred_def = json.loads(await self.get_cred_def(cd_id))
            except ClosedPool:
                LOGGER.debug('HolderProver.offline_intervals <!< no such cred def %s in cred def cache', cd_id)
                raise CacheIndex('No cached delta for non-revoc interval on {}'.format(cd_id))

            rv[cd_id] = {}
            if 'revocation' in cred_def['value']:
                with REVO_CACHE.lock:
                    (fro, to) = REVO_CACHE.dflt_interval(cd_id)
                    if not (fro and to):
                        LOGGER.debug(
                            'HolderProver.offline_intervals <!< no cached delta for non-revoc interval on %s',
                            cd_id)
                        raise CacheIndex('No cached delta for non-revoc interval on {}'.format(cd_id))

                    rv[cd_id]['interval'] = to if fro == to else (fro, to)

        LOGGER.debug('HolderProver.offline_intervals <<< %s', rv)
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
                    'HolderProver.create_link_secret <!< cannot create link secret %s, indy error code %s',
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

        if not ok_cred_def_id(cd_id):
            LOGGER.debug('HolderProver.create_cred_req <!< Bad cred def id %s', cd_id)
            raise BadIdentifier('Bad cred def id {}'.format(cd_id))

        self._assert_link_secret('create_cred_req')

        # Check that ledger has schema on ledger where cred def expects - in case of pool reset with extant wallet
        cred_def_json = await self.get_cred_def(cd_id)
        schema_seq_no = int(json.loads(cred_def_json)['schemaId'])
        schema_json = await self.get_schema(schema_seq_no)
        schema = json.loads(schema_json)
        if not schema:
            LOGGER.debug(
                'HolderProver.create_cred_req <!< absent schema@#%s, cred req may be for another ledger',
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
        rr_def_json = None
        if rr_id:
            await self._sync_revoc_for_proof(rr_id)
            rr_def_json = await self._get_rev_reg_def(rr_id)

        rv = await anoncreds.prover_store_credential(
            self.wallet.handle,
            None,  # cred_id, let indy-sdk generate random uuid
            cred_req_metadata_json,
            cred_json,
            cred_def_json,
            rr_def_json)

        LOGGER.debug('HolderProver.store_cred <<< %s', rv)
        return rv

    async def load_cache_for_proof(self, archive: bool = False) -> int:
        """
        Load caches and optionally archive enough to go offline and be able to generate proof
        on all credentials in wallet.

        Return timestamp (epoch seconds) of cache load event, also used as subdirectory
        for cache archives.

        :param archive: True to archive now or False to demur (subclasses may still need to augment caches further)
        :return: cache load event timestamp (epoch seconds)
        """

        LOGGER.debug('HolderProver.load_cache_for_proof >>> archive: %s', archive)

        rv = int(time())
        box_ids = json.loads(await self.get_box_ids_held())
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
                            'HolderProver %s is offline from pool %s, cannot update revo cache reg delta for %s to %s',
                            self.wallet.name,
                            self.pool.name,
                            rr_id,
                            rv)

        if archive:
            Caches.archive(self.dir_cache)
        LOGGER.debug('HolderProver.load_cache_for_proof <<< %s', rv)
        return rv

    async def get_box_ids_held(self) -> str:
        """
        Return json object on lists of all unique box identifiers for credentials in wallet, as
        evidenced by tails directory content:

        * schema identifiers
        * credential definition identifiers
        * revocation registry identifiers.

        E.g.,

        ::

            {
                "schema_id": [
                    "R17v42T4pk...:2:tombstone:1.2",
                    "9cHbp54C8n...:2:business:2.0",
                    ...
                ],
                "cred_def_id": [
                    "R17v42T4pk...:3:CL:19:tag",
                    "9cHbp54C8n...:3:CL:37:tag",
                    ...
                ]
                "rev_reg_id": [
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:0",
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:1",
                    "9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:0",
                    "9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:1",
                    "9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:2",
                    ...
                ]
            }

        :return: tuple of sets for schema ids, cred def ids, rev reg ids
        """

        LOGGER.debug('HolderProver.get_box_ids_held >>>')

        rr_ids = {basename(link) for link in Tails.links(self._dir_tails)}

        un_rr_ids = set()
        for rr_id in rr_ids:
            if not json.loads(await self.get_cred_infos_by_q(json.dumps({'rev_reg_id': rr_id}), 1)):
                un_rr_ids.add(rr_id)
        rr_ids -= un_rr_ids

        cd_ids = {cd_id for cd_id in listdir(self._dir_tails)
            if isdir(join(self._dir_tails, cd_id)) and ok_cred_def_id(cd_id)}
        s_ids = set()
        for cd_id in cd_ids:
            s_ids.add(json.loads(await self.get_schema(cred_def_id2seq_no(cd_id)))['id'])

        un_cd_ids = set()
        for cd_id in cd_ids:
            if not json.loads(await self.get_cred_infos_by_q(json.dumps({'cred_def_id': cd_id}), 1)):
                un_cd_ids.add(cd_id)
        cd_ids -= un_cd_ids

        un_s_ids = set()
        for s_id in s_ids:
            if not json.loads(await self.get_cred_infos_by_q(json.dumps({'schema_id': s_id}), 1)):
                un_s_ids.add(s_id)
        s_ids -= un_s_ids

        rv = json.dumps({
            'schema_id': list(s_ids),
            'cred_def_id': list(cd_ids),
            'rev_reg_id': list(rr_ids)
        })
        LOGGER.debug('HolderProver.get_box_ids_held <<< %s', rv)
        return rv

    async def get_cred_infos_by_q(self, query_json: str, limit: int = None) -> str:
        """
        A cred-info aggregates:
        * its wallet cred-id (aka wallet referent)
        * its attribute names and values
        * its schema identifier
        * its credential definition identifier
        * its revocation registry identifier
        * its credential revocation identifier.

        Return list of cred-infos from wallet by input WQL query;
        return cred-infos for all credentials in wallet for no query.

        The operation supports a subset of WQL; i.e.,

        ::

            query = {subquery}
            subquery = {subquery, ..., subquery} - WHERE subquery AND ... AND subquery
            subquery = $or: [{subquery},..., {subquery}] - WHERE subquery OR ... OR subquery
            subquery = $not: {subquery} - Where NOT (subquery)
            subquery = "tagName": tagValue - WHERE tagName == tagValue
            subquery = "tagName": {$in: [tagValue, ..., tagValue]} - WHERE tagName IN (tagValue, ..., tagValue)
            subquery = "tagName": {$neq: tagValue} - WHERE tagName != tagValue

        but not

        ::

            subquery = "tagName": {$gt: tagValue} - WHERE tagName > tagValue
            subquery = "tagName": {$gte: tagValue} - WHERE tagName >= tagValue
            subquery = "tagName": {$lt: tagValue} - WHERE tagName < tagValue
            subquery = "tagName": {$lte: tagValue} - WHERE tagName <= tagValue
            subquery = "tagName": {$like: tagValue} - WHERE tagName LIKE tagValue

        :param query_json: WQL query json
        :param limit: maximum number of results to return

        :return: cred-infos as json list; i.e.,

        ::

            [
                {
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
                },
                ...
            ]

        """

        LOGGER.debug('HolderProver.get_cred_infos_by_q >>> query_json: %s, limit: %s', query_json, limit)

        infos = []
        if limit and limit < 0:
            limit = None

        (handle, cardinality) = await anoncreds.prover_search_credentials(
            self.wallet.handle,
            json.dumps(canon_wql(json.loads(query_json))))  # indy-sdk requires attr name canonicalization
        chunk = min(cardinality, limit or cardinality, Wallet.DEFAULT_CHUNK)  # heuristic
        if limit:
            cardinality = min(limit, cardinality)
        try:
            while len(infos) != cardinality:
                batch = json.loads(await anoncreds.prover_fetch_credentials(handle, chunk))
                infos.extend(batch)
                if len(batch) < cardinality:
                    break
            if len(infos) != cardinality:
                LOGGER.warning('Credential search/limit indicated %s results but fetched %s', cardinality, len(infos))
        finally:
            await anoncreds.prover_close_credentials_search(handle)

        rv_json = json.dumps(infos)
        LOGGER.debug('HolderProver.get_cred_infos_by_q <<< %s', rv_json)
        return rv_json

    async def get_cred_infos_by_filter(self, filt: dict = None) -> str:
        """
        Return cred-info (json list) from wallet by input filter for
        schema identifier and/or credential definition identifier components;
        return info of all credentials for no filter.

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

        :return: credential infos as json list; i.e.,

        ::

            [
                {
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
                },
                ...
            ]

        """

        LOGGER.debug('HolderProver.get_cred_infos_by_filter >>> filt: %s', filt)

        rv_json = await anoncreds.prover_get_credentials(self.wallet.handle, json.dumps(filt or {}))
        LOGGER.debug('HolderProver.get_cred_infos_by_filter <<< %s', rv_json)
        return rv_json

    async def get_cred_info_by_id(self, cred_id: str) -> str:
        """
        Return cred-info json from wallet by wallet credential identifier.

        Raise AbsentCred for no such credential.

        :param cred_id: credential identifier of interest
        :return: json with cred for input credential identifier

        :return: cred-info json; i.e.,

        ::

            {
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
            }
        """

        LOGGER.debug('HolderProver.get_cred_info_by_id >>> cred_id: %s', cred_id)

        try:
            rv_json = await anoncreds.prover_get_credential(self.wallet.handle, cred_id)
        except IndyError as x_indy:  # no such cred
            if x_indy.error_code == ErrorCode.WalletItemNotFound:
                LOGGER.debug(
                    'HolderProver.get_cred_info_by_id <!< no cred in wallet %s for cred id %s',
                    self.wallet.name,
                    cred_id)
                raise AbsentCred('No cred in wallet for {}'.format(cred_id))
            else:
                LOGGER.debug(
                    'HolderProver.get_cred_info_by_id <!< wallet %s, cred id %s: indy error code %s',
                    self.wallet.name,
                    cred_id,
                    x_indy.error_code)
                raise

        LOGGER.debug('HolderProver.get_cred_info_by_id <<< %s', rv_json)
        return rv_json

    async def get_cred_briefs_by_proof_req_q(self, proof_req_json: str, x_queries_json: str = None) -> str:
        """
        A cred-brief aggregates a cred-info and a non-revocation interval. A cred-brief-dict maps
        wallet cred-ids to their corresponding cred-briefs.

        Return json (cred-brief-dict) object mapping wallet credential identifiers to cred-briefs by
        proof request and WQL queries by proof request referent. Return empty dict on no WQL query and
        empty requested predicates specification within proof request. Utility util.proof_req2wql_all()
        builds WQL to retrieve all cred-briefs for (some or all) cred-def-ids in a proof request.

        For each WQL query on an item referent, indy-sdk takes the WQL and the attribute name
        and restrictions (e.g., cred def id, schema id, etc.) from its referent.  Note that
        util.proof_req_attr_referents() maps cred defs and attr names to proof req item referents,
        bridging the gap between attribute names and their corresponding item referents.

        :param proof_req_json: proof request as per Verifier.build_proof_req_json(); e.g.,

        ::

            {
                "nonce": "1532429687",
                "name": "proof_req",
                "version": "0.0",
                "requested_predicates": {},
                "requested_attributes": {
                    "17_name_uuid": {
                        "restrictions": [
                            {
                                "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:17:tag"
                            }
                        ],
                        "name": "name"
                    },
                    "17_thing_uuid": {
                        "restrictions": [
                            {
                                "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:17:tag"
                            }
                        ],
                        "name": "thing"
                    }
                }
            }

        :param x_queries_json: json list of extra queries to apply to proof request attribute and predicate
            referents; e.g.,

        ::

            {
                "17_thing_uuid": { # require attr presence on name 'thing', cred def id from proof req above
                    "$or": [
                        {
                            "attr::name::value": "J.R. 'Bob' Dobbs"
                        },
                        {
                            "attr::thing::value": "slack"
                        },
                    ]
                },
            }

        :return: json (cred-brief-dict) object mapping wallet cred ids to cred briefs; e.g.,

        ::

            {
                "b42ce5bc-b690-43cd-9493-6fe86ad25e85": {
                    "interval": null,
                    "cred_info": {
                        "schema_id": "LjgpST2rjsoxYegQDRm7EL:2:non-revo:1.0",
                        "rev_reg_id": null,
                        "attrs": {
                            "name": "J.R. \"Bob\" Dobbs",
                            "thing": "slack"
                        },
                        "cred_rev_id": null,
                        "referent": "b42ce5bc-b690-43cd-9493-6fe86ad25e85",
                        "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:17:tag"
                    }
                },
                "d773434a-0080-4e3e-a03b-f2033eae7d75": {
                    "interval": null,
                    "cred_info": {
                        "schema_id": "LjgpST2rjsoxYegQDRm7EL:2:non-revo:1.0",
                        "rev_reg_id": null,
                        "attrs": {
                            "name": "Chicken Hawk",
                            "thing": "chicken"
                        },
                        "cred_rev_id": null,
                        "referent": "d773434a-0080-4e3e-a03b-f2033eae7d75",
                        "cred_def_id": "LjgpST2rjsoxYegQDRm7EL:3:CL:17:tag"
                    }
                }
            }

        """

        LOGGER.debug(
            ('HolderProver.get_cred_briefs_by_proof_req_q >>> proof_req_json: %s, x_queries_json: %s'),
            proof_req_json,
            x_queries_json)

        def _pred_filter(brief):
            nonlocal pred_refts
            for attr, preds in pred_refts.get(brief['cred_info']['cred_def_id'], {}).items():
                if any(Predicate.get(p[0]).value.no(brief['cred_info']['attrs'][attr], p[1]) for p in preds.values()):
                    return False
            return True

        rv = {}
        item_refts = set()
        x_queries = json.loads(x_queries_json or '{}')
        for k in x_queries:
            x_queries[k] = canon_wql(x_queries[k])  # indy-sdk requires attr name canonicalization
            item_refts.add(k)

        proof_req = json.loads(proof_req_json)
        item_refts.update(uuid for uuid in proof_req['requested_predicates'])
        if not x_queries:
            item_refts.update(uuid for uuid in proof_req['requested_attributes'])  # get all req attrs if no extra wql
        handle = await anoncreds.prover_search_credentials_for_proof_req(
            self.wallet.handle,
            proof_req_json,
            json.dumps(x_queries) if x_queries else None)
        pred_refts = proof_req_pred_referents(proof_req)

        try:
            for item_referent in item_refts:
                count = Wallet.DEFAULT_CHUNK
                while count == Wallet.DEFAULT_CHUNK:
                    fetched = json.loads(await anoncreds.prover_fetch_credentials_for_proof_req(
                        handle,
                        item_referent,
                        Wallet.DEFAULT_CHUNK))
                    count = len(fetched)
                    for brief in fetched:  # apply predicates from proof req here
                        if brief['cred_info']['referent'] not in rv and _pred_filter(brief):
                            rv[brief['cred_info']['referent']] = brief
        finally:
            await anoncreds.prover_close_credentials_search_for_proof_req(handle)

        rv_json = json.dumps(rv)
        LOGGER.debug('HolderProver.get_cred_briefs_by_proof_req_q <<< %s', rv_json)
        return rv_json


    async def create_proof(self, proof_req: dict, briefs: Union[Iterable, dict], requested_creds: dict) -> str:
        """
        Create proof as HolderProver.

        Raise:
            * AbsentLinkSecret if link secret not set
            * CredentialFocus on attempt to create proof on no briefs or multiple briefs for a credential definition
            * AbsentTails if missing required tails file
            * | BadRevStateTime if a timestamp for a revocation registry state in the proof request
              | occurs before revocation registry creation
            * IndyError for any other indy-sdk error.
            * AbsentInterval if briefs missing non-revocation interval, but cred def supports revocation

        :param proof_req: proof request as per Verifier.build_proof_req_json()
        :param briefs: cred-brief, iterable collection thereof, or mapping from wallet cred-id to briefs, to prove
        :param requested_creds: requested credentials data structure; i.e.,

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
            'HolderProver.create_proof >>> proof_req: %s, briefs: %s, requested_creds: %s',
            proof_req,
            briefs,
            requested_creds)

        self._assert_link_secret('create_proof')

        cd_ids = set()
        x_cd_ids = set()
        for brief in iter_briefs(briefs):
            cd_id = brief['cred_info']['cred_def_id']
            if cd_id in cd_ids and cd_id not in x_cd_ids:
                x_cd_ids.add(cd_id)
            cd_ids.add(cd_id)
            if x_cd_ids:
                LOGGER.debug('HolderProver.create_proof <!< briefs specification out of focus (non-uniqueness)')
                raise CredentialFocus('Briefs list repeats cred defs: {}'.format(x_cd_ids))

        s_id2schema = {}  # schema identifier to schema
        cd_id2cred_def = {}  # credential definition identifier to credential definition
        rr_id2timestamp = {}  # revocation registry of interest to timestamp of interest (or None)
        rr_id2cr_id = {}  # revocation registry of interest to credential revocation identifier
        for brief in iter_briefs(briefs):
            interval = brief.get('interval', None)
            cred_info = brief['cred_info']
            s_id = cred_info['schema_id']
            if not ok_schema_id(s_id):
                LOGGER.debug('HolderProver.create_proof <!< Bad schema id %s', s_id)
                raise BadIdentifier('Bad schema id {}'.format(s_id))

            if s_id not in s_id2schema:
                schema = json.loads(await self.get_schema(s_id))  # add to cache en passant
                if not schema:
                    LOGGER.debug(
                        'HolderProver.create_proof <!< absent schema %s, proof req may be for another ledger',
                        s_id)
                    raise AbsentSchema('Absent schema {}, proof req may be for another ledger'.format(s_id))
                s_id2schema[s_id] = schema

            cd_id = cred_info['cred_def_id']
            if not ok_cred_def_id(cd_id):
                LOGGER.debug('HolderProver.create_proof <!< Bad cred def id %s', cd_id)
                raise BadIdentifier('Bad cred def id {}'.format(cd_id))

            if cd_id not in cd_id2cred_def:
                cred_def = json.loads(await self.get_cred_def(cd_id))  # add to cache en passant
                cd_id2cred_def[cd_id] = cred_def

            rr_id = cred_info['rev_reg_id']
            if rr_id:
                if not ok_rev_reg_id(rr_id):
                    LOGGER.debug('HolderProver.create_proof <!< Bad rev reg id %s', rr_id)
                    raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

                await self._sync_revoc_for_proof(rr_id)  # link tails file to its rr_id if it's new
                if interval:
                    if rr_id not in rr_id2timestamp:
                        if interval['to'] > int(time()):
                            LOGGER.debug(
                                'HolderProver.create_proof <!< interval to %s for rev reg %s is in the future',
                                interval['to'],
                                rr_id)
                            raise BadRevStateTime(
                                'Revocation registry {} timestamp {} is in the future'.format(rr_id, interval['to']))
                        rr_id2timestamp[rr_id] = interval['to']
                elif 'revocation' in cd_id2cred_def[cd_id]['value']:
                    LOGGER.debug(
                        'HolderProver.create_proof <!< brief on cred def id %s missing non-revocation interval',
                        cd_id)
                    raise AbsentInterval('Brief on cred def id {} missing non-revocation interval'.format(cd_id))
                if rr_id in rr_id2cr_id:
                    continue
                rr_id2cr_id[rr_id] = cred_info['cred_rev_id']

        rr_id2rev_state = {}  # revocation registry identifier to its state
        with REVO_CACHE.lock:
            for rr_id in rr_id2timestamp:
                revo_cache_entry = REVO_CACHE.get(rr_id, None)
                tails = revo_cache_entry.tails if revo_cache_entry else None
                if tails is None:  # missing tails file
                    LOGGER.debug('HolderProver.create_proof <!< missing tails file for rev reg id %s', rr_id)
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
        wallet_auto_remove = self.wallet.auto_remove
        wallet_cfg = self.wallet.cfg
        wallet_cfg['auto-remove'] = wallet_auto_remove
        wallet_xtype = self.wallet.xtype
        wallet_access_creds = self.wallet.access_creds

        await self.wallet.close()
        if not self.wallet.auto_remove:
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
