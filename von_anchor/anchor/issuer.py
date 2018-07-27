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

from os import listdir, makedirs
from os.path import basename, expanduser, isdir, join

from indy import anoncreds, blob_storage, ledger
from indy.error import IndyError, ErrorCode
from von_anchor.anchor.origin import Origin
from von_anchor.cache import RevoCacheEntry, CRED_DEF_CACHE, REVO_CACHE
from von_anchor.codec import cred_attr_value
from von_anchor.error import (
    AbsentCredDef,
    AbsentSchema,
    AbsentTails,
    BadIdentifier,
    BadRevocation,
    CorruptTails,
    CorruptWallet)
from von_anchor.nodepool import NodePool
from von_anchor.tails import Tails
from von_anchor.util import (
    CD_ID_TAG,
    cred_def_id,
    cred_def_id2seq_no,
    ok_cred_def_id,
    ok_rev_reg_id,
    ok_schema_id,
    rev_reg_id,
    rev_reg_id2cred_def_id_tag,
    schema_key)
from von_anchor.wallet import Wallet


LOGGER = logging.getLogger(__name__)


class Issuer(Origin):
    """
    Mixin for anchor acting in role of Issuer. An Issuer creates credential definitions and
    sends them to the ledger, issues credentials, and revokes credentials. Revocation support
    involves the management of tails files and revocation registries.

    For simplicity, the current design calls to make any issuer anchor an origin anchor.
    """

    def __init__(self, wallet: Wallet, pool: NodePool) -> None:
        """
        Initializer for Issuer anchor. Retain input parameters; do not open wallet nor tails writer.

        :param wallet: wallet for anchor use
        :param pool: pool for anchor use
        """

        LOGGER.debug('Issuer.__init__ >>> wallet: %s, pool: %s', wallet, pool)

        super().__init__(wallet, pool)
        self._dir_tails = join(expanduser('~'), '.indy_client', 'tails')
        makedirs(self._dir_tails, exist_ok=True)

        LOGGER.debug('Issuer.__init__ <<<')

    async def open(self) -> 'Issuer':
        """
        Explicit entry. Perform ancestor opening operations,
        then synchronize revocation registry to tails tree content.

        :return: current object
        """

        LOGGER.debug('Issuer.open >>>')

        await super().open()
        for path_rr_id in Tails.links(self._dir_tails, self.did):
            await self._sync_revoc(basename(path_rr_id))

        LOGGER.debug('Issuer.open <<<')
        return self

    async def _create_rev_reg(self, rr_id: str, rr_size: int = None) -> None:
        """
        Create revocation registry and new tails file (and association to
        corresponding revocation registry definition via symbolic link) for input
        revocation registry identifier.

        :param rr_id: revocation registry identifier
        :param rr_size: revocation registry size (defaults to 256)
        """

        LOGGER.debug('Issuer._create_rev_reg >>> rr_id: %s, rr_size: %s', rr_id, rr_size)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Issuer._create_rev_reg <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        rr_size = rr_size or 256
        (cd_id, tag) = rev_reg_id2cred_def_id_tag(rr_id)

        LOGGER.info('Creating revocation registry (capacity %s) for rev reg id %s', rr_size, rr_id)
        tails_writer_handle = await blob_storage.open_writer(
            'default',
            json.dumps({
                'base_dir': Tails.dir(self._dir_tails, rr_id),
                'uri_pattern': ''
            }))
        apriori = Tails.unlinked(self._dir_tails)
        (rr_id, rrd_json, rre_json) = await anoncreds.issuer_create_and_store_revoc_reg(
            self.wallet.handle,
            self.did,
            'CL_ACCUM',
            tag,
            cd_id,
            json.dumps({
                'max_cred_num': rr_size,
                'issuance_type': 'ISSUANCE_ON_DEMAND'
            }),
            tails_writer_handle)
        delta = Tails.unlinked(self._dir_tails) - apriori
        if len(delta) != 1:
            LOGGER.debug(
                'Issuer._create_rev_reg: <!< Could not create tails file for rev reg id: %s', rr_id)
            raise CorruptTails('Could not create tails file for rev reg id {}'.format(rr_id))
        tails_hash = basename(delta.pop())
        Tails.associate(self._dir_tails, rr_id, tails_hash)

        with REVO_CACHE.lock:
            rrd_req_json = await ledger.build_revoc_reg_def_request(self.did, rrd_json)
            await self._sign_submit(rrd_req_json)
            await self._get_rev_reg_def(rr_id)  # add to cache en passant

        rre_req_json = await ledger.build_revoc_reg_entry_request(self.did, rr_id, 'CL_ACCUM', rre_json)
        await self._sign_submit(rre_req_json)

        LOGGER.debug('Issuer._create_rev_reg <<<')

    async def _sync_revoc(self, rr_id: str, rr_size: int = None) -> None:
        """
        Create revoc registry if need be for input revocation registry identifier;
        open and cache tails file reader.

        :param rr_id: revocation registry identifier
        :param rr_size: if new revocation registry necessary, its size (default as per _create_rev_reg())
        """

        LOGGER.debug('Issuer._sync_revoc >>> rr_id: %s, rr_size: %s', rr_id, rr_size)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Issuer._sync_revoc <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        (cd_id, tag) = rev_reg_id2cred_def_id_tag(rr_id)

        try:
            await self.get_cred_def(cd_id)
        except AbsentCredDef:
            LOGGER.debug(
                'Issuer._sync_revoc: <!< tails tree %s may be for another ledger; no cred def found on %s',
                self._dir_tails,
                cd_id)
            raise AbsentCredDef('Tails tree {} may be for another ledger; no cred def found on {}'.format(
                self._dir_tails,
                cd_id))

        with REVO_CACHE.lock:
            revo_cache_entry = REVO_CACHE.get(rr_id, None)
            tails = None if revo_cache_entry is None else revo_cache_entry.tails
            if tails is None:  #  it's a new revocation registry, or not yet set in cache
                try:
                    tails = await Tails(self._dir_tails, cd_id, tag).open()
                except AbsentTails:
                    await self._create_rev_reg(rr_id, rr_size)   # it's a new revocation registry
                    tails = await Tails(self._dir_tails, cd_id, tag).open()  # symlink should exist now

                if revo_cache_entry is None:
                    REVO_CACHE[rr_id] = RevoCacheEntry(None, tails)
                else:
                    REVO_CACHE[rr_id].tails = tails

        LOGGER.debug('Issuer._sync_revoc <<<')

    def path_tails(self, rr_id: str) -> str:
        """
        Return path to tails file for input revocation registry identifier.

        :param rr_id: revocation registry identifier of interest
        :return: path to tails file for input revocation registry identifier
        """

        LOGGER.debug('Issuer.path_tails >>>')

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Issuer.path_tails <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        rv = Tails.linked(self._dir_tails, rr_id)
        LOGGER.debug('Issuer.path_tails <<< %s', rv)
        return rv

    async def send_cred_def(self, s_id: str, revocation: bool = True, rr_size: int = None) -> str:
        """
        Create a credential definition as Issuer, store it in its wallet, and send it to the ledger.

        Raise CorruptWallet for wallet not pertaining to current ledger, BadLedgerTxn on failure
        to send credential definition to ledger if need be, or IndyError for any other failure
        to create and store credential definition in wallet.

        :param s_id: schema identifier
        :param revocation: whether to support revocation for cred def
        :param rr_size: size of initial revocation registry (default as per _create_rev_reg()), if revocation supported
        :return: json credential definition as it appears on ledger
        """

        LOGGER.debug('Issuer.send_cred_def >>> s_id: %s, revocation: %s, rr_size: %s', s_id, revocation, rr_size)

        if not ok_schema_id(s_id):
            LOGGER.debug('Issuer.send_cred_def <!< Bad schema id %s', s_id)
            raise BadIdentifier('Bad schema id {}'.format(s_id))

        rv_json = json.dumps({})
        schema_json = await self.get_schema(schema_key(s_id))
        schema = json.loads(schema_json)

        cd_id = cred_def_id(self.did, schema['seqNo'])
        private_key_ok = True
        with CRED_DEF_CACHE.lock:
            try:
                rv_json = await self.get_cred_def(cd_id)
                LOGGER.info(
                    'Cred def on schema %s version %s already exists on ledger; Issuer %s not sending another',
                    schema['name'],
                    schema['version'],
                    self.wallet.name)
            except AbsentCredDef:
                pass  # OK - about to create, store, and send it

            try:
                (_, cred_def_json) = await anoncreds.issuer_create_and_store_credential_def(
                    self.wallet.handle,
                    self.did,  # issuer DID
                    schema_json,
                    CD_ID_TAG,  # expect only one cred def per schema and issuer
                    'CL',
                    json.dumps({'support_revocation': revocation}))
                if json.loads(rv_json):
                    private_key_ok = False
                    LOGGER.warning(
                        'New cred def on %s in wallet shadows existing one on ledger: private key not usable', cd_id)
                        # carry on though, this anchor may have other roles so public key may be good enough
            except IndyError as x_indy:
                if x_indy.error_code == ErrorCode.AnoncredsCredDefAlreadyExistsError:
                    if json.loads(rv_json):
                        LOGGER.info(
                            'Issuer wallet %s reusing existing cred def on schema %s version %s',
                            self.wallet.name,
                            schema['name'],
                            schema['version'])
                    else:
                        LOGGER.debug('Issuer.send_cred_def: <!< corrupt wallet %s', self.wallet.name)
                        raise CorruptWallet(
                            'Corrupt Issuer wallet {} has cred def on schema {} version {} not on ledger'.format(
                                self.wallet.name,
                                schema['name'],
                                schema['version']))
                else:
                    LOGGER.debug(
                        'Issuer.send_cred_def: <!< cannot store cred def in wallet %s: indy error code %s',
                        self.wallet.name,
                        x_indy.error_code)
                    raise

            if not json.loads(rv_json):  # checking the ledger returned no cred def: send it
                req_json = await ledger.build_cred_def_request(self.did, cred_def_json)
                await self._sign_submit(req_json)
                rv_json = await self.get_cred_def(cd_id)  # pick up from ledger and parse; add to cache

                if revocation:
                    await self._sync_revoc(rev_reg_id(cd_id, 0), rr_size)  # create new rev reg, tails file for tag 0

        if revocation and private_key_ok:
            for tag in [str(t) for t in range(int(Tails.next_tag(self._dir_tails, cd_id)[0]))]:  # '0' to str(next-1)
                await self._sync_revoc(rev_reg_id(cd_id, tag), rr_size if tag == 0 else None)

        dir_cred_def = join(self._dir_tails, cd_id)
        if not isdir(dir_cred_def):  # make sure a directory exists for box id collection when required, revo or not
            makedirs(dir_cred_def, exist_ok=True)

        LOGGER.debug('Issuer.send_cred_def <<< %s', rv_json)
        return rv_json

    async def create_cred_offer(self, schema_seq_no: int) -> str:
        """
        Create credential offer as Issuer for given schema.

        Raise CorruptWallet if the wallet has no private key for the corresponding credential definition.

        :param schema_seq_no: schema sequence number
        :return: credential offer json for use in storing credentials at HolderProver.
        """

        LOGGER.debug('Issuer.create_cred_offer >>> schema_seq_no: %s', schema_seq_no)

        rv = None
        cd_id = cred_def_id(self.did, schema_seq_no)
        try:
            rv = await anoncreds.issuer_create_credential_offer(self.wallet.handle, cd_id)
        except IndyError as x_indy:
            if x_indy.error_code == ErrorCode.WalletNotFoundError:
                LOGGER.debug(
                    'Issuer.create_cred_offer: <!< did not issue cred definition from wallet %s',
                    self.wallet.name)
                raise CorruptWallet(
                    'Cannot create cred offer: did not issue cred definition from wallet {}'.format(self.wallet.name))
            else:
                LOGGER.debug(
                    'Issuer.create_cred_offer: <!<  cannot create cred offer, indy error code %s',
                    x_indy.error_code)
                raise

        LOGGER.debug('Issuer.create_cred_offer <<< %s', rv)
        return rv

    async def create_cred(
            self,
            cred_offer_json,
            cred_req_json: str,
            cred_attrs: dict,
            rr_size: int = None) -> (str, str, int):
        """
        Create credential as Issuer out of credential request and dict of key:value (raw, unencoded)
        entries for attributes.

        Return credential json, and if cred def supports revocation, credential revocation identifier
        and revocation registry delta ledger timestamp (epoch seconds).

        If the credential definition supports revocation, and the current revocation registry is full,
        the processing creates a new revocation registry en passant. Depending on the revocation
        registry size (by default starting at 256 and doubling iteratively through 4096), this
        operation may delay credential creation by several seconds.

        :param cred_offer_json: credential offer json as created by Issuer
        :param cred_req_json: credential request json as created by HolderProver
        :param cred_attrs: dict mapping each attribute to its raw value (the operation encodes it); e.g.,

        ::

            {
                'favourite_drink': 'martini',
                'height': 180,
                'last_visit_date': '2017-12-31',
                'weaknesses': None
            }

        :param rr_size: size of new revocation registry (default as per _create_rev_reg()) if necessary
        :return: newly issued credential json; credential revocation identifier (if cred def supports
            revocation, None otherwise), and ledger timestamp (if cred def supports revocation, None otherwise)
        """

        LOGGER.debug(
            'Issuer.create_cred >>> cred_offer_json: %s, cred_req_json: %s, cred_attrs: %s, rr_size: %s',
            cred_offer_json,
            cred_req_json,
            cred_attrs,
            rr_size)

        cd_id = json.loads(cred_offer_json)['cred_def_id']
        if not ok_cred_def_id(cd_id):
            LOGGER.debug('Issuer.create_cred <!< Bad cred def id %s', cd_id)
            raise BadIdentifier('Bad cred def id {}'.format(cd_id))

        cred_def = json.loads(await self.get_cred_def(cd_id))  # ensure cred def is in cache

        if 'revocation' in cred_def['value']:
            with REVO_CACHE.lock:
                rr_id = Tails.current_rev_reg_id(self._dir_tails, cd_id)
                tails = REVO_CACHE[rr_id].tails
                assert tails  # at (re)start, at cred def, Issuer sync_revoc() sets this index in revocation cache

                try:
                    (cred_json, cred_revoc_id, rr_delta_json) = await anoncreds.issuer_create_credential(
                        self.wallet.handle,
                        cred_offer_json,
                        cred_req_json,
                        json.dumps({k: cred_attr_value(cred_attrs[k]) for k in cred_attrs}),
                        rr_id,
                        tails.reader_handle)
                    # do not create rr delta frame and append to cached delta frames list: timestamp could lag or skew
                    rre_req_json = await ledger.build_revoc_reg_entry_request(
                        self.did,
                        rr_id,
                        'CL_ACCUM',
                        rr_delta_json)
                    await self._sign_submit(rre_req_json)
                    assert rr_id == tails.rr_id
                    resp_json = await self._sign_submit(rre_req_json)
                    resp = json.loads(resp_json)
                    rv = (cred_json, cred_revoc_id, resp['result']['txnMetadata']['txnTime'])

                except IndyError as x_indy:
                    if x_indy.error_code == ErrorCode.AnoncredsRevocationRegistryFullError:
                        (tag, rr_size_suggested) = Tails.next_tag(self._dir_tails, cd_id)
                        rr_id = rev_reg_id(cd_id, tag)
                        await self._create_rev_reg(rr_id, rr_size or rr_size_suggested)
                        REVO_CACHE[rr_id].tails = await Tails(self._dir_tails, cd_id).open()
                        return await self.create_cred(cred_offer_json, cred_req_json, cred_attrs)  # should be ok now

                    LOGGER.debug('Issuer.create_cred: <!<  cannot create cred, indy error code %s', x_indy.error_code)
                    raise
        else:
            try:
                (cred_json, _, _) = await anoncreds.issuer_create_credential(
                    self.wallet.handle,
                    cred_offer_json,
                    cred_req_json,
                    json.dumps({k: cred_attr_value(cred_attrs[k]) for k in cred_attrs}),
                    None,
                    None)
                rv = (cred_json, _, _)
            except IndyError as x_indy:
                LOGGER.debug('Issuer.create_cred: <!<  cannot create cred, indy error code %s', x_indy.error_code)
                raise

        LOGGER.debug('Issuer.create_cred <<< %s', rv)
        return rv

    async def revoke_cred(self, rr_id: str, cr_id) -> int:
        """
        Revoke credential that input revocation registry identifier and
        credential revocation identifier specify.

        Return (epoch seconds) time of revocation.

        Raise AbsentTails if no tails file is available for input
        revocation registry identifier. Raise BadRevocation if issuer cannot
        revoke specified credential for any other reason (e.g., did not issue it,
        already revoked it).

        :param rr_id: revocation registry identifier
        :param cr_id: credential revocation identifier
        :return: time of revocation, in epoch seconds
        """

        LOGGER.debug('Issuer.revoke_cred >>> rr_id: %s, cr_id: %s', rr_id, cr_id)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Issuer.revoke_cred <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        tails_reader_handle = (await Tails(
            self._dir_tails,
            *rev_reg_id2cred_def_id_tag(rr_id)).open()).reader_handle
        try:
            rrd_json = await anoncreds.issuer_revoke_credential(
                self.wallet.handle,
                tails_reader_handle,
                rr_id,
                cr_id)
        except IndyError as x_indy:
            LOGGER.debug(
                'Issuer.revoke_cred: <!< Could not revoke revoc reg id %s, cred rev id %s: indy error code %s',
                rr_id,
                cr_id,
                x_indy.error_code)
            raise BadRevocation(
                'Could not revoke revoc reg id {}, cred rev id {}: indy error code {}'.format(
                    rr_id,
                    cr_id,
                    x_indy.error_code))

        rre_req_json = await ledger.build_revoc_reg_entry_request(self.did, rr_id, 'CL_ACCUM', rrd_json)
        resp_json = await self._sign_submit(rre_req_json)
        resp = json.loads(resp_json)

        rv = resp['result']['txnMetadata']['txnTime']
        LOGGER.debug('Issuer.revoke_cred <<< %s', rv)
        return rv

    async def get_box_ids_json(self) -> str:
        """
        Return json object on lists of all unique box identifiers (schema identifiers,
        credential definition identifiers, and revocation registry identifiers) for
        all credential definitions and credentials issued; e.g.,

        ::

            {
                "schema_id": [
                    "R17v42T4pk...:2:tombstone:1.2",
                    ...
                ],
                "cred_def_id": [
                    "R17v42T4pk...:3:CL:19:0",
                    ...
                ]
                "rev_reg_id": [
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:0:CL_ACCUM:0",
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:0:CL_ACCUM:1",
                    ...
                ]
            }

        An issuer must issue a credential definition to include its schema identifier
        in the returned values; the schema identifier in isolation belongs properly
        to an Origin, not necessarily to an Issuer.

        The operation may be useful for a Verifier anchor going off-line to seed its
        cache before doing so.

        :return: tuple of sets for schema ids, cred def ids, rev reg ids
        """

        LOGGER.debug('Issuer.get_box_ids_json >>>')

        cd_ids = [d for d in listdir(self._dir_tails)
            if isdir(join(self._dir_tails, d)) and ok_cred_def_id(d) and d.startswith('{}:3:'.format(self.did))]
        s_ids = []
        for cd_id in cd_ids:
            try:
                s_ids.append(json.loads(await self.get_schema(cred_def_id2seq_no(cd_id)))['id'])
            except AbsentSchema:
                LOGGER.error(
                    'Issuer %s has issued cred def %s but no corresponding schema on ledger',
                    self.wallet.name,
                    cd_id)
        rr_ids = [basename(link) for link in Tails.links(self._dir_tails, self.did)]

        rv = json.dumps({
            'schema_id': s_ids,
            'cred_def_id': cd_ids,
            'rev_reg_id': rr_ids
        })
        LOGGER.debug('Issuer.get_box_ids_json <<< %s', rv)
        return rv
