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

from math import sqrt
from os import listdir, makedirs
from os.path import isdir, join
from shutil import rmtree
from threading import RLock
from time import time
from typing import Awaitable, Callable, Tuple, Union
from von_anchor.error import BadIdentifier, BadRevStateTime, CacheIndex
from von_anchor.schema_key import SchemaKey
from von_anchor.tails import Tails
from von_anchor.util import ok_cred_def_id, ok_rev_reg_id, ok_schema_id, rev_reg_id2cred_def_id, schema_key


LOGGER = logging.getLogger(__name__)


class SchemaCache:
    """
    Retain schemata and fetch by schema key (origin_did, name, version) or by sequence number.
    Note that schema key is isomorphic to schema_id, but since schema_id is a str and indy-sdk
    stores sequence number as a str in some cases, it is more defensive to index by schema key
    than schema_id.

    A lock shares access to critical sections as relying code specifies them (e.g., check and get/set).
    Note that this one lock applies across all instances - the design of this class intends it to be a singleton.
    """

    lock = RLock()

    def __init__(self) -> None:
        """
        Initialize schema cache data.
        """

        LOGGER.debug('SchemaCache.__init__ >>>')

        self._schema_key2schema = {}
        self._seq_no2schema_key = {}

        LOGGER.debug('SchemaCache.__init__ <<<')

    def __getitem__(self, index: Union[SchemaKey, int, str]) -> dict:
        """
        Get schema by schema key, sequence number, or schema identifier. Raise CacheIndex for no such schema.

        Raise CacheIndex for no such index in schema store.

        :param index: schema key, sequence number, or schema identifier
        :return: corresponding schema or None
        """

        LOGGER.debug('SchemaCache.__getitem__ >>> index: %s', index)

        rv = None
        if isinstance(index, SchemaKey):
            rv = self._schema_key2schema[index]
        elif isinstance(index, int) or (isinstance(index, str) and not ok_schema_id(index)):
            try:
                rv = self._schema_key2schema[self._seq_no2schema_key[int(index)]]
            except KeyError:
                LOGGER.debug('SchemaCache.__getitem__: <!< index %s not present', index)
                raise CacheIndex('{}'.format(index))
        elif isinstance(index, str):
            rv = self._schema_key2schema[schema_key(index)]
        else:
            LOGGER.debug('SchemaCache.__getitem__: <!< index %s must be int SchemaKey, or schema id', index)
            raise CacheIndex('{} must be int, SchemaKey, or schema id'.format(index))

        LOGGER.debug('SchemaCache.__getitem__ <<< %s', rv)
        return rv

    def __setitem__(self, index: Union[SchemaKey, int], schema: dict) -> dict:
        """
        Put schema into cache and return it.

        :param index: schema key or sequence number
        :param schema: schema to put into cache
        :return: input schema
        """

        LOGGER.debug('SchemaCache.__setitem__ >>> index: %s, schema: %s', index, schema)

        if isinstance(index, SchemaKey):
            self._schema_key2schema[index] = schema
            self._seq_no2schema_key[schema['seqNo']] = index
        elif isinstance(index, int):
            s_key = schema_key(schema['id'])
            self._schema_key2schema[s_key] = schema
            self._seq_no2schema_key[index] = s_key
        else:
            LOGGER.debug('SchemaCache.__setitem__: <!< Bad index %s must be a schema key or a sequence number', index)
            raise CacheIndex('Bad index {} must be a schema key or a sequence number'.format(index))

        LOGGER.debug('SchemaCache.__setitem__ <<< %s', schema)
        return schema

    def contains(self, index: Union[SchemaKey, int, str]) -> bool:
        """
        Return whether the cache contains a schema for the input key, sequence number, or schema identifier.

        :param index: schema key, sequence number, or sequence identifier
        :return: whether the cache contains a schema for the input index
        """

        LOGGER.debug('SchemaCache.contains >>> index: %s', index)

        rv = None
        if isinstance(index, SchemaKey):
            rv = (index in self._schema_key2schema)
        elif isinstance(index, int) or (isinstance(index, str) and not ok_schema_id(index)):
            rv = (int(index) in self._seq_no2schema_key)
        elif isinstance(index, str):
            rv = (schema_key(index) in self._schema_key2schema)
        else:
            rv = False

        LOGGER.debug('SchemaCache.contains <<< %s', rv)
        return rv

    def index(self) -> dict:
        """
        Return dict mapping content sequence numbers to schema keys.

        :return: dict mapping sequence numbers to schema keys
        """

        LOGGER.debug('SchemaCache.index >>>')

        rv = self._seq_no2schema_key
        LOGGER.debug('SchemaCache.index <<< %s', rv)
        return rv

    def schema_key_for(self, seq_no: int) -> SchemaKey:
        """
        Get schema key for schema by sequence number if known, None for no such schema in cache.

        :param seq_no: sequence number
        :return: corresponding schema key or None
        """

        LOGGER.debug('SchemaCache.schema_key_for >>> seq_no: %s', seq_no)

        rv = self._seq_no2schema_key.get(seq_no, None)

        LOGGER.debug('SchemaCache.schema_key_for <<< %s', rv)
        return rv

    def schemata(self) -> list:
        """
        Return list with schemata in cache.

        :return: list of schemata
        """

        LOGGER.debug('SchemaCache.schemata >>>')

        LOGGER.debug('SchemaCache.schemata <<<')
        return [self._schema_key2schema[seq_no] for seq_no in self._schema_key2schema]

    def feed(self, schemata: list) -> None:
        """
        Take schemata from incoming list representation as schemata() returns, unless
        cache already has schema for an incoming schema sequence number.

        :param schemata: list of schema objects
        """

        LOGGER.debug('SchemaCache.feed >>> schemata: %s', schemata)

        for schema in schemata:
            seq_no = schema['seqNo']
            s_id = schema['id']
            if not ok_schema_id(s_id):
                LOGGER.warning('Abstaining from feeding schema cache from bad id %s', s_id)
            elif self.contains(seq_no):
                LOGGER.warning('Schema cache already has schema at seq no %s: skipping', seq_no)
            else:
                self[seq_no] = schema
                LOGGER.info('Schema cache imported schema on id %s at seq no %s', s_id, seq_no)

        LOGGER.debug('SchemaCache.feed <<<')

    def clear(self) -> None:
        """
        Clear the cache.
        """

        LOGGER.debug('SchemaCache.clear >>>')

        self._schema_key2schema = {}
        self._seq_no2schema_key = {}

        LOGGER.debug('SchemaCache.clear <<<')


class RevRegUpdateFrame:
    """
    Revocation registry delta or state update, plus metadata, in revocation cache (which indexes on rev reg id).
    Keeps track of last query time, asked-for ('to') time, timestamp on distributed ledger, and rev reg update.
    The last query time is purely for cache management.

    Holder-Prover anchors use deltas to create proof; verifier anchors use states to verify them.

    Necessarily for each cached update frame, timestamp <= frame.to <= qtime.
    """

    def __init__(self, to: int, timestamp: int, rr_update: dict):
        """
        Initialize a new revocation registry update frame for revocation cache.

        :param to: the time (epoch sec) of interest
        :param timestamp: the timestamp (epoch sec) corresponding to the revocation delta on the ledger
        :param rr_update: the indy-sdk revocation registry delta or state update
        """

        self._qtime = int(time())
        self._timestamp = timestamp
        self._to = to
        self._rr_update = rr_update

    @property
    def qtime(self) -> int:
        """
        Accessor for the latest query time resolving to current frame.

        :return: latest latest query time resolving to current frame
        """

        return self._qtime

    @qtime.setter
    def qtime(self, value: int) -> None:
        """
        Set query time value of cache entry.

        :param value: qtime timestamp (epoch seconds)
        """

        self._qtime = value

    @property
    def timestamp(self) -> int:
        """
        Accessor for timestamp on the distributed ledger for the rev reg update.

        :return: timestamp on distributed ledger for current frame's rev reg update
        """

        return self._timestamp

    @property
    def to(self) -> int:
        """
        Accessor for the latest cached time of interest associated with the rev reg update.

        :return: latest time of interest requested regarding current frame's rev reg update
        """

        return self._to

    @to.setter
    def to(self, value: int) -> None:
        """
        Set to value of cache entry.

        :param value: to timestamp (epoch seconds)
        """

        self._to = value

    @property
    def rr_update(self) -> dict:
        """
        Accessor for rev reg update.

        :return: current frame's rev reg update
        """

        return self._rr_update

    def __repr__(self):
        """
        Return canonical representation of the item.
        """

        return 'RevRegUpdateFrame({}, {}, {})'.format(self.to, self.timestamp, self.rr_update)

    def __str__(self):
        """
        Return representation of the item showing query time.
        """

        return 'RevRegUpdateFrame<qtime={}, to={}, timestamp={}, rr_update={}>'.format(
            self.qtime,
            self.to,
            self.timestamp,
            self.rr_update)


class RevoCacheEntry:
    """
    Revocation cache entry housing:
    * a revocation registry definition
    * a Tails structure
    * a list of revocation delta frames.
    """

    def __init__(self, rev_reg_def: dict, tails: Tails = None):
        """
        Initialize with revocation registry definition, optional tails file.
        Set revocation delta frames lists for rev reg deltas and rev reg states empty.

        :param rev_reg_def: revocation registry definition
        :param tails: current tails file object
        """

        LOGGER.debug('RevoCacheEntry.__init__ >>> rev_reg_def: %s, tails: %s', rev_reg_def, tails)

        self._rev_reg_def = rev_reg_def or None
        self._tails = tails or None
        self._rr_delta_frames = []  # for holder-prover, creating proof
        self._rr_state_frames = []  # for verifier, verifying proof

        LOGGER.debug('RevoCacheEntry.__init__ <<<')

    @property
    def rev_reg_def(self) -> dict:
        """
        Return rev reg def from cache entry.
        """

        return self._rev_reg_def

    @rev_reg_def.setter
    def rev_reg_def(self, value: dict) -> None:
        """
        Set rev reg def for cache entry.

        :param value: rev reg def
        """

        self._rev_reg_def = value

    @property
    def tails(self) -> Tails:
        """
        Return current tails file from cache entry.
        """

        return self._tails

    @tails.setter
    def tails(self, value: Tails) -> None:
        """
        Set tails file for cache entry.

        :param value: tails file
        """

        self._tails = value

    @property
    def rr_delta_frames(self) -> list:
        """
        Return current revocation delta frame list.
        """

        return self._rr_delta_frames

    @rr_delta_frames.setter
    def rr_delta_frames(self, value: list) -> None:
        """
        Set rev reg delta frames list for cache entry.

        :param value: rev reg delta frames list.
        """

        self._rr_delta_frames = value

    @property
    def rr_state_frames(self) -> list:
        """
        Return current revocation state frame list.
        """

        return self._rr_state_frames

    @rr_state_frames.setter
    def rr_state_frames(self, value: list) -> None:
        """
        Set rev reg state frames list for cache entry.

        :param value: rev reg state frames list.
        """

        self._rr_state_frames = value

    def cull(self, delta: bool) -> None:
        """
        Cull cache entry frame list to size, favouring most recent query time.

        :param delta: True to operate on rev reg deltas, False for rev reg states
        """

        LOGGER.debug('RevoCacheEntry.cull >>> delta: %s', delta)

        rr_frames = self.rr_delta_frames if delta else self.rr_state_frames
        mark = sqrt(4096)  # max rev reg size = 4096; heuristic: hover max around sqrt(4096) = 64
        if len(rr_frames) > int(mark * 1.25):
            rr_frames.sort(key=lambda x: -x.qtime)  # order by descending query time
            del rr_frames[int(mark * 0.75):]  # retain most recent, grow again from here
            LOGGER.info(
                'Pruned revocation cache entry %s to %s %s frames',
                self.rev_reg_def['id'],
                len(rr_frames),
                'delta' if delta else 'state')

        LOGGER.debug('RevoCacheEntry.cull <<<')

    async def _get_update(self, rr_builder: Callable, fro: int, to: int, delta: bool) -> (str, int):
        """
        Get rev reg delta/state json, and its timestamp on the distributed ledger,
        from cached rev reg delta/state frames list or distributed ledger,
        updating cache as necessary.

        Raise BadRevStateTime if caller asks for a delta/state in the future. Raise ClosedPool
        if an update requires the ledger but the node pool is closed.

        Issuer anchors cannot revoke retroactively.
        Hence, for any new request against asked-for interval (fro, to):
        * if the cache has a frame f on f.timestamp <= to <= f.to,
          > return its rev reg delta/state; e.g., starred frame below:

          Frames: --------[xxxxx]----[xx]-----[*********]-----[x]-----------[xx]---------> time
          Fro-to:                                ^----^

        * otherwise, if there is a maximum frame f with fro <= f.to and f.timestamp <= to
          > return its rev reg delta/state; e.g., starred frame below:

          Frames: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[*]-----------[xx]---------> time
          Fro-to:                  ^----------------------------------^

        * otherwise, if the cache has a frame f on f.timestamp < to,
          > check the distributed ledger for a delta to/state for the rev reg since e.timestamp;
            - if there is one, bake it through 'to' into a new delta/state, add new frame to cache and
              return rev reg delta/state; e.g., starred frame below:

              Frames: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[x]-----------[xx]---------> time
              Fro-to:                                                 ^------^
              Ledger: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[x]--!--------[xx]---------> time
              Update: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[x]--[*****]--[xx]---------> time

            - otherwise, update the 'to' time in the frame and return the rev reg delta/state;
              e.g., starred frame below:

              Frames: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[x]-----------[xx]---------> time
              Fro-to:                                                 ^------^
              Ledger: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[x]-----------[xx]---------> time
              Update: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[**********]--[xx]---------> time

        * otherwise, there is no cache frame f on f.timestamp < to:
          > create new frame and add it to cache; return rev reg delta/state; e.g., starred frame below:

          Frames: --------[xxxxx]----[xx]-----[xxxxxxxxx]-----[*]-----------[xx]-----> time
          Fro-to:   ^--^
          Ledger: -!------[xxxxx]----[xx]-----[xxxxxxxxx]-----[x]-----------[xx]---------> time
          Update: -[***]--[xxxxx]----[xx]-----[xxxxxxxxx]-----[x]-----------[xx]---------> time

        On return of any previously existing rev reg delta/state frame, always update its query time beforehand.

        :param rr_builder: callback to build rev reg delta/state if need be (specify holder-prover anchor's
            _build_rr_delta_json() or verifier anchor's _build_rr_state_json() as needed)
        :param fro: least time (epoch seconds) of interest; lower-bounds 'to' on frame housing return data
        :param to: greatest time (epoch seconds) of interest; upper-bounds returned revocation delta/state timestamp
        :param delta: True to operate on rev reg deltas, False for states
        :return: rev reg delta/state json and ledger timestamp (epoch seconds)
        """

        LOGGER.debug(
            'RevoCacheEntry.get_update >>> rr_builder: %s, fro: %s, to: %s, delta: %s',
            rr_builder.__name__,
            fro,
            to,
            delta)

        if fro > to:
            (fro, to) = (to, fro)

        now = int(time())
        if to > now:
            LOGGER.debug(
                'RevoCacheEntry._get_update <!< Cannot query a rev reg %s in the future (%s > %s)',
                'delta' if delta else 'state',
                to,
                now)
            raise BadRevStateTime('Cannot query a rev reg {} in the future ({} > {})'.format(
                'delta' if delta else 'state',
                to,
                now))

        cache_frame = None
        rr_update_json = None
        rr_frames = self.rr_delta_frames if delta else self.rr_state_frames

        frames = [frame for frame in rr_frames if frame.timestamp <= to <= frame.to]
        if frames:
            cache_frame = max(frames, key=lambda f: f.timestamp)  # should be unique in any case
            # do not update frame.to, it's already past asked-for 'to'
        else:
            frames = [frame for frame in rr_frames if (fro <= frame.to and frame.timestamp <= to)]
            if frames:
                cache_frame = max(frames, key=lambda f: f.timestamp)
                # do not update frame.to - another update might occur, but we don't care; fro < frame.to, good enough
        if not frames:
            frames = [frame for frame in rr_frames if frame.timestamp < to]  # frame.to < to since not frames coming in
            if frames:
                latest_cached = max(frames, key=lambda frame: frame.timestamp)
                if delta:
                    (rr_update_json, timestamp) = await rr_builder(
                        self.rev_reg_def['id'],
                        to=to,
                        fro=latest_cached.timestamp,
                        fro_delta=latest_cached.rr_update)
                else:
                    (rr_update_json, timestamp) = await rr_builder(self.rev_reg_def['id'], to)
                if timestamp == latest_cached.timestamp:
                    latest_cached.to = to  # this timestamp now known good through more recent 'to'
                    cache_frame = latest_cached
            else:
                (rr_update_json, timestamp) = await rr_builder(self.rev_reg_def['id'], to)

        if cache_frame is None:
            cache_frame = RevRegUpdateFrame(to, timestamp, json.loads(rr_update_json))  # sets qtime to now
            rr_frames.append(cache_frame)
            self.cull(delta)
        else:
            cache_frame.qtime = int(time())

        rv = (json.dumps(cache_frame.rr_update), cache_frame.timestamp)
        LOGGER.debug('RevoCacheEntry._get_update <<< %s', rv)
        return rv

    async def get_delta_json(
            self,
            rr_delta_builder: Callable[['HolderProver', str, int, int, dict], Awaitable[Tuple[str, int]]],
            fro: int,
            to: int) -> (str, int):
        """
        Get rev reg delta json, and its timestamp on the distributed ledger,
        from cached rev reg delta frames list or distributed ledger,
        updating cache as necessary.

        Raise BadRevStateTime if caller asks for a delta to the future.

        On return of any previously existing rev reg delta frame, always update its query time beforehand.

        :param rr_delta_builder: callback to build rev reg delta if need be (specify anchor instance's
            _build_rr_delta())
        :param fro: least time (epoch seconds) of interest; lower-bounds 'to' on frame housing return data
        :param to: greatest time (epoch seconds) of interest; upper-bounds returned revocation delta timestamp
        :return: rev reg delta json and ledger timestamp (epoch seconds)
        """

        LOGGER.debug(
            'RevoCacheEntry.get_delta_json >>> rr_delta_builder: %s, fro: %s, to: %s',
            rr_delta_builder.__name__,
            fro,
            to)

        rv = await self._get_update(rr_delta_builder, fro, to, True)
        LOGGER.debug('RevoCacheEntry.get_delta_json <<< %s', rv)
        return rv

    async def get_state_json(
            self,
            rr_state_builder: Callable[['Verifier', str, int], Awaitable[Tuple[str, int]]],
            fro: int,
            to: int) -> (str, int):
        """
        Get rev reg state json, and its timestamp on the distributed ledger,
        from cached rev reg state frames list or distributed ledger,
        updating cache as necessary.

        Raise BadRevStateTime if caller asks for a state in the future.

        On return of any previously existing rev reg state frame, always update its query time beforehand.

        :param rr_state_builder: callback to build rev reg state if need be (specify anchor instance's
            _build_rr_state())
        :param fro: least time (epoch seconds) of interest; lower-bounds 'to' on frame housing return data
        :param to: greatest time (epoch seconds) of interest; upper-bounds returned revocation state timestamp
        :return: rev reg state json and ledger timestamp (epoch seconds)
        """

        LOGGER.debug(
            'RevoCacheEntry.get_state_json >>> rr_state_builder: %s, fro: %s, to: %s',
            rr_state_builder.__name__,
            fro,
            to)

        rv = await self._get_update(rr_state_builder, fro, to, False)
        LOGGER.debug('RevoCacheEntry.get_state_json <<< %s', rv)
        return rv


class CredDefCache(dict):
    """
    Retain credential definitions by cred def id.

    A lock shares access to critical sections as relying code specifies them (e.g., check and get/set).
    Note that this one lock applies across all instances - the design of this class intends it to be a singleton.
    """

    lock = RLock()

    def __init__(self):
        """
        Initialize cred def cache; set re-entrant lock.
        """

        LOGGER.debug('CredDefCache.__init__ >>>')

        super().__init__()

        LOGGER.debug('CredDefCache.__init__ <<<')


class RevocationCache(dict):
    """
    Retain revocation registries by revocation registry identifier.

    A lock shares access to critical sections as relying code specifies them (e.g., check and get/set).
    Note that this one lock applies across all instances - the design of this class intends it to be a singleton.
    """

    lock = RLock()

    def __init__(self):
        """
        Initialize revocation cache; set re-entrant lock.
        """

        LOGGER.debug('RevocationCache.__init__ >>>')

        super().__init__()

        LOGGER.debug('RevocationCache.__init__ <<<')

    def dflt_interval(self, cd_id: str) -> (int, int):
        """
        Return default non-revocation interval from latest 'to' times on delta frames
        of revocation cache entries on indices stemming from input cred def id.

        Compute the 'from'/'to' values as the earliest/latest 'to' values of all
        cached delta frames on all rev reg ids stemming from the input cred def id.

        E.g., on frames for
            rev-reg-0: -[xx]---[xxxx]-[x]---[xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx]--> time
            rev-reg-1: ----------------------[xxxx]----[xxx]---[xxxxxxxxxxxxxxxxxxxx]---------> time
            rev-reg-2: -------------------------------------------[xx]-----[xxxx]-----[xxxxx]-> time
            rev-reg-3: -----------------------------------------------------------[xxxxxxxx]--> time

        return the most recent interval covering all matching revocation registries in the cache; i.e.,:
            interval:  -------------------------------------------------------------[*******]-> time

        Raise CacheIndex if there are no matching entries.

        :param cd_id: cred def identifier to match
        :return: default non-revocation interval as 2-tuple (fro, to)
        """

        LOGGER.debug('RevocationCache.dflt_interval >>>')

        if not ok_cred_def_id(cd_id):
            LOGGER.debug('RevocationCache.dflt_interval <!< Bad cred def id %s', cd_id)
            raise BadIdentifier('Bad cred def id {}'.format(cd_id))

        fro = None
        to = None

        for rr_id in self:
            if cd_id != rev_reg_id2cred_def_id(rr_id):
                continue
            entry = self[rr_id]
            if entry.rr_delta_frames:
                to = max(entry.rr_delta_frames, key=lambda f: f.to).to
                fro = min(fro or to, to)

        if not (fro and to):
            LOGGER.debug(
                'RevocationCache.dflt_interval <!< No data for default non-revoc interval on cred def id %s',
                cd_id)
            raise CacheIndex('No data for default non-revoc interval on cred def id {}'.format(cd_id))

        rv = (fro, to)
        LOGGER.debug('RevocationCache.dflt_interval <<< %s', rv)
        return rv


SCHEMA_CACHE = SchemaCache()
CRED_DEF_CACHE = CredDefCache()
REVO_CACHE = RevocationCache()


class Caches:
    """
    Management utilities for schema, cred def, and revocation caches taken as a whole: archival, parsing, purging.
    """

    @staticmethod
    def clear() -> None:
        """
        Clear all caches in memory.
        """

        LOGGER.debug('clear >>>')

        with SCHEMA_CACHE.lock:
            SCHEMA_CACHE.clear()
        with CRED_DEF_CACHE.lock:
            CRED_DEF_CACHE.clear()
        with REVO_CACHE.lock:
            REVO_CACHE.clear()

        LOGGER.debug('clear <<<')

    @staticmethod
    def archive(base_dir: str) -> int:
        """
        Archive caches to disk as json.

        :param base_dir: archive base directory
        :return: timestamp (epoch seconds) used as subdirectory
        """

        LOGGER.debug('archive >>> base_dir: %s', base_dir)

        rv = int(time())
        timestamp_dir = join(base_dir, str(rv))
        makedirs(timestamp_dir, exist_ok=True)

        with SCHEMA_CACHE.lock:
            with open(join(timestamp_dir, 'schema'), 'w') as archive:
                print(json.dumps(SCHEMA_CACHE.schemata()), file=archive)

        with CRED_DEF_CACHE.lock:
            with open(join(timestamp_dir, 'cred_def'), 'w') as archive:
                print(json.dumps(CRED_DEF_CACHE), file=archive)

        with REVO_CACHE.lock:
            with open(join(timestamp_dir, 'revocation'), 'w') as archive:
                revo_cache_dict = {}
                for rr_id in REVO_CACHE:
                    revo_cache_dict[rr_id] = {
                        'rev_reg_def': REVO_CACHE[rr_id].rev_reg_def,
                        'rr_delta_frames': [vars(f) for f in REVO_CACHE[rr_id].rr_delta_frames],
                        'rr_state_frames': [vars(f) for f in REVO_CACHE[rr_id].rr_state_frames]
                    }
                print(json.dumps(revo_cache_dict), file=archive)

        LOGGER.debug('archive <<< %s', rv)
        return rv

    @staticmethod
    def parse(base_dir: str, timestamp: int = None) -> int:
        """
        Parse and update from archived cache files. Only accept new content;
        do not overwrite any existing cache content.

        :param base_dir: archive base directory
        :param timestamp: epoch time of cache serving as subdirectory, default most recent
        :return: epoch time of cache serving as subdirectory, None if there is no such archive.
        """

        LOGGER.debug('parse >>> base_dir: %s, timestamp: %s', base_dir, timestamp)

        if not isdir(base_dir):
            LOGGER.info('No cache archives available: not feeding cache')
            LOGGER.debug('parse <<< None')
            return None

        if not timestamp:
            timestamps = [int(t) for t in listdir(base_dir) if t.isdigit()]
            if timestamps:
                timestamp = max(timestamps)
            else:
                LOGGER.info('No cache archives available: not feeding cache')
                LOGGER.debug('parse <<< None')
                return None

        timestamp_dir = join(base_dir, str(timestamp))
        if not isdir(timestamp_dir):
            LOGGER.error('No such archived cache directory: %s', timestamp_dir)
            LOGGER.debug('parse <<< None')
            return None

        with SCHEMA_CACHE.lock:
            with open(join(timestamp_dir, 'schema'), 'r') as archive:
                schemata = json.loads(archive.read())
                SCHEMA_CACHE.feed(schemata)

        with CRED_DEF_CACHE.lock:
            with open(join(timestamp_dir, 'cred_def'), 'r') as archive:
                cred_defs = json.loads(archive.read())
                for cd_id in cred_defs:
                    if not ok_cred_def_id(cd_id):
                        LOGGER.warning('Abstaining feeding cache cred def on bad id %s', cd_id)
                    elif cd_id in CRED_DEF_CACHE:
                        LOGGER.warning('Cred def cache already has cred def on %s: skipping', cd_id)
                    else:
                        CRED_DEF_CACHE[cd_id] = cred_defs[cd_id]
                        LOGGER.info('Cred def cache imported cred def for cred def id %s', cd_id)

        with REVO_CACHE.lock:
            with open(join(timestamp_dir, 'revocation'), 'r') as archive:
                rr_cache_entries = json.loads(archive.read())
                for (rr_id, entry) in rr_cache_entries.items():
                    if not ok_rev_reg_id(rr_id):
                        LOGGER.warning('Abstaining from feeding revocation cache rev reg on bad id %s', rr_id)
                    elif rr_id in REVO_CACHE:
                        LOGGER.warning('Revocation cache already has entry on %s: skipping', rr_id)
                    else:
                        rr_cache_entry = RevoCacheEntry(entry['rev_reg_def'])

                        rr_cache_entry.rr_delta_frames = [
                            RevRegUpdateFrame(
                                f['_to'],
                                f['_timestamp'],
                                f['_rr_update']) for f in entry['rr_delta_frames']
                        ]
                        rr_cache_entry.cull(True)

                        rr_cache_entry.rr_state_frames = [
                            RevRegUpdateFrame(
                                f['_to'],
                                f['_timestamp'],
                                f['_rr_update']) for f in entry['rr_state_frames']
                        ]
                        rr_cache_entry.cull(False)

                        REVO_CACHE[rr_id] = rr_cache_entry
                        LOGGER.info('Revocation cache imported entry for rev reg id %s', rr_id)

        LOGGER.debug('parse <<< %s', timestamp)
        return timestamp

    @staticmethod
    def purge_archives(base_dir: str, retain_latest: bool = False) -> None:
        """
        Erase all (or nearly all) cache archives.

        :param base_dir: archive base directory
        :param retain_latest: retain latest archive if present, purge all others
        """

        LOGGER.debug('purge_archives >>> base_dir: %s, retain_latest: %s', base_dir, retain_latest)

        if isdir(base_dir):
            timestamps = sorted([int(t) for t in listdir(base_dir) if t.isdigit()])
            if retain_latest and timestamps:
                timestamps.pop()
            for timestamp in timestamps:
                timestamp_dir = join(base_dir, str(timestamp))
                rmtree(timestamp_dir)
                LOGGER.info('Purged archive cache directory %s', timestamp_dir)

        LOGGER.debug('purge_archives <<<')
