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


import asyncio
import json
import pytest


from math import ceil
from random import shuffle
from threading import Thread
from time import time as epoch
from von_anchor.cache import CRED_DEF_CACHE, SCHEMA_CACHE
from von_anchor.error import CacheIndex
from von_anchor.frill import Ink, ppjson
from von_anchor.util import cred_def_id, schema_id, SchemaKey


@pytest.mark.asyncio
async def test_schema_cache():
    print(Ink.YELLOW('\n\n== Testing Schema Cache =='))
    N = 32
    s_key = []
    schema = []
    for i in range(N):
        s_key.append(
            SchemaKey('Q4zqM7aXqm7gDQkUVLng{:02d}'.format(i).replace('0', 'Q'),
            'schema-{}'.format(i//5),
            '{}'.format(i%5)))
        schema.append({
            # 'id': schema_id(s_key[i].origin_did, s_key[i].name, s_key[i].version),
            'id': schema_id(*s_key[i]),
            'name': s_key[i].version,
            'version': s_key[i].version,
            'seqNo': i,
            'attrNames': ['attr-{}-{}'.format(i, j) for j in range(N)],
            'ver': '1.0'
        })

    for i in range(N):
        if i % 2:
            SCHEMA_CACHE[s_key[i]] = schema[i]
        else:
            SCHEMA_CACHE[schema[i]['seqNo']] = schema[i]

    for i in range(N):
        assert SCHEMA_CACHE.contains(s_key[i])
        assert SCHEMA_CACHE.contains(schema[i]['seqNo'])
        assert SCHEMA_CACHE[s_key[i]] == SCHEMA_CACHE[schema[i]['seqNo']]

    assert len(SCHEMA_CACHE.index()) == N
    assert not SCHEMA_CACHE.contains(-1)

    try:
        SCHEMA_CACHE[-1]
    except CacheIndex:
        pass

    # Exercise cache clearing and feeding
    cached = SCHEMA_CACHE.schemata()
    assert SCHEMA_CACHE.schemata()
    cached_json = json.dumps(cached)
    SCHEMA_CACHE.clear()
    assert not SCHEMA_CACHE.schemata()
    SCHEMA_CACHE.feed(json.loads(cached_json))
    assert len(SCHEMA_CACHE.schemata()) == len(cached)


def get_loop():
    rv = None
    try:
        rv = asyncio.get_event_loop()
    except RuntimeError:
        rv = asyncio.new_event_loop()
        asyncio.set_event_loop(rv)
    return rv


def do(coro):
    return get_loop().run_until_complete(coro)


DELAY = 3
async def simulate_get(ser_no, did):
    rv = None
    with CRED_DEF_CACHE.lock:  # REVO_CACHE builds on same lock mechanism - this unit test suffices for both caches
        cd_id = cred_def_id(did, ser_no)
        if cd_id in CRED_DEF_CACHE:
            rv = CRED_DEF_CACHE[cd_id]
            # print('<< got from cache[{}] = {}'.format((ser_no, did), rv))
        else:
            rv = hash(cd_id)
            # print('>> added cache[{}] = {}'.format((ser_no, did), rv))
            await asyncio.sleep(DELAY)
            CRED_DEF_CACHE[cd_id] = rv
    return rv


def get(ser_no, did):
    return do(simulate_get(ser_no, did))


def _ser_no2did(ser_no):
    return str(hash(str(ser_no)))


cache_test_done = False
def _dot():
    global cache_test_done
    while not cache_test_done:
        print('.', end='', flush=True)
        do(asyncio.sleep(1))


@pytest.mark.asyncio
async def test_cache_multithread():
    global cache_test_done

    print(Ink.YELLOW('\n\n== Testing Cache Multithreading =='))

    THREADS = 64
    MODULUS = 5
    epoch_start = epoch()
    cache_threads = []

    dot_thread = Thread(target=_dot)
    for ser_no in range(THREADS):
        cache_threads.append(Thread(target=get, args=(ser_no % MODULUS, _ser_no2did(ser_no % MODULUS))))

    dot_thread.start()

    shuffle(cache_threads)
    for thread in cache_threads:
        # print('Starting thread {}'.format(cache_threads.index(thread)))
        thread.start()

    for thread in cache_threads:
        thread.join()

    elapsed = ceil(epoch() - epoch_start)
    assert elapsed < 2 * MODULUS * DELAY # shouldn't get caught waiting more than once per cache write

    cache_test_done = True
    dot_thread.join()
