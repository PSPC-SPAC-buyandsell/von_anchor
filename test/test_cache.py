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

from math import ceil
from random import shuffle
from threading import Thread
from time import time as epoch
from von_agent.cache import claim_def_cache, claim_def_cache_lock, schema_cache, schema_cache_lock
from von_agent.error import CacheIndex
from von_agent.schemakey import SchemaKey
from von_agent.util import ppjson

import asyncio
import pytest


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_schema_cache():
    N = 5 
    s_key = []
    schema = []
    for i in range(N):
        s_key.append(SchemaKey('did.{}'.format(i), 'schema-{}'.format(i//5), '{}'.format(i%5)))
        schema.append({
            'seqNo': i,
            'identifier': s_key[i].origin_did,
            'data': {
                'name': s_key[i].name,
                'version': s_key[i].version
            }
        })

    for i in range(N):
        if i % 2:
            schema_cache[s_key[i]] = schema[i]
        else:
            schema_cache[schema[i]['seqNo']] = schema[i]

    for i in range(N):
        assert schema_cache.contains(s_key[i])
        assert schema_cache.contains(schema[i]['seqNo'])
        assert schema_cache[s_key[i]] == schema_cache[schema[i]['seqNo']]

    assert len(schema_cache.index()) == N
    assert not schema_cache.contains(-1)

    try:
        schema_cache[-1]
    except CacheIndex:
        pass


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


DELAY=3
async def simulate_get(ser_no, did):
    rv = None
    with claim_def_cache_lock:
        if (ser_no, did) in claim_def_cache:
            rv = claim_def_cache[(ser_no, did)]
            # print('<< got from cache[{}] = {}'.format((ser_no, did), rv))
        else:
            rv = hash((ser_no, did))
            # print('>> added cache[{}] = {}'.format((ser_no, did), rv))
            await asyncio.sleep(DELAY)
            claim_def_cache[(ser_no, did)] = rv
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

#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cache_multithread():
    global cache_test_done
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
