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
import logging
from os import environ
from pathlib import Path
from shutil import rmtree
from tempfile import gettempdir

import pytest

from indy import wallet, pool, ledger


logging.basicConfig(level=logging.WARN, format='%(levelname)-8s | %(name)-12s | %(message)s')
logging.getLogger('test.conftest').setLevel(logging.INFO)
logging.getLogger('asyncio').setLevel(logging.WARN)
logging.getLogger('von_anchor').setLevel(logging.WARN)
logging.getLogger('indy').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('requests').setLevel(logging.ERROR)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def seed_trustee1():
    logger = logging.getLogger(__name__)
    logger.debug("seed_trustee1: >>>")

    res = "000000000000000000000000Trustee1"

    logger.debug("seed_trustee1: <<< res: %r", res)
    return res

@pytest.fixture
def path_temp():
    logger = logging.getLogger(__name__)
    logger.debug("path_temp: >>>")

    path = Path(gettempdir()).joinpath("indy_client")

    if path.exists():
        logger.debug("path_temp: Cleanup tmp path: %s", path)
        rmtree(str(path))

    logger.debug("path_temp: yield: %r", path)
    yield path

    if path.exists():
        logger.debug("path_temp: Cleanup tmp path: %s", path)
        rmtree(str(path))

    logger.debug("path_temp: <<<")


@pytest.fixture
def path_home() -> Path:
    logger = logging.getLogger(__name__)
    logger.debug("path_home: >>>")

    path = Path.home().joinpath(".indy_client")

    if path.exists():
        logger.debug("path_home: (abstaining from) cleanup home path: %r", path)
        # rmtree(str(path))

    logger.debug("path_home: yield: %r", path)
    yield path

    if path.exists():
        logger.debug("path_home: (abstaining from) cleanup home path: %r", path)
        # rmtree(str(path))

    logger.debug("path_home: <<<")


@pytest.fixture
def wallet_handle_cleanup():
    logger = logging.getLogger(__name__)
    logger.debug("wallet_handle_cleanup: >>>")

    res = True

    logger.debug("wallet_handle_cleanup: <<< res: %r", res)
    return res

@pytest.fixture
def pool_name():
    logger = logging.getLogger(__name__)
    logger.debug("pool_name: >>>")

    res = "pool1"

    logger.debug("pool_name: <<< res: %r", res)
    return res


@pytest.fixture
def pool_ip():
    logger = logging.getLogger(__name__)
    logger.debug("pool_ip: >>>")

    res = environ.get("TEST_POOL_IP", "127.0.0.1")

    logger.debug("pool_ip: <<< res: %r", res)
    return res


@pytest.fixture
def pool_genesis_txn_count():
    logger = logging.getLogger(__name__)
    logger.debug("pool_genesis_txn_count: >>>")

    res = 4

    logger.debug("pool_genesis_txn_count: <<< res: %r", res)
    return res


@pytest.fixture
def pool_genesis_txn_data(pool_genesis_txn_count, pool_ip):
    logger = logging.getLogger(__name__)
    logger.debug("pool_genesis_txn_data: >>> pool_genesis_txn_count: %r, pool_ip: %r",
                 pool_genesis_txn_count,
                 pool_ip)

    assert 0 < pool_genesis_txn_count <= 4

    res = "\n".join([
                        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node1","blskey":"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba","client_ip":"{}","client_port":9702,"node_ip":"{}","node_port":9701,"services":["VALIDATOR"]}},"dest":"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv"}},"metadata":{{"from":"Th7MpTaRZVRYnPiabds81Y"}},"type":"0"}},"txnMetadata":{{"seqNo":1,"txnId":"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62"}},"ver":"1"}}'.format(
                            pool_ip, pool_ip),
                        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node2","blskey":"37rAPpXVoxzKhz7d9gkUe52XuXryuLXoM6P6LbWDB7LSbG62Lsb33sfG7zqS8TK1MXwuCHj1FKNzVpsnafmqLG1vXN88rt38mNFs9TENzm4QHdBzsvCuoBnPH7rpYYDo9DZNJePaDvRvqJKByCabubJz3XXKbEeshzpz4Ma5QYpJqjk","client_ip":"{}","client_port":9704,"node_ip":"{}","node_port":9703,"services":["VALIDATOR"]}},"dest":"8ECVSk179mjsjKRLWiQtssMLgp6EPhWXtaYyStWPSGAb"}},"metadata":{{"from":"EbP4aYNeTHL6q385GuVpRV"}},"type":"0"}},"txnMetadata":{{"seqNo":2,"txnId":"1ac8aece2a18ced660fef8694b61aac3af08ba875ce3026a160acbc3a3af35fc"}},"ver":"1"}}'.format(
                            pool_ip, pool_ip),
                        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node3","blskey":"3WFpdbg7C5cnLYZwFZevJqhubkFALBfCBBok15GdrKMUhUjGsk3jV6QKj6MZgEubF7oqCafxNdkm7eswgA4sdKTRc82tLGzZBd6vNqU8dupzup6uYUf32KTHTPQbuUM8Yk4QFXjEf2Usu2TJcNkdgpyeUSX42u5LqdDDpNSWUK5deC5","client_ip":"{}","client_port":9706,"node_ip":"{}","node_port":9705,"services":["VALIDATOR"]}},"dest":"DKVxG2fXXTU8yT5N7hGEbXB3dfdAnYv1JczDUHpmDxya"}},"metadata":{{"from":"4cU41vWW82ArfxJxHkzXPG"}},"type":"0"}},"txnMetadata":{{"seqNo":3,"txnId":"7e9f355dffa78ed24668f0e0e369fd8c224076571c51e2ea8be5f26479edebe4"}},"ver":"1"}}'.format(
                            pool_ip, pool_ip),
                        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node4","blskey":"2zN3bHM1m4rLz54MJHYSwvqzPchYp8jkHswveCLAEJVcX6Mm1wHQD1SkPYMzUDTZvWvhuE6VNAkK3KxVeEmsanSmvjVkReDeBEMxeDaayjcZjFGPydyey1qxBHmTvAnBKoPydvuTAqx5f7YNNRAdeLmUi99gERUU7TD8KfAa6MpQ9bw","client_ip":"{}","client_port":9708,"node_ip":"{}","node_port":9707,"services":["VALIDATOR"]}},"dest":"4PS3EDQ3dW1tci1Bp6543CfuuebjFrg36kLAUcskGfaA"}},"metadata":{{"from":"TWwCRQRZ2ZHMJFn9TzLp7W"}},"type":"0"}},"txnMetadata":{{"seqNo":4,"txnId":"aa5e817d7cc626170eca175822029339a444eb0ee8f0bd20d3b0b76e566fb008"}},"ver":"1"}}'.format(
                            pool_ip, pool_ip)
                    ][0:pool_genesis_txn_count])

    logger.debug("pool_genesis_txn_data: <<< res: %r", res)
    return res


@pytest.fixture
def pool_genesis_txn_path(pool_name, path_temp):
    logger = logging.getLogger(__name__)
    logger.debug("pool_genesis_txn_path: >>> pool_name: %r",
                 pool_name)

    res = path_temp.joinpath("{}.txn".format(pool_name))

    logger.debug("pool_genesis_txn_path: <<< res: %r", res)
    return res


# noinspection PyUnusedLocal
@pytest.fixture
def pool_genesis_txn_file(pool_genesis_txn_path, pool_genesis_txn_data):
    logger = logging.getLogger(__name__)
    logger.debug("pool_genesis_txn_file: >>> pool_genesis_txn_path: %r, pool_genesis_txn_data: %r",
                 pool_genesis_txn_path,
                 pool_genesis_txn_data)

    pool_genesis_txn_path.parent.mkdir(parents=True, exist_ok=True)

    with open(str(pool_genesis_txn_path), "w+") as f:
        f.writelines(pool_genesis_txn_data)

    logger.debug("pool_genesis_txn_file: <<<")


@pytest.fixture
def pool_ledger_config_cleanup():
    return True


# noinspection PyUnusedLocal
@pytest.fixture
def pool_ledger_config(event_loop, pool_name, pool_genesis_txn_path, pool_genesis_txn_file,
                       pool_ledger_config_cleanup, path_home):
    logger = logging.getLogger(__name__)
    logger.debug("pool_ledger_config: >>> pool_name: %r, pool_genesis_txn_path: %r, pool_genesis_txn_file: %r,"
                 " pool_ledger_config_cleanup: %r, path_home: %r",
                 pool_name,
                 pool_genesis_txn_path,
                 pool_genesis_txn_file,
                 pool_ledger_config_cleanup,
                 path_home)

    logger.debug("pool_ledger_config: Creating pool ledger config")
    event_loop.run_until_complete(pool.create_pool_ledger_config(
        pool_name,
        json.dumps({
            "genesis_txn": str(pool_genesis_txn_path)
        })))

    logger.debug("pool_ledger_config: yield")
    yield

    logger.debug("pool_ledger_config: Deleting pool ledger config")
    event_loop.run_until_complete(pool.delete_pool_ledger_config(pool_name)) if pool_ledger_config_cleanup else None

    logger.debug("pool_ledger_config: <<<")


@pytest.fixture
def pool_handle_cleanup():
    logger = logging.getLogger(__name__)
    logger.debug("pool_handle_cleanup: >>>")

    res = True

    logger.debug("pool_handle_cleanup: <<< res: %r", res)
    return res


@pytest.fixture
def pool_config():
    logger = logging.getLogger(__name__)
    logger.debug("pool_config: >>>")

    res = None

    logger.debug("pool_config: <<< res: %r", res)
    return res


# noinspection PyUnusedLocal
@pytest.fixture
def pool_handle(event_loop, pool_name, pool_ledger_config, pool_config, pool_handle_cleanup):
    logger = logging.getLogger(__name__)
    logger.debug("pool_handle: >>> pool_name: %r, pool_ledger_config: %r, pool_config: %r, pool_handle_cleanup: %r",
                 pool_name,
                 pool_ledger_config,
                 pool_config,
                 pool_handle_cleanup)

    logger.debug("pool_handle: Opening pool ledger")
    pool_handle = event_loop.run_until_complete(pool.open_pool_ledger(pool_name, pool_config))
    assert type(pool_handle) is int

    logger.debug("pool_handle: yield: %r", pool_handle)
    yield pool_handle

    logger.debug("pool_handle: Closing pool ledger")
    event_loop.run_until_complete(pool.close_pool_ledger(pool_handle)) if pool_handle_cleanup else None

    logger.debug("pool_handle: <<<")


@pytest.fixture
async def identity_trustee1(wallet_handle, seed_trustee1):
    (trustee_did, trustee_verkey, _) = await signus.create_and_store_my_did(wallet_handle,
                                                                            json.dumps({"seed": seed_trustee1}))
    return (trustee_did, trustee_verkey)
