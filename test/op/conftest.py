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

import asyncio
import json
import logging

from os import environ
from pathlib import Path
from shutil import rmtree
from tempfile import gettempdir
from time import time

import pytest

from indy import wallet, pool, ledger


logging.basicConfig(level=logging.WARNING, format='%(levelname)-8s | %(name)-12s | %(message)s')
logging.getLogger('test.conftest').setLevel(logging.INFO)
logging.getLogger('asyncio').setLevel(logging.WARNING)
logging.getLogger('von_anchor').setLevel(logging.WARNING)
logging.getLogger('indy').setLevel(logging.ERROR)


@pytest.fixture
def seed_new_anchor():
    logger = logging.getLogger(__name__)
    logger.debug("seed_new_anchor: >>>")

    res = "{}000000000000NewAnchor1".format(int(time()))

    logger.debug("seed_new_anchor: <<< res: %r", res)
    return res


@pytest.fixture
def path_sendnym_ini(path_temp):
    logger = logging.getLogger(__name__)
    logger.debug("path_sendnym_ini: >>>")

    res = Path(path_temp).joinpath("sendnym.ini")

    logger.debug("path_sendnym_ini: <<< res: %r", res)
    return res


@pytest.fixture
def sendnym_ini_file(path_sendnym_ini, pool_name, seed_trustee1, seed_new_anchor):
    logger = logging.getLogger(__name__)
    logger.debug(
        "sendnym_ini_file: >>> path_sendnym_ini: %r, pool_name: %r, seed_trustee1: %r, seed_new_anchor: %r",
        path_sendnym_ini,
        pool_name,
        seed_trustee1,
        seed_new_anchor)

    path_sendnym_ini.parent.mkdir(parents=True, exist_ok=True)

    data = '\n'.join([
        '[Node Pool]',
        'name={}'.format(pool_name),
        'genesis.txn.path=${{HOME}}/.indy_client/pool/{}/{}.txn'.format(pool_name, pool_name),
        '',
        '[Trustee Anchor]',
        'seed={}'.format(seed_trustee1),
        'wallet.name=trustee-anchor',
        'wallet.type=',
        'wallet.key='
        '',
        '[New Anchor]',
        'role=TRUST_ANCHOR',
        'seed={}'.format(seed_new_anchor),
        'wallet.name=anchor-{}'.format(seed_new_anchor[0:10]),
        'wallet.type=',
        'wallet.key='])

    with open(str(path_sendnym_ini), "w+") as f:
        f.writelines(data)

    logger.debug("sendnym_ini_file: <<<")
