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
def seed_von_anchor():
    logger = logging.getLogger(__name__)
    logger.debug("seed_von_anchor: >>>")

    res = "{}000000000000VonAnchor1".format(int(time()))  # OK while epoch is 10 digits, through circa 2286-11

    logger.debug("seed_von_anchor: <<< res: %r", res)
    return res


@pytest.fixture
def path_setnym_ini(path_temp):
    logger = logging.getLogger(__name__)
    logger.debug("path_setnym_ini: >>>")

    res = Path(path_temp).joinpath("setnym.ini")

    logger.debug("path_setnym_ini: <<< res: %r", res)
    return res


@pytest.fixture
def setnym_ini_file(path_setnym_ini, pool_name, seed_trustee1, seed_von_anchor):
    logger = logging.getLogger(__name__)
    logger.debug(
        "setnym_ini_file: >>> path_setnym_ini: %r, pool_name: %r, seed_trustee1: %r, seed_von_anchor: %r",
        path_setnym_ini,
        pool_name,
        seed_trustee1,
        seed_von_anchor)

    path_setnym_ini.parent.mkdir(parents=True, exist_ok=True)

    data = '\n'.join([
        '[Node Pool]',
        'name={}'.format(pool_name),
        'genesis.txn.path=${{HOME}}/.indy_client/pool/{}/{}.txn'.format(pool_name, pool_name),
        '',
        '[Trustee Anchor]',
        'name=trustee-anchor',
        'seed={}'.format(seed_trustee1),
        'wallet.create=True',
        'wallet.type=',
        'wallet.access=',
        '',
        '[VON Anchor]',
        'role=TRUST_ANCHOR',
        'name=anchor-{}'.format(seed_von_anchor[0:10]),
        'seed={}'.format(seed_von_anchor),
        'wallet.create=True',
        'wallet.type=',
        'wallet.access='])

    with open(str(path_setnym_ini), "w+") as f:
        f.writelines(data)

    logger.debug("setnym_ini_file: <<<")
