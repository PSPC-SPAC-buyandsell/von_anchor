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


import atexit
import logging

from collections import namedtuple
from os import sys
from os.path import dirname, realpath
from sys import exit as sys_exit, path as sys_path, stderr
from typing import Type

DIR_VON_ANCHOR = dirname(dirname(dirname(realpath(__file__))))
if DIR_VON_ANCHOR not in sys_path:
    sys_path.append(DIR_VON_ANCHOR)

from von_anchor import TrusteeAnchor
from von_anchor.anchor.base import BaseAnchor
from von_anchor.error import VonAnchorError
from von_anchor.frill import do_wait, inis2dict
from von_anchor.nodepool import NodePool
from von_anchor.wallet import Wallet


AnchorData = namedtuple('AnchorData', 'role seed wallet_name wallet_type wallet_key')


def usage() -> None:
    """
    Print usage advice.
    """

    print()
    print('Usage: sendnym.py <config-ini>')
    print()
    print('where <config-ini> represents the path to the configuration file.')
    print()
    print('The operation submits a nym to a trustee anchor to send to the ledger.')
    print()


async def main(ini_path: str) -> int:
    """
    Set configuration. Open pool, trustee anchor, and wallet of anchor whose nym to send.
    Register exit hooks to close pool and trustee anchor. Engage trustee anchor to
    send nym of new anchor as per configuration.

    :param ini_path: path to configuration file
    :return: 0 for OK, 1 for failure
    """

    config = inis2dict(ini_path)

    pool_name = config['Node Pool']['name']
    genesis_txn_path = config['Node Pool']['genesis.txn.path']
    pool = NodePool(pool_name, genesis_txn_path)
    await pool.open()
    atexit.register(close_pool, pool)

    tan_data = AnchorData(
        None,
        config['Trustee Anchor']['seed'],
        config['Trustee Anchor']['wallet.name'],
        config['Trustee Anchor'].get('wallet.type', None) or None,  # nudge empty value from '' to None
        config['Trustee Anchor'].get('wallet.key', None) or None)
    tan = TrusteeAnchor(
        await Wallet(
            tan_data.seed,
            tan_data.wallet_name,
            tan_data.wallet_type,
            None,
            {'key': tan_data.wallet_key} if tan_data.wallet_key else None).create(),
        pool)
    await tan.open()
    atexit.register(close_anchor, tan)

    newan_data = AnchorData(
        config['New Anchor'].get('role', None) or None,
        config['New Anchor']['seed'],
        config['New Anchor']['wallet.name'],
        config['New Anchor'].get('wallet.type', None) or None,
        config['New Anchor'].get('wallet.key', None) or None)
    newan = TrusteeAnchor(
        await Wallet(
            newan_data.seed,
            newan_data.wallet_name,
            newan_data.wallet_type,
            None,
            {'key': newan_data.wallet_key} if newan_data.wallet_key else None).create(),
        pool)
    await newan.open()
    atexit.register(close_anchor, newan)

    await tan.send_nym(newan.did, newan.verkey, newan.wallet.name, newan_data.role)  # ok to replace an existing one
    return 0


def close_pool(pool: NodePool) -> None:
    """
    Close node pool.

    :param pool: node pool to close
    """

    do_wait(pool.close())


def close_anchor(anchor: Type[BaseAnchor]) -> None:
    """
    Close anchor.

    :param anchor: anchor to close
    """

    do_wait(anchor.close())


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)-15s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    logging.getLogger('von_anchor').setLevel(logging.WARNING)
    logging.getLogger('indy').setLevel(logging.ERROR)

    if len(sys.argv) == 2:
        try:
            sys_exit(do_wait(main(sys.argv[1])))
        except VonAnchorError as vaerr:
            print(str(vaerr), file=stderr)
            sys_exit(1)
    else:
        usage()
        sys_exit(1)
