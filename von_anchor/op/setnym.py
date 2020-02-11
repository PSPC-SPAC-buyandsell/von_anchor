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


import json
import logging

from os import sys
from os.path import dirname, realpath
from sys import exit as sys_exit, path as sys_path
from typing import Iterable

DIR_VON_ANCHOR = dirname(dirname(dirname(realpath(__file__))))
if DIR_VON_ANCHOR not in sys_path:
    sys_path.append(DIR_VON_ANCHOR)

from von_anchor import NominalAnchor, TrusteeAnchor
from von_anchor.error import BadRole, VonAnchorError
from von_anchor.frill import do_wait, inis2dict
from von_anchor.indytween import Role
from von_anchor.nodepool import NodePool
from von_anchor.util import AnchorData, NodePoolData, ok_role
from von_anchor.wallet import Wallet


def usage() -> None:
    """
    Print usage advice.
    """

    print()
    print('Usage: setnym.py <config-ini>')
    print()
    print('where <config-ini> represents the path to the configuration file.')
    print()
    print('The operation submits a nym to a trustee anchor to send to the ledger,')
    print('if the ledger does not have it already as configured.')
    print()
    print('The configuration file has sections and entries as follows:')
    print('  * section [Node Pool]:')
    print('    - name: the name of the node pool to which the operation applies')
    print('    - genesis.txn.path: the path to the genesis transaction file')
    print('        for the node pool')
    print('  * section [Trustee Anchor]:')
    print("    - seed: the trustee anchor's seed")
    print("    - wallet.name: the trustee anchor's wallet name")
    print("    - wallet.type: (default blank) the trustee anchor's wallet type")
    print("    - wallet.key: (default blank) the trustee anchor's")
    print('        wallet access credential (password) value')
    print('  * section [VON Anchor]:')
    print('    - role: the role to request in the send-nym transaction; specify:')
    print('        - (default) empty value for user with no additional write privileges')
    print('        - TRUST_ANCHOR for VON anchor with write privileges for indy artifacts')
    print('        - TRUSTEE for VON anchor sending further cryptonyms to the ledger')
    print("    - seed: the VON anchor's seed")
    print("    - wallet.name: the VON anchor's wallet name")
    print("    - wallet.type: (default blank) the VON anchor's wallet type")
    print("    - wallet.key: (default blank) the VON anchor's")
    print('        wallet access credential (password) value.')
    print()

async def setnym(ini_path: str) -> int:
    """
    Set configuration. Open pool, trustee anchor, and wallet of anchor whose nym to send.
    Register exit hooks to close pool and trustee anchor.

    Engage trustee anchor to send nym for VON anchor, if it differs on the ledger from configuration.

    :param ini_path: path to configuration file
    :return: 0 for OK, 1 for failure
    """

    config = inis2dict(ini_path)
    cfg_van_role = config['VON Anchor'].get('role', None) or None  # nudge empty value from '' to None
    if not ok_role(cfg_van_role):
        raise BadRole('Configured role {} is not valid'.format(cfg_van_role))

    pool_data = NodePoolData(config['Node Pool']['name'], config['Node Pool']['genesis.txn.path'])
    tan_data = AnchorData(
        Role.TRUSTEE,
        config['Trustee Anchor']['seed'],
        config['Trustee Anchor']['wallet.name'],
        config['Trustee Anchor'].get('wallet.type', None) or None,
        config['Trustee Anchor'].get('wallet.key', None) or None)
    van_data = AnchorData(
        Role.get(cfg_van_role),
        config['VON Anchor']['seed'],
        config['VON Anchor']['wallet.name'],
        config['VON Anchor'].get('wallet.type', None) or None,
        config['VON Anchor'].get('wallet.key', None) or None)

    async with NodePool(pool_data.name, pool_data.genesis_txn_path) as pool, (
        TrusteeAnchor(
            await Wallet(
                tan_data.seed,
                tan_data.wallet_name,
                tan_data.wallet_type,
                None,
                {'key': tan_data.wallet_key} if tan_data.wallet_key else None).create(),
            pool)) as tan, (
        NominalAnchor(
            await Wallet(
                van_data.seed,
                van_data.wallet_name,
                van_data.wallet_type,
                None,
                {'key': van_data.wallet_key} if van_data.wallet_key else None).create(),
            pool)) as van:

        ledger_nym = json.loads(await tan.get_nym(van.did))

        if ledger_nym:
            if Role.get(ledger_nym['role']) == van_data.role:  # ledger is as per configuration
                return 0
            await tan.send_nym(van.did, van.verkey, van.wallet.name, Role.token_reset())
        await tan.send_nym(van.did, van.verkey, van.wallet.name, van_data.role.token())

    return 0


def main(args: Iterable = None) -> int:
    """
    Main line for script: check arguments and dispatch operation to set nym.

    :param args: command-line arguments
    :return: 0 for OK, 1 for failure
    """

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)-15s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    logging.getLogger('von_anchor').setLevel(logging.WARNING)
    logging.getLogger('indy').setLevel(logging.ERROR)

    if args is None:
        args = sys.argv[1:]

    if len(sys.argv) == 2:
        try:
            return do_wait(setnym(sys.argv[1]))
        except VonAnchorError as vax:
            print(str(vax))
            return 1
    else:
        usage()
        return 1

if __name__ == '__main__':
    sys_exit(main())
