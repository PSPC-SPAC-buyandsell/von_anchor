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


import logging

from collections import namedtuple
from os import sys
from os.path import dirname, realpath
from sys import exit as sys_exit, path as sys_path
from typing import Sequence

DIR_VON_ANCHOR = dirname(dirname(dirname(realpath(__file__))))
if DIR_VON_ANCHOR not in sys_path:
    sys_path.append(DIR_VON_ANCHOR)

from von_anchor import NominalAnchor, TrusteeAnchor
from von_anchor.error import AbsentNym, AbsentPool, BadRole, ExtantWallet, VonAnchorError
from von_anchor.frill import do_wait, inis2dict
from von_anchor.indytween import Role
from von_anchor.nodepool import NodePoolManager
from von_anchor.util import ok_role
from von_anchor.wallet import WalletManager


NodePoolData = namedtuple('NodePoolData', 'name genesis_txn_path')
AnchorData = namedtuple('AnchorData', 'role name seed did wallet_create wallet_type wallet_access')


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
    print('        for the node pool (may omit if node pool already exists)')
    print('  * section [Trustee Anchor]:')
    print("    - name: the trustee anchor's (wallet) name")
    print("    - wallet.type: (default blank) the trustee anchor's wallet type")
    print("    - wallet.access: (default blank) the trustee anchor's")
    print('        wallet access credential (password) value')
    print('  * section [VON Anchor]:')
    print('    - role: the role to request in the send-nym transaction; specify:')
    print('        - (default) empty value for user with no additional write privileges')
    print('        - TRUST_ANCHOR for VON anchor with write privileges for indy artifacts')
    print('        - TRUSTEE for VON anchor sending further cryptonyms to the ledger')
    print("    - name: the VON anchor's (wallet) name")
    print("    - seed: the VON anchor's seed (optional, for wallet creation only)")
    print("    - did: the VON anchor's DID (optional, for wallet creation only)")
    print('    - wallet.create: whether create the wallet if it does not yet exist')
    print('        (value True/False, 1/0, or Yes/No)')
    print("    - wallet.type: (default blank) the VON anchor's wallet type")
    print("    - wallet.access: (default blank) the VON anchor's")
    print('        wallet access credential (password) value.')
    print()


async def _set_wallets(an_data: dict) -> dict:
    """
    Set wallets as configured for setnym operation.

    :param an_data: dict mapping profiles to anchor data
    :return: dict mapping anchor names to wallet objects
    """

    w_mgr = WalletManager()
    rv = {}
    for profile in an_data:
        w_cfg = {'id': an_data[profile].name}
        if an_data[profile].wallet_type:
            w_cfg['storage_type'] = an_data[profile].wallet_type
        if an_data[profile].seed:
            w_cfg['seed'] = an_data[profile].seed
        if an_data[profile].did:
            w_cfg['did'] = an_data[profile].did
        if an_data[profile].wallet_create:
            try:
                await w_mgr.create(w_cfg, access=an_data[profile].wallet_access)
            except ExtantWallet:
                pass
        rv[profile] = w_mgr.get(w_cfg, access=an_data[profile].wallet_access)

    return rv


async def setnym(ini_path: str) -> int:
    """
    Set configuration. Open pool, trustee anchor, and wallet of anchor whose nym to send.
    Register exit hooks to close pool and trustee anchor.

    Engage trustee anchor to send nym for VON anchor, if it differs on the ledger from configuration.

    :param ini_path: path to configuration file
    :return: 0 for OK, 1 for failure
    """

    config = inis2dict(ini_path)
    if config['Trustee Anchor']['name'] == config['VON Anchor']['name']:
        raise ExtantWallet('Wallet names must differ between VON Anchor and Trustee Anchor')

    cfg_van_role = config['VON Anchor'].get('role', None) or None  # nudge empty value from '' to None
    if not ok_role(cfg_van_role):
        raise BadRole('Configured role {} is not valid'.format(cfg_van_role))

    pool_data = NodePoolData(
        config['Node Pool']['name'],
        config['Node Pool'].get('genesis.txn.path', None) or None)

    an_data = {
        'tan': AnchorData(
            Role.TRUSTEE,
            config['Trustee Anchor']['name'],
            config['Trustee Anchor'].get('seed', None) or None,
            config['Trustee Anchor'].get('did', None) or None,
            config['Trustee Anchor'].get('wallet.create', '0').lower() in ['1', 'true', 'yes'],
            config['Trustee Anchor'].get('wallet.type', None) or None,
            config['Trustee Anchor'].get('wallet.access', None) or None),
        'van': AnchorData(
            Role.get(cfg_van_role),
            config['VON Anchor']['name'],
            config['VON Anchor'].get('seed', None) or None,
            config['VON Anchor'].get('did', None) or None,
            config['VON Anchor'].get('wallet.create', '0').lower() in ['1', 'true', 'yes'],
            config['VON Anchor'].get('wallet.type', None) or None,
            config['VON Anchor'].get('wallet.access', None) or None)
    }

    an_wallet = await _set_wallets(an_data)

    p_mgr = NodePoolManager()
    if pool_data.name not in await p_mgr.list():
        if pool_data.genesis_txn_path:
            await p_mgr.add_config(pool_data.name, pool_data.genesis_txn_path)
        else:
            raise AbsentPool('Node pool {} has no ledger configuration, but {} specifies no genesis txn path'.format(
                pool_data.name,
                ini_path))

    async with an_wallet['tan'] as w_tan, (
            an_wallet['van']) as w_van, (
            p_mgr.get(pool_data.name)) as pool, (
            TrusteeAnchor(w_tan, pool)) as tan, (
            NominalAnchor(w_van, pool)) as van:

        send_verkey = van.verkey
        try:
            nym_role = await tan.get_nym_role(van.did)
            if an_data['van'].role == nym_role:
                return 0  # ledger is as per configuration
            send_verkey = None  # only owner can touch verkey
            if nym_role != Role.USER:  # only remove role when it is not already None on the ledger
                await tan.send_nym(van.did, send_verkey, van.wallet.name, Role.ROLE_REMOVE)
        except AbsentNym:
            pass  # cryptonym not there yet, fall through

        await tan.send_nym(van.did, send_verkey, van.wallet.name, an_data['van'].role)

    return 0


def main(args: Sequence[str] = None) -> int:
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
