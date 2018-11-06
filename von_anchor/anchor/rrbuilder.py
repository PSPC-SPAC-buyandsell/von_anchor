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


import argparse
import asyncio
import json
import logging
import os
import os.path

from enum import Enum, auto
from shutil import rmtree
from sys import path as sys_path

from indy import anoncreds, blob_storage

DIR_VON_ANCHOR = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
if DIR_VON_ANCHOR not in sys_path:
    sys_path.append(DIR_VON_ANCHOR)

from von_anchor.anchor.base import _BaseAnchor
from von_anchor.error import BadIdentifier
from von_anchor.nodepool import NodePool
from von_anchor.tails import Tails
from von_anchor.util import ok_rev_reg_id, rev_reg_id2cred_def_id, rev_reg_id2cred_def_id_tag
from von_anchor.wallet import Wallet


LOGGER = logging.getLogger(__name__)


class State(Enum):
    """
    Class encapsulating state of revocation registry builder process
    """

    ABSENT = auto()
    RUNNING = auto()
    STOPPING = auto()


class RevRegBuilder(_BaseAnchor):
    """
    Issuer alter ego to build revocation registries in parallel to regular Issuer processing.

    Once the indy-sdk can operate from a subprocess, this logic can go into the Issuer itself,
    which can spawn it as a subprocess. Until then, to build revocation registries in parallel,
    whatever process creates an Issuer must create its corresponding RevRegBuilder separately.
    """

    def __init__(self, wallet: Wallet, pool: NodePool, *, rrbx: bool = False) -> None:
        """
        Initializer for RevRegBuilder anchor. Retain input parameters; do not open wallet nor tails writer.

        :param wallet: wallet for anchor use
        :param pool: pool for anchor use
        :param rrbx: whether revocation registry builder is an external process from the Issuer
        """

        LOGGER.debug('RevRegBuilder.__init__ >>> wallet: %s, pool: %s, rrbx: %s', wallet, pool, rrbx)

        _BaseAnchor.__init__(self, wallet, pool)
        self._dir_tails = RevRegBuilder.dir_tails()
        self._dir_tails_hopper = os.path.join(self._dir_tails, '.hopper')

        self._rrbx = rrbx
        if self._rrbx:
            os.makedirs(self._dir_tails_hopper, exist_ok=True)
            self._dir_tails_sentinel = RevRegBuilder.dir_tails_sentinel(wallet.name)
            os.makedirs(self._dir_tails_sentinel, exist_ok=True)

        LOGGER.debug('RevRegBuilder.__init__ <<<')

    @staticmethod
    def get_state(wallet_name: str) -> State:
        """
        Return current state of revocation registry builder process.

        :param wallet_name: name of wallet for corresponding Issuer
        :return: current process state as State enum.
        """

        dir_sentinel = RevRegBuilder.dir_tails_sentinel(wallet_name)
        file_pid = os.path.join(dir_sentinel, '.pid')
        file_start = os.path.join(dir_sentinel, '.start')
        file_stop = os.path.join(dir_sentinel, '.stop')

        if os.path.isfile(file_stop):
            return State.STOPPING

        if os.path.isfile(file_start) or os.path.isfile(file_pid):
            return State.RUNNING

        return State.ABSENT

    @staticmethod
    def dir_tails() -> str:
        """
        Return the top directory of the tails tree, the same for all revocation registry builders,
        without instantiating any.

        :return: path to top of tails directory
        """

        return os.path.join(os.path.expanduser('~'), '.indy_client', 'tails')

    @staticmethod
    def dir_tails_sentinel(wallet_name: str) -> str:
        """
        Return the sentinel directory for a revocation registry builder on input wallet name, without
        instantiating the anchor.

        :param wallet_name: name of revocation registry builder, as specified in its wallet configuration
        :return: path to sentinel directory for revocation registry builder on wallet name
        """

        return os.path.join(RevRegBuilder.dir_tails(), '.sentinel', wallet_name)

    def dir_tails_top(self, rr_id) -> str:
        """
        Return top of tails tree for input rev reg id.

        :param rr_id: revocation registry identifier
        :return: top of tails tree
        """

        return os.path.join(self._dir_tails_hopper, rr_id) if self._rrbx else self._dir_tails

    def dir_tails_target(self, rr_id) -> str:
        """
        Return target directory for revocation registry and tails file production.

        :param rr_id: revocation registry identifier
        :return: tails target directory
        """

        return os.path.join(self.dir_tails_top(rr_id), rev_reg_id2cred_def_id(rr_id))

    async def serve(self) -> None:
        """
        Write pidfile to sentinel directory if need be, and wait for sentinels
        to shut down or build revocation registry and tails file.
        """

        LOGGER.debug('RevRegBuilder.serve >>>')

        assert self._rrbx

        file_pid = os.path.join(self._dir_tails_sentinel, '.pid')
        if os.path.isfile(file_pid):
            with open(file_pid, 'r') as fh_pid:
                pid = int(fh_pid.read())
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                os.remove(file_pid)
                LOGGER.info('RevRegBuilder removed derelict .pid file')
            except PermissionError:
                LOGGER.info('RevRegBuilder process already running with pid %s: exiting', pid)
                LOGGER.debug('RevRegBuilder.serve <<<')
                return
            else:
                LOGGER.info('RevRegBuilder process already running with pid %s: exiting', pid)
                LOGGER.debug('RevRegBuilder.serve <<<')
                return

        pid = os.getpid()
        with open(file_pid, 'w') as pid_fh:
            print(str(pid), file=pid_fh)

        file_stop = os.path.join(self._dir_tails_sentinel, '.stop')

        while True:
            if os.path.isfile(file_stop):  # stop now, pick up any pending tasks next invocation
                os.remove(file_stop)
                os.remove(file_pid)
                break

            p_pending = [os.path.join(self._dir_tails_sentinel, d) for d in os.listdir(self._dir_tails_sentinel)
                if os.path.isdir(os.path.join(self._dir_tails_sentinel, d))]
            p_pending = [p for p in p_pending if [s for s in os.listdir(p) if s.startswith('.')]]  # size marker
            if p_pending:
                pdir = os.path.basename(p_pending[0])
                rr_id = pdir
                rr_size = int([s for s in os.listdir(p_pending[0]) if s.startswith('.')][0][1:])
                open(os.path.join(p_pending[0], '.in-progress'), 'w').close()
                await self._create_rev_reg(rr_id, rr_size or None)
                rmtree(p_pending[0])
            await asyncio.sleep(1)

        LOGGER.debug('RevRegBuilder.serve <<<')

    @staticmethod
    async def stop(wallet_name: str) -> None:
        """
        Gracefully stop an external revocation registry builder, waiting for its current.

        The indy-sdk toolkit uses a temporary directory for tails file mustration,
        and shutting down the toolkit removes the directory, crashing the external
        tails file write. This method allows a graceful stop to wait for completion
        of such tasks already in progress.

        :wallet_name: name external revocation registry builder to check
        :return: whether a task is pending.
        """

        LOGGER.debug('RevRegBuilder.stop >>>')

        dir_sentinel = os.path.join(RevRegBuilder.dir_tails_sentinel(wallet_name))

        if os.path.isdir(dir_sentinel):
            open(os.path.join(dir_sentinel, '.stop'), 'w').close()  # touch

            while any(os.path.isfile(os.path.join(dir_sentinel, d, '.in-progress')) for d in os.listdir(dir_sentinel)):
                await asyncio.sleep(1)

        LOGGER.debug('RevRegBuilder.stop <<<')

    async def _create_rev_reg(self, rr_id: str, rr_size: int = None) -> None:
        """
        Create revocation registry artifacts and new tails file (with association to
        corresponding revocation registry identifier via symbolic link name)
        for input revocation registry identifier. Symbolic link presence signals completion.
        If revocation registry builder operates in a process external to its Issuer's,
        target directory is hopper directory.

        :param rr_id: revocation registry identifier
        :param rr_size: revocation registry size (defaults to 256)
        """

        LOGGER.debug('RevRegBuilder._create_rev_reg >>> rr_id: %s, rr_size: %s', rr_id, rr_size)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('RevRegBuilder._create_rev_reg <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        rr_size = rr_size or 256

        (cd_id, tag) = rev_reg_id2cred_def_id_tag(rr_id)

        dir_tails = self.dir_tails_top(rr_id)
        dir_target = self.dir_tails_target(rr_id)
        if self._rrbx:
            try:
                os.makedirs(dir_target, exist_ok=False)
            except FileExistsError:
                LOGGER.warning(
                    'RevRegBuilder._create_rev_reg found dir %s, but task not in progress: rebuilding rev reg %s',
                    dir_target,
                    rr_id)
                rmtree(dir_target)
                os.makedirs(dir_target, exist_ok=False)

        LOGGER.info('Creating revocation registry (capacity %s) for rev reg id %s', rr_size, rr_id)
        tails_writer_handle = await blob_storage.open_writer(
            'default',
            json.dumps({
                'base_dir': dir_target,
                'uri_pattern': ''
            }))

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

        tails_hash = os.path.basename(Tails.unlinked(dir_target).pop())
        with open(os.path.join(dir_target, 'rrd.json'), 'w') as rrd_fh:
            print(rrd_json, file=rrd_fh)
        with open(os.path.join(dir_target, 'rre.json'), 'w') as rre_fh:
            print(rre_json, file=rre_fh)
        Tails.associate(dir_tails, rr_id, tails_hash)  # associate last: it signals completion

        LOGGER.debug('RevRegBuilder._create_rev_reg <<<')


async def main(pool_name: str, pool_genesis_txn_path: str, wallet_name: str) -> None:
    """
    Main line for revocation registry builder operating in external process on behalf of issuer agent.

    :param pool_name: name of (running) node pool
    :param genesis_txn_path: path to genesis transaction file
    :param wallet_name: wallet name - must match that of issuer
    """

    logging.basicConfig(level=logging.WARN, format='%(levelname)-8s | %(name)-12s | %(message)s')
    logging.getLogger('indy').setLevel(logging.ERROR)

    pool = NodePool(pool_name, pool_genesis_txn_path)
    path_start = os.path.join(RevRegBuilder.dir_tails_sentinel(wallet_name), '.start')

    with open(path_start, 'r') as fh_start:
        start_lines = [line.rstrip() for line in fh_start.readlines()]
        seed = start_lines[0]
        logging.getLogger(__name__).setLevel(int(start_lines[1]))
        for log_file in start_lines[2:]:
            logging.getLogger(__name__).addHandler(logging.FileHandler(log_file))

    os.remove(path_start)

    async with RevRegBuilder(await Wallet(seed, wallet_name).create(), pool, rrbx=True) as rrban:
        await rrban.serve()


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('-p', '--pool', help='pool name', required=True)
    PARSER.add_argument('-g', '--genesis', help='genesis transaction path', required=True)
    PARSER.add_argument('-n', '--name', help='wallet name', required=True)
    ARGS = PARSER.parse_args()

    LOOP = asyncio.get_event_loop()
    LOOP.run_until_complete(main(ARGS.pool, ARGS.genesis, ARGS.name))
