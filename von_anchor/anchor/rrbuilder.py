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


import argparse
import asyncio
import json
import logging

from enum import Enum
from os import getpid, kill, listdir, makedirs, remove
from os.path import basename, dirname, expanduser, isdir, isfile, join, realpath
from shutil import rmtree
from subprocess import Popen
from sys import path as sys_path

from indy import anoncreds, blob_storage

DIR_VON_ANCHOR = dirname(dirname(dirname(realpath(__file__))))
if DIR_VON_ANCHOR not in sys_path:
    sys_path.append(DIR_VON_ANCHOR)

from von_anchor.anchor.base import BaseAnchor
from von_anchor.error import AbsentProcess, BadIdentifier, WalletState
from von_anchor.tails import Tails
from von_anchor.util import ok_rev_reg_id, rev_reg_id2cred_def_id, rev_reg_id2cred_def_id_tag
from von_anchor.wallet import Wallet, WalletManager


LOGGER = logging.getLogger(__name__)


_STATE = Enum('_STATE', 'ABSENT RUNNING STOPPING')


class RevRegBuilder(BaseAnchor):
    """
    Issuer alter ego to build revocation registries in parallel to regular Issuer processing.

    Once the indy-sdk can operate from a subprocess, this logic can go into the Issuer itself,
    which can spawn it as a subprocess. Until then, to build revocation registries in parallel,
    whatever process creates an Issuer must create its corresponding RevRegBuilder separately.
    """

    DIR_TAILS = join(expanduser('~'), '.indy_client', 'tails')
    DIR_TAILS_HOPPER = join(DIR_TAILS, '.hopper')

    def __init__(self, wallet: Wallet, **kwargs) -> None:
        """
        Initializer for RevRegBuilder anchor. Retain input parameters; do not open wallet nor tails writer.

        :param wallet: wallet for anchor use
        :param rrbx: whether revocation registry builder is an external process from the Issuer
            (default False for backward-compatible behaviour)
        """

        LOGGER.debug('RevRegBuilder.__init__ >>> wallet: %s, kwargs: %s', wallet, kwargs)

        super().__init__(wallet, None, **kwargs)
        self._external = kwargs.get('rrbx', False)
        self._dir_tails_sentinel = RevRegBuilder.dir_tails_sentinel(wallet.name) if self.external else None

        if self.external:
            makedirs(self.dir_tails_hopper, exist_ok=True)  # self is RevRegBuilder or descendant: spawn rrbx proc
            makedirs(self._dir_tails_sentinel, exist_ok=True)

            rrb_state = RevRegBuilder._get_state(wallet.name)

            if rrb_state == _STATE.STOPPING:
                try:  # cancel the stop order
                    remove(join(RevRegBuilder.dir_tails_sentinel(wallet.name), '.stop'))
                except FileNotFoundError:
                    pass  # too late, it's gone
                else:
                    rrb_state = _STATE.ABSENT

            if rrb_state == _STATE.ABSENT:  # run it
                start_data_json = self._start_data_json()
                with open(join(RevRegBuilder.dir_tails_sentinel(wallet.name), '.start'), 'w') as fh_start:
                    print(start_data_json, file=fh_start)
                rrb_proc = Popen([
                    'python',
                    realpath(__file__),
                    '-n',
                    wallet.name])
                if rrb_proc and rrb_proc.pid:
                    LOGGER.info(
                        '%s %s spawned pid %s to run external revocation registry builder',
                        type(self).__name__,
                        wallet.name,
                        rrb_proc.pid)
                else:
                    LOGGER.debug('%s %s could not spawn rev reg builder', type(self).__name__, wallet.name)
                    raise AbsentProcess('RevRegBuilder.__init__ <!< {} {} could not spawn rev reg builder'.format(
                        type(self).__name__,
                        wallet.name))

        LOGGER.debug('RevRegBuilder.__init__ <<<')

    @property
    def external(self) -> bool:
        """
        Accessor for revocation registry builder posture: external (True) or internal (False)

        :return: whether revocation registry builder posture is external
        """

        return self._external

    @property
    def dir_tails(self) -> str:
        """
        Accessor for root of tails directory

        :return: tails directory
        """

        return RevRegBuilder.DIR_TAILS

    @property
    def dir_tails_hopper(self) -> str:
        """
        Accessor for tails hopper directory

        :return: tails hopper directory
        """

        return RevRegBuilder.DIR_TAILS_HOPPER

    def _start_data_json(self) -> str:
        """
        Output json with start data to write for external revocation registry builder process pickup.

        :return: logging and wallet init data json
        """

        rv = {
            'logging': {
                'paths': []
            },
            'wallet': {
            }
        }

        logger = LOGGER
        while not logger.level:
            logger = logger.parent
            if logger is None:
                break
        rv['logging']['level'] = logger.level

        logger = LOGGER
        log_paths = [realpath(h.baseFilename) for h in logger.handlers if hasattr(h, 'baseFilename')]
        while not log_paths:
            logger = logger.parent
            if logger is None:
                break
            log_paths = [realpath(h.baseFilename) for h in logger.handlers if hasattr(h, 'baseFilename')]
        for log_path in log_paths:
            rv['logging']['paths'].append(log_path)

        rv['wallet']['storage_type'] = self.wallet.storage_type
        rv['wallet']['config'] = self.wallet.config
        rv['wallet']['access_creds'] = self.wallet.access_creds

        return json.dumps(rv)

    @staticmethod
    def _get_state(wallet_name: str) -> _STATE:
        """
        Return current state of revocation registry builder process.

        :param wallet_name: name of wallet for corresponding Issuer
        :return: current process state as _STATE enum
        """

        dir_sentinel = RevRegBuilder.dir_tails_sentinel(wallet_name)
        file_pid = join(dir_sentinel, '.pid')
        file_start = join(dir_sentinel, '.start')
        file_stop = join(dir_sentinel, '.stop')

        if isfile(file_stop):
            return _STATE.STOPPING

        if isfile(file_start) or isfile(file_pid):
            return _STATE.RUNNING

        return _STATE.ABSENT

    @staticmethod
    def dir_tails_sentinel(wallet_name: str) -> str:
        """
        Return the sentinel directory for a revocation registry builder on input wallet name, without
        instantiating the anchor.

        :param wallet_name: name of revocation registry builder, as specified in its wallet configuration
        :return: path to sentinel directory for revocation registry builder on wallet name
        """

        return join(RevRegBuilder.DIR_TAILS, '.sentinel', wallet_name)

    def dir_tails_top(self, rr_id) -> str:
        """
        Return top of tails tree for input rev reg id.

        :param rr_id: revocation registry identifier
        :return: top of tails tree
        """

        return join(self.dir_tails_hopper, rr_id) if self.external else self.dir_tails

    def dir_tails_target(self, rr_id) -> str:
        """
        Return target directory for revocation registry and tails file production.

        :param rr_id: revocation registry identifier
        :return: tails target directory
        """

        return join(self.dir_tails_top(rr_id), rev_reg_id2cred_def_id(rr_id))

    def mark_in_progress(self, rr_id: str, rr_size: int) -> None:
        """
        Prepare sentinel directory for revocation registry construction.

        :param rr_id: revocation registry identifier
        :rr_size: size of revocation registry to build
        """
        try:
            makedirs(join(self._dir_tails_sentinel, rr_id), exist_ok=False)
        except FileExistsError:
            LOGGER.warning('Rev reg %s construction already in progress', rr_id)
        else:
            open(join(self._dir_tails_sentinel, rr_id, '.{}'.format(rr_size)), 'w').close()

    async def serve(self) -> None:
        """
        Write pidfile to sentinel directory if need be, and wait for sentinels
        to shut down or build revocation registry and tails file.
        """

        LOGGER.debug('RevRegBuilder.serve >>>')

        assert self.external

        file_pid = join(self._dir_tails_sentinel, '.pid')
        if isfile(file_pid):
            with open(file_pid, 'r') as fh_pid:
                pid = int(fh_pid.read())
            try:
                kill(pid, 0)
            except ProcessLookupError:
                remove(file_pid)
                LOGGER.info('RevRegBuilder removed derelict .pid file')
            except PermissionError:
                LOGGER.info('RevRegBuilder process already running with pid %s: exiting', pid)
                LOGGER.debug('RevRegBuilder.serve <<<')
                return
            else:
                LOGGER.info('RevRegBuilder process already running with pid %s: exiting', pid)
                LOGGER.debug('RevRegBuilder.serve <<<')
                return

        pid = getpid()
        with open(file_pid, 'w') as pid_fh:
            print(str(pid), file=pid_fh)

        file_stop = join(self._dir_tails_sentinel, '.stop')

        while True:
            if isfile(file_stop):  # stop now, pick up any pending tasks next invocation
                remove(file_stop)
                remove(file_pid)
                break

            p_pending = [join(self._dir_tails_sentinel, d) for d in listdir(self._dir_tails_sentinel)
                if isdir(join(self._dir_tails_sentinel, d))]
            p_pending = [p for p in p_pending if [s for s in listdir(p) if s.startswith('.')]]  # size marker
            if p_pending:
                pdir = basename(p_pending[0])
                rr_id = pdir
                rr_size = int([s for s in listdir(p_pending[0]) if s.startswith('.')][0][1:])
                open(join(p_pending[0], '.in-progress'), 'w').close()
                await self.create_rev_reg(rr_id, rr_size or None)
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

        dir_sentinel = join(RevRegBuilder.dir_tails_sentinel(wallet_name))

        if isdir(dir_sentinel):
            open(join(dir_sentinel, '.stop'), 'w').close()  # touch

            while any(isfile(join(dir_sentinel, d, '.in-progress')) for d in listdir(dir_sentinel)):
                await asyncio.sleep(1)

        LOGGER.debug('RevRegBuilder.stop <<<')

    async def create_rev_reg(self, rr_id: str, rr_size: int = None) -> None:
        """
        Create revocation registry artifacts and new tails file (with association to
        corresponding revocation registry identifier via symbolic link name)
        for input revocation registry identifier. Symbolic link presence signals completion.
        If revocation registry builder operates in a process external to its Issuer's,
        target directory is hopper directory.

        Raise WalletState for closed wallet.

        :param rr_id: revocation registry identifier
        :param rr_size: revocation registry size (defaults to 64)
        """

        LOGGER.debug('RevRegBuilder.create_rev_reg >>> rr_id: %s, rr_size: %s', rr_id, rr_size)

        if not self.wallet.handle:
            LOGGER.debug('RevRegBuilder.create_rev_reg <!< Wallet %s is closed', self.name)
            raise WalletState('Wallet {} is closed'.format(self.name))

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('RevRegBuilder.create_rev_reg <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        rr_size = rr_size or 64

        (cd_id, tag) = rev_reg_id2cred_def_id_tag(rr_id)

        dir_tails = self.dir_tails_top(rr_id)
        dir_target = self.dir_tails_target(rr_id)
        if self.external:
            try:
                makedirs(dir_target, exist_ok=False)
            except FileExistsError:
                LOGGER.warning(
                    'RevRegBuilder.create_rev_reg found dir %s, but task not in progress: rebuilding rev reg %s',
                    dir_target,
                    rr_id)
                rmtree(dir_target)
                makedirs(dir_target, exist_ok=False)

        LOGGER.info('Creating revocation registry (capacity %s) for rev reg id %s', rr_size, rr_id)
        tails_writer_handle = await blob_storage.open_writer(
            'default',
            json.dumps({
                'base_dir': dir_target,
                'uri_pattern': ''
            }))

        (created_rr_id, rr_def_json, rr_ent_json) = await anoncreds.issuer_create_and_store_revoc_reg(
            self.wallet.handle,
            self.did,
            'CL_ACCUM',
            tag,
            cd_id,
            json.dumps({
                'max_cred_num': rr_size,
                'issuance_type': 'ISSUANCE_BY_DEFAULT'
            }),
            tails_writer_handle)

        tails_hash = basename(Tails.unlinked(dir_target).pop())
        with open(join(dir_target, 'rr_def.json'), 'w') as rr_def_fh:
            print(rr_def_json, file=rr_def_fh)
        with open(join(dir_target, 'rr_ent.json'), 'w') as rr_ent_fh:
            print(rr_ent_json, file=rr_ent_fh)
        Tails.associate(dir_tails, created_rr_id, tails_hash)  # associate last: symlink signals completion

        LOGGER.debug('RevRegBuilder.create_rev_reg <<<')


async def main(wallet_name: str) -> None:
    """
    Main line for revocation registry builder operating in external process on behalf of issuer agent.

    :param wallet_name: wallet name - must match that of issuer with existing wallet
    """

    logging.basicConfig(level=logging.WARN, format='%(levelname)-8s | %(name)-12s | %(message)s')
    logging.getLogger('indy').setLevel(logging.ERROR)

    path_start = join(RevRegBuilder.dir_tails_sentinel(wallet_name), '.start')

    with open(path_start, 'r') as fh_start:
        start_data = json.loads(fh_start.read())
    remove(path_start)

    logging.getLogger(__name__).setLevel(start_data['logging']['level'])
    for path_log in start_data['logging']['paths']:
        logging.getLogger(__name__).addHandler(logging.FileHandler(path_log))

    wallet = WalletManager().get(
        {
            'id': wallet_name,
            'storage_type': start_data['wallet']['storage_type'],
            **start_data['wallet']['config'],
        },
        access=start_data['wallet']['access_creds'].get('key', None))
    async with wallet, RevRegBuilder(wallet, rrbx=True) as rrban:
        await rrban.serve()


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('-n', '--name', help='wallet name', required=True)
    ARGS = PARSER.parse_args()

    LOOP = asyncio.get_event_loop()
    LOOP.run_until_complete(main(ARGS.name))
