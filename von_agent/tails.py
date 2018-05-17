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

import json

from os import chdir, getcwd, listdir, makedirs, readlink, symlink, walk
from os.path import basename, dirname, isfile, islink, join

from indy import anoncreds, blob_storage, ledger
from indy.error import IndyError, ErrorCode
from von_agent.error import AbsentTailsFile
from von_agent.util import rev_reg_id, rev_reg_id2cred_def_id, rev_reg_id2tag

class Tails:
    """
    Abstraction layer to manage tails files for Issuers and HolderProvers. Uses symbolic link
    to retain association between tails file and corresponding revocation registry identifier.
    """

    def __init__(self, base_dir: str, cd_id: str, tag: str = None):
        """
        Initialize programmatic association between revocation registry identifier
        (on credential definition on input identifier plus tag, default most recent),
        and tails file, via symbolic link.

        Raise AbsentTailsFile if (rev reg id) symbolic link or (tails hash) tails file not present.

        :param base_dir: top directory for tails files, thereafter split by cred def id
        :param cd_id: credential definition identifier of interest
        :param tag: revocation registry identifier tag of interest, default to most recent
        """

        if tag == None:
            self._rr_id = Tails.current_rev_reg_id(base_dir, cd_id)
        else:  # including tag == 0
            self._rr_id = rev_reg_id(cd_id, tag)
            if self._rr_id not in [basename(f) for f in Tails.links(base_dir)]:
                raise AbsentTailsFile('No tails files present for cred def id {} on tag {}'.format(cd_id, tag))

        path_link = join(Tails.dir(base_dir, self._rr_id), self._rr_id)
        if not islink(path_link):
            raise AbsentTailsFile('No symbolic link present at {} for rev reg id {}'.format(path_link, self._rr_id))

        path_tails = Tails.linked(base_dir, self._rr_id)
        if not isfile(path_tails):
            raise AbsentTailsFile('No tails file present at {} for rev reg id {}'.format(path_tails, self._rr_id))

        self._tails_cfg_json = json.dumps({
            'base_dir': dirname(path_tails),
            'uri_pattern': '',
            'file': basename(path_tails)
        })

        self._reader_handle = None

    async def open(self) -> 'Tails':
        """
        Open reader handle and return current object.

        :return: current object
        """

        self._reader_handle = await blob_storage.open_reader('default', self._tails_cfg_json)

        return self

    @staticmethod
    def associate(base_dir: str, rr_id: str, tails_hash: str) -> None:
        """
        Create symbolic link to tails file named tails_hash for rev reg id rr_id.

        :param rr_id: rev reg id
        :param tails_hash: hash of tails file, serving as file name
        """

        cd_id = rev_reg_id2cred_def_id(rr_id)
        d = join(base_dir, cd_id)
        cwd = getcwd()
        makedirs(d, exist_ok=True)
        chdir(d)
        symlink(tails_hash, rr_id)
        chdir(cwd)

    @staticmethod
    def dir(base_dir: str, rr_id: str) -> str:
        """
        Return correct subdirectory of input base dir for artifacts corresponding to input rev reg id.

        :param base_dir: top directory for tails files, thereafter split by cred def id
        :param rr_id: rev reg id
        """

        return join(base_dir, rev_reg_id2cred_def_id(rr_id))

    @staticmethod
    def linked(base_dir: str, rr_id: str) -> str:
        """
        Get, from the specified directory, the path to the tails file associated with
        the input revocation registry identifier, or None for no such file.

        :param base_dir: top directory for tails files, thereafter split by cred def id
        :param rr_id: rev reg id
        :return: (stringified) path to tails file of interest, or None for no such file.
        """

        cd_id = rev_reg_id2cred_def_id(rr_id)
        link = join(base_dir, cd_id, rr_id)
        return join(base_dir, cd_id, readlink(link)) if islink(link) else None

    @staticmethod
    def links(base_dir: str) -> set:
        """
        Return set of all paths to symbolic links (rev reg ids) associating
        their respective tails files, in specified base tails directory.

        :param base_dir: top directory for tails files, thereafter split by cred def id
        :return: set of paths to symbolic links associating tails files
        """

        return {join(dp, f) for dp, dn, fn in walk(base_dir) for f in fn if islink(join(dp, f))}

    @staticmethod
    def unlinked(base_dir: str) -> set:
        """
        Return all paths to tails files, in specified tails top directory (recursively),
        without symbolic links associating revocation registry identifiers.

        At an Issuer, tails files should not persist long without revocation registry identifier
        association via symbolic link. At a HolderProver, a newly downloaded tails file stays
        unlinked until the agent stores a credential or creates a proof needing it, or else the
        agent restarts.

        :param base_dir: top directory for tails files, thereafter split by cred def id
        :return: set of paths to tails files with no local symbolic links to them
        """

        return {join(dp, f) for dp, dn, fn in walk(base_dir)
            for f in fn if isfile(join(dp, f)) and not islink(join(dp, f))} - {
                join(dirname(path_link), readlink(path_link)) for path_link in Tails.links(base_dir)}

    @staticmethod
    def next_tag(base_dir: str, cd_id: str) -> (str, int):
        """
        Return the next tag name available for a new rev reg id on input cred def id in base directory,
        and suggested size of associated rev reg.

        :param base_dir: top directory for tails files, thereafter split by cred def id
        :param cd_id: credential definition identifier of interest
        :return: stringified least non-negative integer not yet used in a rev reg id associated with a tails file
            in base directory, and recommendation for next size to use
        """

        tag = 1 + max([int(rev_reg_id2tag(basename(f)))
            for f in Tails.links(base_dir) if cd_id in basename(f)] + [-1])  # -1: next tag is '0' if no tags so far
        size = min(2**(tag + 8), 4096)
        return (tag, size)

    @staticmethod
    def current_rev_reg_id(base_dir: str, cd_id: str) -> str:
        """
        Return the current revocation registry identifier for
        input credential definition identifier, in input directory.

        Raise AbsentTailsFile if no corresponding tails file, signifying no such revocation registry defined.

        :param base_dir: top directory for tails files, thereafter split by cred def id
        :param cd_id: credential definition identifier of interest
        :return: identifier for current revocation registry on input credential definition identifier
        """

        tags = [int(rev_reg_id2tag(basename(f))) for f in Tails.links(base_dir)
            if cd_id in basename(f)]
        if not tags:
            raise AbsentTailsFile('No tails files present for cred def id {}'.format(cd_id))

        return rev_reg_id(cd_id, str(max(tags)))  # ensure 10 > 9, not '9' > '10'

    @property
    def reader_handle(self) -> int:
        """
        Accessor for reader handle on current tails file.
        Note that the current object must be open() for the handle to exist.

        :return: reader handle
        """

        return self._reader_handle

    @property
    def rr_id(self) -> str:
        """
        Accessor for revocation registry identifier.

        :return: revocation registry identifier for current tails file
        """

        return self._rr_id

    @property
    def path(self) -> str:
        """
        Accessor for (stringified) path to current tails file.

        :return: (stringified) path to current tails file.
        """

        return join(cfg['base_dir'], cfg['file'])

    def __str__(self) -> str:
        """
        Return string representation.

        :return: string representation
        """

        cfg = json.loads(self._tails_cfg_json)
        return 'Tails: {}/{} -> {}'.format(cfg['base_dir'], self._rr_id, cfg['file'])
