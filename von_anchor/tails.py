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
import logging
import re

from os import chdir, getcwd, makedirs, readlink, symlink, walk
from os.path import basename, dirname, isfile, islink, join

from indy import blob_storage

from von_anchor.error import AbsentTails, BadIdentifier
from von_anchor.util import (
    B58,
    ok_did,
    ok_cred_def_id,
    ok_rev_reg_id,
    rev_reg_id,
    rev_reg_id2cred_def_id,
    rev_reg_id2tag)


LOGGER = logging.getLogger(__name__)


class Tails:
    """
    Abstraction layer to manage tails files for Issuers and HolderProvers. Uses symbolic link
    to retain association between tails file and corresponding revocation registry identifier.
    """

    MAX_SIZE = 100000

    def __init__(self, base_dir: str, cd_id: str, tag: str = None):
        """
        Initialize programmatic association between revocation registry identifier
        (on credential definition on input identifier plus tag, default most recent),
        and tails file, via symbolic link.

        Raise AbsentTails if (rev reg id) symbolic link or (tails hash) tails file not present.

        :param base_dir: base directory for tails files, thereafter split by cred def id
        :param cd_id: credential definition identifier of interest
        :param tag: revocation registry identifier tag of interest, default to most recent
        """

        LOGGER.debug('Issuer.__init__ >>> base_dir: %s, cd_id: %s, tag: %s', base_dir, cd_id, tag)

        if not ok_cred_def_id(cd_id):
            LOGGER.debug('Tails.__init__ <!< Bad cred def id %s', cd_id)
            raise BadIdentifier('Bad cred def id {}'.format(cd_id))

        if tag is None:
            self._rr_id = Tails.current_rev_reg_id(base_dir, cd_id)
        else:  # including tag == 0
            self._rr_id = rev_reg_id(cd_id, tag)
            if self._rr_id not in [basename(f) for f in Tails.links(base_dir)]:
                LOGGER.debug(
                    'Tails.__init__ <!< No tails file present for cred def id %s on rev reg id tag %s',
                    cd_id,
                    tag)
                raise AbsentTails('No tails file present for cred def id {} on rev reg id tag {}'.format(cd_id, tag))

        path_link = join(Tails.dir(base_dir, self._rr_id), self._rr_id)
        if not islink(path_link):
            raise AbsentTails('No symbolic link present at {} for rev reg id {}'.format(path_link, self._rr_id))

        path_tails = Tails.linked(base_dir, self._rr_id)
        if not isfile(path_tails):
            raise AbsentTails('No tails file present at {} for rev reg id {}'.format(path_tails, self._rr_id))

        self._tails_cfg_json = json.dumps({
            'base_dir': dirname(path_tails),
            'uri_pattern': '',
            'file': basename(path_tails)
        })

        self._reader_handle = None

        LOGGER.debug('Tails.__init__ <<<')

    async def open(self) -> 'Tails':
        """
        Open reader handle and return current object.

        :return: current object
        """

        LOGGER.debug('Tails.open >>>')

        self._reader_handle = await blob_storage.open_reader('default', self._tails_cfg_json)

        LOGGER.debug('Tails.open <<<')
        return self

    @staticmethod
    def ok_hash(token: str) -> bool:
        """
        Whether input token looks like a valid tails hash.

        :param token: candidate string
        :return: whether input token looks like a valid tails hash
        """

        LOGGER.debug('Tails.ok_hash >>> token: %s', token)

        rv = re.match('[{}]{{42,44}}$'.format(B58), token) is not None
        LOGGER.debug('Tails.ok_hash <<< %s', rv)
        return rv

    @staticmethod
    def associate(base_dir: str, rr_id: str, tails_hash: str) -> None:
        """
        Create symbolic link to tails file named tails_hash for rev reg id rr_id.

        :param rr_id: rev reg id
        :param tails_hash: hash of tails file, serving as file name
        """

        LOGGER.debug('Tails.associate >>> base_dir: %s, rr_id: %s, tails_hash: %s', base_dir, rr_id, tails_hash)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Tails.associate <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        if not Tails.ok_hash(tails_hash):
            LOGGER.debug('Tails.associate <!< Bad tails hash %s', tails_hash)
            raise BadIdentifier('Bad tails hash {}'.format(tails_hash))

        cd_id = rev_reg_id2cred_def_id(rr_id)
        directory = join(base_dir, cd_id)
        cwd = getcwd()
        makedirs(directory, exist_ok=True)
        chdir(directory)
        symlink(tails_hash, rr_id)
        chdir(cwd)

        LOGGER.debug('Tails.associate <<<')

    @staticmethod
    def dir(base_dir: str, rr_id: str) -> str:
        """
        Return correct subdirectory of input base dir for artifacts corresponding to input rev reg id.

        :param base_dir: base directory for tails files, thereafter split by cred def id
        :param rr_id: rev reg id
        """

        LOGGER.debug('Tails.dir >>> base_dir: %s, rr_id: %s', base_dir, rr_id)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Tails.dir <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        rv = join(base_dir, rev_reg_id2cred_def_id(rr_id))
        LOGGER.debug('Tails.dir <<< %s', rv)
        return rv

    @staticmethod
    def linked(base_dir: str, rr_id: str) -> str:
        """
        Get, from the specified directory, the path to the tails file associated with
        the input revocation registry identifier, or None for no such file.

        :param base_dir: base directory for tails files, thereafter split by cred def id
        :param rr_id: rev reg id
        :return: (stringified) path to tails file of interest, or None for no such file.
        """

        LOGGER.debug('Tails.linked >>> base_dir: %s, rr_id: %s', base_dir, rr_id)

        if not ok_rev_reg_id(rr_id):
            LOGGER.debug('Tails.linked <!< Bad rev reg id %s', rr_id)
            raise BadIdentifier('Bad rev reg id {}'.format(rr_id))

        cd_id = rev_reg_id2cred_def_id(rr_id)
        link = join(base_dir, cd_id, rr_id)

        rv = join(base_dir, cd_id, readlink(link)) if islink(link) else None
        LOGGER.debug('Tails.linked <<< %s', rv)
        return rv

    @staticmethod
    def links(base_dir: str, issuer_did: str = None) -> set:
        """
        Return set of all paths to symbolic links (rev reg ids) associating their
        respective tails files, in specified base tails directory recursively
        (omitting the .hopper subdirectory), on input issuer DID if specified.

        :param base_dir: base directory for tails files, thereafter split by cred def id
        :param issuer_did: issuer DID of interest
        :return: set of paths to symbolic links associating tails files
        """

        LOGGER.debug('Tails.links >>> base_dir: %s, issuer_did: %s', base_dir, issuer_did)

        if issuer_did and not ok_did(issuer_did):
            LOGGER.debug('Tails.links <!< Bad DID %s', issuer_did)
            raise BadIdentifier('Bad DID {}'.format(issuer_did))

        rv = set()
        for dir_path, dir_names, file_names in walk(base_dir, topdown=True):
            dir_names[:] = [d for d in dir_names if not d.startswith('.')]
            for file_name in file_names:
                if islink(join(dir_path, file_name)) and (not issuer_did or ok_rev_reg_id(file_name, issuer_did)):
                    rv.add(join(dir_path, file_name))

        LOGGER.debug('Tails.links <<< %s', rv)
        return rv

    @staticmethod
    def unlinked(base_dir: str) -> set:
        """
        Return all paths to tails files, in specified tails base directory recursively
        (omitting the .hopper subdirectory), without symbolic links associating
        revocation registry identifiers.

        At an Issuer, tails files should not persist long without revocation registry identifier
        association via symbolic link. At a HolderProver, a newly downloaded tails file stays
        unlinked until the anchor stores a credential or creates a proof needing it, or else the
        anchor restarts.

        :param base_dir: base directory for tails files, thereafter split by cred def id
        :return: set of paths to tails files with no local symbolic links to them
        """

        LOGGER.debug('Tails.unlinked >>> base_dir: %s', base_dir)

        rv = set()
        for dir_path, dir_names, file_names in walk(base_dir, topdown=True):
            dir_names[:] = [d for d in dir_names if not d.startswith('.')]
            for file_name in file_names:
                if isfile(join(dir_path, file_name)) and Tails.ok_hash(file_name):
                    rv.add(join(dir_path, file_name))
        rv -= {join(dirname(path_link), readlink(path_link)) for path_link in Tails.links(base_dir)}

        LOGGER.debug('Tails.unlinked <<< %s', rv)
        return rv

    @staticmethod
    def next_tag(base_dir: str, cd_id: str) -> (str, int):
        """
        Return the next tag name available for a new rev reg id on input cred def id in base directory,
        and suggested size of associated rev reg.

        :param base_dir: base directory for tails files, thereafter split by cred def id
        :param cd_id: credential definition identifier of interest
        :return: stringified least non-negative integer not yet used in a rev reg id associated with a tails file
            in base directory, and recommendation for next size to use
        """

        LOGGER.debug('Tails.next_tag >>> base_dir: %s, cd_id: %s', base_dir, cd_id)

        if not ok_cred_def_id(cd_id):
            LOGGER.debug('Tails.next_tag <!< Bad cred def id %s', cd_id)
            raise BadIdentifier('Bad cred def id {}'.format(cd_id))

        tag = 1 + max([int(rev_reg_id2tag(basename(f)))
            for f in Tails.links(base_dir) if cd_id in basename(f)] + [-1])  # -1: next tag is '0' if no tags so far
        size = min(2**(tag + 6), Tails.MAX_SIZE)

        rv = (tag, size)
        LOGGER.debug('Tails.next_tag <<< %s', rv)
        return rv

    @staticmethod
    def current_rev_reg_id(base_dir: str, cd_id: str) -> str:
        """
        Return the current revocation registry identifier for
        input credential definition identifier, in input directory.

        Raise AbsentTails if no corresponding tails file, signifying no such revocation registry defined.

        :param base_dir: base directory for tails files, thereafter split by cred def id
        :param cd_id: credential definition identifier of interest
        :return: identifier for current revocation registry on input credential definition identifier
        """

        LOGGER.debug('Tails.current_rev_reg_id >>> base_dir: %s, cd_id: %s', base_dir, cd_id)

        if not ok_cred_def_id(cd_id):
            LOGGER.debug('Tails.current_rev_reg_id <!< Bad cred def id %s', cd_id)
            raise BadIdentifier('Bad cred def id {}'.format(cd_id))

        tags = [int(rev_reg_id2tag(basename(f))) for f in Tails.links(base_dir)
            if cd_id in basename(f)]
        if not tags:
            raise AbsentTails('No tails files present for cred def id {}'.format(cd_id))

        rv = rev_reg_id(cd_id, str(max(tags)))  # ensure 10 > 9, not '9' > '10'
        LOGGER.debug('Tails.current_rev_reg_id <<< %s', rv)
        return rv

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

        cfg = json.loads(self._tails_cfg_json)
        return join(cfg['base_dir'], cfg['file'])

    def __str__(self) -> str:
        """
        Return string representation.

        :return: string representation
        """

        cfg = json.loads(self._tails_cfg_json)
        return 'Tails: {}/{} -> {}'.format(cfg['base_dir'], self._rr_id, cfg['file'])
