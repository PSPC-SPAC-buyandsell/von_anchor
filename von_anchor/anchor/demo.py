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


import logging

from os import makedirs
from os.path import basename, expanduser, join

from von_anchor.anchor.holder_prover import HolderProver
from von_anchor.anchor.issuer import Issuer
from von_anchor.anchor.smith import AnchorSmith
from von_anchor.anchor.verifier import Verifier
from von_anchor.cache import Caches
from von_anchor.error import ClosedPool
from von_anchor.nodepool import NodePool
from von_anchor.tails import Tails
from von_anchor.validate_config import validate_config
from von_anchor.wallet import Wallet

LOGGER = logging.getLogger(__name__)


class TrusteeAnchor(AnchorSmith):
    """
    TrusteeAnchor demonstrator class acts as an anchor smith to forge new anchors.
    """

    pass


class BCRegistrarAnchor(Issuer):
    """
    BCRegistrarAnchor demonstrator class acts as an issuer.
    """

    pass


class OrgBookAnchor(HolderProver):
    """
    Basic OrgBookAnchor demonstrator class acts as a holder-prover for any of its registrars' credentials.
    """

    pass


class OrgHubAnchor(OrgBookAnchor, Issuer, Verifier):
    """
    OrgHubAnchor demonstrator class acts as an issuer and verifier for its own credentials
    (principally metadata), and as a holder-prover for its own and any of its registrars' credentials.
    """

    def __init__(self, wallet: Wallet, pool: NodePool, cfg: dict = None) -> None:
        """
        Initializer for org hub anchor. Retain input parameters; do not open wallet nor tails writer.

        :param wallet: wallet for anchor use
        :param pool: pool for anchor use
        :param cfg: configuration dict for cache archive behaviour; e.g.,

        ::

            {
                'parse-caches-on-open': True,
                'archive-holder-prover-caches-on-close': True,
                'archive-verifier-caches-on-close': {
                    'schema_id': [
                        'R17v42T4pk...:2:tombstone:1.2',
                        '9cHbp54C8n...:2:business:2.0',
                        'Pcq76cx6jE...:2:birth_cert:1.0',
                        ...
                    ],
                    'cred_def_id': [
                        'R17v42T4pk...:3:CL:19:tag',
                        '9cHbp54C8n...:3:CL:37:tag',
                        'Pcq76cx6jE...:3:CL:51:tag',
                        ...
                    ]
                    'rev_reg_id': [
                        'R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:0',
                        'R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:1',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:0',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:1',
                        '9cHbp54C8n...:4:9cHbp54C8n...:3:CL:37:tag:CL_ACCUM:2',
                        ...
                    ]
                }
            }

        """

        LOGGER.debug('OrgHubAnchor.__init__ >>> wallet: %s, pool: %s, cfg: %s', wallet, pool, cfg)

        super().__init__(wallet, pool)
        self._link_secret = None

        self._dir_tails = join(expanduser('~'), '.indy_client', 'tails')
        makedirs(self._dir_tails, exist_ok=True)

        self._cfg = cfg or {}
        validate_config('org-hub', self._cfg)

        self._dir_cache = join(expanduser('~'), '.indy_client', 'cache', self.wallet.name)
        makedirs(self._dir_cache, exist_ok=True)

        LOGGER.debug('OrgHubAnchor.__init__ <<<')

    @staticmethod
    def role() -> str:
        """
        Return the indy-sdk role for Org Hub anchor.

        :return: role string
        """

        rv = 'TRUST_ANCHOR'
        return rv

    async def close(self) -> None:
        """
        Explicit exit. If so configured, populate cache to prove for any creds on schemata,
        cred defs, and rev regs marked of interest in configuration at initialization,
        archive cache, and purge prior cache archives.

        :return: current object
        """

        LOGGER.debug('OrgHubAnchor.close >>>')

        archive_caches = False
        if self.cfg.get('archive-holder-prover-caches-on-close', False):
            archive_caches = True
            await self.load_cache_for_proof(False)
        if self.cfg.get('archive-verifier-caches-on-close', {}):
            archive_caches = True
            await self.load_cache_for_verification(False)
        if archive_caches:
            Caches.archive(self.dir_cache)
            Caches.purge_archives(self.dir_cache, True)

        await self.wallet.close()
        # Do not close pool independently: let relying party decide when to go on-line and off-line

        for path_rr_id in Tails.links(self._dir_tails):
            rr_id = basename(path_rr_id)
            try:
                await self._sync_revoc(rr_id)
            except ClosedPool:
                LOGGER.warning('OrgHubAnchor sync-revoc on close required ledger for %s but pool was closed', rr_id)

        LOGGER.debug('OrgHubAnchor.close <<<')


class SRIAnchor(Verifier, Issuer):  # Put Verifier first in MRO for its __init__() configuration processing
    """
    SRIAnchor demonstrator class acts as both an issuer of its own credentials and a verifier
    of any holder-prover's.
    """

    @staticmethod
    def role() -> str:
        """
        Return the indy-sdk role for SRI anchor.

        :return: role string
        """

        rv = 'TRUST_ANCHOR'
        return rv
