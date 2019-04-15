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

from typing import Sequence
from indy import non_secrets

from von_anchor.canon import canon_non_secret_wql
from von_anchor.error import BadSearch, WalletState
from von_anchor.wallet.wallet import Wallet
from von_anchor.wallet.record import StorageRecord

LOGGER = logging.getLogger(__name__)


class StorageRecordSearch:
    """
    Interactive batch-wise (non-secret) storage record search.
    """

    OPTIONS_JSON = json.dumps({
        'retrieveRecords': True,
        'retrieveTotalCount': True,
        'retrieveType': True,
        'retrieveValue': True,
        'retrieveTags': True
    })

    def __init__(self, wallet: Wallet, typ: str, query: dict):
        """
        Initialize search instance.

        :param wallet: wallet to search
        :param typ: type marking (non-secret) storage records to search
        :param query: WQL query
        """

        LOGGER.debug('StorageRecordSearch.__init__ >>> wallet: %s, typ: %s, query: %s', wallet, typ, query)

        self._wallet = wallet
        self._type = typ
        self._query_json = json.dumps(canon_non_secret_wql(query))

        self._handle = None

        LOGGER.debug('StorageRecordSearch.__init__ <<<')

    @property
    def handle(self) -> int:
        """
        Accessor for search handle.

        :return: search handle
        """

        return self._handle

    @property
    def opened(self) -> bool:
        """
        Accessor for search state.

        :return: whether search is open
        """

        return self._handle is not None

    async def __aenter__(self) -> 'StorageRecordSearch':
        """
        Context manager entry. Open search, for closure on context manager exit.

        :return: current object
        """

        LOGGER.debug('StorageRecordSearch.__aenter__ >>>')

        rv = await self.open()
        LOGGER.debug('StorageRecordSearch.__aenter__ <<<')
        return rv

    async def open(self) -> None:
        """
        Begin the search operation.
        """

        LOGGER.debug('StorageRecordSearch.open >>>')

        if self.opened:
            LOGGER.debug('StorageRecordSearch.open <!< Search is already opened')
            raise BadSearch('Search is already opened')

        if not self._wallet.opened:
            LOGGER.debug('StorageRecordSearch.open <!< Wallet %s is closed', self._wallet.name)
            raise WalletState('Wallet {} is closed'.format(self._wallet.name))

        self._handle = await non_secrets.open_wallet_search(
            self._wallet.handle,
            self._type,
            self._query_json,
            StorageRecordSearch.OPTIONS_JSON)

        LOGGER.debug('StorageRecordSearch.open <<<')

    async def fetch(self, limit: int = None) -> Sequence[StorageRecord]:
        """
        Fetch next batch of search results.

        Raise BadSearch if search is closed, WalletState if wallet is closed.

        :param limit: maximum number of records to return (default value Wallet.DEFAULT_CHUNK)
        :return: next batch of records found
        """

        LOGGER.debug('StorageRecordSearch.fetch >>> limit: %s', limit)

        if not self.opened:
            LOGGER.debug('StorageRecordSearch.fetch <!< Storage record search is closed')
            raise BadSearch('Storage record search is closed')

        if not self._wallet.opened:
            LOGGER.debug('StorageRecordSearch.fetch <!< Wallet %s is closed', self._wallet.name)
            raise WalletState('Wallet {} is closed'.format(self._wallet.name))

        records = json.loads(await non_secrets.fetch_wallet_search_next_records(
            self._wallet.handle,
            self.handle,
            limit or Wallet.DEFAULT_CHUNK))['records'] or []  # at exhaustion results['records'] = None

        rv = [StorageRecord(typ=rec['type'], value=rec['value'], tags=rec['tags'], ident=rec['id']) for rec in records]
        LOGGER.debug('StorageRecordSearch.fetch <<< %s', rv)
        return rv

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Close search.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        LOGGER.debug('StorageRecordSearch.__aexit__ >>>')

        await self.close()

        LOGGER.debug('StorageRecordSearch.__aexit__ <<<')

    async def close(self) -> None:
        """
        Close search.
        """

        LOGGER.debug('StorageRecordSearch.close >>>')

        if self._handle:
            await non_secrets.close_wallet_search(self.handle)
            self._handle = None

        LOGGER.debug('StorageRecordSearch.close <<<')
