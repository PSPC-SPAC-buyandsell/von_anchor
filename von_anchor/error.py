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


from enum import IntEnum


class ErrorCode(IntEnum):
    """
    Error codes particular to von_anchor operation.
    """

    Success = 0

    # Errors to do with von_anchor operation
    CredentialFocus = 1003
    AbsentLinkSecret = 1005
    CorruptWallet = 1006
    AbsentSchema = 1007
    AbsentCredDef = 1008
    AbsentTails = 1009
    CorruptTails = 1010
    BadRevocation = 1011
    BadLedgerTxn = 1012
    BadRevStateTime = 1013
    AbsentInterval = 1014
    AbsentRevReg = 1015
    BadIdentifier = 1016
    AbsentProcess = 1017
    BadKey = 1018
    BadRole = 1019
    BadAttribute = 1020
    AbsentNym = 1021

    # Errors to do with wallet operation
    AbsentWallet = 3000
    BadWalletQuery = 3001
    AbsentCred = 3002
    ExtantWallet = 3004
    WalletState = 3005
    ExtantRecord = 3006
    AbsentRecord = 3007
    AbsentMessage = 3008
    BadRecord = 3009
    BadAccess = 3010
    BadSearch = 3011

    # Errors to do with node pool management and operation
    ClosedPool = 4000
    AbsentPool = 4002
    ExtantPool = 4003

    # Errors to do with caching
    CacheIndex = 5000

    # Errors in DID Doc processing
    AbsentDIDDocItem = 6000
    BadDIDDocItem = 6001

    # JSON validation
    JSONValidation = 9000


class VonAnchorError(Exception):
    """
    Error class for von_anchor operation.
    """

    def __init__(self, error_code: ErrorCode, message: str):
        """
        Initialize on code and message.

        :param error_code: error code
        :param message: error message
        """

        super().__init__(message)
        self.error_code = error_code
        self.message = message

    def __str__(self):
        """
        String representation of error.
        """

        return '({}) {}'.format(self.error_code, self.message)

class CredentialFocus(VonAnchorError):
    """
    Attempt to prove credential in specification that resolve to no claims,
    or to multiple claims for any single claim definition.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.CredentialFocus, message)


class CorruptWallet(VonAnchorError):
    """
    Anchor wallet is inconsistent with ledger.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.CorruptWallet, message)


class AbsentSchema(VonAnchorError):
    """
    (HolderProver) anchor attempting operation requiring unavailable schema.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentSchema, message)


class AbsentCredDef(VonAnchorError):
    """
    (Issuer or HolderProver) anchor attempting operation requiring unavailable claim definition.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentCredDef, message)


class AbsentTails(VonAnchorError):
    """
    (Issuer or HolderProver) anchor attempting to open nonexistent tails file.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentTails, message)


class CorruptTails(VonAnchorError):
    """
    (Issuer or HolderProver) anchor attempting to sync tails dir from distributed ledger not having
    corresponding revocation registry.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.CorruptTails, message)


class BadRevocation(VonAnchorError):
    """
    Issuer anchor attempting to perform illegitimate revocation
    (another issuer issued credential, credential revoked already, etc.).
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadRevocation, message)


class BadLedgerTxn(VonAnchorError):
    """
    Ledger rejected transaction.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadLedgerTxn, message)


class BadRevStateTime(VonAnchorError):
    """
    Proof request includes revocation state timestamp for credential before its revocation registry creation,
    or in the future.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadRevStateTime, message)


class AbsentLinkSecret(VonAnchorError):
    """
    (HolderProver) anchor attempting operation requiring absent link secret.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentLinkSecret, message)


class AbsentInterval(VonAnchorError):
    """
    (HolderProver) anchor attempting to create proof on credentials missing
    a non-revocation interval for credential definition that supports revocation.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentInterval, message)


class AbsentRevReg(VonAnchorError):
    """
    Anchor attempting to create revocation registry state but
    revocation registry is not present on the ledger.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentRevReg, message)


class BadIdentifier(VonAnchorError):
    """
    Encountered incorrectly formatted:
      - distributed identifier (DID),
      - schema identifier,
      - credential definition identifier,
      - revocation registry identifier, or
      - tails hash.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadIdentifier, message)


class AbsentProcess(VonAnchorError):
    """
    Required external process not running.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentProcess, message)


class BadKey(VonAnchorError):
    """
    Cryptographic operation revealed bad key.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadKey, message)


class BadRole(VonAnchorError):
    """
    Invalid specifier for indy-sdk role.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadRole, message)


class BadAttribute(VonAnchorError):
    """
    Invalid specifier for indy-sdk role.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadAttribute, message)


class AbsentNym(VonAnchorError):
    """
    Ledger has no such cryptonym.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentNym, message)


class AbsentWallet(VonAnchorError):
    """
    Wallet has not been created (within indy-sdk).
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentWallet, message)


class BadWalletQuery(VonAnchorError):
    """
    Wallet query is badly formed.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadWalletQuery, message)


class AbsentCred(VonAnchorError):
    """
    No such credential.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentCred, message)


class ExtantWallet(VonAnchorError):
    """
    Wallet already exists.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.ExtantWallet, message)


class WalletState(VonAnchorError):
    """
    Wallet needs to be open.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.WalletState, message)


class ExtantRecord(VonAnchorError):
    """
    Wallet record already exists.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.ExtantRecord, message)


class AbsentRecord(VonAnchorError):
    """
    Wallet record does not exist.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentRecord, message)


class AbsentMessage(VonAnchorError):
    """
    Absent target for cryptographic operation.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentMessage, message)


class BadRecord(VonAnchorError):
    """
    Record as specified is not valid for wallet storage.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadRecord, message)


class BadAccess(VonAnchorError):
    """
    Wallet access credentials value is incorrect.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadAccess, message)


class BadSearch(VonAnchorError):
    """
    Search operation failed.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadSearch, message)


class ClosedPool(VonAnchorError):
    """
    Pool needs to be open.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.ClosedPool, message)


class AbsentPool(VonAnchorError):
    """
    Pool required for operation but none is present.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentPool, message)


class ExtantPool(VonAnchorError):
    """
    Pool already exists.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.ExtantPool, message)


class CacheIndex(VonAnchorError):
    """
    Indexation error on a cache.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.CacheIndex, message)


class AbsentDIDDocItem(VonAnchorError):
    """
    Absent item in DID document.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentDIDDocItem, message)


class BadDIDDocItem(VonAnchorError):
    """
    Bad item in DID document processing.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadDIDDocItem, message)


class JSONValidation(VonAnchorError):
    """
    Exception in JSON validation.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.JSONValidation, message)
