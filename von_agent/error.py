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

from enum import IntEnum


class ErrorCode(IntEnum):
    """
    Error codes particular to von_agent operation. Start at 1000 to avoid collisions with HTTP error codes.
    """

    Success = 0,

    # Errors to do with von_agent operation
    # TokenType = 1000,
    # ProxyRelayConfig = 1001,
    # ProxyHop = 1002,
    CredentialFocus = 1003,
    AbsentAttribute = 1004,
    AbsentLinkSecret = 1005,
    CorruptWallet = 1006,
    AbsentSchema = 1007,
    AbsentCredDef = 1008,
    AbsentTailsFile = 1009,
    CorruptTails = 1010,
    BadRevocation = 1011,
    BadLedgerTxn = 1012,
    BadRevStateTime = 1013,
    AbsentInterval = 1014,
    AbsentRevRegDef = 1015,

    # Errors to do with schema identifiers
    SchemaIdSpec = 2000,

    # Errors to do with wallet operation
    AbsentWallet = 3000,

    # Errors to do with node pool operation
    ClosedPool = 4000,

    # Errors to do with caching
    CacheIndex = 5000,

    # JSON validation
    JSONValidation = 9000


class VonAgentError(Exception):
    """
    Error class for von_agent operation.
    """

    def __init__(self, error_code: ErrorCode, message: str):
        """
        Initialize on code and message.

        :param error_code: error code
        :param message: error message
        """

        super().__init__()
        self.error_code = error_code
        self.message = message


'''
class TokenType(VonAgentError):
    """
    Agent does not process a given message token type.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.TokenType, message)


class ProxyRelayConfig(VonAgentError):
    """
    Agent does not operate as a proxy relay.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.ProxyRelayConfig, message)


class ProxyHop(VonAgentError):
    """
    Agent does not operate as a proxy relay.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.ProxyHop, message)
'''


class CredentialFocus(VonAgentError):
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


class AbsentAttribute(VonAgentError):
    """
    Agent attempting to send attribute (e.g., endpoint) to ledger but has none defined.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentAttribute, message)


class CorruptWallet(VonAgentError):
    """
    Agent wallet is inconsistent with ledger.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.CorruptWallet, message)


class AbsentSchema(VonAgentError):
    """
    (HolderProver) agent attempting operation requiring unavailable schema.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentSchema, message)


class AbsentCredDef(VonAgentError):
    """
    (Issuer or HolderProver) agent attempting operation requiring unavailable claim definition.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentCredDef, message)


class AbsentTailsFile(VonAgentError):
    """
    (Issuer or HolderProver) agent attempting to open nonexistent tails file.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentTailsFile, message)


class CorruptTails(VonAgentError):
    """
    (Issuer or HolderProver) agent attempting to sync tails dir from distributed ledger not having
    corresponding revocation registry.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.CorruptTails, message)


class BadRevocation(VonAgentError):
    """
    Issuer agent attempting to perform illegitimate revocation
    (another issuer issued credential, credential revoked already, etc.).
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadRevocation, message)


class BadLedgerTxn(VonAgentError):
    """
    Ledger rejected transaction.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.BadLedgerTxn, message)


class BadRevStateTime(VonAgentError):
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


class AbsentLinkSecret(VonAgentError):
    """
    (HolderProver) agent attempting operation requiring absent link secret.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentLinkSecret, message)


class AbsentInterval(VonAgentError):
    """
    (HolderProver) agent attempting to create proof on credentials missing
    a non-revocation interval for credential definition that supports revocation.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentInterval, message)


class AbsentRevRegDef(VonAgentError):
    """
    (HolderProver) agent attempting to create revocation registry state but
    revocation registry definition is not defined on the ledger.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentRevRegDef, message)


class SchemaIdSpec(VonAgentError):
    """
    Cannot derive a schema key from a given specification.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.SchemaIdSpec, message)


class AbsentWallet(VonAgentError):
    """
    Wallet has not been created (within indy-sdk).
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.AbsentWallet, message)


class ClosedPool(VonAgentError):
    """
    Pool needs to be open.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.ClosedPool, message)


class CacheIndex(VonAgentError):
    """
    Indexation error on a cache.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.CacheIndex, message)


class JSONValidation(VonAgentError):
    """
    Exception in JSON validation.
    """

    def __init__(self, message: str):
        """
        Initialize on message.

        :param message: error message
        """

        super().__init__(ErrorCode.JSONValidation, message)
