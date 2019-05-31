****************************
Exceptions
****************************

This section outlines the Exception descendants that the von_anchor package defines. Each exception class descends from VonAnchorError, which itself inherits Exception, and each exception class encapsulates a simple error code and message as per the table.

.. csv-table::
    :header: "Exception Class", "Error Code", "Semantics", "Example"
    :widths: 20, 15, 50, 50

    "CredentialFocus", "1003", "Anchor attempting to prove zero credentials, or more than one credentials per cred def", "Actuator posts a get-proof form with credential filter resolving to multiple credentials for a single credential definition, or to no credentials at all"
    "AbsentLinkSecret", "1005", "Anchor attempts to perform operation requiring link secret which is not set", "Actuator calls holder-prover anchor to create credential request, but anchor has no link secret set"
    "CorruptWallet", "1006", "Anchor wallet includes references to a ledger that no longer exists", "Developer resets the distributed ledger and runs an anchor with an existing wallet from prior ledger instance."
    "AbsentSchema", "1007", "Anchor cannot find specified schema on ledger (or cache)", "Verifier anchor attempts to verify proof that refers to a credential definition on a schema from a ledger to which the anchor's wallet does not pertain"
    "AbsentCredDef", "1008", "Anchor cannot find specified specified credential definition on ledger (or cache)", "Holder-prover anchor attempts to create a credential request against a credential definition from a ledger to which the anchor's wallet does not pertain"
    "AbsentTails", "1009", "Anchor cannot find tails file that it requires", "Holder-prover anchor calls to store credential that specifies a revocation registry for which anchor has no tails file"
    "CorruptTails", "1010", "Issuer failed to create tails file", "Issuer anchor attempts to create new revocation registry, but indy-sdk fails to create tails file"
    "BadRevocation", "1011", "Issuer cannot revoke credential as requested", "Issuer anchor attempts to revoke credential that is already revoked, or that another anchor issued"
    "BadLedgerTxn", "1012", "Distributed ledger transaction failed", "Origin anchor attempts to send new schema to distributed ledger, but node pool is not responding"
    "BadRevStateTime", "1013", "Revocation registry state timestamp predates revocation registry creation", "Holder-prover anchor attempts to create proof on credential with non-revocation timestamp predating its registry creation (indy-sdk cannot)"
    "AbsentInterval", "1014", "Credentials missing non-revocation interval, but credential definition supports revocation", "Holder-prover anchor attempts to create proof on credentials that omit non-revocation interval, but credential definition supports revocation"
    "AbsentRevReg", "1015", "Revocation registry not present on distributed ledger", "Verifier anchor receives proof citing revocation registry that does not exist on the distributed ledger"
    "BadIdentifier", "1016", "Encountered bad tails hash, DID, schema id, cred def id, rev reg id", "Holder-prover anchor attempts to create proof on credentials citing bad cred def id"
    "AbsentProcess", "1017", "Required external process not running", "Issuer could not spawn external revocation registry builder"
    "BadKey", "1018", "Cryptographic operation revealed bad key", "Authenticated decryption operation revealed unexpected proof of origin"
    "BadRole", "1019", "Invalid specifier for indy-sdk role", "Configured value is not a valid indy-sdk anchor role"
    "BadAttribute", "1020", "Bad attribute name", "Originating anchor attempted to specify schema attribute name reserved for indy-sdk"
    "AbsentNym", "1021", "Expected cryptonym not present on ledger", "Anchor attempts to query its role from the ledger but its cryptonym is not registered"
    "AbsentWallet", "3000", "Wallet cannot open as it does not exist", "Anchor attempts to open a wallet that is not yet created"
    "BadWalletQuery", "3001", "Bad WQL", "Caller attempts to search wallet with bad WQL"
    "AbsentCred", "3002", "No such credential in wallet", "Caller calls to get cred info on missing cred identifier"
    "ExtantWallet", "3004", "Attempted to create a wallet that already exists", "Anchor attempts to create a wallet on a name corresponding to an existing wallet"
    "WalletState", "3005", "Attempted to operate on a wallet in wrong state", "Anchor attempts to reseed its closed wallet"
    "ExtantRecord", "3006", "Attempted to overwrite an existing wallet record", "Anchor attempts to write local DID that already exists"
    "AbsentRecord", "3007", "No such wallet record", "Anchor attempts to get metadata for pairwise DID that does not exist"
    "AbsentMessage", "3008", "Message is empty", "Anchor attempts to encrypt empty message"
    "BadRecord", "3009", "Record as specified is not valid for wallet storage", "Non-secrets tags do not comply with indy specification"
    "BadAccess", "3010", "Wallet access credentials value is incorrect", "Anchor attempts to open a wallet with incorrect access credentials value"
    "BadSearch", "3011", "Non-secret storage record search cannot proceed", "Anchor attempts to fetch the next batch of results from a search that is closed"
    "ClosedPool", "4000", "Pool is closed but operation needs it open", "Anchor attempts to call a node pool for ledger data, but the pool is not open"
    "AbsentPool", "4002", "Operation requires node pool, but none specified", "Anchor attempts ledger transaction but has no node pool"
    "ExtantPool", "4003", "Pool already exists", "Actuator attempts to create configuration for pool that already exists"
    "CacheIndex", "5000", "Schema cache, credential definition cache, or revocation cache has no entry at given index", "Anchor attempts to retrieve schema for a transaction number or schema key that it has not yet cached"
    "AbsentDIDDocItem", "6000", "Absent item in DID document", "Actuator attempts to parse DID document with no DID as identifier"
    "BadDIDDocItem", "6001", "Bad item in DID document processing", "Actuator attempts to set malformed public key in DOD document"
    "JSONValidation", "9000", "JSON schema is corrupt or JSON form does not match schema", "Node pool configuration dict missing required properties"

Table: Exception Particulars
