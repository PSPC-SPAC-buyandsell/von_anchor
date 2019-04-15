***********************
Wallet
***********************

The Wallet subpackage encapsulates the indy-sdk wallet, a wallet manager, and abstractions useful for its records. It resides in ``von_anchor/wallet/``.

.. _wallet-manager:

Wallet Manager
#######################

The Wallet Manager provides management utilities for wallets and retains default wallet configuration values. Its source resides in file ``von_anchor/wallet/manager.py``.

Initialization
++++++++++++++++++++++++++++

The initializer takes and retains default configuration values to use in creating new VON Anchor wallets:

* ``storage_type``: storage type (default None for indy-sdk default)
* ``freshness_time``: freshness time (default 0 for infinite)
* ``auto_create``: automatically create on first wallet open
* ``auto_remove``: automatically remove on first wallet close (default False)
* ``key``: access credentials value (default ``key``).

Accessors
++++++++++++++++++++++++++++

The class exposes accessors for default wallet configuration values.

Wallet Instance Management
++++++++++++++++++++++++++++

The ``create()`` method takes configuration (overriding Wallet Manager instance defaults), access credentials value, and whether to replace an existing wallet on the same name (with the same access credentials). The configuration data includes:

* ``id``: the wallet name
* ``storage_type``, ``freshness_time``: indy-sdk configuration items
* ``did``, ``seed``: optional DID an seed to use
* ``auto_create``: automatic creation behaviour on first wallet close
* ``auto_remove``: automatic removal behaviour on first wallet close
* ``link_secret_label``: optional link secret label to use to create link secret.

The implementation creates the indy-sdk wallet, sets the anchor DID and verification key (using the seed and DID if provided), and creates the link secret if the configuration specifies its label.

The ``get()`` method takes a configuration dict and an access credentials value. Its operation returns a corresponding VON anchor wallet instance. Note that the corresponding indy-sdk wallet need not exist in persistent storage.

The ``reset()`` method takes an open VON wallet and an optional seed. It closes and deletes the wallet, then re-creates a replacement on the same configuration.

The ``remove()`` method takes a (closed) VON anchor wallet and removes it from persistent storage. Its implementation simply delegates to the wallet itself.

Import and Export
++++++++++++++++++++++++++++

The ``export_wallet()`` method serializes and exports an (open) VON anchor wallet to a file path. It uses the wallet's access credentials value as the export key, on the ``ARGON2I_MOD`` indy-sdk default key derivation algorithm.

The ``import_wallet()`` method deserializes and imports an exported wallet file into the indy-sdk wallet collection. It takes configuration data for the wallet including its identifier (name). The call requires the access credentials value for the wallet as exported *a priori*.

Storage Type Registration
++++++++++++++++++++++++++++

The static method ``register_storage_library()`` registers a wallet storage plug-in with the indy-sdk.

VON Anchor Wallet
#######################

The VON Anchor wallet provides functionality for VON anchors to use indy-sdk wallets to manage keyed and non-secret storage records. It resides in ``von_anchor/wallet/wallet.py``.

Initialization
++++++++++++++++++++++++++++

Actuators should not call the wallet initializer directly; they should prefer the ``WalletManager.get()`` method of :ref:`wallet-manager` instead, which filters configuration parameters through preset defaults.

The initializer takes:

* a configuration dict with indy-sdk wallet configuration keys and values
* the wallet access credentials value
* auto_create (behaviour) boolean.
* auto_remove (behaviour) boolean.

Its operation stores input parameters or sensible defaults, in waiting for further calls to create the wallet in storage or to open it for indy-sdk operations.

Accessors
++++++++++++++++++++++++++++

The class exposes accessors for the wallet name, indy-sdk handle, configuration, automatic creation and remove status, access credentials, storage type, anchor DID, and (public) verification key.

.. _wallet-create:

Context Management
++++++++++++++++++++++++++++

The context manager methods set up and tear down the wallet within the indy-sdk. On opening, the indy-sdk returns a wallet handle, which the the ``Wallet`` object retains for future indy-sdk interaction. On closing, the  instance directs the indy-sdk to invalidate the handle and to delete the wallet from persistent storage (if so configured).

.. _wallet-reseed:

Key Rotation
++++++++++++++++++++++++++++

The ``reseed_init()`` and ``reseed_apply()`` methods perform key rotation in the wallet (not on the ledger). Actuators should not call these methods directly, but use the owning anchor's or the Wallet Manager's delegators instead.

Anchor Cryptonym Key Rotation
-----------------------------

The anchor that owns the wallet calls these methods via its ``reseed()`` method to realize the operation, generating new keys from a new seed, as per :ref:`base-anchor`, en route to updating the anchor's cryptonym on the ledger.

Wallet-Only Key Rotation
-------------------------

For the case where a wallet does not correspond to an anchor on the ledger, the ``WalletManager`` class (see :ref:`wallet-manager`) exposes a single ``reseed_local()`` method to perform a complete key rotation in the wallet without attempting to go to the ledger.

Removal
++++++++++++++++++++++++++++

The ``remove()`` method attempts to remove the wallet from persistent storage if it exists. It raises ``WalletState`` if the wallet is open; otherwise it returns True on success and False on error (e.g., currently specified access credentials value is not valid for wallet in persistent storage).

.. _did-management:

Non-Secret Storage Record Operations
------------------------------------

This section discusses operations within the wallet for non-secret storage record management. The implementation delegates to the indy-sdk non-secrets storage API to manage pairwise DIDs.

Writing
...............

Method ``write_non_secrets()`` takes:

* a ``StorageRecord`` object as per :ref:`storage-record`
* an optional flag to replace, rather than (default) augment and overwrite, any existing metadata for an existing non-secret storage record (by type and identifier).

Its operation checks input metdata tags and delegates to indy-sdk ``non_secret`` API calls to write or update content according to input parameters. It returns the non-secret storage record as the wallet has added or updated it.

Fetching
...............

The ``get_non_secret()`` method takes a non-secret storage record type, a filter, and a canonicalization function (defaulting to ``canon_non_secret_wql()`` as per :ref:`canon-util`.

If the filter is a string, it uses it as an identifier with the record type to perform a straightforward lookup via the indy-sdk ``non_secret`` API.

Otherwise, the operation interprets the filter as WQL (default None, which canonicalizes to a query to get all on input record type). The processing uses the input canonicalization function to canonicalize the query, then delegates to indy-sdk to fetch all matching records. Finally the method returns a dict mapping identifiers to corresponding ``StorageRecord`` instances, or an empty dict for no match. This method fetches all results before returning; note that an actuator can use :ref:`storage-record-search` to perform an interactive batch-wise search, in the expectation of a larger result set.

Deleting
...............

The ``delete_non_secret()`` method takes a non-secret storage record type identifier, which uniquely identifies a non-secret storage record in the wallet, and removes it if present. If absent, it logs at level ``INFO`` and carries on.

Link Secret Management
++++++++++++++++++++++++++++

The wallet uses non-secret storage records to retain link secret labels.

On creating a link secret, the wallet operation writes a corresponding non-secret storage record with its label. When the operation needs a link secret, it fetches it using its most recent label. In this way the wallet obviates the need to recall and (attempt to) re-create the link secret on every subsequent open.

The ``create_link_secret()`` creates a link secret on the input label, logging instead if it duplicates the current link secret. It adds a corresponding non-secret storage record with the link secret label.

The ``get_link_secret_label()`` method retrieves the current link secret label from non-secret storage records.

DID Management
++++++++++++++++++++++++++++

The design identifies several kinds of DIDs.

An **anchor DID** is a DID in current or past use for the VON anchor using the wallet, in transacting with the node pool implementing the distributed ledger. The current anchor DID is in its cryptonym on the ledger, and in its wallet with the corresponding private key.

A **local DID** is a DID in use for communication between an agent using the current wallet (typically, via a VON anchor) and another agent. A local DID forms part of a pairwise DID. The wallet implementation uses ``DIDInfo`` objects (see :ref:`did-info`) to associate local DIDs with their verification keys and metadata.

A **pairwise DID** groups a DID and verification key from both local ('my') and remote ('their') sides of an agent-to-agent ('pairwise') relation. The wallet implementation uses ``PairwiseInfo`` objects (see :ref:`pairwise-info`) to associate these data plus any metadata for the relation. The wallet's pairwise DID processing stores pairwise DIDs via the indy-sdk ``non_secret`` API, allowing updates and searches on such records.

Anchor DID Operations
---------------------

The ``create()`` method (:ref:`wallet-create`) creates the anchor DID from seed. The ``reseed_apply()`` method (:ref:`wallet-reseed`) creates a new anchor DID in its operation.

The ``get_anchor_did()`` method returns the current anchor DID.

Signing Key Pair Operations
---------------------------

This section discusses signing key pair operations within the wallet. The implementation uses indy-sdk cryptographic API calls to manage signing key pairs in the wallet.

Writing
...............

Method ``create_signing_key()`` creates a signing key pair from an optional input optional seed (default random) and metadata (default empty).

Fetching
...............

Method ``get_signing_key()`` takes a verification key and returns a ``KeyInfo`` (:ref:`key-info`) for the corresponding signing key pair, raising ``AbsentRecord`` if none exists.

Replacing Metadata
..................

Method ``replace_signing_key_metadata()`` takes a verification key and metadata. Its operation sets the input metadata for the signing key pair that the verification key identifies, raising ``AbsentRecord`` if none exists.

Local DID Operations
---------------------

This section discusses local DID operations within the wallet. The implementation uses indy-sdk local DID storage API calls to manage local DIDs.

Writing
...............

Method ``create_local_did()`` creates a local DID from input optional seed, local DID, and metadata, and calls indy-sdk to create and store a corresponding local DID in the wallet; this process also creates an ed25519 verification key pair.

Fetching
...............

Method ``get_local_dids()`` returns a list with a ``DIDInfo`` (:ref:`did-info`) object corresponding to every local DID in the wallet. Method ``get_local_did()`` takes a DID or verification key and returns a ``DIDInfo`` for the corresponding local DID, raising ``AbsentRecord`` if none exists.

Replacing Metadata
..................

Method ``replace_local_did_metadata()`` takes a local DID and metadata. Its operation sets the input metadata for the local DID, raising ``AbsentRecord`` if none exists.

Pairwise DID Operations
-----------------------

This section discusses pairwise DID operations within the wallet. The implementation uses the ``Wallet`` class's native non-secrets methods, which delegate to the indy-sdk non_secret storage API to manage pairwise DIDs.

Writing
...............

Method ``write_pairwise()`` takes:

* a remote DID
* an optional remote verification key (operation replaces default value from existing pairwise record by remote DID or raises ``AbsentRecord``)
* an optional local DID
* an optional metadata for the pairwise relation
* an optional flag to replace, rather than (default) augment and overwrite, any existing metadata for the pairwise relation.

Its operation retrieves a local ``DIDInfo`` (:ref:`did-info`) and verification key corresponding to the input local DID, or creates a new one if the caller does not specify such. It assembles the remote and local DIDs and verification keys into a ``PairwiseInfo`` (:ref:`pairwise-info`), plus metadata passed in to replace or augment and overwrite any existing such metadata as the flag directs. The operation canonicalizes metadata to indy-sdk ``non_secrets`` API tags (marking them for unencrypted storage as per :ref:`canon-util`) and adds remote and local DIDs and verification keys, enabling WQL search. Finally, the operation creates a ``StorageRecord`` object from the ``PairwiseInfo`` and delegates to the ``write_non_secret()`` method to write the content to the wallet.

Fetching
...............

The ``get_pairwise()`` method takes a remote DID or WQL json query (default None, which canonicalizes to a query to get all pairwise relations). Its operation uses the wallet's ``get_non_secret()`` method to fetch all matching non-secret storage records of the pairwise type, and returns a dict mapping remote DIDs to corresponding ``PairwiseInfo`` instances, or an empty dict for no match.

Deleting
...............

The ``delete_pairwise()`` method takes a remote DID and delegates to ``delete_non_secret()`` to remove its corresponding pairwise relation, if present. If absent, it logs at level ``INFO`` and carries on.

Cryptographic Operations
++++++++++++++++++++++++++++

The ``encrypt()`` method takes a message, a recipient verification key (default value of current verification key for anchor DID), and whether to use authenticated encryption for proof of origin. Its operation delegates to indy-sdk to encrypt the message and return the ciphertext as a byte string.

The ``decrypt()`` method takes ciphertext and a verification key (default value of ``None`` for unauthenticated decryption). It delegates to indy-sdk to decrypt the message and, given a verification key, authenticate against it for proof of origin. It returns the plaintext payload as a byte string.

The ``sign()`` method takes a message and a verification key (default value of current verification key for anchor DID). It delegates to indy-sdk to sign the message and returns the signature as a byte string.

The ``verify()`` method takes a message and putative signature plus a verification key (default value of current verification key for anchor DID). It delegates to indy-sdk to verify the signature and returns ``True`` or ``False`` to indicate the goodness of the signature.

The ``pack()`` method takes a message, recipient verification key or keys (default value of current verification key for anchor DID), and sender verification key (default ``None`` for anonymous encryption). Its operation delegates to the indy-sdk to pack a JWE of https://tools.ietf.org/html/rfc7516, which it returns.

The ``unpack()`` method takes JWE ciphertext and delegates to indy-sdk to unpack it. It returns a triple with the message, the sender verification key, and the recipient verification key (``None`` for anonymous encryption).

Supporting Info Classes
###################################

The ``von_anchor/wallet`` subpackage holds several classes for wallet records and pairwise relation abstractions.

.. _storage-record:

StorageRecord
+++++++++++++++++++++++++++++++++++

The ``von_anchor/wallet/record.py`` source file houses the ``StorageRecord`` class to represent general non-secret storage records for use with wallets.

Its initializer takes a type, identifier, value, and a tags dict. Non-secret tags, where present, must be a flat dict mapping strings to strings. Keys in the tags dict starting with a tilde (``~``) correspond to values to store in the clear in the wallet; otherwise, the indy-sdk implementation stores such values encrypted. Where tags are encrypted, indy-sdk supports only a limited subset of WQL search (equality and inequality) as per https://github.com/hyperledger/indy-sdk/tree/master/docs/design/011-wallet-query-language.

The static ``ok_tags()`` method validates the fitness of tags for use with non-secret storage records. The class operation calls this method where possible, but note that a perverse operator can hot-swap invalid tags onto a ``StorageRecord`` object.

The ``type`` and ``id`` properties are read-only once set. The ``value`` and ``tags`` properties are read-write. The ``clear_tags`` and ``encr_tags`` conveniences act as read-only properties to return clear and encrypted tags respectively, as demarcated with a leading tilde (or not).

.. _storage-record-search:

StorageRecordSearch
+++++++++++++++++++++++++++++++++++

The ``von_anchor/wallet/search.py`` source file houses the ``StorageRecordSearch`` class to broker an interactive batch-wise indy-sdk wallet search over non-secret storage records.

Its initializer takes a wallet, a non-secret storage record type marking records to search, and a WQL query to invoke. On storage, the initializer canonicalizes the query, stringifying any numeric content (recall however that WQL operators are lexicographical, not numeric; e.g., WQL '9' > '10').

The class provides an access to return whether the search is open or not, plus context manager and monolithic openers and closers for the search.

Finally, the ``fetch()`` method returns the next batch of results in the search, with an optional limit on their number (default is ``Wallet.DEFAULT_CHUNK``, currently 256).

.. _key-info:

KeyInfo
+++++++++++++++++++++++++++++++++++

The ``KeyInfo`` named tuple of file ``info.py`` bundles information for a key (pair) in a wallet. It aggregates a verification key and metadata.

.. _did-info:

DIDInfo
+++++++++++++++++++++++++++++++++++

The ``DIDInfo`` class of file ``info.py`` bundles information for a local DID in a wallet. It aggregates a DID, verification key, and metadata.

.. _pairwise-info:

PairwiseInfo
+++++++++++++++++++++++++++++++++++

The ``info.py`` file holds class ``PairwiseInfo`` and utilities.

The ``PairwiseInfo`` class bundles information for a pairwise DID to store via the indy-sdk ``non_secret`` API in the wallet. It aggregates a remote DID and verification key, a local DID and verification key, and metadata. VON Anchor operation intermediates to direct indy-sdk to store such metadata unencrypted, canonicalizing tags accordingly as per :ref:`canon-util`, to maximize WQL search capacity.

The ``storage_record2pairwise_info()`` free function creates a ``PairwiseInfo`` instance from a ``StorageRecord`` that a ``non_secret`` API search returns.

The ``pairwise_info2tags()`` free function takes a ``PairwiseInfo`` instance and maps its metadata to non-secret storage record tags, canonicalized for unencrypted storage to enable full WQL queries.

.. _endpoint-info:

EndpointInfo
+++++++++++++++++++++++++++++++++++

The ``von_anchor/wallet/endpointinfo.py`` source file contains the ``EndpointInfo`` class, which bundles information for a remote DID endpoint. It aggregates an endpoint and a (transport) verification key. It exposes ``ip_addr``, ``port``, ``endpoint``, and ``verkey`` properties; an indy endpoint comprises colon-delimited IP address and port.
