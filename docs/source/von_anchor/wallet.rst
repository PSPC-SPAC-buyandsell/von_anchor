***********************
Wallet
***********************

The Wallet subpackage encapsulates the indy-sdk wallet and abstractions useful for its records. It resides in ``von_anchor/wallet/``.

VON Anchor Wallet
#######################

The VON Anchor wallet provides functionality for VON anchors to use indy-sdk wallets to manage keyed and non-secret records. It resides in ``von_anchor/wallet/wallet.py``.

Initialization
++++++++++++++++++

The initializer takes:

* the wallet name,
* a storage type (default ``None``),
* an optional configuration dict supporting:

    - the ``auto_remove`` key (set its value ``True`` to instruct the wallet implementation to delete serialized indy-sdk configuration data on exit),
    - any further properties to pass through to the indy-sdk for its own wallet configuration; and
    - an optional access credentials dict.

Its operation stores input parameters or sensible defaults, in waiting for further calls to create the wallet in storage or to open it for indy-sdk operations.

Accessors
++++++++++++++++++

The class exposes accessors for the wallet name, indy-sdk handle, configuration, auto-remove status, access credentials, storage type, anchor DID, and verkey.

.. _wallet-create:

Creation
++++++++++++++++++

The ``create()`` call takes a 32-character seed. Its operation creates the wallet in storage, then to derive and store the anchor DID (see :ref:`did-management`) from its seed. When creating a new DID from seed for its user, the implementation writes the effective epoch time, and an anchor DID marker to metadata. If a wallet already exists on the ``Wallet`` object's name, the operation raises an ``ExtantWallet`` exception.

Context Management
++++++++++++++++++

The context manager methods set up and tear down the wallet within the indy-sdk. On opening, the indy-sdk returns a wallet handle, which the the ``Wallet`` object retains for future indy-sdk interaction. On closing, the  instance directs the indy-sdk to invalidate the handle and to delete the wallet from persistent storage (if so configured).

.. _wallet-reseed:

Key Rotation
++++++++++++++++++

The ``reseed_init()`` and ``reseed_apply()`` methods perform key rotation. The anchor that owns the wallet calls these methods via its ``reseed()`` method to realize the operation, generating new keys from a new seed, as per :ref:`base-anchor`.

Deletion
++++++++++++++++++

The ``remove()`` method removes the wallet from persistent storage if it exists.

.. _did-management:

Non-Secret Record Operations
----------------------------

This section discusses operations within the wallet for non-secret record management. The implementation delegates to the indy-sdk non-secrets storage API to manage pairwise DIDs.

Writing
...............

Method ``write_non_secrets()`` takes:

* a ``NonSecret`` object as per :ref:`non-secret`
* an optional flag to replace, rather than (default) augment and overwrite, any existing metadata for an existing non-secret record (by non-secret type and identifier).

Its operation checks input metdata tags and delegates to indy-sdk non-secrets API calls to write or update content according to input parameters. It returns the non-secret record as the wallet has added or updated it.

Fetching
...............

The ``get_non_secret()`` method takes a non-secret record type, a filter, and a canonicalization function (defaulting to ``canon_non_secret_wql()`` as per :ref:`canon-util`. If the filter is a string, it uses it as an identifier with the record type to perform a straightforward lookup via the indy-sdk non-secrets API. Otherwise, the operation interprets the filter as WQL (default None, which canonicalizes to a query to get all on input record type). The processing uses the input canonicalization function to canonicalize the query, then delegates to indy-sdk to fetch all matching records. Finally the method returns a dict mapping identifiers to corresponding ``NonSecrets`` instances, or an empty dict for no match.

Deleting
...............

The ``delete_non_secret()`` method takes a non-secret record type identifier, which uniquely identifies a non-secret record in the wallet, and removes it if present. If absent, it logs at level ``INFO`` and carries on.

DID Management
++++++++++++++++++

The design identifies several kinds of DIDs.

An **anchor DID** is a DID in current or past use for the VON anchor using the wallet, in transacting with the node pool implementing the distributed ledger. The current anchor DID is in its cryptonym on the ledger, and in its wallet with the corresponding private key.

A **local DID** is a DID in use for communication between an agent using the current wallet (typically, via a VON anchor) and another agent. A local DID forms part of a pairwise DID. The wallet implementation uses ``DIDInfo`` objects (see :ref:`did-info`) to associate local DIDs with their verification keys and metadata.

A **pairwise DID** groups a DID and verification key from both local ('my') and remote ('their') sides of an agent-to-agent ('pairwise') relation. The wallet implementation uses ``PairwiseInfo`` objects (see :ref:`pairwise-info`) to associate these data plus any metadata for the relation. The wallet's pairwise DID processing stores pairwise DIDs via the indy-sdk non-secrets API, allowing updates and searches on such records.

Anchor DID Operations
---------------------

The ``create()`` method (:ref:`wallet-create`) creates the anchor DID from seed. The ``reseed_apply()`` method (:ref:`wallet-reseed`) creates a new anchor DID in its operation.

The ``get_anchor_did()`` method returns the current anchor DID.

Local DID Operations
---------------------

This section discusses local DID operations within the wallet. The implementation uses indy-sdk local DID storage API calls to manage local DIDs.

Writing
...............

Method ``create_local_did()`` creates a local DID from input optional seed, local DID, and metadata, and calls indy-sdk to create and store a corresponding local DID in the wallet; this process also creates an ed25519 verification key pair.

Fetching
...............

Method ``get_local_did_infos()`` returns a list with a ``DIDInfo`` (:ref:`did-info`) object corresponding to every local DID in the wallet. Method ``get_local_did_info()`` takes a DID or verification key and returns a ``DIDInfo`` for the corresponding local DID, raising ``AbsentRecord`` if none exists.

Pairwise DID Operations
-----------------------

This section discusses pairwise DID operations within the wallet. The implementation uses the ``Wallet`` class's native non-secrets methods, which delegate to the indy-sdk non-secrets storage API to manage pairwise DIDs.

Writing
...............

Method ``write_pairwise()`` takes:

* a remote DID
* a remote verification key
* an optional local DID
* an optional metadata for the pairwise relation
* an optional flag to replace, rather than (default) augment and overwrite, any existing metadata for the pairwise relation.

Its operation retrieves a local ``DIDInfo`` (:ref:`did-info`) and verification key corresponding to the input local DID, or creates a new one if the caller does not specify such. It assembles the remote and local DIDs and verification keys into a ``PairwiseInfo`` (:ref:`pairwise-info`), plus metadata passed in to replace or augment and overwrite any existing such metadata as the flag directs. The operation canonicalizes metadata to indy-sdk ``non_secrets`` API tags (marking them for unencrypted storage as per :ref:`canon-util`) and adds remote and local DIDs and verification keys, enabling WQL search. Finally, the operation creates a ``NonSecret`` object from the ``PairwiseInfo`` and delegates to the ``write_non_secret()`` method to write the content to the wallet.

Fetching
...............

The ``get_pairwise()`` method takes a remote DID or WQL json query (default None, which canonicalizes to a query to get all pairwise relations). Its operation uses the wallet's ``get_non_secret()`` method to fetch all matching non-secret records of the pairwise type, and returns a dict mapping remote DIDs to corresponding ``PairwiseInfo`` instances, or an empty dict for no match.

Deleting
...............

The ``delete_pairwise()`` method takes a remote DID and delegates to ``delete_non_secret()`` to remove its corresponding pairwise relation, if present. If absent, it logs at level ``INFO`` and carries on.

Cryptographic Operations
+++++++++++++++++++++++++

The ``encrypt()`` method takes a message, a recipient verification key (default value of current verification key for anchor DID), and whether to use authenticated encryption for proof of origin. Its operation delegates to indy-sdk to encrypt the message and return the ciphertext as a byte string.

The ``decrypt()`` method takes ciphertext and a verification key (default value of ``None`` for unauthenticated decryption). It delegates to indy-sdk to decrypt the message and, given a verification key, authenticate against it for proof of origin. It returns the plaintext payload as a byte string.

The ``sign()`` method takes a message and a verification key (default value of current verification key for anchor DID). It delegates to indy-sdk to sign the message and returns the signature as a byte string.

The ``verify()`` method takes a message and putative signature plus a verification key (default value of current verification key for anchor DID). It delegates to indy-sdk to verify the signature and returns ``True`` or ``False`` to indicate the goodness of the signature.

The ``pack()`` method takes a message, recipient verification key or keys (default value of current verification key for anchor DID), and sender verification key (default ``None`` for anonymous encryption). Its operation delegates to the indy-sdk to pack a JWE of https://tools.ietf.org/html/rfc7516, which it returns.

The ``unpack()`` method takes JWE ciphertext and delegates to indy-sdk to unpack it. It returns a triple with the message, the recipient verification key, and the sender verification key (``None`` for anonymous encryption).

Storage Type Registration
+++++++++++++++++++++++++

The free function ``register_wallet_storage_library()`` in ``von_anchor/wallet.py`` registers a wallet storage plug-in with the indy-sdk.

Supporting Classes
###################################

The ``von_anchor/wallet`` subpackage holds several classes for wallet records and pairwise relation abstractions.

.. _did-info:

DIDInfo
+++++++++++++++++++++++++++++++++++

The ``von_anchor/wallet/didinfo.py`` source file contains the ``DIDInfo`` class, which bundles information for a local DID in a wallet. It aggregates a DID, verification key, and metadata.

.. _non-secret:

NonSecret
+++++++++++++++++++++++++++++++++++

The ``von_anchor/wallet/nonsecret.py`` source file houses the ``NonSecret`` class to represent general non-secret records for use with wallets.

Its initializer takes a type, identifier, value, and a tags dict. Non-secret tags, where present, must be a flat dict mapping strings to strings. Keys in the tags dict starting with a tilde (``~``) correspond to values to store in the clear in the wallet; otherwise, the indy-sdk implementation stores such values encrypted. Where tags are encrypted, indy-sdk supports only a limited subset of WQL search (equality and inequality) as per https://github.com/hyperledger/indy-sdk/tree/master/docs/design/011-wallet-query-language.

The static ``ok_tags()`` method validates the fitness of tags for use with non-secret records. The class operation calls this method where possible, but note that a perverse operator can hot-swap invalid tags onto a ``NonSecret`` object.

The ``type`` and ``id`` properties are read-only once set. The ``value`` and ``tags`` properties are read-write. The ``clear_tags`` and ``encr_tags`` conveniences act as read-only properties to return clear and encrypted tags respectively, as demarcated with a leading tilde (or not).

.. _pairwise-info:

PairwiseInfo
+++++++++++++++++++++++++++++++++++

Source file ``von_anchor/wallet/pairwise.py`` houses the ``PairwiseInfo`` class and the ``non_secret2pairwise_info()`` utility.

The ``PairwiseInfo`` class bundles information for a pairwise DID to store via the indy-sdk non-secrets API in the wallet. It aggregates a remote DID and verification key, a local DID and verification key, and metadata. VON Anchor operation intermediates to direct indy-sdk to store such metadata unencrypted, canonicalizing tags accordingly as per :ref:`canon-util`, to maximize WQL search capacity.

The ``non_secret2pairwise_info()`` free function creates a ``PairwiseInfo`` instance from a ``NonSecret`` that a non-secrets API search returns.

.. _endpoint-info:

EndpointInfo
+++++++++++++++++++++++++++++++++++

The ``von_anchor/wallet/endpointinfo.py`` source file contains the ``EndpointInfo`` class, which bundles information for a remote DID endpoint. It aggregates an endpoint and a (transport) verification key. It exposes ``ip_addr``, ``port``, ``endpoint``, and ``verkey`` properties; an indy endpoint comprises colon-delimited IP address and port.
