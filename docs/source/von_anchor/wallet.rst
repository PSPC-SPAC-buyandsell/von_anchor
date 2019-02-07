***********************
Wallet
***********************

The Wallet class encapsulates the indy-sdk wallet. It resides in ``von_anchor/wallet.py``.

Initialization
==============

The initializer takes:

* the wallet name,
* a storage type (default ``None``),
* an optional configuration dict supporting:

    - the ``auto_remove`` key (set its value ``True`` to instruct the wallet implementation to delete serialized indy-sdk configuration data on exit),
    - any further properties to pass through to the indy-sdk for its own wallet configuration; and
    - an optional access credentials dict.

Its operation stores input parameters or sensible defaults, in waiting for further calls to create the wallet in storage or to open it for indy-sdk operations.

Accessors
=========

The class exposes accessors for the wallet name, indy-sdk handle, configuration, auto-remove status, access credentials, storage type, anchor DID, and verkey.

.. _wallet-create:

Creation
========

The ``create()`` call takes a 32-character seed. Its operation creates the wallet in storage, then to derive and store the anchor DID (see :ref:`did-management`) from its seed. When creating a new DID from seed for its user, the implementation writes the effective epoch time, and an anchor DID marker to metadata. If a wallet already exists on the ``Wallet`` object's name, the operation raises an ``ExtantWallet`` exception.

Context Management
==================

The context manager methods set up and tear down the wallet within the indy-sdk. On opening, the indy-sdk returns a wallet handle, which the the ``Wallet`` object retains for future indy-sdk interaction. On closing, the  instance directs the indy-sdk to invalidate the handle and to delete the wallet from persistent storage (if so configured).

.. _wallet-reseed:

Key Rotation
============

The ``reseed_init()`` and ``reseed_apply()`` methods perform key rotation. The anchor that owns the wallet calls these methods via its ``reseed()`` method to realize the operation, generating new keys from a new seed, as per :ref:`base-anchor`.

Deletion
========

The ``remove()`` method removes the wallet from persistent storage if it exists.

.. _did-management:

DID Management
=================

The design identifies several kinds of DIDs.

An **anchor DID** is a DID in current or past use for the VON anchor using the wallet, in transacting with the node pool implementing the distributed ledger. The current anchor DID is in its cryptonym on the ledger, and in its wallet with the corresponding private key.

A **local DID** is a DID in use for communication between an agent using the current wallet (typically, via a VON anchor) and another agent. A local DID forms part of a pairwise DID. The wallet implementation uses ``DIDInfo`` objects (see :ref:`did-info`) to associate local DIDs with their verification keys and metadata.

A **pairwise DID** groups a DID and verification key from both local ('my') and remote ('their') sides of an agent-to-agent ('pairwise') relation. The wallet implementation uses ``PairwiseInfo`` objects (see :ref:`pairwise-info`) to associate these data plus any metadata for the relation. The wallet's pairwise DID processing stores pairwise DIDs via the indy-sdk non-secrets API, allowing updates and searches on such records.

Anchor DID Operations
+++++++++++++++++++++

The ``create()`` method (:ref:`wallet-create`) creates the anchor DID from seed. The ``reseed_apply()`` method (:ref:`wallet-reseed``) creates a new anchor DID in its operation.

The ``get_anchor_did()`` method returns the current anchor DID.

Local DID Operations
++++++++++++++++++++

This section discusses local DID operations within the wallet. The implementation uses indy-sdk local DID storage API calls to manage local DIDs.

Writing
--------

Method ``create_local_did()`` creates a local DID from input optional seed, local DID, and metadata, and calls indy-sdk to create and store a corresponding local DID in the wallet; this process also creates an ed25519 verification key pair.

Fetching
--------

Method ``get_local_did_infos()`` returns a list with a ``DIDInfo`` (:ref:`did-info`) object corresponding to every local DID in the wallet. Method ``get_local_did_info()`` takes a DID or verification key and returns a ``DIDInfo`` for the corresponding local DID, raising ``AbsentRecord`` if none exists.

Pairwise DID Operations
+++++++++++++++++++++++

This section discusses pairwise DID operations within the wallet. The implementation uses indy-sdk the non-secrets storage API to manage pairwise DIDs.

Writing
-------

Method ``write_pairwise()`` takes:

* a remote DID
* a remote verification key
* an optional local DID
* an optional metadata for the pairwise relation
* an optional flag to replace, rather than (default) augment and overwrite, any existing metadata for the pairwise relation.

Its operation retrieves a local ``DIDInfo`` (:ref:`did-info`) and verification key corresponding to the input local DID, or creates a new one if the caller does not specify such. It assembles the remote and local DIDs and verification keys into a ``PairwiseInfo`` (:ref:`pairwise-info`), plus metadata passed in to replace or augment and overwrite any existing such metadata as the flag directs. The operation canonicalizes metadata to indy-sdk ``non_secrets`` API tags (prepending `~` if not present to mark their attributes for non-encrypted storage) and adds remote and local DIDs and verification keys, enabling WQL search.

Fetching
--------

The ``get_pairwise()`` method takes a remote DID or WQL json query (default None, which canonicalizes to get-all). Its operation fetches all matching pairwise DID relations and returns a dict mapping remote DIDs to corresponding ``PairwiseInfo`` instances, or an empty dict for no match.

Deleting
--------

The ``delete_pairwise()`` method takes a remote DID and removes its corresponding pairwise relation, if present. If absent, it logs at level ``INFO`` and carries on.

Cryptographic Operations
=========================

The ``encrypt()`` method takes a message, a recipient verification key (default value of current verification key for anchor DID), and whether to use authenticated encryption for proof of origin. Its operation delegates to indy-sdk to encrypt the message and return the ciphertext as a byte string.

The ``decrypt()`` method takes ciphertext and a verification key (default value of ``None`` for unauthenticated decryption). It delegates to indy-sdk to decrypt the message and, given a verification key, authenticate against it for proof of origin. It returns the plaintext payload as a byte string.

The ``sign()`` method takes a message and a verification key (default value of current verification key for anchor DID). It delegates to indy-sdk to sign the message and returns the signature as a byte string.

The ``verify()`` method takes a message and putative signature plus a verification key (default value of current verification key for anchor DID). It delegates to indy-sdk to verify the signature and returns ``True`` or ``False`` to indicate the goodness of the signature.

The ``pack()`` method takes a message, recipient verification key or keys (default value of current verification key for anchor DID), and sender verification key (default ``None`` for anonymous encryption). Its operation delegates to the indy-sdk to pack a JWE of https://tools.ietf.org/html/rfc7516, which it returns.

The ``unpack()`` method takes JWE ciphertext and delegates to indy-sdk to unpack it. It returns a triple with the message, the recipient verification key, and the sender verification key (``None`` for anonymous encryption).

Storage Type Registration
=========================

The free function ``register_wallet_storage_library()`` in ``von_anchor/wallet.py`` registers a wallet storage plug-in with the indy-sdk.

