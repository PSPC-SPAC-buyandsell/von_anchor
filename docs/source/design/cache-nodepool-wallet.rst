*****************************************************
Caching, NodePools and Wallets
*****************************************************

Caching
=======

This section outlines the cache implementations for schemata, credential definitions, and revocation registries.

Schema Cache
###########################################

The von_anchor package defines singletons for caching schemata, claim definitions, and revocation registries in ``von_anchor/cache.py``. The singleton construction allows all anchors running in a process to share the caches; for example, if an issuer anchor sends a credential definition to its cache, then a holder-prover in the same process may use the cache to get it without going to the ledger. Each class has a (re-entrant) lock to manage access.

The ``SchemaCache`` class allows for storage and retrieval by sequence number, by schema identifier, or by ``SchemaKey`` instance, reducing network chat with the distributed ledger.

The ``schemata()`` method lists all schemata in the instance.

The ``feed()`` method takes a list of schemata to add to the cache. If a schema on an incoming sequence number is already in the cache, the operation logs a warning and demurs: it is not possible for an archived schema to represent an update on one already in the live cache.

The ``clear()`` method clears the cache.

Credential Definition Cache
###########################################

The ``CredDefCache`` derives from simple ``dict`` and offers a class-wide (re-entrant) lock. It indexes credential definition data by credential definition identifier, reducing network chat with the distributed ledger.

All anchors share a common credential definition cache; hence, any anchor in the process benefits from any other anchor's contribution.

Revocation Cache
###########################################

The ``RevoCache`` derives from simple ``dict`` and offers a class-wide (re-entrant) lock. It indexes definitions, associated Tails instances, and update frames (on deltas and states) for revocation registries, reducing network chat with the distributed ledger and open file handles (recall that indy-sdk does not allow for the closing of a tails file reader at present).

The revocation cache additionally offers the ``dflt_interval()`` instance method, computing a default non-revocation interval by credential definition identifier on the current content of the revocation cache. This interval is the latest interval touching all revocation registries against the input credential definition identifier; the following figure illustrates.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/default-interval.png
    :align: center
    :alt: Revocation Cache Default Interval Computation per Credential Definition Identifier
 
All anchors share a common credential definition cache; hence, any anchor in the process benefits from any other anchor's contribution.

Caches Utility Class
###########################################

The Caches class collects static methods to operate on all caches in unison, primarily for archival and parsing to inform off-line, cache-only operations. Note that all anchors share all caches, and so the anchor that invokes these methods should be the only one in the process.

The ``clear()`` method clears all caches.

The ``archive()`` method writes a cache archive to a subdirectory, named for the current timestamp in epoch seconds, of an input base directory.

The ``parse()`` method takes a base directory and timestamp (defaulting to the most current subdirectory name); its operation feeds the caches with the content in the archived files in that subdirectory. Note that since the distributed ledger only augments and never removes content, it is not possible for a cache archive to update a live cache if the cache has content for the same item: in this case, the operation logs a warning and demurs.

The ``purge_archives()`` method deletes old archived cache files, optionally preserving the most recent.

Node Pool
=======================

The ``NodePool`` class encapsulates the indy-sdk node pool. It resides in ``von_anchor/nodepool.py``.

Its initializer stores a pool name for use with indy-sdk and the path to a file with a (copy of the) genesis transactions. It takes an optional configuration dict supporting the ``auto-remove`` and ``protocol`` keys. An ``auto-remove`` value of True to instructs the node pool implementation to delete serialized indy-sdk configuration data on exit. The ``protocol`` value overrides the default (latest) indy-node protocol version to use.

The context manager methods set up and tear down the pool within the indy-sdk. On opening, the indy-sdk creates control files on the pool name in directory ``$HOME/.indy_client/pool/`` and returns a pool handle, which the ``NodePool`` object retains for future indy-sdk interaction. On closing, the instance directs the indy-sdk to invalidate the handle and delete its control files (if so configured).

The ``Protocol`` enumeration encapsulates all differences in indy-node protocol messages.

Wallet
=======================

The Wallet class encapsulates the indy-sdk wallet. It resides in ``von_anchor/wallet.py``.

Its initializer takes:

- a cryptographic seed,
- the wallet name,
- a storage type (default ``None``),
- an optional configuration dict supporting:
    - the ``auto_remove`` key (set its value ``True`` to instruct the wallet implementation to delete serialized indy-sdk configuration data on exit),
    - any further properties to pass through to the indy-sdk for its own wallet configuration; and
- an optional access credentials dict.

A distinct asynchronous ``create()`` call prompts the wallet object to bootstrap the wallet as an object in the underlying indy-sdk (if it does not yet exist, serialized per its wallet type). When creating a new DID from seed for its user, the implementation writes the seed's (SHA-256) hash to metadata.

The context manager methods set up and tear down the wallet within the indy-sdk. On opening, the indy-sdk opens its control files (per its wallet type) and returns a wallet handle, which the the ``Wallet`` object retains for future indy-sdk interaction. On closing, the  instance directs the indy-sdk to invalidate the handle and delete its control files (if so configured).

An internal ``_seed2did()`` utility retrieves the DID from a matching seed (by hash value) in metadata. The ``open()`` and ``__aenter__()`` context manager methods, as well as the ``create()`` method when the wallet already exists, use this utility to get the DID without overwriting it in the wallet, then to populate the verification key from this DID. Abstaining from overwriting the DID on every open allows for support of key update.

The ``reseed_init()`` and ``reseed_apply()`` methods perform key rotation. The anchor that owns the wallet calls these methods to realize the operation as per :ref:`base-anchor`.

Finally, the free function ``register_wallet_storage_library()`` in ``von_anchor/wallet.py`` registers a wallet storage plug-in with the indy-sdk.

