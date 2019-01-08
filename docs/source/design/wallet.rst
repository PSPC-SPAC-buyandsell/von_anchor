***********************
Wallet
***********************

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

