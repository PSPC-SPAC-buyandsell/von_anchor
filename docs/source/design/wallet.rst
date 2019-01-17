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

Creation
========

The ``create()`` call takes a 32-character seed. Its operation creates the wallet in storage, then to derive and store the anchor's DID from its seed. When creating a new DID from seed for its user, the implementation writes the seed's (SHA-256) hash and effective epoch time to metadata. If a wallet already exists on the ``Wallet`` object's name, the operation raises an ``ExtantWallet`` exception.

Context Management
==================

The context manager methods set up and tear down the wallet within the indy-sdk. On opening, the indy-sdk returns a wallet handle, which the the ``Wallet`` object retains for future indy-sdk interaction. On closing, the  instance directs the indy-sdk to invalidate the handle and to delete the wallet from persistent storage (if so configured).

Key Rotation
============

The ``reseed_init()`` and ``reseed_apply()`` methods perform key rotation. The anchor that owns the wallet calls these methods via its ``reseed()`` method to realize the operation, generating new keys from a new seed, as per :ref:`base-anchor`.

Deletion
========

The ``remove()`` method removes the wallet from persistent storage if it exists.

Storage Type Registration
=========================

The free function ``register_wallet_storage_library()`` in ``von_anchor/wallet.py`` registers a wallet storage plug-in with the indy-sdk.

