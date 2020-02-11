***********************
Node Pool
***********************

The ``NodePool`` class encapsulates the indy-sdk node pool. It resides in ``von_anchor/nodepool.py``.

Its initializer stores a pool name for use with indy-sdk and the path to a file with a (copy of the) genesis transactions. It takes an optional configuration dict supporting the ``auto-remove`` and ``protocol`` keys. An ``auto-remove`` value of True to instructs the node pool implementation to delete serialized indy-sdk configuration data on exit. The ``protocol`` value overrides the default (latest) indy-node protocol version to use.

The context manager methods set up and tear down the pool within the indy-sdk. On opening, the indy-sdk creates control files on the pool name in directory ``$HOME/.indy_client/pool/`` and returns a pool handle, which the ``NodePool`` object retains for future indy-sdk interaction. On closing, the instance directs the indy-sdk to invalidate the handle and delete its control files (if so configured).

The ``Protocol`` enumeration encapsulates all differences in indy-node protocol messages.
