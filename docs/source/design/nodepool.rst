***********************
Node Pool
***********************

The ``NodePool`` class encapsulates the indy-sdk node pool. It resides in ``von_anchor/nodepool.py``.

Initialization
==============

Its initializer stores a pool name for use with indy-sdk and the path to a file with a (copy of the) genesis transactions, which it stores to create the pool if one does not yet exist on the input pool name. It takes an optional configuration dict supporting the ``auto-remove`` and ``protocol`` keys. An ``auto-remove`` value of True to instructs the node pool implementation to delete serialized indy-sdk configuration data on exit. The ``protocol`` value overrides the default (latest) indy-node protocol version to use.

Context Management
==================

The context management methods set up and tear down the pool within the indy-sdk.

Creation and Opening
++++++++++++++++++++

On opening, if there is no pool yet created on its name, the operation uses the configured genesis transaction file to create its control files; the call opens the pool in indy-sdk and retains the corresponding handle in the object for future indy-sdk interaction.

Note that if the object has a genesis transaction path (typically, via initialization parameter) but indy-sdk control files already exist for a pool on the object's name, the opener ignores the specified genesis transaction path and adopts the existing pool. If there is no such pool already, but the genesis transaction path does not correspond to an actual file on disk, the opener raises ``AbsentGenesis``.

Closing and Teardown
++++++++++++++++++++

On closing, the instance directs the indy-sdk to invalidate the indy-sdk handle and delete its control files (if so configured). The class exposes an explicit ``remove()`` method to remove a node pool's indy-sdk control files manually.

***********************
Protocol
***********************

The ``Protocol`` enumeration encapsulates all differences in indy-node protocol messages. It resides in ``von_anchor/nodepool.py``.

At present, it accommodates node protocol versions 1 and 2, corresponding to indy-node releases 1.3 and 1.4 (or higher) respectively. The indy-node release versions track the indy-sdk toolkit versions but not all releases augment the indy-node protocol; a ``ProtocolMap`` named tuple manages this association as it evolves.

Currently, indy-node protocols differ for VON anchor use in:

* credential definition identifiers and their tags (credential definition identifier tags are new for protocol version 2)
* ledger transaction format details encoding schema keys, transaction times, and metadata.
