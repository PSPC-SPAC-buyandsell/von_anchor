***********************
Node Pool
***********************

The ``NodePool`` subpackage encapsulates the indy-sdk node pool manager, node pools, and node protocols. It resides in ``von_anchor/nodepool``.


Protocol
=================

The ``Protocol`` enumeration encapsulates all differences in indy-node protocol messages. It resides in ``von_anchor/nodepool/protocol.py``.

At present, it accommodates node protocol versions 1 and 2, corresponding to indy-node releases 1.3 and 1.4 (or higher) respectively. The indy-node release versions track the indy-sdk toolkit versions but not all releases augment the indy-node protocol; a ``ProtocolMap`` named tuple manages this association as it evolves.

Currently, indy-node protocols differ for VON anchor use in:

* credential definition identifiers and their tags (credential definition identifier tags are new for protocol version 2)
* ledger transaction format details encoding schema keys, transaction times, and metadata.

Node Pool Manager
=================

The node pool manager class adds and removes ledger configurations for node pools by name and genesis transaction data, lists node pools available by name, and returns node pools by name for client use. It resides in ``von_anchor/nodepool/manager.py``.

Initialization
++++++++++++++

The initializer takes a node protocol enum, which it stores and makes available as a read/write property.

The ``add_config()`` method takes a pool name and either raw genesis transaction data or a path to a genesis transaction file. If the named pool does not yet have a ledger configuration, it adds it, making it available. Othewise, it raises ``ExtantPool``.

The ``list()`` method lists all available node pool names.

The ``get()`` method creates a ``NodePool`` object on the given pool name. It is acceptable to create the node pool's ledger configuration any time before the actuator opens the node pool.

The ``remove()`` method deletes the ledger configuration for the named pool, making it unavailable.

Node Pool
=================

The node pool class encapsulates the indy node pool. It retains its node protocol, pool name, indy-sdk handle, and configuration.

Initialization
++++++++++++++++++

The initializer stores a pool name and an optional protocol (default most recent) and indy-sdk configuration dict. 

Context Management
++++++++++++++++++

The context management methods (``open()``, ``close()``, ``__aenter()``, ``__aexit()__``) open and close the node pool.

Refresh
++++++++++++++++++

The ``refresh()`` method refreshes indy node pool connections.
