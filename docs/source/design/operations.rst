******************************
Operations
******************************

The ``von_anchor/op`` subpackage includes callable python scripts for low-level users of ``von_anchor``. At present, it includes only ``sendnym.py``, useful for nominal anchors implementing the VON Tails server and its clients for synchronization and administration.

sendnym.py
==============================

The ``sendnym.py`` script directs a trustee anchor (:ref:`rrbx`) to send an anchor's cryptonym to the ledger. The trustee anchor must already be anchored to the ledger, either by genesis transactions or by subsequent registration. The user must have access credentials to operate the trustee anchor.

From the shell, the script returns 0 for OK or 1 for an exception. It outputs any exception particulars to stderr.

Its invocation takes a configuration file as an argument; the section below outlines its content.

Configuration
------------------------------

This section outlines the content of the configuration file for the ``sendnym.py`` script.

Section [Node Pool]
******************************

This section configures the node pool to which the operation applies. It contains:

* ``name``: the name of the node pool to which the operation applies
* ``genesis.txn.path``: the path to the genesis transaction file for the node pool.

Section [Trustee Anchor]
******************************

This section configures the trustee anchor calling to send the cryptonym to the ledger. It contains:

* ``seed``: the trustee anchor's seed 
* ``wallet.name``: the trustee anchor's wallet name
* ``wallet.type``: (default blank) the trustee anchor's wallet type
* ``wallet.key``: (default blank) the trustee anchor's wallet access credential value.

Section [New Anchor]
******************************

This section configures the anchor under registration to the ledger. It contains:

* ``role``: the role to request in the send-nym transaction.
* ``seed``: the new anchor's seed 
* ``wallet.name``: the new anchor's wallet name
* ``wallet.type``: (default blank) the new anchor's wallet type
* ``wallet.key``: (default blank) the new anchor's wallet access credential value.
