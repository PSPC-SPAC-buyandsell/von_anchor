******************************
Operations
******************************

The ``von_anchor/op`` subpackage includes callable python scripts for low-level users of ``von_anchor``. At present, it includes ``setnym.py``, useful for nominal anchors implementing the VON Tails server and its clients for synchronization and administration.

setnym.py
==============================

The ``setnym.py`` script directs a trustee anchor (:ref:`demo-anchors`) to send an anchor's cryptonym to the ledger, if the ledger does not yet have one as configured. The trustee anchor must already be anchored to the ledger, either by genesis transactions or by subsequent registration. The operator must have the trustee anchor's seed or wallet access credentials, as the configuration file (:ref:`setnym-config`) specifies, so that trustee anchor may write the cryptonym.

From the shell, the script returns 0 for OK or 1 for an exception. It outputs any exception particulars it encounters to stdout; stderr is reserved errors that the indy-sdk toolkit produces.

Its invocation takes a configuration file as an argument; the section below outlines its content.

.. _setnym-config:

Configuration
------------------------------

This section outlines the content of the configuration file for the ``setnym.py`` script.

Section [Node Pool]
******************************

This section configures the node pool to which the operation applies. It contains:

* ``name``: the name of the node pool to which the operation applies
* ``genesis.txn.path``: the path to the genesis transaction file for the node pool (may omit if node pool already exists).

Section [Trustee Anchor]
******************************

This section configures the trustee anchor calling to send the cryptonym to the ledger. It contains:

* ``seed``: the trustee anchor's seed (omit if its wallet already exists)
* ``name``: the trustee anchor's name (wallet id)
* ``wallet.type``: (default blank) the trustee anchor's wallet type
* ``wallet.access``: (default blank) the trustee anchor's wallet access credential (password) value.

Section [VON Anchor]
******************************

This section configures the anchor under registration to the ledger. It contains:

* ``role``: the role to request in the send-nym transaction (default empty value for self-sovereign user with no additional write privileges)
* ``name``: the VON anchor's name (wallet id)
* ``seed``: the VON anchor's seed (omit if its wallet exists)
* ``wallet.create``: specify True to create the wallet if it does not exist
* ``wallet.type``: (default blank) the VON anchor's wallet type
* ``wallet.access``: (default blank) the VON anchor's wallet access credential (password) value.

The ``role`` value should be:

* empty value for a self-sovereign user with no additional write privileges
* ``TRUST_ANCHOR`` for a descendant of ``Origin``, ``Issuer``, ``HolderProver`` (e.g., ``OrgBookHub``, ``SRIAnchor``)
* ``TRUSTEE`` for a descendant of ``AnchorSmith`` (e.g., ``TrusteeAnchor``).
