******************************
Anchors
******************************

This section outlines the design of the classes implementing anchor functionality. Anchor source code resides in ``von_anchor/anchor/``. Anchors of use principally for the demonstration in scope reside in file  ``von_anchor/anchor/demo.py``.; the remainder of the source code implements purely indy-sdk concepts.

.. _base-anchor:

BaseAnchor
****************************************************

The ``BaseAnchor`` class implements essential functionality that defines an anchor: it holds references to a wallet and an optional node pool for use within indy-sdk. The code implements calls common to all anchors of all kinds.

Its property methods make an instance's pool and wallet available; convenience methods delegate to the wallet to make its DID and verification keys available.

Its context manager methods are placeholders for descendants to perform setup and teardown operations.

The class's ``_submit()`` and ``_sign_submit()`` methods encapsulate boilerplate to submit requests and return responses against the indy-sdk ledger. Both methods raise ``ClosedPool`` if operating off-line (holder-prover and verifier anchors off-line must operate entirely from caches) or ``BadLedgerTxn`` on a request that the indy-sdk cannot process; ``_sign_submit()`` raises ``CorruptWallet`` on a signed request that appears to use a wallet for node pool distinct from the anchor's current one.

The ``_verkey_for()`` method takes a DID and retrieves a corresponding verification key. It checks the wallet first, then the node pool if the anchor has one.

The ``reseed()`` method updates the private signing and public verification key in anchor's the wallet and its corresponding nym on the ledger as per the following illustration.

Its ``get_nym()`` method fetches and return the anchor's cryptonym from the distributed ledger via the indy-sdk.

Its ``get_nym_role()`` method fetches and return the anchor's role from its current cryptonym on the ledger, raising AbsentNym if not yet anchored on the ledger.

Its ``get_did_endpoint()`` and ``set_did_endpoint()`` methods manage endpoint and (transport) verification keys for pairwise remote DIDs. These methods use ``EndpointInfo`` instances as per :ref:`endpoint-info`. At present, indy-sdk does not define a practice to store pairwise remote DID on the ledger, but anticipates such a development shortly. As such, ``BaseAnchor`` stores remote DID information as metadata in pairwise relations via the indy-sdk ``non_secrets`` API in the wallet. Once indy defines a practice to write such data to the ledger, the implementation will adapt accordingly.

Its ``get_endpoint()`` method gets the endpoint attribute that the ledger associates with the identity on the input DID, or the current anchor's endpoint if the caller specifies no DID. The ``send_endpoint()`` method sends the input endpoint attribute value to the ledger to associate with the current anchor, if such is not already the case – the caller can specify a null to clear the anchor's endpoint attribute on the ledger.

Its ``get_rev_reg_def()`` method gets a revocation registry definition from the ledger. Typically the result comes from the revocation cache; if it goes to the ledger, the implementation populates the cache before returning.

Its (static) ``least_role()`` method returns the ``TRUST_ANCHOR`` role, sufficing for most subclasses.

Its ``get_schema()`` and ``get_cred_def()`` methods retrieve schema and credential definitions the ledger. Typically the result comes from its cache; if it goes to the ledger, the implementation populates the applicable cache before returning.

Its ``sign()`` and ``verify()`` methods delegate to indy-sdk to sign and verify content. The operation performs any required DID resolution to verification keys, then delegates to the wallet.

Its ``encrypt()`` and ``decrypt()`` methods delegate to indy-sdk to encrypt, anonymously or with (proof-of-origin) authentication, content for itself or another anchor owning an input DID or verification key. The operation performs any required DID resolution to verification keys, then delegates to the wallet.

The ``get_txn()`` method returns a distributed ledger transaction's content by sequence number.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/reseed.png
    :align: center
    :alt: Key Rotation Sequence

AnchorSmith
****************************************************

The ``AnchorSmith`` class exposes ``send_nym()`` to fulfill calls to send a cryptonym to the ledger.

Its (static) ``least_role()`` method returns the ``TRUSTEE`` role.

Origin
****************************************************

The ``Origin`` class exposes ``send_schema()`` to fulfill calls to send a schema to the ledger. First, its operation checks if the schema is present already; if so, it logs an error and returns it. Otherwise, it sends the schema to the ledger and adds it to the schema cache before returning it.

RevRegBuilder
****************************************************

The ``RevRegBuilder`` class builds revocation registries. Its purpose is to serve an ``Issuer`` instance, which aggregates and delegates to it.

Its initializer method sets up key tails directory locations and starts the revocation registry builder if necessary. The design admits two postures for a revocation registry builder: internal or external to its aggregating ``Issuer`` instance. Both configurations use ``RevRegBuilder`` methods to initialize and to build revocation registries, and ``RevRegBuilder`` utilities to return locations in the tails tree for issuer implementation.

Actuators need not call  ``_create_rev_reg()`` method; the issuer uses it internally as required to create new revocation registries and tails files, and to synchronize their associations.


Internal Revocation Registry Builder Posture
============================================

An internal revocation registry builder operates within the issuer anchor's process to build a new revocation registry when there is no revocation registry with space.

Specifying internal posture takes less time at initialization, but much more time to issue a credential when it requires a new revocation registry as it only builds them in-band when there is no such revocation registry with space available. Building revocation registries and their corresponding tails files is an expensive operation that blocks the entire indy-sdk for its process while it is underway.

The design recommends specifying internal posture only for issuer anchors known to use only credential definitions not supporting revocation.

.. _rrbx:

External Revocation Registry Builder Posture
============================================

An external revocation registry builder operates in a process separate and detached from its issuer anchor's process to build a new revocation registry on demand. All issuers on a wallet name share a common external revocation registry process, if their initializers specify external revocation registry posture.

Specifying external posture takes more time at initialization (to spawn a new process for the issuer anchor if one is not running), but less time to issue a credential when it requires a new revocation registry. When an issuer anchor uses an external revocation registry builder, it signals it to pre-generate one revocation registry ahead (in the tails hopper directory) and moves it into place on demand.

The design recommends specifying external posture for issuer anchors that may use credential definitions supporting revocation.

Within the initializer, an external revocation registry builder checks the state of the revocation registry process. If starting a new process, it first writes configuration data (logging directives and wallet configuration) to a file in the tails tree for the new process to pick up and delete nearly instantaneously. Wallet access credentials are sensitive; in this way the process obviates exposing them, in the clear, as a parameter in the operating system's process tree.

The external posture uses the RevRegBuilder methods ``_get_state()``, ``start_data_json()``, ``serve()``, ``stop()``, the (free) ``main()`` line, and the ``RevRegBuilder._State`` enum to manage the operation of the external process running the external revocation registry builder.

The ``_State`` enum encapsulates the operational state of an external revocation registry builder process: absent, running, or stopping (gracefully).

The ``serve()`` method writes the pid file to signal its running state, then runs the message loop for an external revocation registry builder to monitor its subdirectory within ``tails/.sentinel/`` to parse directions to create revocation registries and to stop gracefully.

The ``stop()`` method directs the message loop to stop, then waits for any revocation registry builds in progress to complete. The indy-sdk's aggressive removal of its temporary directory structure makes the waiting an essential part of the operation for the external revocation registry builder posture.

The free ``main()`` line picks up configuration parameters from its location in the tails tree and starts the new revocation registry builder process.

The figure illustrates the process of starting and stopping an external revocation registry builder for an issuer anchor.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/rrbx-proc.png
    :align: center
    :alt: External Revocation Registry Builder Start and Stop

.. _issuer:

Issuer
****************************************************

The ``Issuer`` class issues credential definitions, against which it issues credentials - an Issuer can also revoke any credential it issues.

Its initializer aggregates a ``RevRegBuilder`` instance, to which it delegates to build revocation registries.

The class has its own ``open()`` method to synchronize its tails tree content (revocation registry identifiers to tails files). Actuators need not call its ``_sync_revoc_for_issue()`` methods; ``Issuer`` uses them internally as required to synchronize tails file associations on startup.

Housekeeping Operations
===================================

This section outlines methods to open an issuer instance and query it for data.

Its ``open()`` method synchronizes its revocation registries, configuring reader handles in indy-sdk for opening when required and setting their Tails objects in the revocation cache if need be.

It exposes the ``path_tails()`` method to inform its service wrapper API of the path to a tails file for a given revocation registry identifier.

Its ``get_box_ids_json()`` method collects and returns box identifiers (schema identifiers, credential definition identifiers, and revocation registry identifiers) for all credential definitions and credentials that the issuer has issued. This operation can be useful for a verifier going off-line to seed its cache before doing so (potentially, via the emerging VON-X layer).

Credential Operations
===================================

This section outlines credential operations. The figure illustrates operations as they interact with an external revocation registry builder for fulfillment; further discussion follows.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/rrbx-op.png
    :align: center
    :alt: External Revocation Registry Builder Operation
 
Its ``send_cred_def()`` method attempts to create a credential definition, given a schema and boolean indicating revocation support, and to send it to the distributed ledger. The operation checks whether credential definition already exists on the ledger and in the wallet, and behaves as per the following:

- **Absent from Wallet and Ledger:** Create in wallet, send to distributed ledger
- **Present in Wallet and Ledger:** Log info (reuse existing cred def)
- **Present only in Wallet:** Create in wallet, log warning (private key operations not possible), and carry on: sometimes anchors have many roles and so public key operations may suffice for the session (e.g., forensic scenario)
- **Present only on Ledger:** Raise ``CorruptWallet``: anchor wallet does not correspond to anchor's node pool

On creating a new credential definition with revocation support, the process signals the revocation registry builder to create an initial (tiny) revocation registry, awaiting its completion before proceeding. Even if the call indicates revocation non-support, the operation creates a subdirectory for the credential definition identifier in the tails directory against future box identifier collection. Finally, the method synchronizes tails files against revocation registries; this call fires the next revocation registry build asynchronously against near-term need in the case of external revocation registry builder posture as per :ref:`rrbx`.

Its  ``create_cred_offer()`` method creates and returns a credential offer for a schema on a given sequence (transaction) number. Note that the schema sequence number is the last token in a credential definition identifier.

Its ``create_cred()`` method takes an indy-sdk credential offer structure, an indy-sdk credential request structure, and a dict of attribute names and values comprising the credential to issue. The operation finds the requisite credential definition from the credential offer and the distributed ledger (typically, from the cache). If the credential definition supports revocation and the current revocation registry is full, the operation awaits the next revocation registry and tails file, which it finds in the Tails ``.hopper``  subdirectory, sends its definition and initial entry to the ledger, then sets tails content in the Tails directory as per :ref:`tails-tree`. If its revocation registry builder is external, it also signals its process to create the next revocation registry out-of-band in the tails hopper directory. Once a revocation registry is in place for the current credential, the operation issues the new credential. It returns a pair with the new credential and, if the credential definition supports revocation, its credential revocation identifier.

Its  ``revoke_cred()`` method revokes a credential by revocation registry identifier and credential revocation identifier, updating the revocation registry state on the distributed ledger and returning the time of the ledger transaction in epoch seconds.

HolderProver
****************************************************

The HolderProver class has its own initializer method to set its directory for cache archives and to set any configuration parameters. Actuators need not call its ``_sync_revoc_for_proof()`` nor ``_build_rr_delta_json()`` methods; the implementation uses them internally as required to create manage tails file associations, and to build revocation registry delta structures (as a callback per :ref:`revo-cache-entry`).

It implements properties for access to its configuration and cache directory.

Its configuration dict, specified on initialization, has boolean settings for keys ``parse-caches-on-open`` and ``archive-holder-prover-caches-on-close``.

.. _holder-prover-ctx-mgr-caching-offline-op:

Context Manager Methods, Caching, and Off-Line Operation
====================================================================

Its  ``get_box_ids_json()`` method collects and returns box identifiers (schema identifiers, credential definition identifiers, and revocation registry identifiers) for all credentials in the wallet, in preparation to go off-line. Its operation starts with the credential definition identifiers and revocation registry identifiers of its tails file associations, from which it derives germane schema identifiers. It filters out any box identifiers for which its wallet has no credentials.

Its ``load_cache_for_proof()`` method loads caches and archives enough data to go off-line and be able to prove all credentials in the wallet (assuming that its content is not so voluminous that it overwhelms the cache).

Its ``dir_cache()`` method returns the location where serialized caches reside.

Its ``open()`` method synchronizes its tails file associations (in case of a new tails file download) and, if its configuration sets ``parse-caches-on-open``, feeds the caches with its most recent archive.

Its ``close()`` method synchronizes its tails file associations (in case of a new tails file download) and, if its configuration sets  ``archive-holder-prover-caches-on-close``, populates the shared caches with enough data to prove all credentials in its wallet before archiving cache content to file.

Because cache loading operations could monopolize the (shared) caches, it is best for an off-line holder-prover to be the only anchor in its process. The following figure illustrates the process of priming a holder-prover anchor for off-line operation.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/offline.holderprover.png
    :align: center
    :alt: Priming Holder-Prover Anchor for Off-Line Operation
 
The class's ``offline_intervals()`` helper takes an iterable collection of credential definition identifiers. It returns a specification dict on credential definition identifiers, mapping to default non-revocation intervals by current cache content. The actuator can augment this specification structure with desired attributes and minima to pass to the Verifier's ``build_proof_req()`` method to build a proof request.

Tails and Revocation Registry Helpers
====================================================

Its  ``dir_tails()`` method returns the path to the subdirectory of the tails tree where an incoming tails file should go - the service wrapper layer must implement the upload itself.

Its  ``rev_regs()`` method returns a list of revocation registry identifiers for which the anchor has associated tails files, creating such associations for newly landed tails files without (so that an actuator may poll this method to find a listing for a tails file as soon as it lands). A service wrapper layer (or possibly VON-X) may use this to determine whether it needs a tails file for an upcoming operation.

.. _cred-like-data:

Operations with Credential-Like Data
========================================================

This section outlines the methods dealing with credentials and their representations in indy-sdk. The indy-sdk uses three representations for credential-like data; the following subsections elaborate.

Cred-Info
-----------------------------------------

The design defines a cred-info as a dict with the following information:

- credential revocation identifier on key cred_rev_id
- credential definition identifier on key cred_def_id
- schema identifier on key schema_id
- revocation registry identifier on key reg_rev_id
- referent (a.k.a. wallet credential identifier) on key referent
- attributes, as a dict mapping names to raw values, on key attrs.

Cred-Brief
-----------------------------------------

The design defines a cred-brief as a dict nesting a cred-info structure on key cred_info and a non-revocation interval on key interval (the non-revocation interval has a null value if the corresponding credential definition does not support revocation).

Cred-Brief-Dict
-----------------------------------------

The design defines a cred-brief-dict as a dict mapping wallet cred identifiers to corresponding cred-briefs. As per :ref:`holder-prover-cred-like-ops`, ``HolderProver.get_cred_briefs_by_proof_req_q()`` returns a cred-brief-dict.

Credentials
-----------------------------------------

A credentials (in indy-sdk, "credentials for proof request") structure, is a dict on predicates (key predicates) and attributes (key attrs) identifying each attribute (or predicate) by item referent (formerly known as UUID) to a list of credential briefs for credentials containing it. To create a proof on such a credentials structure, indy-sdk requires exactly one such brief per item referent in its corresponding list.


.. _holder-prover-cred-like-ops:

Methods Implementing Operations with Credential-Like Data
==============================================================

Its  ``create_cred_req()`` method creates a credential request for an input credential offer and credential definition, using a specified local DID (from a pairwise relation) or defaulting to the anchor DID. It returns the credential request and its associated metadata.

Its  ``store_cred()`` method stores a credential in the wallet. It returns the credential identifier as it appears in the wallet. Note that the credential attribute tagging policy :ref:`catpol` specifies the credential attributes for which the indy-sdk builds WQL searchable tags in the wallet on storage.

Its  ``delete_cred()`` method deletes a credential in the wallet by its wallet credential identifier.

Its ``build_req_creds_json()`` helper builds an indy-sdk requested credentials structure. It takes an indy-sdk credentials structure and an optional filter to apply, plus an additional optional boolean specifying default behaviour for that filter as follows:

- an absent filter parameter means no filter: request all credentials
- otherwise, request any credential on a credential definition identifer that is not present in the filter if and only if the boolean is set (True).

The filter itself maps credential definition identifiers to criteria for attribute values and minima to include in the requested credentials via the following specifications per credential definition identifier:

- ``'attr-match'`` to a dict mapping attribute names to values to match
    - if the key is absent or the value is null or empty, match everything
- ``'>'``, ``'>='``, ``'<='``, ``'<'`` to a dict of corresponding bound values to respect (by predicate) per attribute
    - if such a key is absent or its value is null or empty, match everything.

Its  ``get_cred_infos_by_q()`` method takes a WQL query and an optional result limit; its operation retrieves cred-infos for credentials satisfying it, applying the search within the indy-sdk wallet.

Its  ``get_cred_infos_by_filter()`` method takes a coarse filter (matching values against any schema identifier, schema origin DID, schema name, schema version, credential issuer DID, and/or credential definition identifier). Its operation retrieves cred-infos for each corresponding credential in the wallet, searching the wallet within indy-sdk itself.

Its  ``get_cred_info_by_id()`` method takes a wallet credential identifier and retrieves cred-info for the corresponding credential in the wallet.

Its  ``get_cred_briefs_by_proof_req_q()`` method takes a proof request and a structure of extra [WQL] queries, indexed as a dict by their referents in the proof request (the ``proof_req_attr_referents()`` and ``proof_req2wql_all()`` utilities of :ref:`wranglers` can aid in the construction of this WQL). It uses indy-sdk to search within the wallet to retrieve credential briefs matching the extra WQL queries. It filters the results against any predicates within the proof request before returning. Note however that predicate filtration is relatively expensive, since it occurs outside the wallet: indy-sdk supports only exact attribute matches for (WQL) in-wallet filtration. The method returns a cred-briefs-dict as per :ref:`cred-like-data`.

Note that a credential's revocation status does not affect whether any anchor returns it via the methods above.

.. _catpol:

Methods Operating on Credential Attribute Tagging Policy
========================================================

Credential attribute tagging policy specifies the attributes to build into WQL searchable tags on credential storage -- the default policy marks all attributes as taggable. For each taggable attribute (by credential definition), the indy-sdk implementation stores a marker tag and a value tag per credential.

The ``set_cred_attr_tag_policy()`` method sets (or clears) a credential attribute tagging policy for a credential definition identifier. If the call specifies retroactive operation, the method directs indy-sdk to visit all existing credentials on the credential definition and rebuild their tags to the specified policy: note that this could be an expensive operation.

The ``get_cred_attr_tag_policy()`` method returns the current policy as a JSON list of attributes marked for tagging. If there is no current policy, it returns a JSON null.

Proof Methods
===================================

The class's  ``create_link_secret()`` method sets the link secret, for proof creation, in the wallet.

Its  ``create_proof()`` method creates a proof for input indy-sdk proof request, credentials (or iterable collection of credential briefs), and requested-credentials structures.

Reset
-----------------------------------------

Its  ``reset_wallet()`` method allows the service wrapper layer to delete the wallet and start a new one of the same type, setting link secret to the prior value. Its implementation delegates to the wallet manager's ``reset()`` method (:ref:`wallet-manager`).

Verifier
****************************************************

The ``Verifier`` class has its own initializer method to set its directory for cache archives and to set any configuration parameters. Actuators need not call its ``_build_rr_state_json()`` method; the implementation uses it internally as required to build revocation registry state structures as per :ref:`revo-cache-entry` for the revocation cache.

The class implements properties for access to its configuration and cache directory.

Its configuration dict, specified on initialization, has a boolean setting for key parse-caches-on-open and a box-ids structure (i.e., a dict of lists on keys schema_id, cred_def_id, and rev_reg_id) for key ``archive-verifier-caches-on-close``. Note that ``HolderProver`` anchors provide these box-ids on request (as per :ref:`holder-prover-ctx-mgr-caching-offline-op`) via ``HolderProver.get_box_ids_json()``; actuators would need to poll holder-provers of interest if off-line operation is in scope.

The ``Verifier`` class exposes the ``verify_proof()`` method to verify an input proof against its proof request. It returns True or False.

Its static ``least_role()`` method returns the ``USER`` role; pure verifier anchors need not write to the ledger.

The class's ``build_proof_req_json()`` helper takes a specification construct. It returns an indy-sdk proof_request structure (JSON encoded). The specification construct is a dict on credential definition identifiers. Each key is a credential definition identifier; its value is a dict mapping:

- ``'attrs'`` to a list of attributes of interest
    - if the key is absent, request all attributes
    - if the key is present but the value is null or empty, request no attributes (i.e., only predicates)
- ``'>'``, ``'>='``, ``'<='``, ``'<'`` to a dict of bound values to request (by predicate) per attribute (at present, indy-sdk supports only ``'>='`` predicates)
    - if such a key is absent or its value is null or empty, request no such predicates
- ``'interval'`` to a single timestamp of interest, in integer epoch seconds, or to a pair of integers marking the boundaries of a non-revocation interval; if absent,
    - request the present moment if the credential definition supports revocation,
    - omit if the credential definition does not support revocation.

Its ``load_cache_for_verification()`` method loads caches and archives enough data to go off-line and be able to verify proofs using the schemata, credential definitions, and revocation registries specified in configuration.

Its ``open()`` method, if its configuration sets ``parse-caches-on-open``, feeds the caches with its most recent archive.

Its ``close()`` method, if its configuration has content for ``archive-verifier-caches-on-close``, populates the shared caches for all specified box identifiers before archiving cache content to file.

Because these operations could monopolize the (shared) caches, it is best for an off-line verifier to be the only anchor in its process. The following figure illustrates the process of priming a verifier anchor for off-line operation.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/offline.verifier.png
    :align: center
    :alt: Priming Verifier Anchor for Off-Line Operation
 
.. _demo-anchors:

Demonstration Anchor Classes
****************************************************

The ``TrusteeAnchor``, ``ProctorAnchor``, ``OrgBookAnchor``, ``OrgHubAnchor``, ``RegistrarAnchor``, and ``NominalAnchor`` demonstration anchors of file ``von_anchor/anchor/demo.py`` use the derived mixins above to create their respective demonstration VON anchor classes:

.. csv-table::
    :header: "Demonstration Class", "Roles", "Notes"

    "TrusteeAnchor", "Trustee", "Writes nyms to ledger"
    "ProctorAnchor", "Origin, Issuer, Verifier", "Originates schemata, issues credentials, and verifies presentations"
    "OrgBookAnchor", "Holder-Prover", "Stores credentials"
    "OrgHubAnchor", "Origin, Issuer, Holder-Prover, Verifier", "Acts as both OrgBook for community and Proctor for its own program"
    "RegistrarAnchor", "Origin, Issuer", "Originates schemata, issues credentials"
    "NominalAnchor", "Base", "Uses ledger primarily for cryptonym access to perform cryptographic operations"
