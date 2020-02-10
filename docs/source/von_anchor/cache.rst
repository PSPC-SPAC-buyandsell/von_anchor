*****************************************************
Caching
*****************************************************

This section outlines the cache implementations for schemata, credential definitions, and revocation registries.

A cache is archivable if the implementation allows anchors to serialize them on going off-line, and then to parse their content upon returning to on-line operation. The design calls for all caches to be archivable.

The von_anchor package defines singletons for caching schemata, claim definitions, and revocation registries in ``von_anchor/cache.py``. The singleton construction allows all anchors running in a process to share the caches; for example, if an issuer anchor sends a credential definition to its cache, then a holder-prover in the same process may use the cache to get it without going to the ledger. Each class has a (re-entrant) lock to manage access.

Schema Cache
===========================================

The ``SchemaCache`` class allows for storage and retrieval by sequence number, by schema identifier, or by ``SchemaKey`` instance, reducing network chat with the distributed ledger.

The ``schemata()`` method lists all schemata in the instance.

The ``feed()`` method takes a list of schemata to add to the cache. If a schema on an incoming sequence number is already in the cache, the operation logs a warning and demurs: it is not possible for an archived schema to represent an update on one already in the live cache.

The ``clear()`` method clears the cache.

Credential Definition Cache
===========================================

The ``CredDefCache`` derives from simple ``dict``. It indexes credential definition data by credential definition identifier, reducing network chat with the distributed ledger.

Revocation Cache
===========================================

The ``RevoCache`` derives from simple ``dict`` and offers a class-wide (re-entrant) lock. It indexes definitions, associated Tails instances, and update frames (on deltas and states) for revocation registries, reducing network chat with the distributed ledger and open file handles (recall that indy-sdk does not allow for the closing of a tails file reader at present).

The revocation cache additionally offers the ``dflt_interval()`` instance method, computing a default non-revocation interval by credential definition identifier on the current content of the revocation cache. This interval is the latest interval touching all revocation registries against the input credential definition identifier; the following figure illustrates.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/default-interval.png
    :align: center
    :alt: Revocation Cache Default Interval Computation per Credential Definition Identifier
 
ArchivableCaches Utility Class
===========================================

The ArchivableCaches class collects static methods to operate on all archivable caches in unison, primarily for archival and parsing to inform off-line, cache-only operations. Note that all anchors share all caches, and so the anchor that invokes these methods should be the only one in the process.

The ``clear()`` method clears all archivable caches.

The ``archive()`` method writes a cache archive to a subdirectory, named for the current timestamp in epoch seconds, of an input base directory.

The ``parse()`` method takes a base directory and timestamp (defaulting to the most current subdirectory name); its operation feeds the archivable caches with the content in the archived files in that subdirectory. Note that since the distributed ledger only augments and never removes content, it is not possible for a cache archive to update a live cache if the cache has content for the same item: in this case, the operation logs a warning and demurs.

The ``purge_archives()`` method deletes old archived cache files, optionally preserving the most recent.
