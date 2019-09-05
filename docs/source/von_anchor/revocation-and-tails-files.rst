***************************************************
Revocation and Tails Files Handling
***************************************************

Tails
###########################################

The Tails class forms an abstraction layer to manage tails file for issuer and holder-prover anchors. Principally, it heads a directory tree with tails files, and retains associations between revocation registries and their respective tails files.

Revocation Registries
****************************************************

A revocation registry comprises metadata regarding a credential definition, in addition to specifying the credential issue strategy (by default or on demand), the revocation accumulator, and the associated tails file. Issuer anchors write revocation registry definitions and states to the distributed ledger. The strategy of issue by default requires longer to create tails files, but obviates the need to write a revocation registry delta per credential issue to the ledger. Since VON Anchor allows for an external revocation registry builder posture, its design adopts issue by default as more efficient overall.

In addition to delimiters and numeric identifier type markers (both invariant), each revocation registry identifier comprises its issuer DID, its credential definition identifier, and a trailing tag specific to the revocation registry.

The convention for von_anchor revocation registry tags is to begin on tag (stringified) ``'0'`` and increment with each new revocation registry on any given credential definition. In this way, Tails operation can discover the current revocation registry for a new credential, and default to the next tag on creation of a new revocation registry.

Tails Files
****************************************************

The issuer anchor uses the indy-sdk library to create a tails file to back a new revocation registry. Tails file generation requires an issuer anchor's private key. A tails file contains (randomly generated, enormous) factors multiplying into a revocation accumulator for as many potential credentials as the capacity of the revocation registry. Once generated, tails files are invariant and public. Note that [VT] presents the von_tails package, which includes an external tails file server and synchronization scripts to make them available.

Tails files are potentially enormous and expensive to generate – so much so that using an underlying libindy.so compiled for debug produces unacceptable performance for credential definitions supporting revocation. Tails file generation time scales linearly on the size of the revocation registry; hence, one expects every credential definition that supports revocation to produces many revocation registries. Revocation registry identifiers include a trailing tag to disambiguate between revocation registries for any given credential definition.

.. _tails-tree:

Tails Tree
****************************************************

Given that an issuer anchor may support many credential definitions, and that a credential definition may entail many (possibly, thousands of) revocation registries, a Tails tree splits a base directory by credential definition, and houses tails files in their respective subdirectories by their respective credential definition identifiers.

Issuer VON anchors asynchronously build revocation registry definitions and initial entries, plus corresponding tails files, in the ``.hopper`` subdirectory. The last operation in this process links the revocation registry identifier to its tails file. Once the symbolic link appears, the Issuer can send the definition and initial entry to the ledger and then move the directory named for the corresponding credential definition identifier to the tails directory, setting the revocation registry in place.

An additional ``.sentinel`` subdirectory houses control files for an issuer to queue startup, work, and shutdown orders to its designated revocation registry builder.

The figure illustrates the structure of the tails tree.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/dir_tails.png
    :align: center
    :alt: Tails Tree
 
Association
****************************************************

The indy-sdk library requires each tails file name to match the hash of its respective content as indy-sdk computes it. However, this convention provides no intrinsic label to associate which revocation registry produces which tails file – the only such association resides on the ledger, from revocation registry to tails hash. As such, the ``Tails`` class retains an association through local symbolic links, revocation registry identifier to tails file, on disk. On restart, an issuer or holder-prover anchor uses this association to re-establish which tails files belong to which revocation registries.

Instance Methods
****************************************************

The ``Tails`` class includes an initializer taking a base directory for the tails tree, a credential definition identifier for its associated revocation registry, and a tag (defaulting to the current, greatest numerically valued, tag on a symbolic link to a tails file in the subdirectory for the input credential definition identifier). The initializer finds the symbolic link and its tails file, and creates a configuration JSON object for indy-sdk handling of the tails file, and it sets a place holder for the indy-sdk tails file reader handle. If the operation does not find the link and the tails file, it raises AbsentTailsFile.

The (asynchronous) ``open()`` method opens the tails file reader via indy-sdk, setting the instance's reader handle.

The ``reader_handle()``, ``rr_id()``, and ``path()`` methods implement properties to query the indy-sdk reader handle, revocation registry identifier association, and path to the tails file of the current object.

Effectively, the only use of the instance methods is to ensure that required files are present (on initialization), to use the tails file reader, and to query 
either side of the (symbolic link to tails file) association. As the indy-sdk does not currently provide a means to close the tails file reader, the Tails file instance goes into a revocation cache entry that all anchors share, thus minimizing the number of open tails file handles.

.. _tails-static-methods:

Static Methods
****************************************************

The ``ok_hash()`` method returns whether an input string represents, by composition alone, a candidate for a tails hash.

The ``associate()`` method creates a symbolic link in its proper subdirectory to associate the revocation registry identifier and its tails file. Anchors use this method in synchronizing revocation registries.

The ``dir()`` method returns the subdirectory corresponding to the input credential definition identifier. The service wrapper API for a holder-prover anchor should use this method in uploading a tails file, to write it to the location where the Tails initializer can find it.

The ``linked()`` method takes a base directory and a revocation registry identifier, and returns the path to its associated tails file.

The ``links()`` method takes a base directory and an optional issuer DID, and returns a set of paths to all symbolic links under the base directory, retaining only those issued against the issuer DID if specified. Recall that revocation registry identifiers name every symbolic link in this tree. The operation ignores the .hopper subdirectory as its content builds.

The ``unlinked()`` method finds all tails files in the tree, excluding the .hopper subdirectory, without associations via symbolic link. A tails file has no association until its issuer anchor associates it with its revocation registry identifier (immediately after creation). Neither does it have an association when a holder-prover anchor's service wrapper uploads it to its location in the tails tree – the holder-prover's revocation registry synchronization  Note that the synchronization scripts in [VT] perform the association on download to the holder-prover.

The ``next_tag()`` method returns the next tag name available for a new revocation registry identifier on an input credential definition identifier, plus a size suggestion for the revocation registry. Given the expense of tails file creation, there is naturally a tension between the creation of large revocation registries for seldom-used credential definitions (too much compute time initially), against the creation of small revocation registries for often-used credential definitions (too many revocation registries and tails files). As such, the default behaviour of the von_anchor package is to begin with an initial revocation registry size of 64, doubling with each new revocation registry to a maximum of 100000.

The ``current_rev_reg_id()`` method returns the current (with highest value tag, numerically) revocation registry identifier for the input credential definition identifier. With no tag specified, the initializer uses this method to determine the current revocation registry per credential definition identifier, for new credential issue. The operation ignores the .hopper subdirectory as its content builds.

.. _rev-reg-update-frame:

RevRegUpdateFrame
###########################################

A revocation registry update frame f retains cached information about deltas or states for a revocation registry:

- a ledger timestamp time ``f.timestamp``, preceding or matching
- a requested timestamp ``f.to``, preceding or matching
- a query timestamp ``f.qtime`` (for bookkeeping), and
- a revocation registry update, representing a delta or state (dict).

The revocation registry identifier is extrinsic; the revocation cache entry itself retains it in its revocation registry definition as per section ``3.2.1.3``.

Note that a query at a given time must be for a timestamp in the past or present, and the ledger timestamp for the most recent revocation registry update on the ledger corresponds to initial revocation registry creation or a revocation (not credential issue, since VON anchor adopts issue by default). Hence it must precede the requested timestamp (since an issuer anchor cannot mark revocation time in the future); i.e.,

``f.timestamp <= f.to <= f.qtime``

for all frames ``f``.

.. _revo-cache-entry:

RevoCacheEntry
###########################################

Each revocation cache entry, implemented in von_anchor/cache.py, retains:

- a revocation registry definition,
- its associated Tails instance, and
- two managed lists of frames, housing revocation registry deltas (for proof creation) and updates (for proof verification).

The revocation cache entry implementation exposes methods ``get_delta_json()`` and ``get_state_json()`` as wrappers for workhorse ``_get_update_json()`` to retrieve its revocation registry's delta or state frame for a requested query interval ``(fro, to)``, in epoch seconds, past or present. The query interval represents goalposts on the window of interest for a revocation update; any information in that interval suffices.

The diagram illustrates actionable state cases; further elaboration follows.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/revo-cache-reg-upd-frames.png
    :align: center
    :alt: Querying Revocation Cache Update Frames

Case 1: Prior Request for Posterior Update Got Frame on Earlier Timestamp
*****************************************************************************

If a frame f exists in the list where interval ``[f.timestamp, f.to]`` spans ``q.to`` for query ``q`` (i.e., ``f.timestamp <= q.to <= f.to``), then any new update between this frame and the call's requested timestamp would represent a retroactive revocation, which indy-sdk does not support. The frame satisfies the update request: the execution updates its query time and returns its revocation registry update along with the ledger timestamp.

Non-Case: Prior Request for Posterior Update Got Frame on Exact Timestamp
*****************************************************************************

Consider the case where the case 1 above does not apply, but the list has a frame with the ledger timestamp matching ``q.to`` for query ``q`` and the frame's requested timestamp strictly precedes ``q.to``.

Consider such a frame ``f`` in the list.

Since the above case does not apply, ``f.to < q.to``.

But ``f.timestamp <= f.to``, as per :ref:`rev-reg-update-frame`.

Hence  ``f.timestamp <= f.to < q.to == f.timestamp``,

and we have ``f.timestamp < f.timestamp``, a contradiction.

Case 2: Existing Frame Satisfies Query Interval
*****************************************************************************

If case 1 above does not apply but there is a maximal (by timestamp) frame ``f`` with ``q.fro <= f.to`` and ``f.timestamp <= q.to``, the frame satisfies the query interval. The execution returns the corresponding update, but does not extend the frame to ``q.to``: an update may exist on the ledger after ``f.to``, but it is not of interest to the current request, since the current frame is satisfies the query.

Case 3: Prior Request Got Frame on Earlier Timestamp
*****************************************************************************

If neither case 1 nor case 2 above apply but maximal (by timestamp) frame ``f`` exists in the list with ``f.timestamp <= q.to``, the execution isolates the frame and calls back to build a revocation registry update from ``f.to`` through ``q.to``.

If the builder callback returns a new update on a ledger timestamp not yet known to the revocation cache, the operation creates a new frame on it, adds it to the list, and prunes old list entries if need be.

Otherwise, the update exhibits the same ledger timestamp as frame ``f``: there is no new update and the frame can serve through the requested time ``q.to``. The operation extends the frame accordingly; i.e., it sets ``f.to = q.to``, then returns it along with its ledger timestamp.

Case 4: No Prior Request Got Frame on Earlier Ledger Timestamp
*****************************************************************************

If the query's requested timestamp ``q.to`` precedes any cached frame's ledger timestamp ``f.timestamp``, the execution calls back to build a revocation registry update from inception to the requested timestamp ``q.to``. It creates a new frame on it, adds it to the list and prunes old list entries if need be. It returns the frame's revocation registry update and the ledger timestamp.

Pruning Heuristic
*****************************************************************************

The revocation cache prunes registry update frame lists, when they exceed 346 frames, to retain the  most recent 296 frames by query time. Given a typical maximum revocation registry size of 100 000, the motivation is to hover the cache size about the the square root (326) of this figure.

In case of (say) about 16 million drivers licences, the tails file sizing strategy of :ref:`tails-static-methods` yields up to 164 revocation registries on a credential definition. Since each registry update frame list (json-deserialized) requires about 300 bytes per frame, this heuristic sets a maximum memory requirement of about 32 MB per credential definition for revocation registry delta cache operation.

