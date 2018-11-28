******************************
Anchor Interactions
******************************

This section introduces typical interactions involving demonstrator VON anchors. The following subsections discuss:

- bootstrap operations
- credential operations: load, revoke, request, reset
- proof operations: creation, verification

**Actuation**

The high level design does not specify the client (actuator) to prompt VON anchor operations; it could be a configuration item for a Web application or it could be a custom application prodding one or more anchors via their respective wrapper APIs. The ``test/test_anchors.py`` test harness of the von_anchor package offers a (crude) sample actuator.

In higher level VON applications, VON-X embeds VON Anchor, and VON-X drives the VON-IVy instances of Credential Issuer/Verifiers and TheOrgBook.

Bootstrap Operations
###################################

This section specifies VON anchor bootstrap operations.

Trustee VON Anchor Boot Sequence
***********************************************

The node pool's genesis transactions must specify the trustee VON anchor's cryptonym (nym), or that of an ancestral trustee that registered (possibly, transitively) the trustee of interest. At boot time, the anchor must check for its own nym on the distributed ledger. If not present, it must write it to the ledger – however, this check is a formalism since the genesis transactions should include its cryptonym.

The following figure illustrates the boot sequence for a trustee VON anchor.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/boot.trust-anchor.png
    :align: center
    :alt: Trustee VON Anchor Boot Sequence
 
Issuer Anchor Boot Sequence
***********************************************

At present, for simplicity, the design of von_anchor automatically sets up all issuer anchors (creating credentials) as origin anchors (defining schemata). At boot time, the issuer anchor must check the ledger for its own nym; if absent, it must prompt the trustee VON anchor (via its service wrapper API) to write it to the ledger.

The anchor must look up each schema and associated credential definition for which it is responsible as an origin and issuer (respectively). It must create and send all such absent productions to the ledger. If creating a new credential definition with revocation support, the call to send the credential definition creates an initial revocation registry (plus a corresponding tails file) and writes the registry state with its initial entry to the ledger, then schedules the creation of the next tails file and revocation registry in the hopper to run when possible, to avoid a long delay when a future credential creation requires such.

The following figure illustrates the boot sequence for an issuer anchor.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source//pic/boot.origin+issuer.png
    :align: center
    :alt: Issuer VON Anchor Boot Sequence

Holder-Prover Anchor Boot Sequence
***********************************************

Recall that indy-sdk condenses the W3C holder and indy-sdk prover roles.

The holder-prover anchor may operate on-line (with the distributed ledger available via the node pool) or off-line.
At boot time, if on-line, the holder-prover anchor must check the ledger for its own nym; if absent, it must prompt the trustee VON anchor to write it to the ledger. If off-line, its configuration should prod the operation to load the schema, credential definition, and revocation caches with archived content. Since all anchors in a process share these caches, a holder-prover anchor operating off-line should be the only anchor in the process.

On boot, the anchor must set its link secret, which it uses to create proofs.

The following figure illustrates the (on-line) boot sequence for a holder-prover anchor.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/boot.holderprover.png
    :align: center
    :alt: Holder-Prover VON Anchor (On-Line) Boot Sequence

Verifier Anchor Boot Sequence
***********************************************

The verifier anchor may operate on-line (with the distributed ledger available via the node pool) or off-line.

At boot time, if on-line, the verifier anchor must check the ledger for its own nym; if absent, it must prompt the trustee VON anchor to write it to the ledger. If off-line, its configuration should prod the operation to load the schema, credential definition, and revocation caches with archived content. Since all anchors in a process share these caches, a verifier anchor operating off-line should be the only anchor in the process.

The following figure illustrates the (on-line) boot sequence for a verifier anchor.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/boot.verifier.png
    :align: center
    :alt: Verifier VON Anchor (On-Line) Boot Sequence

Credential Operations
###################################

This section introduces VON anchor interactions regarding credentials.

Credential Load
***********************************************

This section outlines the interactions required to prompt an issuer anchor to create credentials for storage at a holder-prover anchor.

The actuator must call on the issuer anchor to create a credential offer, based on the distributed ledger's transaction number for the schema underpinning the credential (via the issuer's corresponding credential definition). The anchor creates and returns the credential offer.

Then the actuator must prompt the holder-prover anchor to create a credential request on the credential offer; the anchor creates the request and returns it with some associated metadata that the actuator must retain for the duration of the credential load sequence.

For each credential, the actuator must prompt the issuer anchor to create it on the credential offer, the credential request, and the attribute name/value pairs comprising the content. The issuer anchor returns the credential, with its credential revocation identifier if the credential definition supports revocation. The actuator then must prompt the holder-prover anchor to store the credential (passing the metadata from the credential offer). At this point, the implementation on holder-prover anchor checks whether it has any required tails file in its tails tree. If it does not, it raises an exception and the actuator must fetch it from the issuer and supply it for a subsequent attempt.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/cred-load.png
    :align: center
    :alt: Credential Load Sequence
 
Credential Revoke
***********************************************

This section outlines the interactions required to prompt an issuer to revoke a credential.

The actuator must isolate the revocation information, comprising a revocation registry identifier and a credential revocation identifier, for the credential of interest. If the holder-prover is pliable, the actuator can get the credential directly (see section 2.2.3); alternatively, the service may store such metadata at credential creation time.

The actuator must call on the issuer anchor to revoke the credential by its revocation information. The issuer implementation updates the revocation registry state on the ledger and returns the transaction time in epoch seconds.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/cred-revoc.png
    :align: center
    :alt: Credential Revocation Sequence
 
Credential Request
***********************************************

This section outlines the interactions required to prompt an issuer to return credentials from its wallet.

The actuator must call upon the holder-prover anchor to get credentials by desired filtration parameters:

- coarsely, by components of schema identifier and/or credential definition identifier:
    - credential identifier definition (including issuer DID, schema sequence number)
    - credential issuer DID
    - schema identifier (including origin DID, name, version)
    - schema origin DID
    - schema name
    - schema version
- by attribute and/or predicate value filtration
- by credential identifier in the wallet (a.k.a. referent in credential info context).

The implementation on the holder-prover anchor fetches and filters credentials from its wallet as requested, and returns cred-info or cred-brief (as per :ref:`holder-prover-cred-like-ops`) structures accordingly. The utilities provide further filtration and display options, to facilitate user selection and refinement via feedback to augment filtration in further calls to get credentials from the holder-prover anchor.

Note that no filtration can isolate credentials by revocation status at this stage: all credentials in a wallet are subject to return, whether revoked or not. Issuers publish revocation updates to the ledger, not to any holder-prover's wallet.

The following figure illustrates.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/cred-request.png
    :align: center
    :alt: Credential Request Sequence
 
Credentials Reset
***********************************************

This section outlines the interactions required to prompt an issuer to reset a holder-prover wallet, effectively deleting it and starting another on the same link secret. Note that resetting a VON anchor's wallet makes any of its credential definitions inoperable, if it is an issuer in addition to a holder-prover.

The actuator calls upon VON anchor to reset its wallet; the implementation on the holder-prover anchor completes the operation and returns.

The following figure illustrates.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/creds-reset.png
    :align: center
    :alt: Credential Reset Sequence

Proof Operations
###################################

This section introduces anchor interactions regarding proofs: proof creation and proof verification.

Proof Sequences
***********************************************

This section outlines the interactions required to marshal a tails file to a holder-prover anchor, and to create a proof.

Tails File Marsalling
===================================

To marshal a tails file from its issuer anchor to a holder-prover anchor that requires it, the actuator must have a credential on a credential definition supporting revocation, or else the revocation registry identifier itself. The actuator may use a utility to get revocation information out of a creds structure, including revocation registry identifier and credential revocation identifier.

The actuator calls the issuer anchor's service wrapper to locate and download the tails file corresponding to the revocation registry identifier – although the anchor as currently implemented can provide its location, the service wrapper must complete the download process to the actuator. Alternatively [VT] presents the von_tails package, which includes an external tails file server and synchronization scripts to expedite this process.

The actuator then calls the holder anchor's service wrapper to upload the tails file to the holder-prover anchor. The holder-prover anchor can provide the service wrapper with the location to write the tails file so it may find it and synchronize as required, but at present the anchor leaves the work of uploading the file itself to the service wrapper layer.

Both downloading and uploading the tails files present interesting achievable goals for integration into the emerging VON-X layer.

Proof Creation
===================================

The actuator calls upon the verifier anchor to build indy-sdk proof requests. Alternatively, the actuator may craft these structures manually, but using the builders guarantees that they exhibit a sensible configuration that VON anchor proof creation supports. Typically, the actuator calls upon the holder-prover to retrieve cred-briefs for a proof request (with attributes to retrieve and predicates to satisfy) and any additional WQL queries to apply. The ``proof_req_infos2briefs()`` utility generates an indy-sdk ``requested_credentials`` structure from a proof request and the cred-briefs that the holder returned, possibly filtered through human interaction.

The actuator calls upon the holder-prover anchor to create proof on a proof request, an iterable collection of cred-briefs, and an indy-sdk requested credentials structure. The test harnesses provides several concrete examples.

The holder-prover anchor implementation then gets (from the distributed ledger or, where possible, from the caches) such schemata and credential definitions as are required for proof, plus any revocation registry definitions. If any tails files are required and not present in its tails tree, the holder-prover anchor raises an exception noting the absent tails file; the actuator must marshal it to the holder-prover anchor (or await synchronization as per [VT]) as above. Otherwise, the implementation consults the distributed ledger to get the revocation registry deltas to the timestamp in the requested credentials structure, and constructs revocation registry states as required to create a proof (however, some credential definitions may not support revocation; such credential definitions require no tails files content nor revocation registry states to contribute to the proof).

Finally, the holder-prover returns the proof to the actuator.

The following figure illustrates the proof sequence above.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/proof.png
    :align: center
    :alt: Proof Sequences

Verification Sequence
***********************************************

This section outlines the interactions required to verify a proof.

The actuator calls upon the verifier anchor to verify a proof against a proof request. The verifier anchor implementation consults the distributed ledger (or the caches) to get such schemata, credential definitions, and revocation information from the ledger as the proof identifies, then passes the information to the indy-sdk to verify the proof as true or false. It returns the result to the actuator.

The following figure illustrates the verification sequence.

.. image:: https://raw.githubusercontent.com/PSPC-SPAC-buyandsell/von_anchor/master/docs/source/pic/verification.png
    :align: center
    :alt: Verification Sequences

