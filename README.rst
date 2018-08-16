VON Anchor
==========
As part of the technology demonstrator project using Hyperledger indy to explore, among other VON network facilities, the use of the distributed ledger with PSPC Supplier Registration Information (SRI), the design specifies anchors to interact with the sovrin distributed ledger as realized through indy-sdk.

The demonstration defines the following anchors:

- the Trustee anchor as:

  - the anchor writing further anchors onto the distributed ledger
- the BC Registrar anchor as:

  - a schema originator for its own credentials
  - an issuer of credentials
- the BC Org Book anchor as, for credentials that the BC Registrar issues:

  - a W3C credentials holder
  - an indy-sdk prover
- the SRI anchor as:

  - a schema originator for its own credentials
  - an issuer of credentials
  - a verifier of credentials, whether itself or the BC Registrar anchor issued them
- the PSPC Org Book as, for credentials that the SRI anchor issues:

  - a W3C credentials holder
  - an indy-sdk prover.

Design Document
===============
The design document is available from the ``von_base`` repository (<https://github.com/PSPC-SPAC-buyandsell/von_base.git>) at ``doc/anchor-design.doc``.  The design document includes instructions for installation, configuration, and operation of ``von_anchor``.

Pypi
====
The latest release of the ``von_anchor`` python package is available at <https://pypi.org/project/von-anchor/#history>.
