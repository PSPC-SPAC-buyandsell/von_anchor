von_agent
=========
As part of the technology demonstrator project using Hyperledger indy to explore, among other VON network facilities, the use of the distributed ledger with PSPC Supplier Registration Information (SRI), the design specifies agents to interact with the sovrin distributed ledger as realized through indy-sdk.

The demonstration defines the following agents:

- the Trust Anchor agent as:

  - the agent registrar on the distributed ledger
  - a schema originator (purely academically, for the demonstration)
- the BC Registrar agent as:

  - a schema originator for its own claims
  - an issuer of claims
- the BC Org Book agent as, for claims that the BC Registrar issues:

  - a W3C claims holder
  - an indy-sdk prover
- the SRI agent as:

  - a schema originator for its own claims
  - an issuer of claims
  - a verifier of claims, whether itself or the BC Registrar agent issued them
- the PSPC Org Book as, for claims that the SRI agent issues:

  - a W3C claims holder
  - an indy-sdk prover.

Documentation
=============
The design document is available from the ``von_base`` repository (<https://github.com/PSPC-SPAC-buyandsell/von_base.git>) at ``doc/agent-design.doc``.  The design document includes instructions for installation, configuration, and operation of ``von_agent``.
