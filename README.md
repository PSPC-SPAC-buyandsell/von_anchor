# von_agent
As part of the technology demonstrator project using Hyperledger indy to explore the use of the distributed ledger with PSPC Supplier Registration Information (SRI), the design specifies agents with service wrapper APIs to facilitate interoperability. This package implements the base code for (bare) VON agents, to which the service wrapper API layer delegates.

The current state of the project aims to fulfil a demonstration use case enabling collaboration between the SRI and the British Columbia government's The Org Book project, underpinning its Verified Organization Network (VON).

The demonstration defines four agents:
  - the Trust Anchor as:
    - schema originator
    - agent registrar on the distributed ledger
  - the BC Registrar as an issuer
  - the BC Org Book as, for BC Registrar-issued claims, both
    - a W3C claims holder
    - an indy-sdk prover
  - the PSPC-SRI as:
    - a verifier of claims that the BC Registrar issues and the Org Book proves
    - an issuer holder, and porver for its own claims of SRI registration.

## Documentation
The design document is available from the `von_base` repository (<https://github.com/PSPC-SPAC-buyandsell/von_base.git>) at `doc/agent-design.doc`. It discusses in detail the packages comprising the technology demonstrator project:
  - `von_base`
  - `von_agent`
  - `von_connector`

including instructions for installation, configuration, and operation.
