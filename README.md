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

# Prerequisites
Use the directions at `https://github.com/hyperledger/indy-sdk/blob/master/doc/ubuntu-build.md` to:
  - build and install `libindy.so` in the `LD_LIBRARY_PATH` or `/usr/lib/`
  - set up the docker `indy_pool` container and the docker `indy_pool_network` network.
