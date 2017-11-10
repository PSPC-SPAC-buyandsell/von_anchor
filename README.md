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
  - create a virtual environment on python 3.5

# Installing with pip
Activate the virtual environment, then issue:
```
(py35) $ pip install -i https://testpypi.python.org/pypi von_agent
```

for the latest development version at test-pypi; omit the -i option to get it from pypi instead.

# Using the Agents
The pytest code exercises the agents themselves. The `von_connector` (django) package sets up a RESTful service wrapper around each demonstration agent. To complete the demonstration, a front end may wire the service wrappers to its user interface, providing an accessible view.
