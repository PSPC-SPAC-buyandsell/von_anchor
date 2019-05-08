VON Anchor
==========
VON anchor is a Python 3 library that presents a set of useful abstractions and conveniences by which developers may use the Hyperledger Indy's indy-sdk toolkit to interact with the any instance of an Indy distributed ledger, including the Sovrin Network. Originally called "VON Agent" - VON Anchor is not an Agent, but rather the core capabilities and abstractions (the "Anchor") needed for building an agent. While VON Anchor is an Agent implemention-agnostic, it was initially implemented to be the foundation of the Verifiable Organizations Network (https://vonx.io), a production implementation of Indy that has issued more than 10M (to date) production Verifiable Credentials about all of the incorporated entities in both British Columbia and Ontario. Those VCs are likewise held in community wallets by TheOrgBook, a VON Anchor-based Holder/Prover/Verifier component.

For full documentation, please go to: https://von-anchor.readthedocs.io/en/latest/

VON Anchor's abstractions enable the implementation of Indy Agents with various roles related to Verifiable Credentials exchange, including any combination of:

- Issuer
- Holder/Prover
- Verifier 

In doing so, VON Anchor implements a range of necessary Agent capabilities, including:

- wallet and cryptographic seed management including creation and key rotation
- ledger read actions to synchronize an Agent with the Ledger on restart
- ledger caching to minimize ledger interactions
- ledger writing of Agent entities - schemata, credential definitions and revocation registries
- full revocation support, including the creation of revocation registries and the efficient generation/management of tails files
- a Tails File server implementation (via the von_tails project)
- claim attribute value encoding support as part of the Credential Issuance and Proof process
- proof handling support for predicates (GE and new predicates)
- proof handling credential selection using Wallet Query Language (WQL) and Credential IDs
- support for offline operation of Provers and Verifiers
- a series of utilities to simplify the implementation of Indy Agents.

VON Anchor continues to evolve in lock step with the capabilities in indy-node and indy-sdk, shielding the Agent Developer from much of the churn in those applications. Feature development of VON Anchor is also driven the needs of the indy-agent developer community.

VON Anchor does not currently implement the Indy Community's Agent to Agent Protocol. As the definition of that protoocol clarifies, we expect underlying support of the protocol will be added to VON Anchor.

VON Anchor Demonstration
========================

The VON Anchor repository includes a demonstration that includes the following anchors in their roles:

- the Trustee anchor as:

  - the anchor smith writing further anchors onto the distributed ledger

- the BC Registrar anchor as:

  - a schema origin for its own credentials
  - an issuer of credentials

- the BC Org Book anchor as,

  - for credentials that the BC Registrar issues:

    - a W3C credentials holder
    - an indy-sdk prover

  - for its own credentials,

    - an issuer
    - a W3C credentials holder
    - an indy-sdk prover
    - a verifier of proofs

- the SRI anchor as:

  - a schema origin for its own credentials
  - an issuer of credentials
  - a verifier of proofs, whether itself or the BC Registrar anchor issued them

- the PSPC Org Book as, for credentials that the SRI anchor issues:

  - a W3C credentials holder
  - an indy-sdk prover.

Pypi
====
The latest release of the ``von_anchor`` python package is available at <https://pypi.org/project/von-anchor/#history>.

History
=======

As part of the technology demonstrator project using Hyperledger indy to explore the use of the distributed ledger with PSPC Supplier Registration Information (SRI), the original von_agent (v0 series) design specified anchors with service wrapper APIs to facilitate interoperability, including the capacity to relay messages to other agents.

As the SRI integration exercise developed, it adopted an intermediary layer (initially, The Org Book and Permitify, then VON-X) to engage the SRI agent rather than using agent-to-agent communication directly. The agent design dropped its inter-agent communication layer via the provisional VON protocol and the VON agent became headless, serving primarily as a back-end conduit to the distributed ledger for the intermediary layers as they developed.

Then, as the design of the indy (contrast VON) agent emerged, implementing a communications framework between indy-sdk trust anchors facilitating write operations to the distributed ledger. To disambiguate these projects, the VON agent became the VON anchor circa v1.6.

The current generation of von_anchor (v1.x series) design allows interoperability with the Hyperledger indy distributed ledger via the indy-sdk toolkit, without prejudice to any particular use case – it is not geared specifically to SRI integration. In addition to (Government of Canada) integration of the SRI system with the indy distributed ledger, the British Columbia Government is currently using the anchors to facilitate a variety of use cases such as The Org Book, Permitify, and VON-X.

Taxonomy
========

Throughout this project, "VON anchor" refers to the layer implementing the trust anchor technology using the indy-sdk; "VON connector" refers to a service wrapper API accepting transport layer messages and delegating them to its underlying VON anchor (potentially, among other back ends). "VON-X" is a BC Government initiative to generalize communications between anchors (e.g., from an issuer of credentials to a holder-prover, or from a holder-prover to a verifier).

Anchor Level
------------

The indy-sdk mechanism presents a role engineering model for anchors specifying anchor smiths, (schema) origins, issuers, provers, and verifiers (plus anchor smiths and schema origins). The W3C model of https://www.w3.org/TR/verifiable-claims-data-model, roughly in alignment with the subset implementing credential operations, uses issuers, holders, and inspector-verifiers.

The design of the von_anchor toolkit includes demonstration anchors as above. In the context of the Alice story of https://github.com/hyperledger/indy-sdk/blob/master/doc/getting-started/getting-started.md, the von_anchor toolkit would allow for the development of:

- the Steward anchor as an anchor smith
- a Government anchor as an origin of schemata for transcripts and job certificates
- a Faber anchor as the issuer of transcripts (credentials)
- an Acme anchor as the issuer of job certificates (credentials)
- an Alice anchor as an indy-sdk prover (W3C holder) of a transcript and job certificate
- a Thrift Bank anchor as a verifier.

Version Numbering
=================

Since version 1.6, the von_anchor major and minor version numbers (i.e., *x.y* in *x.y.z*) of any given release track the version that its corresponding indy-sdk (master development version) anticipates. Note that indy-sdk version numbering, has

*x.(y-1).z-*\ dev-\ *nnn < x.y.z-*\ rc\ *\ -n <= x.y.z*

for any release *x.y.z*. For example, development release 1.6.7-dev-834 follows release 1.6.7 but precedes release candidate 1.6.8-rc-43 and release 1.6.8. Any corresponding ``von_anchor`` releases would take version number series 1.6.\ *z*. The micro version number (i.e., *z* in *x.y.z*), and any numbers beyond, count only VON anchor increments, and have no relation to any external information.

References
==========

[VT] – "The von_tails External Tails File Server". Public Services and Procurement Canada, 2018-2019. https://github.com/PSPC-SPAC-buyandsell/von_tails/blob/master/README.rst

[WQL] – "Wallet Query Language". Sovrin Foundation, 2018. https://github.com/hyperledger/indy-sdk/tree/master/docs/design/011-wallet-query-language
