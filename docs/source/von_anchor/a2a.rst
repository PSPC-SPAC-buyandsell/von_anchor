******************************
Agent-to-Agent Utilities
******************************

This section outlines the utilities of the ``von_anchor/a2a`` subpackage supporting and inter-agent communications with the ``DIDDoc`` class for DID documents, plus ``PairwiseInfo`` and ``DIDInfo`` classes for agent-to-agent communications.

In this context, an agent comprises software built on top of ``von_anchor`` demonstrator classes or mixins, presenting an interface to the outside world - possibly only other agents. Such an agent or agents represent a service wrapper to VON anchor functionality.

Agent-to-agent protocols continue to evolve via the W3C and indy HIPE discussions. At present, the ``DIDDoc`` class offers creation and parsing of DID documents.

DID Document Class
###################################

The ``DIDDoc`` class represents a DID document, aggregating public keys and services.

The ``DIDDoc.CONTEXT`` class constant contains the context link for JSON-LD output; its value codifies the current version of the DID document specification.

The initializer takes only the DID that is the subject for the DID document. Note that in the context of the DID document, this is an ``id``.

The caller must use the accessor methods to populate (public) verification keys and endpoints.

The ``to_json()`` method outputs the DID document in its current state as JSON-LD. The static ``from_json()`` method returns a ``DIDDoc`` object from an input JSON-LD DID document.

Public Keys
+++++++++++++++++++++++++++++++++++

The ``PublicKey`` class helps to specify public keys to embed in DID documents.

Each such key requires:

* the DID of the DID document embedding the public key
* a public key type
* an owner, specified by DID
* a key value
* whether the DID document marks the public key as an authentication key.

The implementation stores the DID document subject and controller DIDs in raw base58 sovrin format, geared toward
interoperation with indy applications. It stores all other references as URIs, geared toward interoperation
with W3C applications.

The ``to_dict()`` method returns a dict representation of the public key to embed in a DID document.

Public Key Types
+++++++++++++++++++++++++++++++++++

The ``PublicKeyType`` enum encapsulates public key types available for specification in DID documents. It relies on a ``LinkedDataKeySpec`` namedtuple that retains identifiers for verification and authentication, and the associated value specifier for such a key type occurring in DID document references. At present, the enum supports public key types:

* Ed25519Signature2018
* RsaSignature2018
* EdDsaSASignatureSecp256k1

as per http://w3c-ccg.github.il/ld-cryptosuite-registry.

Services
+++++++++++++++++++++++++++++++++++

The ``Service`` class helps to specify a service to embed in DID documents.

Each such service requires:

* the DID of the DID document embedding the service
* an identifier
* a service type
* a service endpoint.

The implementation stores the DID document subject DID in raw base58 sovrin format, geared toward
interoperation with indy applications. It stores all other references as URIs, geared toward interoperation
with W3C applications.

The ``to_dict()`` method returns a dict representation of the service to embed in a DID document.

DID Document Utilities
+++++++++++++++++++++++++++++++++++

The ``von_anchor/a2a/docutil.py`` source contains utilities for DID document processing.

The ``resource()`` free function takes a URI and returns its resource, stripping off any anchor (``#``).

The ``canon_did()`` takes a URI that could be in URI fomrat and converts it to indy-sdk format if need be.

The ``canon_ref()`` takes a reference in a DID document, which could be a fragment (implicitly building on the identity DID for the document) or a full URI, and returns it in canonical URI form.

.. _did-info:

DIDInfo
###################################

The ``von_anchor/a2a/didinfo.py`` source file contains the ``DIDInfo`` class, which bundles information for a local DID in a wallet. It aggregates a DID, verification key, and metadata.

.. _pairwise-info:

PairwiseInfo
###################################

This section outlines the content of the ``von_anchor/a2a/pairwise.py`` source file, containing the ``PairwiseInfo`` class and utility functions.

The ``PairwiseInfo`` class bundles information for a pairwise DID to store via the indy-sdk non-secrets API in the wallet. It aggregates a remote DID and verification key, a local DID and verification key, and metadata.

The ``record2pairwise_info()`` free function creates a ``PairwiseInfo`` instance from a record that a indy-sdk non-secrets wallet API search returns.

The ``canon_pairwise_tag()`` free function canonicalizes a metadata attribute name into a tag for WQL use within the indy-sdk non-secrets API. Its operation prepends a tilde (``~``) for any attribute name not starting with one already; this nomenclature identifies the attribute for non-encrypted storage, allowing full WQL search.

The ``canon_pairwise_wql()`` free function canonicalizes WQL for use in the indy-sdk non-secrets API to search pairwise DIDs by metadata.

.. _endpoint-info:

EndpointInfo
###################################

The ``von_anchor/a2a/endpointinfo.py`` source file contains the ``EndpointInfo`` class, which bundles information for a remote DID endpoint. It aggregates an endpoint and a (transport) verification key. It exposes ``ip_addr``, ``port``, ``endpoint``, and ``verkey`` properties; an indy endpoint comprises colon-delimited IP address and port.
