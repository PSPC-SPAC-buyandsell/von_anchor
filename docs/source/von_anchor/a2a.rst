******************************
Agent-to-Agent Utilities
******************************

This section outlines the utilities of ``a2a.py`` supporting inter-agent communications.

In this context, an agent comprises software built on top of ``von_anchor`` demonstrator classes or mixins, presenting an interface to the outside world - possibly only other agents. Such an agent or agents represent a service wrapper to VON anchor functionality.

Agent-to-agent protocols continue to evolve via the W3C and indy HIPE discussions. At present, ``a2a.py`` utilities revolve around the creation and parsing of DID documents.

Public Key Types
###################################

The ``PublicKeyType`` enum encapsulates public key types available for specification in DID documents. It relies on a ``LinkedDataKeySpec`` namedtuple that retains identifiers for verification and authentication, and the associated value specifier for such a key type occurring in DID document references. At present, the enum supports public key types:

* Ed25519Signature2018
* RsaSignature2018
* EdDsaSASignatureSecp256k1

as per http://w3c-ccg.github.il/ld-cryptosuite-registry.

Public Keys
###################################

The ``PublicKey`` class helps to specify public keys to embed in DID documents.

Each such key requires:

* the DID of the DID document embedding the public key
* an identifier (the class includes the ``PublicKey.ID_ROUTING`` class constant for the designated routing identifier)
* a public key type
* an owner, specified by DID
* a key value
* whether the public key is an authentication key in the context of a DID document.

The implementation stores the DID document subject and controller DIDs in raw base58 sovrin format, geared toward
interoperation with indy applications. It stores all other references as URIs, geared toward interoperation
with W3C applications.

The ``to_dict()`` method returns a dict representation of the public key to embed in a DID document.

Services
###################################

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

DID Document Class
###################################

The ``DIDDoc`` class represents a DID document.

The ``DIDDoc.CONTEXT`` class constant contains the context link for JSON-LD output; its value codifies the current version of the DID document specification.

The initializer takes only the DID that is the subject for the DID document. Note that in the context of the DID document, this is an ``id``.

The caller must use the accessor methods to populate (public) verification keys and endpoints.

The ``to_json()`` method outputs the DID document in its current state as JSON-LD. The static ``from_json()`` method returns a ``DIDDoc`` object from an input JSON-LD DID document.
