``````````````````````````````
Utility Functions
``````````````````````````````

This section outlines utilities available within the package. Utility functions reside in files ``von_anchor/util.py``, ``von_anchor/indytween.py``, and ``von_anchor/canon.py``. File ``von_anchor/frill.py`` holds niceties for common use cases, debugging and troubleshooting.

Utilities in util.py
###################################

This section discusses utilities in ``von_anchor/util.py``.

.. _id_wranglers:

Identifier Wranglers
***********************************

File ``von_anchor/util.py`` exposes several functions to work with indy-sdk identifiers.

Identifiers for indy-sdk schemata, credential definitions, and revocation registry definitions take forms as per the following table.

.. csv-table::
   :header: "Identifier Type", "Format", "Example"
   :widths: 25, 50, 50

    "Schema Identifier", "<origin-did>:2:<schema-name>:<schema-version>","V4SGRU86Z58d6TV7PBUe6f:2:gvt:1.0"
    "Credential Definition Identifier (short form)", "<issuer-did>:3:CL:<schema-seq-no>:<tag>", "V4SGRU86Z58d6TV7PBUe6f:3:CL:13:tag"
    "Credential Definition Identifier (long form)", "<issuer-did>:3:CL:<origin-did>:2:<schema-name>:<schema-version>:<tag>", "V4SGRU86Z58d6TV7PBUe6f:3:CL:V4SGRU86Z58d6TV7PBUe6f:2:gvt:1.0:tag"
    "Revocation Registry Identifier", "<issuer-did>:4:<cred-def-id>:CL_ACCUM:<tag>", "V4SGRU86Z58d6TV7PBUe6f:4:V4SGRU86Z58d6TV7PBUe6f:3:CL:13:tag:CL_ACCUM:0"

Table: Identifiers Forms within indy-sdk

The ``schema_id()`` function returns a schema identifier on the input origin DID, schema name, and schema version.

The ``schema_key()`` function returns a SchemaKey named tuple corresponding to the input schema identifier.

The ``cred_def_id()`` function returns a credential definition identifier on input issuer DID and schema sequence number. Recall that a schema may root a credential definition for any issuer anchor.

The ``cred_def_id2schema_seq_no_or_id()`` function returns the schema sequence number or schema identifier from an input credential definition identifier. By construction, VON anchor ``Issuer`` anchors :ref:`issuer` always create short-form credential definition identifiers with a schema sequence number (see :ref:`id_wranglers`). Other implementations of indy-sdk may, if they create a credential definition from a schema not having a ledger transaction sequence number, generate credential definition identifiers with a schema identifier instead.

The ``rev_reg_id()`` function returns a revocation registry identifier on input credential definition identifier and tag. Recall that a credential definition may root a revocation registry per issuer and tag.

The ``rev_reg_id2cred_def_id()`` function returns the credential definition identifier embedded in the input revocation registry identifier.

The ``rev_reg_id2tag()`` function returns the tag of an input revocation registry identifier.

The ``rev_reg_id2cred_def_id__tag()`` convenience function returns the a tuple with the credential definition identifier, and the tag, embedded in the input revocation registry identifier.

The ``ok_endpoint()``, ``ok_wallet_reft()``, ``ok_did()``, ``ok_role()``, ``ok_schema_id()``, ``ok_cred_def_id()``, and ``ok_rev_reg_id()`` functions return whether, on composition alone, their respective input strings represent acceptable indy endpoints, wallet referents (a.k.a. wallet credential uuids or wallet credential identifiers), DIDs, indy anchor roles, schema identifiers, credential definition identifiers, and revocation registry identifiers.

The ``did2uri()`` and ``uri2did()`` functions convert between native sovrin (base58) DIDs and their corresponding URIs. The conversion is straightforward: the URI formulation prepends ``did:sov:`` to the native DID.

.. _wranglers:

Credential and Proof Data Structure Wranglers
**********************************************************************

File ``von_anchor/util.py`` houses several functions to work with indy-sdk credential and proof data structures for display, triage, and filtration.

Utility ``iter_briefs()`` takes a cred-info or cred-brief, an iterable collection thereof, or a cred-brief-dict as per :ref:`cred-like-data`. It returns a tuple comprising all cred-briefs (or cred-infos) in the input. This utility is primarily for VON anchor code.

Utility ``box_ids()`` takes a cred-info; a cred-brief, an iterable collection thereof, or a cred-brief-dict as per :ref:`cred-like-data`; and an optional list of wallet credential identifiers (a.k.a. referents; default all credentials) for inclusion (default all). It returns a python dict mapping each input credential identifier to its box identifier dict (schema identifier, credential definition identifier, revocation registry identifier). This operation can be useful in choosing credentials of interest.

Utility ``prune_creds_json()`` takes an indy-sdk credentials structure and a set of wallet credential identifiers (a.k.a. referents). It returns an indy-sdk credentials JSON structure on pruned of any credentials that the input set does not identify. This operation can be useful in narrowing the focus of a set of credentials for proof – recall that indy-sdk can create proof on at most one credential per credential definition at a time.

Utility ``proof_req_infos2briefs()`` takes a proof request and a cred-info or iterable collection thereof. Its operation matches the cred-infos against the proof request and computing any corresponding non-revocation intervals to build and return a list of cred-briefs (recall that the holder-prover anchor's proof creation method accepts either a credentials structure or a list of cred-briefs as per :ref:`cred-like-data`). The input proof request must have credential definition identifier restrictions on all requested attribute specifications.

Utility ``proof_req_briefs2req_creds()`` takes a proof request and a cred-info orcred-brief, an iterable collection thereof, or a cred-brief-dict as per :ref:`cred-like-data`, and builds a requested-credentials structure for proof creation. The input proof request must have credential definition identifier restrictions on all requested attribute and predicate specifications.

Utility ``proof_req2wql_all()`` takes a proof request, which must have credential definition identifier restrictions on all requested attribute specifications, and an optional list of excepted credential definition identifiers to omit. It returns a dict of extra WQL queries for use in credential searching that will find all credentials in the wallet, exactly once, not including those on any input list of excepted credential definition identifiers. The caller would then augment this dict of extra WQL queries with logic for the attributes of excepted credential definition identifiers.

Utility ``proof_req_attr_referents()`` takes a proof request, which must have credential definition identifier restrictions on all requested attribute specifications. Its operation creates and returns a nested dict mapping credential identifiers to attribute names to item referents in the proof request. This intermediary structure can help callers build extra WQL queries for credential search with proof request: since indy-sdk keys extra WQL queries by proof request item referent, callers with logic concerning any attribute in a given credential definition identifier can use this structure to bridge the gap.

Utility ``proof_req_pred_referents()`` takes a proof request, which must have credential definition identifier restrictions on all requested attribute specifications. Its operation creates and returns a nested dict mapping credential identifiers to attribute names to item referents (in the proof request) to a 2-list of predicate specifiers: operator and bound. This intermediary structure helps VON anchor code specify and apply predicates as required.

Utility ``creds_display()`` takes an indy-sdk credentials structure; cred-info or cred-brief, an iterable collection thereof, or a cred-brief-dict as per :ref:`cred-like-data`; an optional filter; and an optional inclusivity toggle. The filter is a python dict mapping schema identifiers to their own python dicts, each mapping an attribute name of the schema to a value. Should the credentials structure include credentials on more than one schema, the inclusivity toggle informs the operation whether to include those that the filter does not cite (default, True) or not (False). The output is a python dict mapping credential identifiers to human-readable cred-info content; e.g.,

.. code-block:: json

    {
        "5820a07c-d92e-4ba3-8d8b-0799ee4338ec": {
            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:15:tag",
            "schema_id": "Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0",
            "referent": "5820a07c-d92e-4ba3-8d8b-0799ee4338ec",
            "attrs": {
                "endDate": "None",
                "orgTypeId": "2",
                "effectiveDate": "2012-12-01",
                "legalName": "Tart City",
                "busId": "11144444",
                "id": "3",
                "jurisdictionId": "1"
            },
            "rev_reg_id": "Q4zqM7aXqm7gDQkUVLng9h:4:Q4zqM7aXqm7gDQkUVLng9h:3:CL:15:0:CL_ACCUM:tag",
            "cred_rev_id": "3"
        },
        "c28b99dc-d800-3cf6-808f-913ba8b90fee": {
            "cred_def_id": "Q4zqM7aXqm7gDQkUVLng9h:3:CL:15:tag",
            "schema_id": "Q4zqM7aXqm7gDQkUVLng9h:2:bc-reg:1.0",
            "referent": "c28b99dc-d800-3cf6-808f-913ba8b90fee",
            "attrs": {
                "endDate": "None",
                "orgTypeId": "2",
                "effectiveDate": "2018-12-01",
                "legalName": "Flan Nebula",
                "busId": "11198765",
                "id": "4",
                "jurisdictionId": "1"
            },
            "rev_reg_id": "Q4zqM7aXqm7gDQkUVLng9h:4:Q4zqM7aXqm7gDQkUVLng9h:3:CL:15:0:CL_ACCUM:tag",
            "cred_rev_id": "4"
        }
    }

for display and triage. This operation can be useful for an actuator to work with a human operator to choose cred-infos of interest (dict values), isolate their credential identifiers (dict keys), and feed them back to prune_creds_json(), for example.

Utility ``revoc_info()`` takes a cred-info or cred-brief, an iterable collection thereof, or a cred-brief-dict as per :ref:`cred-like-data`; and an optional filter mapping attribute names to values. It returns a python dict mapping revocation data pairs (revocation registry identifier, credential revocation identifier within the revocation registry) to the (stringified representations of) attributes of credentials matching the input filter; e.g., 

.. code-block:: python

    {
        ('Q4zqM7aXqm7gDQkUVLng9h:4:Q4zqM7aXqm7gDQkUVLng9h:3:CL:15:0:CL_ACCUM:tag', '3'):
            {
                'busId': '11144444',
                'effectiveDate': '2012-12-01',
                'endDate': 'None',
                'id': '3',
                'jurisdictionId': '1',
                'legalName': 'Tart City',
                'orgTypeId': '2'
            },
        ('Q4zqM7aXqm7gDQkUVLng9h:4:Q4zqM7aXqm7gDQkUVLng9h:3:CL:15:0:CL_ACCUM:tag', '4'):
            {
                'busId': '11198765',
                'effectiveDate': '2018-01-01',
                'endDate': 'None',
                'id': '4',
                'jurisdictionId': '1',
                'legalName': 'Flan Nebula',
                'orgTypeId': '2'
            },
        ...
    }

for an actuator to work with a human to isolate a credential of interest to revoke by its revocation data.

Utility ``revealed_attrs()`` takes an indy-sdk proof and returns its revealed attributes, credential by credential, as a python dict mapping each credential definition identifier to its attribute names and their corresponding (decoded) values in the proof; e.g.,

.. code-block:: json

    {
        "Q4zqM7aXqm7gDQkUVLng9h:3:CL:16:tag": {
            "effectivedate": "2012-12-01",
            "enddate": null,
            "id": 3,
            "busid": "11144444",
            "orgtypeid": 2,
            "jurisdictionid": 1,
            "legalname": "Tart City"
        }
    }

for an actuator to build proof of one credential into another that stems from it (recall that an indy-sdk proof can have at most one credential per credential definition). Mapping attributes from the credential definitions in the proof to relying credential definitions must be an exercise for the actuator (or possibly the VON-X layer), but note that indy-sdk canonicalizes attribute names in proofs (also, credential offers) – the ``canon()`` utility of :ref:`canon-util` may be of interest in navigating this detail.

.. _canon-util:

Canonicalization Utilities
###################################

File ``von_anchor/canon.py`` houses utilities to canonicalize attribute names as proofs, credential offers, and WQL queries require.

The ``canon()`` convenience method canonicalizes an attribute name to its indy-sdk representation inside proofs and credential offers. This canonicalization is simple: it eliminates internal spaces and converts to lower case.

The ``canon_wql()`` convenience method canonicalizes an WQL attribute marker and value keys for input to credential search. The caller need not use this method; the anchor search methods already call it before applying WQL queries.

The ``canon_non_secret_wql()`` free function canonicalizes WQL for use in the indy-sdk non-secrets API to search non-secret records by metadata. It coerces comparison values to strings.

The ``canon_pairwise_tag()`` free function canonicalizes a metadata attribute name into a tag for WQL use within the indy-sdk non-secrets API. Its operation prepends a tilde (``~``) for any attribute name not starting with one already; this nomenclature identifies the attribute for non-encrypted storage, allowing full WQL search.

The ``canon_pairwise_wql()`` free function canonicalizes WQL for use in the indy-sdk non-secrets API to search pairwise DIDs by metadata. It delegates to ``canon_pairwise_tag()`` to mark all attributes for non-encrypted storage, and coerces comparison values to strings.


Indytween Utilities
###################################

File ``von_anchor/indytween.py`` houses utilities to go in between VON anchor and the indy-sdk.

Schema Key
***********************************

The content of a ``SchemaKey`` named tuple instance specifies a schema unambiguously through its ``origin_did``, ``name``, and ``version`` slots. Historically, the indy-sdk ledger used schema keys to identify schemas before migrating to schema identifiers. At present, the VON anchor design retains the schema key abstraction principally to help disambiguate calls to get a schema via ``_BaseAnchor.get_schema()`` as per :ref:`base-anchor`.

Relation and Predicates
***********************************

The ``Relation`` named tuple retains nomenclature by Fortran, WQL, and mathematical conventions, plus ``yes`` and ``no`` slots for lambdas indicating predicate satisfaction or failure.

The ``Predicate`` enumeration specifies predicate relations as they appear in indy-sdk data specifications and VON anchor filters. Each takes a ``Relation`` namedtuple as its value; the ``yes`` and ``no`` lambdas for satisfaction or failure use an int converter to map reasonable values to integers before comparison. Reasonable values include integers, stringified integers, and booleans. They do not include floating point numbers as indy-sdk predicates only operate on 32-bit integers as the encoding specification earmarks them.

Encoding
***********************************

The encoding implementation operates on indy-sdk attributes. Recall that indy-sdk operates elliptic curve cryptography on (immense) numeric input, and hence its callers must map all attribute values to non-negative integers for processing. Each attribute in indy-sdk structures carries a dict mapping raw and encoded keys to their respective values. Note however that indy-sdk has a 256-bit limit on encoded (integer) values.

The ``cred_attr_value()`` convenience method takes a raw value and returns its indy-sdk mapping to its raw and encoded values.

The ``encode()`` functions convert attribute values to a (numeric string) form that the indy-sdk can use in issuing credentials, creating proofs, and in verifying proofs. Booleans, integers, and stringified integers encode to their corresponding stringified 32-bit integer values.

Motivation: Predicates Need int32 Encoding
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The indy-sdk requires any attributes that might be used in predicate proofs be 32-bit integers, such that the encoded value equals the raw value.

Motivation: Encodings Must Be Stringified 256 Bit Integers
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The indy-sdk requires all encodings' corresponding integers to fit into 256 bits to guarantee proper operation.

Solution: 32-bit Integer Check and SHA-256
++++++++++++++++++++++++++++++++++++++++++++++++++++

The ``encode()`` function leaves (signed) 32-bit integers alone, encoding them to their string representations. For all other content, the implementation stringifies, then uses SHA-256 and big-endian byte ordering and stringification again to build a stringified large integer. Note that indy-sdk requires only that 32-bit integers (and only 32-bit integers) encode to their own stringified representations.

Role
***********************************

The ``Role`` enumeration specifies indy-sdk roles for use in cryptonyms:

* ``STEWARD`` for a steward role, which operates the node pool
* ``TRUSTEE`` for a trustee role, which sends cryptonyms to the ledger for other anchors
* ``TRUST_ANCHOR`` for a trust anchor role, which writes artifacts to the ledger
* ``USER`` for a self-sovereign user role, which reads artifacts and writes its own entries on the ledger.
* ``ROLE_REMOVE`` for the (temporary) role sentinel marking a reassignment operation in progress on the ledger.

Frills
###################################

This section discusses utilities in ``von_anchor/frill.py``.

Function ppjson()
***********************************

The ``ppjson()`` utility takes a JSON serialized or serializable structure and returns a pretty-print. If the structure is not compatible with JSON, it returns a python pretty-print instead. An optional parameter allows a maximum length, at which the operation truncates the output (excluding three characters for a terminating ellipsis).

Function do_wait()
***********************************

The ``do_wait`` utility takes a coroutine. Its operation creates an event loop if necessary, then runs the coroutine on the event loop and returns the response. Users of ``von_agent`` may use this nicety to run an asynchronous method in synchronous space.

Function inis2dict()
***********************************

The ``inis2dict()`` utility takes a path to a Windows ``.ini``-style configuration file or an iterable collection thereof. Its operation parses such files and returns a ``dict`` with their configuration (string) data, nesting a further ``dict`` for each section. The processing interpolates bash-style environment variables with braces (e.g., ``${HOME}``), substituting defaults where specified (e.g., ``${VAR:-DEFAULT}`` would interpolate to ``DEFAULT`` if the environment did not set ``${VAR}``).

Input configuration files must not repeat section headers.

Class Stopwatch
***********************************

The ``Stopwatch`` class provides a timer of configurable precision to help profile operations.

Class Ink
***********************************

The ``Ink`` enumeration colours text to highlight content of interest on output.
