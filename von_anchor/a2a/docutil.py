"""
Copyright 2017-2020 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from urllib.parse import urlparse

from von_anchor.error import BadIdentifier
from von_anchor.util import ok_did


def resource(ref: str, delimiter: str = None) -> str:
    """
    Given a (URI) reference, return up to its delimiter (exclusively), or all of it if there is none.

    :param ref: reference
    :param delimiter: delimiter character (default None maps to '#', or ';' introduces identifiers)
    """

    return ref.split(delimiter if delimiter else '#')[0]


def canon_did(uri: str) -> str:
    """
    Convert a URI into a DID if need be, left-stripping 'did:sov:' if present.
    Return input if already a DID. Raise BadIdentifier for invalid input.

    :param uri: input URI or DID
    :return: corresponding DID
    """

    if ok_did(uri):
        return uri

    if uri.startswith('did:sov:'):
        rv = uri[8:]
        if ok_did(rv):
            return rv
    raise BadIdentifier('Bad specification {} does not correspond to a sovrin DID'.format(uri))


def canon_ref(did: str, ref: str, delimiter: str = None):
    """
    Given a reference in a DID document, return it in its canonical form of a URI.

    :param did: DID acting as the identifier of the DID document
    :param ref: reference to canonicalize, either a DID or a fragment pointing to a location in the DID doc
    :param delimiter: delimiter character marking fragment (default '#') or
        introducing identifier (';') against DID resource
    """

    if not ok_did(did):
        raise BadIdentifier('Bad DID {} cannot act as DID document identifier'.format(did))

    if ok_did(ref):  # e.g., LjgpST2rjsoxYegQDRm7EL
        return 'did:sov:{}'.format(did)

    if ok_did(resource(ref, delimiter)):  # e.g., LjgpST2rjsoxYegQDRm7EL#keys-1
        return 'did:sov:{}'.format(ref)

    if ref.startswith('did:sov:'):  # e.g., did:sov:LjgpST2rjsoxYegQDRm7EL, did:sov:LjgpST2rjsoxYegQDRm7EL#3
        rv = ref[8:]
        if ok_did(resource(rv, delimiter)):
            return ref
        raise BadIdentifier('Bad URI {} does not correspond to a sovrin DID'.format(ref))

    if urlparse(ref).scheme:  # e.g., https://example.com/messages/8377464
        return ref

    return 'did:sov:{}{}{}'.format(did, delimiter if delimiter else '#', ref)  # e.g., 3
