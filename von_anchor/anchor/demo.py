"""
Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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


from von_anchor.anchor.holder_prover import HolderProver
from von_anchor.anchor.issuer import Issuer
from von_anchor.anchor.smith import AnchorSmith
from von_anchor.anchor.verifier import Verifier


class TrusteeAnchor(AnchorSmith):
    """
    TrusteeAnchor demonstrator class acts as an anchor smith to forge new anchors.
    """

    pass


class BCRegistrarAnchor(Issuer):
    """
    BCRegistrarAnchor demonstrator class acts as an issuer.
    """

    pass


class OrgBookAnchor(HolderProver):
    """
    OrgBookAnchor demonstrator class acts as a holder-prover.
    """

    pass


class SRIAnchor(Verifier, Issuer):
    """
    SRIAnchor demonstrator class acts as both an issuer of its own credentials and a verifier
    of any holder-prover's.
    """

    @staticmethod
    def role() -> str:
        """
        Return the indy-sdk role for SRI anchor.

        :return: role string
        """

        rv = 'TRUST_ANCHOR'
        return rv
