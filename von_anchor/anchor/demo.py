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


TrusteeAnchor = type('TrusteeAnchor', (AnchorSmith,), {})
SRIAnchor = type('SRIAnchor', (Verifier, Issuer), {})
BCRegistrarAnchor = type('BCRegistrarAnchor', (Issuer,), {})
OrgBookAnchor = type('OrgBookAnchor', (HolderProver,), {})
