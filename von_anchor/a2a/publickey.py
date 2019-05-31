"""
Copyright 2017-2019 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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


from collections import namedtuple
from enum import Enum

from von_anchor.a2a.docutil import canon_did, canon_ref


LinkedDataKeySpec = namedtuple('LinkedDataKeySpec', 'ver_type authn_type specifier')


class PublicKeyType(Enum):
    """
    Class encapsulating public key types.
    """

    RSA_SIG_2018 = LinkedDataKeySpec(
        'RsaVerificationKey2018',
        'RsaSignatureAuthentication2018',
        'publicKeyPem')
    ED25519_SIG_2018 = LinkedDataKeySpec(
        'Ed25519VerificationKey2018',
        'Ed25519SignatureAuthentication2018',
        'publicKeyBase58')
    EDDSA_SA_SIG_SECP256K1 = LinkedDataKeySpec(
        'Secp256k1VerificationKey2018',
        'Secp256k1SignatureAuthenticationKey2018',
        'publicKeyHex')

    @staticmethod
    def get(val: str) -> 'PublicKeyType':
        """
        Return enum instance corresponding to input value ('RsaVerificationKey2018' etc.)

        :param val: input value marking public key type
        :return: public key type
        """

        for pktype in PublicKeyType:
            if val in (pktype.ver_type, pktype.authn_type):
                return pktype
        return None

    @property
    def ver_type(self) -> str:
        """
        Return verification type identifier in public key specification.

        :return: verification type
        """

        return self.value.ver_type

    @property
    def authn_type(self) -> str:
        """
        Return authentication type identifier in public key specification.

        :return: authentication type
        """

        return self.value.authn_type

    @property
    def specifier(self) -> str:
        """
        Return value specifier in public key specification.

        :return: value specifier in public key specification
        """

        return self.value.specifier

    def specification(self, val: str) -> str:
        """
        Return specifier and input value for use in public key specification.

        :param val: value of public key
        :return: dict mapping applicable specifier to input value
        """

        return {self.specifier: val}


class PublicKey:
    """
    Public key specification to embed in DID document. Retains DIDs as raw values
    (orientated toward indy-facing operations), everything else as URIs
    (oriented toward W3C-facing operations).
    """

    def __init__(
            self,
            did: str,
            ident: str,
            value: str,
            pk_type: PublicKeyType = None,
            controller: str = None,
            authn: bool = False) -> None:
        """
        Retain key specification particulars. Raise BadIdentifier on any bad input DID.

        :param did: DID of DID document embedding public key
        :param ident: identifier for public key
        :param value: key content, encoded as key specification requires
        :param pk_type: public key type (enum), default ED25519_SIG_2018
        :param controller: controller DID (default DID of DID document)
        :param authn: whether key as has DID authentication privilege (default False)
        """

        self._did = canon_did(did)
        self._id = canon_ref(self._did, ident)
        self._value = value
        self._type = pk_type or PublicKeyType.ED25519_SIG_2018
        self._controller = canon_did(controller) if controller else self._did
        self._authn = authn

    @property
    def did(self) -> str:
        """
        Return DID.

        :return: DID
        """

        return self._did

    @property
    def id(self) -> str:
        """
        Return public key identifier.

        :return: public key identifier
        """

        return self._id

    @property
    def type(self) -> PublicKeyType:
        """
        Return public key type.

        :return: public key type
        """

        return self._type

    @property
    def value(self) -> str:
        """
        Return public key value.

        :return: public key value
        """

        return self._value

    @property
    def controller(self) -> str:
        """
        Return controller DID.

        :return: controller DID
        """

        return self._controller

    @property
    def authn(self) -> bool:
        """
        Return whether public key is marked as having DID authentication privilege.

        :return: whether public key is marked as having DID authentication privilege
        """

        return self._authn

    @authn.setter
    def authn(self, value: bool) -> None:
        """
        Set or clear authentication marker.

        :param value: authentication marker
        """

        self._authn = value

    def to_dict(self):
        """
        Return dict representation of public key to embed in DID document.
        """

        return {
            'id': self.id,
            'type': str(self.type.ver_type),
            'controller': canon_ref(self.did, self.controller),
            **self.type.specification(self.value)
        }

    def __repr__(self):
        """
        Return representation.
        """

        return 'PublicKey({}, {}, {}, {}, {}, {})'.format(
            self.did,
            self.id,
            self.value,
            self.type,
            self.controller,
            self.authn)
