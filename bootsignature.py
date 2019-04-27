#!/usr/bin/env python

from __future__ import print_function

import argparse
import hashlib
import os
import shutil
import struct
import sys

from M2Crypto import RSA, X509
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import char, namedtype, univ
from pyasn1_modules import rfc2459, rfc4055


class AuthenticatedAttributes(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('target', char.PrintableString()),
        namedtype.NamedType('length', univ.Integer())
    )


class BootSignature(univ.Sequence):
    """
    BootSignature ::= SEQUENCE {
        formatVersion ::= INTEGER
        certificate ::= Certificate
        algorithmIdentifier ::= SEQUENCE {
            algorithm OBJECT IDENTIFIER,
            parameters ANY DEFINED BY algorithm OPTIONAL
        }
        authenticatedAttributes ::= SEQUENCE {
            target CHARACTER STRING,
            length INTEGER
        }
        signature ::= OCTET STRING
    }
    """

    _FORMAT_VERSION = 1

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('formatVersion', univ.Integer()),
        namedtype.NamedType('certificate', rfc2459.Certificate()),
        namedtype.NamedType('algorithmIdentifier',
                            rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('authenticatedAttributes',
                            AuthenticatedAttributes()),
        namedtype.NamedType('signature', univ.OctetString())
    )

    @classmethod
    def create(cls, target, length):
        boot_signature = cls()
        boot_signature['formatVersion'] = cls._FORMAT_VERSION
        boot_signature['authenticatedAttributes']['target'] = target
        boot_signature['authenticatedAttributes']['length'] = length
        return boot_signature


def __get_signable_image_size(f):
    magic = f.read(8)
    if magic != 'ANDROID!':
        raise ValueError('Invalid image header: missing magic')

    header = struct.Struct('<'    # little endian
                           + 'i'  # kernel_size
                           + 'i'  # kernel_addr
                           + 'i'  # ramdisk_size
                           + 'i'  # ramdisk_addr
                           + 'i'  # second_size
                           + 'q'  # second_addr + tags_addr
                           + 'i'  # page_size
                           )

    header_raw = f.read(header.size)
    header_struct = header.unpack_from(header_raw)

    kernel_size = header_struct[0]
    ramdsk_size = header_struct[2]
    second_size = header_struct[4]
    page_size = header_struct[6]

    # include the page aligned image header
    length = page_size \
             + ((kernel_size + page_size - 1) // page_size) * page_size \
             + ((ramdsk_size + page_size - 1) // page_size) * page_size \
             + ((second_size + page_size - 1) // page_size) * page_size

    length = ((length + page_size - 1) // page_size) * page_size

    if length <= 0:
        raise ValueError('Invalid image header: invalid length')

    return length


def get_signable_image_size(image_path):
    with open(image_path, 'rb') as f:
        return __get_signable_image_size(f)


def get_image_hash(image_path, extra_data=None, chunk_size=1*1024*1024):
    digest = hashlib.sha256()

    with open(image_path, 'rb') as f:
        for block in iter(lambda: f.read(chunk_size), b''):
            digest.update(block)

    if extra_data is not None:
        digest.update(extra_data)

    return digest.digest()


def sign(target, image_path, key_path, cert_path):
    image_length = os.path.getsize(image_path)
    signable_size = get_signable_image_size(image_path)

    if signable_size < image_length:
        print('NOTE: truncating file', image_path, 'from', image_length,
              'to', signable_size, 'bytes', file=sys.stderr)
        with open(image_path, 'rb+') as f:
            f.truncate(signable_size)
    elif signable_size > image_length:
        raise ValueError('Invalid image: too short, expected {} bytes'.format(signable_size))

    boot_signature = BootSignature.create(target, image_length)

    cert = X509.load_cert(cert_path)
    cert_decoded, _ = der_decoder(cert.as_der(), asn1Spec=rfc2459.Certificate())
    boot_signature['certificate'] = cert_decoded

    authenticated_attributes = boot_signature['authenticatedAttributes']
    encoded_authenticated_attributes = der_encoder(authenticated_attributes)

    digest = get_image_hash(image_path,
                            extra_data=encoded_authenticated_attributes)

    key = RSA.load_key(key_path)
    signature = key.sign(digest, algo='sha256')

    boot_signature['signature'] = signature
    boot_signature['algorithmIdentifier']['algorithm'] = rfc4055.sha256WithRSAEncryption

    encoded_boot_signature = der_encoder(boot_signature)

    with open(image_path, 'ab') as f:
        f.write(encoded_boot_signature)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sign android boot image.')
    parser.add_argument('-t', '--target', required=True,
                        help='target name, typically /boot')
    parser.add_argument('-k', '--key', required=True,
                        help='path to a private key (PEM)')
    parser.add_argument('-c', '--cert', required=True,
                        help='path to the matching public key certificate')
    parser.add_argument('-i', '--input', required=True,
                        help='path to boot image to sign')
    parser.add_argument('-o', '--output', required=True,
                        help='where to output the signed boot image')
    args = parser.parse_args()

    shutil.copy(args.input, args.output)

    sign(target=args.target, image_path=args.input,
         key_path=args.key, cert_path=args.cert)
