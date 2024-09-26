#!/usr/bin/env python3

import argparse
import sys
import os.path

from saml2.config import Config
from saml2.mdstore import MetadataStore
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
import base64

_version = 0.1

def main():
    # parse arguments
    parser = argparse.ArgumentParser(description='Get x509 certificates from SAML metadata. Either an idP or SP metadata XML document or URL can be supplied.  The certificates will be extracted to files local to where you run this script.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--version', action='version', version='%(prod)s {}'.format(_version))
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='Turn on debugging')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Turn on verbose output')
# todo - add validator to see if file exists or location is a URL
    parser.add_argument(dest='metadata_location', type=str, help='metadata XML file or URL to metadata')

    args = parser.parse_args()

    if args.debug is True:
        print(args.__dict__)
        for key in args.__dict__:
            print('args.{} == {}'.format(key, args.__dict__[key]))

    mds = MetadataStore(attrc=None, config=Config())

    if urlparse(args.metadata_location).scheme in ['http', 'https']:
        mds.load("remote", url=args.metadata_location)
    else:
        # check if file exists
        if os.path.isfile(args.metadata_location):
            mds.load("local", args.metadata_location)
        else:
            print('ERROR: filename supplied does not exist - "{}"'.format(args.metadata_location))
            sys.exit(1)

    if args.debug is True:
        print('mds == {}'.format(mds))
        print('mds type == {}'.format(type(mds)))
        print('mds.entities() == {}'.format(mds.entities()))
        print('mds length() == {}'.format(len(mds)))
        print('mds.keys() == {}'.format(mds.keys()))
        print('mds.name() == {}'.format(mds.name('http://christopher.instructure.com/saml2')))
        print('mds.metadata.entity == {}'.format(mds.metadata[args.metadata_location].entity))
        print('mds.metadata.entity keys == {}'.format(mds.metadata[args.metadata_location].entity.keys()))
        for _entity in mds.metadata[args.metadata_location].entity.keys():
            print('mds.entity_id == {}'.format(_entity))

    # this is a little kludgy, but generally there should be only 1 entity_id in the supplied location
    # so, just taking the first one
    entity_id = list(mds.metadata[args.metadata_location].entity.keys())[0]

    # there can be one or two certificates included in the metadata
    _encryption_cert = mds.certs(entity_id, descriptor='any', use='encryption')
    _signing_cert = mds.certs(entity_id, descriptor='any', use='signing')

    cert_list = []

    if not _encryption_cert:
        if args.verbose is True:
            print('no encryption certificate')
    else:
        cert_list.append({'cert':_encryption_cert, 'type':'encryption'})
    if not _signing_cert:
        if args.verbose is True:
            print('no signing certificate')
    else:
        cert_list.append({'cert':_signing_cert, 'type':'signing'})

    for cert_type in cert_list:
        cert = x509.load_der_x509_certificate(base64.b64decode(cert_type["cert"][0][1]), default_backend())
        if args.debug is True:
            print('cert == {}'.format(cert))
            print('cert.subject == ({}) {}'.format(len(cert.subject), cert.subject))
            for attribute in cert.subject:
                print('cert.subject attribute == {}'.format(attribute))
                print('cert.subject attribute value == {}'.format(attribute.value))
            print('cert.issuer == {}'.format(cert.issuer))
            print('cert.start_date == {}'.format(cert.not_valid_before))
            print('cert.end_date == {}'.format(cert.not_valid_after))
            print('cert.version == {}'.format(cert.version))
            print('cert.fingerprint() == {}'.format(cert.fingerprint(hashes.SHA256())))
            print('cert.serial_number == {}'.format(cert.serial_number))
            print('cert.signature_hash_algorithm == {}'.format(cert.signature_hash_algorithm))
        if args.verbose is True:
            print('cert.subject == {}'.format(cert.subject))
            print('cert.issuer == {}'.format(cert.issuer))
            print('cert.start_date == {}'.format(cert.not_valid_before))
            print('cert.end_date == {}'.format(cert.not_valid_after))

        # get a structed breakdown of the location to create a nice (i.e. sanitised) filename
        parsed_location = urlparse(entity_id)
        if args.debug is True:
            print(parsed_location)
        if parsed_location.hostname is None:
            # location must be a file
            cert_filename = f"{parsed_location.path.replace('.','_')}_{cert_type['type']}.crt"
        else:
            # location must be a URL
            cert_filename = f"{parsed_location.hostname.replace('.', '_')}_{parsed_location.path.replace('/','_')}_{cert_type['type']}.crt"
        if args.debug is True:
            print(cert_filename)
        with open(cert_filename, 'wb') as ofp:
            ofp.write(cert.public_bytes(Encoding.PEM))
        print('Certificate saved - "{}"'.format(cert_filename))

if __name__ == '__main__':
    main()

# vim:expandtab ts=4 sw=4
# END OF FILE
