#!/usr/bin/env python
# -*- coding: UTF-8 -*-
""" convert a hex string into all supported python codecs """

import pkgutil
import encodings

def get_encodings() -> list:
    """ get a list of supported encodings in the running version of python"""
    false_positives = set([
        # encoding aliases
        'aliases',
        # python specific text encodings
        'idna', 'mbcs', 'oem', 'palmos', 'punycode', 'raw_unicode_escape', 'undefined', 'unicode_escape',
        # python specific binary transforms
        'base64_codec', 'bz2_codec', 'hex_codec', 'quopri_codec', 'uu_codec', 'zlib_codec',
        # Non-text encodings
        'rot_13'
        ])

    supported_encodings = set(name for imp, name, ispkg in pkgutil.iter_modules(encodings.__path__) if not ispkg)
    supported_encodings.difference_update(false_positives)
    supported_encodings = sorted(supported_encodings)
    return supported_encodings

def test_encodings_hex(
        hex_value: str,
        encoding_list: list,
        show_all: bool = False
) -> dict:
    """ convert hex value to string using all supported encoding formats """
    successes = dict()
    failures = []
    if show_all:
        for encoding in encoding_list:
            successes[encoding] = bytes.fromhex(hex_value).decode(encoding=encoding, errors='replace')
    else:
        for encoding in encoding_list:
            try:
                successes[encoding] = bytes.fromhex(hex_value).decode(encoding=encoding, errors='strict')
            except UnicodeDecodeError:
                failures.append(encoding)
    print("Successes:")
    for key, value in successes.items():
        print(f"Encoding: {str(key).ljust(20)}Value: [{value}]")
    print("\n\nFailures:")
    print(*failures, sep='\n')

test_encodings_hex('d0bad0bed13fd13fd0bdd0bed0ba323031310d', get_encodings(), show_all=False)
# test_encodings_hex('35454561', get_encodings())
