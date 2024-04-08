#!/usr/bin/env python
# -*- coding: UTF-8 -*-
""" convert a hex string into all supported python codecs """

# import modules
try:
    import argparse
    from argparse import RawDescriptionHelpFormatter
    import encodings
    import pkgutil
    import sys
    from typing import Union
except ImportError as import_error:
    print(f"An error occurred importing libraries:\n {type(import_error).__name__} - {import_error}")
    quit(-1)

# define functions
def parse_arguments(
    ) -> Union[argparse.ArgumentParser, bool]:
    """ Parse shell arguments """
    # create argparse instance
    try:
        # define arguments
        arg_parser = argparse.ArgumentParser(
            formatter_class = RawDescriptionHelpFormatter,
            description =
                "Convert a hex string to all supported python encodings to identify potential text equivalents.")
        # general arguments
        arg_parser.add_argument(
            '-i', '--input',
            default = None,
            type = str,
            help = 'Hex string to convert with no leading 0x  e.g. [313233] not [0x313233]')
        arg_parser.add_argument(
            '-a', '--all',
            action = 'store_true',
            default = False,
            help = "Show encodings that cannot fully decode the hex string. Characters that cannot be decoded are " \
                   "replaced with � (U+FFFD)")
        return arg_parser
    except OSError as error:
        print("ERROR: An error occurred parsing arguments:\n:" \
            f"{type(error).__name__} - {error}",
            file=sys.stderr)
        return False

def get_encodings() -> list:
    """ get a list of supported encodings in the running version of python """
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
):
    """ convert hex value to string using all supported encoding formats """
    successes = dict()
    failures = []
    if show_all:
        for encoding in encoding_list:
            successes[encoding] = bytes.fromhex(hex_value).decode(encoding = encoding, errors = 'replace')
    else:
        for encoding in encoding_list:
            try:
                successes[encoding] = bytes.fromhex(hex_value).decode(encoding = encoding, errors = 'strict')
            except UnicodeDecodeError:
                failures.append(encoding)
    print(f"{'Encoding'.ljust(20)} | Value: ")
    print("------------------------------")
    for key, value in successes.items():
        print(f"{str(key).ljust(20)} | {value}")

def main() -> int:
    """ collect arguments, parse settings and init based on threading selection """
    # collect shell arguments and process settings
    arg_parser = parse_arguments()
    arguments = arg_parser.parse_args()
    # check if scripts expects data over <STDIN> and return help screen if TTY detected
    if not arguments.input and sys.stdin.isatty():
        arg_parser.print_help()
        sys.exit(0)
    # process job
    if arguments.input:
        test_encodings_hex(hex_value = arguments.input, encoding_list = get_encodings(), show_all=arguments.all)
    else:
        test_encodings_hex(hex_value = sys.stdin.readline(), encoding_list = get_encodings(), show_all=arguments.all)


# auto start if called directly
if __name__ == '__main__':
    sys.exit(main())
