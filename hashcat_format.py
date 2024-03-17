#!/usr/bin/env python

"""
Translate hashcat output/potfile, decoding $HEX[...]  to the cleartext password.
    NOTE: The field separator may be in the cleartext password
    NOTE: Non-printable characters are retained in the output
    NOTE: Passwords not valid in UTF-8 are skipped (see -e,-v,-q switches)
"""

######################
#  IMPORT LIBRARIES  #
######################
import sys
import hashlib
import argparse
import fileinput
from argparse import RawDescriptionHelpFormatter

######################
## DEFINE FUNCTIONS ##
######################
def argument_parser() -> argparse.Namespace:
    """
    Parse shell arguments:
        -h, --help
            show this help message and exit
        -s, --separator SEPARATOR
            The column separator to use in the output file (default ':')

    File Management:
        -i, --input-file [FILE]
            The input file to parse, if omitted STDIN is used
        -o, --output-file OUTPUT_FILE
            Output file, if omitted STDOUT is used
        -e, --error-file ERROR_FILE
            Optional file to write lines that cannot be parsed

    Hash:
        -a, --hash-algorithm
        -u, --hash-upper      Output the hash value in UPPERCASE (default)
        -l, --hash-lower      Output the hash value in lowercase

    Output Verbosity:
        -v, --verbose         Verbose reporting of warnings (skipped lines) to STDERR (see -e switch)
        -q, --quiet           Suppress all console output (STDOUT/STDERR)

    """
    arg_parser = argparse.ArgumentParser(
        formatter_class = RawDescriptionHelpFormatter,
        description = "Translate hashcat output/potfile, decoding $HEX[...]  to the cleartext password.\n"\
                      "    NOTE: The field separator may be in the cleartext password\n"\
                      "    NOTE: Non-printable characters are retained in the output\n"\
                      "    NOTE: Passwords not valid in UTF-8 are skipped (see -e,-v,-q switches)")
    # GENERAL ARGUMENTS
    arg_parser.add_argument('-s','--separator',
                                default = ':',
                                help = "The column separator to use in the output file (default ':')")
    # FILE ARGUMENTS
    argument_group_files = arg_parser.add_argument_group('File Management')
    argument_group_files.add_argument('-i', '--input-file',
                                    metavar = 'FILE',
                                    nargs = '?',
                                    default = [],
                                    help = "The input file to parse, if omitted STDIN is used")
    argument_group_files.add_argument('-o', '--output-file',
                                    help = "Output file, if omitted STDOUT is used")
    argument_group_files.add_argument('-e', '--error-file',
                                    help = "Optional file to write lines that cannot be parsed")
    # HASH FORMATTING
    argument_group_hash_wrapper = arg_parser.add_argument_group('Hash')
    argument_group_hash_wrapper.add_argument('-a', '--hash-algorithm',
                                    default = 'sha1',
                                    help = 'Hash algorithm to use (default: sha1) options are: '\
                                           'sha1, sha224, sha256, sha384, sha512, '\
                                           'sha3_224, sha3_256, sha3_384, sha3_512, '\
                                           'blake2b, blake2s, md5')
    argument_group_hash = argument_group_hash_wrapper.add_mutually_exclusive_group()
    argument_group_hash.add_argument('-u', '--hash-upper',
                                    action='store_true',
                                    default=True,
                                    help='Output the hash value in UPPERCASE (default)')
    argument_group_hash.add_argument('-l', '--hash-lower',
                                    action='store_true',
                                    help='Output the hash value in lowercase')
    # CONSOLE OUTPUT
    argument_group_verbosity_parent =  arg_parser.add_argument_group('Output Verbosity')
    argument_group_verbosity = argument_group_verbosity_parent.add_mutually_exclusive_group()
    argument_group_verbosity.add_argument('-v', '--verbose',
                                        action='store_true',
                                        help="Verbose reporting of warnings (skipped lines) to STDERR (see -e switch)")
    argument_group_verbosity.add_argument('-q', '--quiet',
                                        action='store_true',
                                        help="Suppress all console output (STDOUT/STDERR)")
    script_arguments= arg_parser.parse_args()
    return script_arguments

def hash_string(text_string: str, hash_type: str = "sha1") -> str:
    """
    Returns a hex hash based on the hash_type and text_string provided
    """
    match hash_type:
        case "sha1":
            return hashlib.sha1(text_string.encode()).hexdigest().upper()
        case "sha224":
            return hashlib.sha224(text_string.encode()).hexdigest().upper()
        case "sha256":
            return hashlib.sha256(text_string.encode()).hexdigest().upper()
        case "sha384":
            return hashlib.sha384(text_string.encode()).hexdigest().upper()
        case "sha512":
            return hashlib.sha512(text_string.encode()).hexdigest().upper()
        case "sha3_224":
            return hashlib.sha3_224(text_string.encode()).hexdigest().upper()
        case "sha3_256":
            return hashlib.sha3_256(text_string.encode()).hexdigest().upper()
        case "sha3_384":
            return hashlib.sha3_384(text_string.encode()).hexdigest().upper()
        case "sha3_512":
            return hashlib.sha3_512(text_string.encode()).hexdigest().upper()
        # Shake requires an unknown length argument
        #case "shake_128":
        #    return hashlib.shake_128(text_string.encode()).hexdigest().upper()
        #case "shake_256":
        #    return hashlib.shake_256(text_string.encode()).hexdigest().upper()
        case "blake2b":
            return hashlib.blake2b(text_string.encode()).hexdigest().upper()
        case "blake2s":
            return hashlib.blake2s(text_string.encode()).hexdigest().upper()
        case "md5":
            return hashlib.md5(text_string.encode()).hexdigest().upper()
        case _:
            print(f"hash type: {hash_type}, not supported, exiting.")
            exit(-1)

def main() -> int:
    """
    Main entry point.
    """
    # Initialize counters
    counter_warnings = 0
    counter_errors   = 0
    counter_success  = 0

    # Parse arguments
    script_arguments = argument_parser()

    # Open files if specified
    if script_arguments.output_file:
        try:
            file_output = open(file=script_arguments.output_file, mode='w', encoding="utf-8")
        except IOError as err:
            print(f"ERROR: unable to open file '{script_arguments.output_file}' for writing", file=sys.stderr)
            print("    Details: ", end='', file=sys.stderr)
            print(Exception, err, file=sys.stderr)
            sys.exit(0)
    if script_arguments.error_file:
        try:
            file_error = open(file=script_arguments.error_file, mode='w', encoding="utf-8")
        except IOError as err:
            print(f"ERROR: unable to open file '{script_arguments.error_file}' for writing errors", file=sys.stderr)
            print("    Details: ", end='', file=sys.stderr)
            print(Exception, err, file=sys.stderr)
            sys.exit(0)

    # Process input file or STDIN
    for input_line in fileinput.input(files=script_arguments.input_file):
        input_line_list = input_line[0:-1].split(':',1)
        input_line_hash = input_line_list[0].upper()
        input_line_clear = input_line_list[1]
        if input_line_list[1][0:5] == '$HEX[':
            try:
                decoded_clear = bytes.fromhex(input_line_clear[5:-1]).decode()
                if input_line_hash ==  hash_string(decoded_clear,script_arguments.hash_algorithm):
                    cleartext_result = decoded_clear
                else:
                    if script_arguments.quiet is not True:
                        print(f"ERROR: hash mismatch, line #{fileinput.lineno()} skipped: {input_line[0:-1]}",\
                               file=sys.stderr)
                        counter_errors += 1
                    if script_arguments.error_file:
                        file_error.write(input_line)
                    continue
            except ValueError as err:
                if script_arguments.verbose:
                    print(f"WARNING: line #{fileinput.lineno()} skipped: {input_line[0:-1]}", file=sys.stderr)
                    print("    Details: ", end='', file=sys.stderr)
                    print(Exception, err, file=sys.stderr)
                if script_arguments.error_file:
                    file_error.write(input_line)
                counter_warnings += 1
                continue

        else:
            cleartext_result = input_line_clear

        try:
            if script_arguments.output_file:
                if script_arguments.hash_lower:
                    print(f"{input_line_hash.lower()}{script_arguments.separator}{cleartext_result}", file=file_output)
                else:
                    print(f"{input_line_hash.upper()}{script_arguments.separator}{cleartext_result}", file=file_output)
            else:
                if script_arguments.hash_lower:
                    print(f"{input_line_hash.lower()}{script_arguments.separator}{cleartext_result}")
                else:
                    print(f"{input_line_hash.upper()}{script_arguments.separator}{cleartext_result}")
            counter_success += 1
        except IOError as err:
            if script_arguments.verbose:
                print(f"ERROR: line #{str(fileinput.lineno())} skipped: {input_line[0:-1]}", file=sys.stderr)
                print("    Details: ", end='', file=sys.stderr)
                print(Exception, err, file=sys.stderr)
            if script_arguments.error_file:
                file_error.write(input_line)
            counter_errors += 1

    if script_arguments.quiet is not True:
        if script_arguments.output_file:
            if counter_success:
                print(f"{str(fileinput.lineno()).rjust(12)} lines processed from: {fileinput.filename()}")
                print(f"{str(counter_success).rjust(12)} lines written to: {file_output.name}.")
            if file_error:
                print(f"{str(counter_warnings + counter_errors).rjust(12)} errored lines written to: "\
                      f"{file_error.name}.")
            else:
                if counter_errors > 0:
                    print(f"Errors identified: {str(counter_errors)}", file=sys.stderr)
                if counter_warnings > 0:
                    print(f"Warnings detected: {counter_warnings} (use -v / --verbose for details)", file=sys.stderr)
    # CLEANUP
    fileinput.close()
    if script_arguments.output_file:
        file_output.close()
    if script_arguments.error_file:
        file_error.close()
    return

#####################
#  BEGIN PROCESSING #
#####################
if __name__ == '__main__':
    sys.exit(main())
