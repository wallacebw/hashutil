#!/usr/bin/env python

"""
Translate a file of cleartext strings (passwords) to hashes.
    NOTE: The field separator may be in the cleartext password
    NOTE: Non-printable characters are retained in the output
    NOTE: Strings not valid in UTF-8 are skipped
"""

######################
#  IMPORT LIBRARIES  #
######################
import argparse
from argparse import RawDescriptionHelpFormatter
import fileinput
import hashlib
import os
import sys


######################
## DEFINE FUNCTIONS ##
######################
def argument_parser() -> argparse.Namespace:
    """
    Parse shell arguments
    Help return is:
    -----------------
    usage: hash_generator.py [-h] [-s SEPARATOR] [-n] [-i [FILE]] [-o OUTPUT_FILE] [-e ERROR_FILE] [-a HASH_ALGORITHMS]
           [-l | -u] [-v | -q]

    Translate a file of cleartext strings (passwords) to hashes
        NOTE: The field separator may be in the cleartext
        NOTE: Non-printable characters are retained in the output
        NOTE: strings not valid in UTF-8 are skipped (see -e,-v,-q switches)

    options:
    -h, --help            show this help message and exit
    -s SEPARATOR, --separator SEPARATOR
                            The column separator to use in the output file if specified (default ':')
    -n, --no-header       Do not print the header line

    File Management:
    -i [FILE], --input-file [FILE]
                            The input file of strings to parse, if omitted STDIN is used
    -o OUTPUT_FILE, --output-file OUTPUT_FILE
                            Output file, if omitted STDOUT is used
    -e ERROR_FILE, --error-file ERROR_FILE
                            Optional file to write lines that cannot be parsed

    Hash:
    -a HASH_ALGORITHMS, --hash-algorithms HASH_ALGORITHMS
                            Comma separated Hash list to use (default: sha1) options are:
                            sha1, sha224, sha256, sha384, sha512,
                            sha3_224, sha3_256, sha3_384, sha3_512,
                            blake2b, blake2s, md5
    -l, --hash-lower      Output the hash value in lowercase (default)
    -u, --hash-upper      Output the hash value in UPPERCASE

    Output Verbosity:
    -v, --verbose         Verbose reporting of warnings (skipped lines) to STDERR (see -e switch)
    -q, --quiet           Suppress all console output (STDOUT/STDERR)
    -----------------
    """
    # Create argparse instance
    arg_parser = argparse.ArgumentParser(
        formatter_class = RawDescriptionHelpFormatter,
        description = "Translate a file of cleartext strings (passwords) to hashes\n"\
                      "    NOTE: The field separator may be in the cleartext\n"\
                      "    NOTE: Non-printable characters are retained in the output\n"\
                      "    NOTE: strings not valid in UTF-8 are skipped (see -e,-v,-q switches)")
    # General Arguments
    arg_parser.add_argument('-s', '--separator',
                                default = ':',
                                help = "The column separator to use in the output (default ':')")
    arg_parser.add_argument('-n', '--no-header',
                                action = 'store_true',
                                default = False,
                                help = "Do not print the header line")
    # File Arguments
    argument_group_files = arg_parser.add_argument_group('File Management')
    argument_group_files.add_argument('-i', '--input-file',
                                    metavar = 'FILE',
                                    nargs = '?',
                                    default = [],
                                    help = "The input file of strings to parse, if omitted STDIN is used")
    argument_group_files.add_argument('-o', '--output-file',
                                    help = "Output file, if omitted STDOUT is used")
    argument_group_files.add_argument('-e', '--error-file',
                                    help = "Optional file to write lines that cannot be parsed")
    # Hash formatting
    argument_group_hash_wrapper = arg_parser.add_argument_group('Hash')
    argument_group_hash_wrapper.add_argument('-a', '--hash-algorithms',
                                    default = 'sha1',
                                    help = 'Comma separated Hash list to use (default: sha1) options are: '\
                                           'sha1, sha224, sha256, sha384, sha512, '\
                                           'sha3_224, sha3_256, sha3_384, sha3_512, '\
                                           'blake2b, blake2s, md5')
    argument_group_hash = argument_group_hash_wrapper.add_mutually_exclusive_group()
    argument_group_hash.add_argument('-l', '--hash-lower',
                                    action='store_true',
                                    help='Output the hash value in lowercase (default)')
    argument_group_hash.add_argument('-u', '--hash-upper',
                                    action='store_true',
                                    help='Output the hash value in UPPERCASE')
    # Console output
    argument_group_verbosity_parent =  arg_parser.add_argument_group('Output Verbosity')
    argument_group_verbosity = argument_group_verbosity_parent.add_mutually_exclusive_group()
    argument_group_verbosity.add_argument('-v', '--verbose',
                                        action='store_true',
                                        help="Verbose reporting of warnings (skipped lines) to STDERR (see -e switch)")
    argument_group_verbosity.add_argument('-q', '--quiet',
                                        action='store_true',
                                        help="Suppress all console output (STDOUT/STDERR)")
    return arg_parser.parse_args()

def hash_string(text_string: str, hash_type: str = "sha1", hash_uppercase: bool = False) -> str:
    """
    Returns a hex hash based on the hash_type and text_string provided
    """
    match hash_type:
        case "sha1":
            return_value = hashlib.sha1(text_string.encode()).hexdigest()
        case "sha224":
            return_value = hashlib.sha224(text_string.encode()).hexdigest()
        case "sha256":
            return_value = hashlib.sha256(text_string.encode()).hexdigest()
        case "sha384":
            return_value = hashlib.sha384(text_string.encode()).hexdigest()
        case "sha512":
            return_value = hashlib.sha512(text_string.encode()).hexdigest()
        case "sha3_224":
            return_value = hashlib.sha3_224(text_string.encode()).hexdigest()
        case "sha3_256":
            return_value = hashlib.sha3_256(text_string.encode()).hexdigest()
        case "sha3_384":
            return_value = hashlib.sha3_384(text_string.encode()).hexdigest()
        case "sha3_512":
            return_value = hashlib.sha3_512(text_string.encode()).hexdigest()
        # Shake requires an unknown length argument
        #case "shake_128":
        #    return_value = hashlib.shake_128(text_string.encode()).hexdigest()
        #case "shake_256":
        #    return_value = hashlib.shake_256(text_string.encode()).hexdigest()
        case "blake2b":
            return_value = hashlib.blake2b(text_string.encode()).hexdigest()
        case "blake2s":
            return_value = hashlib.blake2s(text_string.encode()).hexdigest()
        case "md5":
            return_value = hashlib.md5(text_string.encode()).hexdigest()
        case _:
            print(f"hash type: {hash_type}, not supported, exiting.")
            exit(-1)
    if hash_uppercase:
        return return_value.upper()
    else:
        return return_value

def main() -> int:
    """
    Main entry point.
    """
    # Initialize variables
    counter_warnings = 0
    counter_errors   = 0
    counter_success  = 0
    supported_hashes = [
        "sha1", "sha224", "sha256", "sha284", "sha512", #SHA
        "sha3_224", "sha3_384", "sha3_512", # SHA3
        "blake2b", "blake2s", "md5" # Misc
    ]

    # Parse arguments
    script_arguments = argument_parser()

    # Verify hash list includes only supported hashes
    hash_list = str(script_arguments.hash_algorithms).lower().split(",")
    hash_list[:] = [entry.strip() for entry in hash_list] # strip spaces from entries
    for hash_name in hash_list:
        if hash_name not in supported_hashes:
            print(f"hash type: {hash_name}, not supported, exiting.")
            exit(-1)
    if script_arguments.verbose:
        if script_arguments.output_file:
            print(f"The following hashes were selected: {hash_list}")
        else:
            print(f"The following hashes were selected: {hash_list}", file=sys.stderr)

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

    # Print header line
    if script_arguments.no_header is not True:
        if script_arguments.output_file:
            print(*hash_list, "clear", sep=script_arguments.separator, file=file_output)
        else:
            print(*hash_list, "clear", sep=script_arguments.separator)

    # Process input file or STDIN
    for input_line in fileinput.input(files=script_arguments.input_file):
        try:
            result_line=""
            for hash_name in hash_list:
                if script_arguments.hash_upper:
                    result_line += hash_string(input_line[0:-1], hash_name, True) + script_arguments.separator
                else:
                    result_line += hash_string(input_line[0:-1], hash_name, False) + script_arguments.separator
            result_line += input_line[0:-1]

            if script_arguments.output_file:
                print(result_line, file=file_output)
            else:
                print(result_line)
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
            if script_arguments.error_file:
                if (counter_warnings + counter_errors) > 0:
                    print(f"{str(counter_warnings + counter_errors).rjust(12)} errored lines written to: "\
                        f"{file_error.name}.")
            else:
                if counter_errors > 0:
                    print(f"Errors identified: {str(counter_errors)}", file=sys.stderr)
                if counter_warnings > 0:
                    print(f"Warnings detected: {counter_warnings} (use -v / --verbose for details)", file=sys.stderr)

    # Cleanup and exit
    fileinput.close()
    if script_arguments.output_file:
        file_output.close()
        if os.path.getsize(script_arguments.output_file) == 0:
            os.remove(script_arguments.output_file)
            print(f"No output to file ({script_arguments.output_file}), file deleted.")
    if script_arguments.error_file:
        file_error.close()
        if os.path.getsize(script_arguments.error_file) == 0:
            os.remove(script_arguments.error_file)
    return

#####################
#  BEGIN PROCESSING #
#####################
if __name__ == '__main__':
    sys.exit(main())
