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
import multiprocessing
import _mt_io_

######################
## DEFINE FUNCTIONS ##
######################
def append_files(_from: str, _to: str) -> int:
    """
    Append one file to another using binary read/write in 1MB blocks
    return 0 on success, -1 on error
    """
    try:
        block_size = 1024*1024
        with open(_to, "ab") as file_out, open(_from, "rb") as file_in:
            while True:
                input_block = file_in.read(block_size)
                if not input_block:
                    break
                file_out.write(input_block)
        return 0
    except IOError:
        return -1

def argument_parser() -> argparse.Namespace:
    """
    Parse shell arguments
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
    arg_parser.add_argument('-p', '--parallel',
                                default = 1,
                                help = "Number of parallel threads to use or 'a' for automatic detection")
    arg_parser.add_argument('-t', '--temp-directory',
                                default="./",
                                help = "Directory to use for temp files when --parallel is used default PWD)")
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
            sys.exit(-1)
    if hash_uppercase:
        return return_value.upper()
    else:
        return return_value

def hash_chunk_printonly(chunk_number: int,
               file_name: str,
               chunk_start: int,
               chunk_end: int,
               hash_list: str,
               hash_upper: bool = False,
               separator: str = ":",
               temp_path: str = "./",
               log_errors: bool = False,
               verbose: bool = False
               ):
    """ docstring
    stupid placeholder to test line duplication
    """
    temp_path = os.path.abspath(temp_path)
    os.makedirs(temp_path,exist_ok=True)
    with open(file_name, mode='r', encoding='utf8') as file_input, \
         open(f"{temp_path}/{os.getpid()}_{chunk_number}.dat", mode='w', encoding='utf8') as file_temp:
        file_input.seek(chunk_start)
        for input_line in file_input:
            chunk_start += len(input_line)
            if chunk_start > chunk_end: # exit at end of chunk
                break
            print(input_line[0:-1], file=file_temp)

def hash_chunk(chunk_number: int,
               file_name: str,
               chunk_start: int,
               chunk_end: int,
               hash_list: str,
               hash_upper: bool = False,
               separator: str = ":",
               temp_path: str = "./",
               log_errors: bool = False,
               verbose: bool = False
               ):
    """
    Open input file and create & populate temporary files with results
    return 0 on success, -1 on error
    """
    try:
        # define variables
        counter_success = 0
        counter_warning = 0
        # open files
        temp_path = os.path.abspath(temp_path)
        os.makedirs(temp_path,exist_ok=True)
        with open(file_name, mode='r', encoding='utf8') as file_input, \
             open(f"{temp_path}/{os.getpid()}_{chunk_number}.dat", mode='w', encoding='utf8') as file_temp, \
             open(f"{temp_path}/{os.getpid()}_{chunk_number}.err", mode='w', encoding='utf8') as file_temp_err:

            # record temp files with sequence number
            temp_file_path = f"{temp_path}/{os.getpid()}_{chunk_number}.dat"
            temp_err_file_path = f"{temp_path}/{os.getpid()}_{chunk_number}.err"

            # process chunk lines
            file_input.seek(chunk_start)
            for input_line in file_input:
                try:
                    chunk_start += len(input_line)
                    if chunk_start > chunk_end: # exit at end of chunk
                        break
                    result_line=""
                    for hash_name in hash_list:
                        if hash_upper:
                            result_line += hash_string(input_line[0:-1], hash_name, True) + separator
                        else:
                            result_line += hash_string(input_line[0:-1], hash_name, False) + separator
                    result_line += input_line[0:-1]
                    print(result_line, file=file_temp)
                    counter_success += 1
                except IOError as err:
                    if verbose:
                        print(f"ERROR: {input_line[0:-1]}", file=sys.stderr)
                        print("    Details: ", end='', file=sys.stderr)
                        print(Exception, err, file=sys.stderr)
                    if log_errors:
                        file_temp_err.write(input_line)
                    counter_warning += 1
        results = [chunk_number, temp_file_path, temp_err_file_path, counter_success, counter_warning]
        return results
    except IOError:
        return -1

def main() -> int:
    """
    Main entry point.
    """
    # define variables
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

    # process threading argument
    if script_arguments.parallel:
        if not str(script_arguments.parallel).isnumeric() and str(script_arguments.parallel).lower() == 'a':
            script_arguments.parallel = os.cpu_count()
            if script_arguments.parallel is None or script_arguments.parallel > len(os.sched_getaffinity(0)):
                script_arguments.parallel = 1
        if str(script_arguments.parallel).isnumeric():
            script_arguments.parallel = int(script_arguments.parallel)
        if str(script_arguments.parallel).isnumeric() \
           and script_arguments.parallel < 1 \
           and script_arguments.parallel > len(os.sched_getaffinity(0)):
            script_arguments.parallel = 1

    if script_arguments.verbose:
        if script_arguments.output_file:
            print(f"The following hashes were selected: {hash_list}")
        else:
            print(f"The following hashes were selected: {hash_list}", file=sys.stderr)

    ################################
    # run hashing on chunk or file #
    ################################
    #check for parallel argument and input file (not STDIN)
    if script_arguments.parallel > 1 \
       and script_arguments.output_file \
       and not fileinput.input(files=script_arguments.input_file).isstdin():

        # assign variables
        if script_arguments.error_file:
            log_errors = True
        else:
            log_errors = False

        # process and collect results
        print("multi-threaded baby!")
        chunk_details = _mt_io_.chunk_file(script_arguments.input_file, script_arguments.parallel)
            #  contents [Chunk_number, file_path, start_position, end_position]
        print(*chunk_details, sep='\n')

        for chunk in chunk_details:
            chunk += [hash_list,
                      script_arguments.hash_upper is True,
                      script_arguments.separator,
                      script_arguments.temp_directory,
                      log_errors,
                      script_arguments.verbose]
        with multiprocessing.Pool(script_arguments.parallel) as pool:
            # run chunks in parallel
            #chunk_results = pool.starmap(hash_chunk, chunk_details)
            chunk_results = pool.starmap(hash_chunk_printonly, chunk_details)
                # content [chunk_number, temp_file_path, temp_err_file_path, counter_success, counter_warning]

        # output header line
        if script_arguments.no_header is not True:
            with open(script_arguments.output_file, mode='w', encoding='utf8', errors='surrogateescape') as file_output:
                print(*hash_list, "clear", sep=script_arguments.separator, file=file_output)

        # merge and output results
        chunk_results.sort()
        for result in chunk_results:
            append_files(result[1], script_arguments.output_file)

        if script_arguments.error_file:
            for result in chunk_results:
                append_files(result[2], script_arguments.error_file)

        # remove temp files
        for chunk in chunk_results:
            if os.access(chunk[1], os.W_OK): # temp file
                os.remove(chunk[1])
            if os.access(chunk[2], os.W_OK): # temp error file
                os.remove(chunk[2])
            if not script_arguments.temp_directory == './':
                temp_path = os.path.abspath(script_arguments.temp_directory)
                if len(os.listdir(temp_path)) == 0: # empty temp directory
                    os.rmdir(temp_path)
        success_lines = 0
        warning_lines = 0
        for chunk in chunk_results:
            success_lines += chunk[3]
            warning_lines += chunk[4]
        print(*chunk_results, sep='\n')
        print(f"successfully processed: {success_lines} lines")
        print(f"              warnings: {warning_lines} lines")
    else:
        print("Boo, no threading!")
        if script_arguments.output_file:
            file_output = open(script_arguments.output_file, 'w', encoding='utf8', errors='surrogateescape')
        if script_arguments.error_file:
            file_error = open(script_arguments.error_file, mode='a', encoding='utf8', errors='surrogateescape')
        for input_line in fileinput.input(files=script_arguments.input_file):
            try:
                # output header line
                if script_arguments.no_header is not True:
                    if script_arguments.output_file:
                        with open(script_arguments.output_file, mode='w', encoding='utf8', errors='surrogateescape') \
                          as file_output:
                            print(*hash_list, "clear", sep=script_arguments.separator, file=file_output)
                    else:
                        print(*hash_list, "clear", sep=script_arguments.separator)

                # output results
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

        fileinput.close()
        if not file_output.closed():
            file_output.close()
        if not file_error.closed():
            file_error.close()



    # Cleanup and exit
    try:
        if file_output in locals():
            if not file_output.closed:
                file_output.close()
        if file_error in locals():
            if not file_error.closed:
                file_error.close()
        if os.path.getsize(script_arguments.output_file) == 0:
            if os.access(script_arguments.output_file, os.W_OK):
                os.remove(script_arguments.output_file)
                print(f"No output to file ({script_arguments.output_file}), file deleted.")
        if os.path.getsize(script_arguments.error_file) == 0:
            if os.access(script_arguments.error_file, os.W_OK):
                os.remove(script_arguments.error_file)
    except UnboundLocalError:
        pass

    return 0

#####################
#  BEGIN PROCESSING #
#####################
if __name__ == '__main__':
    sys.exit(main())
