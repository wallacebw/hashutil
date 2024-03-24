#!/usr/bin/env python

"""
Translate a file of cleartext strings (passwords) to hashes of the specified format(s)
to a text based separated file (TSV) with fields separated by -s / --separator [default ':']
    NOTE: The field separator may be in the cleartext string
    NOTE: Non-printable UTF-8 characters are retained in the output
          Some UTF-8 characters may result in duplicate lines if the pile is segmented (-p/--parallel)
          Characters not valid in UTF-8 will cause the line to be skipped
"""
# todo: verbose output across all functions
# todo: handle function returns
# todo dict to named tuple for function args and return

# import libraries
try:
    import argparse
    from argparse import RawDescriptionHelpFormatter
    import fileinput
    import hashlib
    import multiprocessing
    import os
    import sys
    import time
    from typing import Union
except ImportError as import_error:
    # pylint: disable=R1722
    print(f"An error occurred importing libraries:\n {type(import_error).__name__} - {import_error}")
    quit()

# define functions
def append_files(from_file: str, to_file: str, block_size:int = 1048576) -> bool:
    """
    Append one file to another using binary read/write in 1MB blocks
    return 0 on success, -1 on error
    """
    try:
        from_file_path = os.path.abspath(from_file)
        to_file_path = os.path.abspath(to_file)
        with open(from_file_path, "rb") as file_in, open(to_file_path, "ab") as file_out:
            while True:
                input_block = file_in.read(block_size)
                if not input_block:
                    break
                file_out.write(input_block)
        return True
    except OSError as error:
        print(f"ERR: An error occurred appending file [{from_file_path}] to file[{to_file_path}]:\n" /
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        return False

def argument_parser() -> Union[argparse.Namespace, bool]:
    """
    Parse shell arguments
    """
    # create argparse instance
    try:
        arg_parser = argparse.ArgumentParser(
            formatter_class = RawDescriptionHelpFormatter,
            description =
                "Translate a file of cleartext strings (passwords) to hashes of the specified format(s)\n" \
                "to a text based separated file (TSV) with fields separated by -s / --separator [default ':']\n" \
                "NOTE: The field separator may be in the cleartext string\n" \
                "NOTE: Non-printable UTF-8 characters are retained in the output\n" \
                "      Some UTF-8 characters may result in duplicate lines if the pile is segmented (-p/--parallel)\n" \
                "      Characters not valid in UTF-8 will cause the line to be skipped")
        # general arguments
        arg_parser.add_argument('-a', '--hash-algorithms',
                                default = 'sha1',
                                help = 'Comma separated Hash list to use (default: sha1) options are: ' \
                                    'sha1, sha224, sha256, sha384, sha512, ' \
                                    'sha3_224, sha3_256, sha3_384, sha3_512, ' \
                                    'blake2b, blake2s, md5')
        arg_parser.add_argument('-i', '--input-file',
                                metavar = 'FILE',
                                nargs = '?',
                                default = [],
                                help = "The input file of strings to parse, if omitted STDIN is used")
        arg_parser.add_argument('-p', '--parallel',
                                default = 'a',
                                help = "Number of processes to use or 'a' (default) for automatic detection")
        arg_parser.add_argument('-t', '--temp-directory',
                                default="./",
                                help = "Directory to use for temp files when --parallel is used default PWD)")
        # output format
        arg_group_format = arg_parser.add_argument_group('Output Formatting')
        arg_group_format.add_argument('-s', '--separator',
                                    default = ':',
                                    help = "The column separator to use in the output (default ':')")
        arg_group_format.add_argument('-n', '--no-header',
                                    action = 'store_true',
                                    default = False,
                                    help = "Do not print the header line")
        arg_group_format.add_argument('-o', '--output-file',
                                    help = "Output file, if omitted STDOUT is used")
        arg_group_format.add_argument('-e', '--error-file',
                                    help = "Optional file to write lines that cannot be parsed")
        arg_group_format.add_argument('-u', '--hash-upper',
                                    action='store_true',
                                    help='Output the hash value in UPPERCASE (default is lowercase)')
        # Verbosity
        arg_group_verbosity_parent =  arg_parser.add_argument_group('Output Verbosity')
        arg_group_verbosity = arg_group_verbosity_parent.add_mutually_exclusive_group()
        arg_group_verbosity.add_argument('-v', '--verbose',
                                        action='store_true',
                                        help="Verbose reporting of warnings (skipped lines) to STDERR (see -e switch)")
        arg_group_verbosity.add_argument('-q', '--quiet',
                                        action='store_true',
                                        help="Suppress all console output (STDOUT/STDERR)")
        return arg_parser.parse_args()
    except OSError as error:
        print("ERR: An error occurred parsing arguments:\n:" /
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        return False

def count_lines(file_name: str, block_size: int = 1048576) -> Union[int, bool]:
    """ Count number of lines in a file reading in [block_size] segments """
    def read_block(file, block_size):
        while True:
            block = file.read(block_size)
            if not block:
                break
            yield block
    try:
        file_path = os.path.abspath(file_name)
        with open(file_path, "r", encoding="UTF-8", errors='ignore') as file:
            line_count = (sum(block.count("\n") for block in read_block(file, block_size)))
        return line_count
    except OSError as error:
        print(f"ERR: An error occurred counting lines in file [{file_path}]:\n" /
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        sys.exit(-1)

def hash_string(text_string: str, hash_type: str = "sha1", hash_uppercase: bool = False) -> Union[str, tuple]:
    """
    Returns a hex hash based on the hash_type and text_string provided
    Shake hashes require an unknown length argument and are not included
    """
    try:
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
    except OSError as error:
        error_return = {
            'name': type(error).__name__,
            'details': error,
            'message': f"ERR: An error occurred performing {hash_type} hash on [{text_string}]:"
        }
        return error_return

def hash_file_segment(args: dict) -> Union[dict, int]:

    """
    Open input file and create & populate temporary files with results
        [dict] args{
            segment_number: int
            file_name: str
            segment_start: int
            segment_end: int
            hash_list: str
            hash_upper: bool (optional, default: False)
            separator: str (optional, default: ":")
            temp_path: str (optional, default: "./")
            log_errors: bool (optional, default: False)
            verbose: bool  (optional, default: False)
        }

    return [dict] on success, -1 on error
        [dict]{
            'segment_number' = int,
            'temp_file_path' = str,
            'temp_err_file_path' = str or None,
            'counter_success' = int,
            'counter_warning' = int
        }
    """
    try:
        # define variables
        counter_success = 0
        counter_warning = 0
        # open files
        temp_path = os.path.abspath(args['temp_path'])
        os.makedirs(temp_path, exist_ok=True)
        input_file_path = os.path.abspath(args['file_name'])
        with open(input_file_path, mode='r', encoding='UTF-8', errors='strict') as file_input, \
             open(f"{temp_path}/_hashgen_{os.getpid()}.dat", mode='w', encoding='UTF-8') as file_temp, \
             open(f"{temp_path}/_hashgen_{os.getpid()}.err", mode='w', encoding='UTF-8') as file_temp_err:

            # record temp files absolute paths
            temp_file_path = os.path.abspath(file_temp.name)
            temp_err_file_path = os.path.abspath(file_temp_err.name)

            # process chunk lines
            file_input.seek(args['segment_start'])
            for input_line in file_input:
                try:
                    segment_start += len(input_line)
                    if segment_start > args['segment_end']: # exit at end of chunk
                        break
                    result_line=""
                    for hash_name in args['hash_list']:
                        if args['hash_upper']:
                            hash_hex = hash_string(input_line[0:-1], hash_name, True)
                            if isinstance(hash_hex,str):
                                result_line += hash_hex + args['separator']
                            elif isinstance(hash_hex, dict): # error
                                raise ValueError("Hashing Error")
                        else:
                            hash_hex = hash_string(input_line[0:-1], hash_name, False)
                            if isinstance(hash_hex,str):
                                result_line += hash_hex + args['separator']
                            elif isinstance(hash_hex, dict): # error
                                raise ValueError("Hashing Error")
                    result_line += input_line[0:-1]
                    print(result_line, file=file_temp)
                    counter_success += 1
                except ValueError:
                    if args['verbose']:
                        print(hash_hex['message'], file=sys.stderr)
                        print(f"{hash_hex['name']} - {hash_hex['details']}", file=sys.stderr)
                    if args['log_errors']:
                        file_temp_err.write(input_line)
                    counter_warning += 1
                    break
        results = {
            'segment_number': args['segment_number'],
            'temp_file_path': temp_file_path,
            'temp_err_file_path': temp_err_file_path,
            'counter_success': counter_success,
            'counter_warning': counter_warning
        }
        return results
    except OSError as error:
        print(f"ERR: An error occurred processing segment [{args['segment_number']}]:\n" /
              f"    Segment temp file: {temp_file_path}",
              f"    Source file range: {input_file_path} [{args['segment_start']} to {args['segment_end']}]",
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        return False

def segment_file(file_name: str, segments: int = 1) -> list:
    """
    Scan a file to identifying the start and end position of the defined number of
    segments, aligning each segment to the nearest line break.
        REF: https://nurdabolatov.com/parallel-processing-large-file-in-python
    """
    try:
        segment_number = 1
        file_path = os.path.abspath(file_name)
        file_size = os.path.getsize(file_name)
        segment_size = file_size // segments
        segment_parts = []

        with open(file_path, 'r', encoding="UTF-8", errors="surrogateescape") as file:
            def is_start_of_line(position):
                """ Check whether the previous character od EOL """
                if position == 0:
                    return True
                file.seek(position - 1)
                return file.read(1) == '\n'

            def get_next_line_position(position):
                """ Read the line starting as [position], return  the position after reading the line """
                file.seek(position)
                file.readline()
                return file.tell()

            # Iterate over all chunks and construct arguments for `process_chunk`
            segment_start = 0

            while segment_start < file_size:
                if segment_number == segments:
                    # grow the last chunk to be larger honoring # of segments
                    segment_end = file_size
                else:
                    segment_end = min(file_size, segment_start + segment_size)
                # Make sure the chunk ends at the beginning of the next line
                while not is_start_of_line(segment_end):
                    segment_end -= 1
                # Handle the case when a line is too long to fit the chunk size
                if segment_start == segment_end:
                    segment_end = get_next_line_position(segment_end)
                # Save `process_chunk` arguments
                #args = [segment_number, file_name, segment_start, segment_end]
                args = {
                    'segment_number': segment_number,
                    'file_name': file_name,
                    'segment_start': segment_start,
                    'segment_end': segment_end
                }
                segment_number +=1
                segment_parts.append(args)
                # Move to the next chunk
                segment_start = segment_end
        return segment_parts
    except OSError as error:
        print(f"ERR: An error occurred defining file segments in file [{file_path}]:\n" /
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        sys.exit(-1)

def track_jobs(job: multiprocessing.Pool, update_interval: int = 1, message_prefix: str = "Tasks remaining: "):
    """ Track the status of running multi-process async pools printing status at [update_interval] """
    # pylint: disable=W0212
    try:
        while job._number_left > 0:
            print(f"\r{message_prefix}{job._number_left * job._chunksize : < {len(message_prefix) + 10}}", end="")
            time.sleep(update_interval)
        print(f"\r{message_prefix}{0 : < {len(message_prefix) + 10}}")
    except OSError as error:
        print("ERR: An error occurred tracking child processes, exiting.  Temp files may persist:\n" /
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        sys.exit(-1)

def main() -> int:
    """ main entry point """
    # define variables
    supported_hashes = [
    "sha1", "sha224", "sha256", "sha284", "sha512", #SHA
    "sha3_224", "sha3_384", "sha3_512", # SHA3
    "blake2b", "blake2s", "md5" # Misc
    ]

    # Parse arguments
    script_arguments = argument_parser()
    if script_arguments is False:
        sys.exit(-1)

    # Verify hash list includes only supported hashes
    hash_list = str(script_arguments.hash_algorithms).lower().split(",")
    hash_list[:] = [entry.strip() for entry in hash_list] # strip spaces from entries
    for hash_name in hash_list:
        if hash_name not in supported_hashes:
            print(f"ERR: hash type: {hash_name}, not supported, exiting.",
                  file=sys.stderr
            )
            sys.exit(-1)

    # process threading argument
    if script_arguments.parallel:
        # automatic processor detection
        if not str(script_arguments.parallel).isnumeric() and str(script_arguments.parallel).lower() == 'a':
            parallel_jobs = os.cpu_count()
            if parallel_jobs is None:
                print("WARN: Unable to determine cpu thread count, disabling multi-processing",
                      file=sys.stderr
                )
                parallel_jobs = 1
        # manual process count specified
        if str(script_arguments.parallel).isnumeric():
            parallel_jobs = int(script_arguments.parallel)
        if str(script_arguments.parallel).isnumeric() \
           and script_arguments.parallel < 1:
            print(f"WARN: Invalid -p/--parallel argument ({script_arguments.parallel}), disabling multi-processing",
                  file=sys.stderr
            )
            script_arguments.parallel = 1
    else:
        parallel_jobs = os.cpu_count()
        if parallel_jobs is None:
            print("WARN: Unable to determine cpu thread count, disabling multi-processing",
                  file=sys.stderr
            )
            parallel_jobs = 1

    # pass to core processing function
    if isinstance(parallel_jobs,int):
        if parallel_jobs > 1:
            if not fileinput.input(files=script_arguments.input_file).isstdin():
                # parallel processing
                # todo: handle arguments for core_multi_process
                #core_multi_process()
                pass
            else:
                # fall back to single threaded if using <STDIN>
                print("WARN: parallel processing (-p/--parallel) does not support <STDIN>\n:" \
                      " -- reverting to single-process mode.",
                    file=sys.stderr
                )
                # todo: handle arguments for core_single_process
                # core_single_process()
        elif parallel_jobs == 1:
            #single threaded
            # todo: handle arguments for core_single_process
            # core_single_process()
            pass
        else:
            # unable to determine threading
            print("ERR: Unable to determine a threading strategy, exiting.",
                  file=sys.stderr
            )
            sys.exit(-1)
    else:
        # unable to determine threading
        print("ERR: Unable to determine a threading strategy, exiting.",
                file=sys.stderr
        )
        sys.exit(-1)
    return 0

def core_multi_process(args: dict) -> int:
    """
    Process via multi_processing
    args [dict]:
        'input_file': str,
        'output_file': str
        'error_file': str or None,
        'hash_list': list,
        'hash_upper': bool,
        'parallel': int > 0,
        'no_header': bool,
        'separator': str,
        'temp_directory': str,
        'log_errors': bool,
        'verbose': bool

    """
    # count lines in source file
    try:
        input_file_path = os.path.basename(args['input_file'])
        print(f"Counting lines in '{input_file_path}': ", end='', flush=True)
        input_file_lines = count_lines(input_file_path)
        print(input_file_lines)
        if not isinstance(input_file_lines,int) or input_file_lines < 1:
            print(f"ERR: Unable to count lines in file: {input_file_path}, exiting.", file=sys.stderr)
            sys.exit(-1)
    except OSError:
        print(f"ERR: Unable to count lines in file: {input_file_path}, exiting.", file=sys.stderr)
        sys.exit(-1)

    # determine file segment details: errors handled by segment_file()
    if input_file_lines >= args['parallel']:
        segment_details = segment_file(file_name=args['input_file'], segments=args['parallel'])
    else:
        #less lines in file than cores assigned
        segment_details = segment_file(file_name=args['input_file'], segments=input_file_lines)

    # append segment dict with additional parameters needed for hashing process
    for segment in segment_details:
        segment['hash_list'] = args['hash_list']
        segment['hash_upper'] = args['hash_upper']
        segment['separator'] = args['separator']
        segment['temp_directory'] = args['temp_directory']
        segment['log_errors'] = args['log_errors']
        segment['verbose'] = args['verbose']

    # start and monitor child processes: errors handled by track_jobs()
    try:
        with multiprocessing.Pool(processes=args['parallel']) as process_pool:
            process_pool_results = process_pool.starmap_async(hash_file_segment, segment_details, chunksize = 1)
            track_jobs(process_pool_results, message_prefix = "Creating hashes - Jobs remaining: ")
            segment_results = process_pool_results.get()
    except OSError as error:
        print("ERR: An error occurred starting child jobs, exiting.  Temp files may persist.:\n" /
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        sys.exit(-1)

    # create output file(s)
    try:
        # create output directory if needed
        output_file_path = os.path.abspath(args['output_file'])
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        if args['error_file']:
            output_error_file_path = os.path.abspath(args['error_file'])
            os.makedirs(os.path.dirname(output_error_file_path), exist_ok=True)

        # output header
        if not args['no_header']:
            with open(output_file_path, mode='w', encoding='UTF-8', errors='strict') as file_output:
                print(*args['hash_list'], "cleartext", sep=args['separator'], file=file_output)

        # merge and output results temp files
        for i, result in enumerate(segment_results):
            print(f"\rMerging temporary files: {len(segment_results) - i} remaining          ", end="")
            append_files(result['temp_file_path'], args['output_file'])
            # delete temp file after merge
            if os.access(result['temp_file_path'], os.W_OK):
                os.remove(result['temp_file_path'])
        print("\rMerging temporary files: 0 remaining          ")

        # merge and output results temp error files
        if args['error_file']:
            for i, result in enumerate(segment_results):
                print(f"\rMerging temporary error files: {len(segment_results) - i} remaining          ", end="")
                append_files(result['temp_err_file_path'], output_error_file_path)
                if os.access(result['temp_err_file_path'], os.W_OK): # temp error file
                    os.remove(result['temp_err_file_path'])
            print("\rMerging temporary error files: 0 remaining          ")

        # delete temp directory if not PWD or not empty
        if not args['temp_directory'] == './':
            temp_path = os.path.abspath(args['temp_directory'])
            if len(os.listdir(temp_path)) == 0: # empty temp directory
                os.rmdir(temp_path)

    except OSError as error:
        print("ERR: An error occurred merging temp files, exiting.  Temp files may persist.:\n" /
              f"{type(error).__name__} - {error}",
              file=sys.stderr
        )
        sys.exit(-1)


    # show results
    success_lines = 0
    warning_lines = 0
    for segment in segment_results:
        success_lines += segment['counter_success']
        warning_lines += segment['counter_warning']

    print("Results:")
    if success_lines == input_file_lines:
        print(f"      Input lines: {input_file_lines}")
        print(f"    skipped lines: {warning_lines}")
        print(f"     Output lines: {success_lines}")
    else:
        print(f"      Input lines: {input_file_lines}")
        print(f"    skipped lines: {warning_lines}")
        print(f"     Output lines: {success_lines}")
        print("======================================================")
        print("WARNING: Result count does not match input file lines!")
        if success_lines > input_file_lines:
            print(f"Note: {success_lines - input_file_lines} more output lines than input file lines:")
            print("      Your input file may contain UTF-8 characters causing duplicate result lines")
            print("      such as control characters, line endings, or right-to-left printing ex: arabic")
            print("      Consider processing without multithreading (--parallel / -r)")
            print("      Alternately clean input file or remove duplicate lines from output file. ex:")
            print("         [sort --unique] sorted deduplicated output")
            print("         [rli or rling] unsorted deduplicated output")
    return 0

def core_single_process(args: dict) -> int:
    """
    Process via main process
    [dict] args{
        'input_file': str,
        'output_file': str or None,
        'error_file': str or None,


    }

    """

    # todo: refactor single-threaded code
    print('nothing to see here...')


# begin processing
if __name__ == '__main__':
    sys.exit(main())
