#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
Translate a file of cleartext strings (passwords) to hashes of the specified format(s)
to a text based separated file (TSV) with fields separated by -s / --separator [default ':']
    NOTE: The field separator may be in the cleartext string
    NOTE: Non-printable UTF-8 characters are retained in the output
          Some UTF-8 characters may result in duplicate lines if the pile is segmented (-p/--parallel)
          Characters not valid in UTF-8 will cause the line to be skipped
"""

# import modules
try:
    import argparse
    from argparse import RawDescriptionHelpFormatter
    from collections import namedtuple
    from datetime import timedelta
    import fileinput
    import hashlib
    import inspect
    import multiprocessing
    import os
    import sys
    import time
    from typing import Union
except ImportError as import_error:
    print(f"An error occurred importing libraries:\n {type(import_error).__name__} - {import_error}")
    quit(-1)

# define named tuples
HashError = namedtuple('HashError',[
    'error_name', # type(error).__name__
    'error_details', # error
    'message' # str
])
HexError = namedtuple('HexError',[
    'error_name', # type(error).__name__
    'error_details', # error
    'message' # str
])
HashGeneratorSettings = namedtuple('Settings',[
    'hash_algorithms', # list
    'hash_upper', # bool
    'input_file', # str
    'parallel', # int or 'a'
    'temp_directory', # str
    'separator', # str
    'no_header', # bool
    'output_file', # str
    'error_file', # str
    'verbose', # bool
    'quiet' # bool
])
FileSegment = namedtuple('FileSegment',[
    'segment_number', # int
    'file_name', # str
    'segment_start', # int
    'segment_end', # int
])
SegmentResults = namedtuple('SegmentResults',[
    'segment_number', # int
    'temp_file_path', # str
    'temp_err_file_path', # str or None
    'counter_success', # int
    'counter_warning', # int
    'time_elapsed', # float
    'time_processor' # float
])

# define constants
SUPPORTED_HASHES = [
    "sha1", "sha224", "sha256", "sha384", "sha512", #SHA
    "sha3_224", "sha3_256", "sha3_384", "sha3_512", # SHA3
    "blake2b", "blake2s", "md5"] # Misc


# define functions
def append_files(
        from_file: str,
        to_file: str,
        block_size:int = 1048576,
        settings: HashGeneratorSettings = None
    ) -> bool:
    """ Append one file to another using binary read/write in 1MB blocks return 0 on success, -1 on error  """
    try:
        # verbose output prep
        time_start = time.time()
        _function_name = inspect.currentframe().f_code.co_name
        # append file
        from_file_path = os.path.abspath(from_file)
        to_file_path = os.path.abspath(to_file)
        with open(from_file_path, "rb") as file_in, open(to_file_path, "ab") as file_out:
            while True:
                input_block = file_in.read(block_size)
                if not input_block:
                    break
                file_out.write(input_block)
        # print verbose details to STDERR to avoid polluting output in STDOUT mode
        if settings:
            if settings.verbose >= 1:
                print(f"\nVERBOSE ({_function_name}): Appending took " \
                    f"{timedelta(seconds=(time.time() - time_start))}: from[{from_file}] to [{to_file}]",
                    file=sys.stderr)
        return True
    except OSError as error:
        print(f"ERROR: An error occurred appending file [{from_file_path}] to file[{to_file_path}]:\n" \
            f"{type(error).__name__} - {error}",
            file=sys.stderr)
        return False

def count_lines(
        file_name: str,
        block_size: int = 1048576,
        settings: HashGeneratorSettings = None
    ) -> Union[int, bool]:
    """ Count number of lines in a file reading in [block_size] segments """
    def read_block(file, block_size):
        while True:
            block = file.read(block_size)
            if not block:
                break
            yield block
    try:
        # verbose output prep
        time_start = time.time()
        _function_name = inspect.currentframe().f_code.co_name
        # count occurrences of \n via binary block reads
        file_path = os.path.abspath(file_name)
        with open(file_path, "r", encoding="UTF-8", errors='ignore') as file:
            line_count = (sum(block.count("\n") for block in read_block(file, block_size)))
        # print verbose details to STDERR to avoid polluting output in STDOUT mode
        if settings:
            if settings.verbose >= 1:
                print(f"\nVERBOSE ({_function_name}): Counting Lines took " \
                      f"{timedelta(seconds=(time.time() - time_start))} for [{file_path}]",
                    file=sys.stderr)
        return line_count
    except OSError as error:
        print(f"ERROR: An error occurred counting lines in file [{file_path}]:\n" \
            f"{type(error).__name__} - {error}",
            file=sys.stderr)
        sys.exit(-1)

def parse_arguments(
    ) -> Union[argparse.ArgumentParser, bool]:
    """ Parse shell arguments """
    # create argparse instance
    try:
        # verbose output prep
        time_start = time.time()
        _function_name = inspect.currentframe().f_code.co_name
        # define arguments
        arg_parser = argparse.ArgumentParser(
            formatter_class = RawDescriptionHelpFormatter,
            description =
                "Translate a file of cleartext strings (passwords) to hashes of the specified format(s)\n" \
                "to a text based separated file (TSV) with fields separated by -s / --separator [default ':']\n" \
                "NOTE: The field separator may be in the cleartext string which is always last output field\n" \
                "NOTE: Non-printable UTF-8 characters are retained in the output\n" \
                "NOTE: Hex values matching the pattern '$HEX[...]' are converted and hashed \n" \
                "      Some UTF-8 characters result in duplicate lines if the file is segmented (-p/--parallel)\n" \
                "      Characters not valid in UTF-8 will cause the line to be skipped")
        # general arguments
        arg_parser.add_argument(
            '-a', '--hash-algorithms',
            default = 'sha1',
            type = str,
            help = 'Comma separated Hash list to use (default: sha1) options are: ' \
                    'sha1, sha224, sha256, sha384, sha512, ' \
                    'sha3_224, sha3_256, sha3_384, sha3_512, ' \
                    'blake2b, blake2s, md5')
        arg_parser.add_argument(
            '-i', '--input-file',
            metavar = 'FILE',
            nargs = '?',
            default = [],
            type = str,
            help = "The input file(s) of strings to parse, if omitted STDIN is used (comma separated)")
        arg_parser.add_argument(
            '-p', '--parallel',
            default = 'a',
            type = lambda p: p if p.isnumeric() or p.lower() == 'a'else False, # INT or A or a
            help = "Number of processes to use or 'a' (default) for automatic detection")
        arg_parser.add_argument(
            '-t', '--temp-directory',
            default="./",
            type = str,
            help = "Directory to use for temp files when --parallel is used default PWD)")
        # output format
        arg_group_format = arg_parser.add_argument_group('Output Formatting')
        arg_group_format.add_argument(
            '-s', '--separator',
            default = ':',
            type = str,
            help = "The column separator to use in the output (default ':')")
        arg_group_format.add_argument(
            '-n', '--no-header',
            action = 'store_true',
            default = False,
            help = "Do not print the header line")
        arg_group_format.add_argument(
            '-o', '--output-file',
            type=str,
            help = "Output file, if omitted STDOUT is used")
        arg_group_format.add_argument(
            '-e', '--error-file',
            type=str,
            help = "Optional file to write lines that cannot be parsed")
        arg_group_format.add_argument(
            '-u', '--hash-upper',
            action='store_true',
            help='Output the hash value in UPPERCASE (default is lowercase)')
        # Verbosity
        arg_group_verbosity_parent = arg_parser.add_argument_group('Output Verbosity')
        arg_group_verbosity = arg_group_verbosity_parent.add_mutually_exclusive_group()
        arg_group_verbosity.add_argument(
            '-v', '--verbose',
            action='count',
            default=0,
            help='Verbose reporting of warnings (skipped lines) to STDERR (see -e)\n' \
                 '*** specify twice [-vv] for debugging (multiple messages per file line ***)')
        arg_group_verbosity.add_argument(
            '-q', '--quiet',
            action='store_true',
            help="Suppress all console output (STDOUT/STDERR)")
        arguments = arg_parser.parse_args()
        # print verbose details to STDERR to avoid polluting output in STDOUT mode
        if arguments.verbose >= 1:
            print(f"VERBOSE ({_function_name}): Processing arguments took " \
                  f"{timedelta(seconds=(time.time() - time_start))}\n" \
                  f"VERBOSE ({_function_name}): arguments: [{arguments}]\n",
                file=sys.stderr)
        return arg_parser
    except OSError as error:
        print("ERROR: An error occurred parsing arguments:\n:" \
            f"{type(error).__name__} - {error}",
            file=sys.stderr)
        return False

def parse_settings(
        arguments: argparse.Namespace = None
    ) -> HashGeneratorSettings:
    """ populate class settings from arguments provided by parse_arguments """
    # verbose output prep
    time_start = time.time()
    _function_name = inspect.currentframe().f_code.co_name
    # store final settings in results
    results = {}
    # parse arguments if not present
    if arguments is None:
        arguments = parse_arguments()
    # verify successful type
    if arguments is False or arguments is None:
        print("Unable to parse arguments, exiting. ", file=sys.stderr)
        sys.exit(-1)
    # Verify hash list includes only supported hashes
    hash_list = str(arguments.hash_algorithms).lower().split(",")
    hash_list[:] = [entry.strip() for entry in hash_list] # strip spaces from entries
    for hash_name in hash_list:
        if hash_name not in SUPPORTED_HASHES:
            print(f"ERROR: hash type: {hash_name}, not supported, exiting.", file=sys.stderr)
            sys.exit(-1)
    results['hash_algorithms'] = hash_list
    # process threading argument
    if arguments.parallel:
        # automatic processor detection
        if not str(arguments.parallel).isnumeric() and str(arguments.parallel).lower() == 'a':
            parallel_jobs = os.cpu_count()
            if parallel_jobs is None or parallel_jobs > len(os.sched_getaffinity(0)):
                parallel_jobs = 1
        # manual process count specified
        if str(arguments.parallel).isnumeric():
            parallel_jobs = int(arguments.parallel)
        if str(arguments.parallel).isnumeric() \
        and int(arguments.parallel) < 1:
            print(f"WARN: Invalid -p/--parallel argument ({arguments.parallel}), disabling multi-processing",
                file=sys.stderr)
            arguments.parallel = 1
    else:
        parallel_jobs = os.cpu_count()
        if parallel_jobs is None:
            print("WARN: Unable to determine cpu thread count, disabling multi-processing", file=sys.stderr)
            parallel_jobs = 1
    results['parallel'] = parallel_jobs
    # convert file/dir references to absolute paths
    path_args = {
        'input_file': arguments.input_file,
        'output_file': arguments.output_file,
        'error_file': arguments.error_file,
        'temp_directory': arguments.temp_directory}
    for key, value in path_args.items():
        if isinstance(value,list) and key == 'input_file': # no input specified
            results[key] = []
        elif value is not None and value != "":
            results[key] = os.path.abspath(value)
        else:
            results[key] = None
    # parse bool values
    bool_args = {
        'hash_upper': arguments.hash_upper,
        'no_header': arguments.no_header,
        'quiet': arguments.quiet}
    for key, value in bool_args.items():
        if value is True:
            results[key] = True
        else:
            results[key] = False
    # verify argument separator exists
    if len(arguments.separator):
        results['separator'] = arguments.separator
    else:
        print(f"ERROR: separator value [{arguments.separator}], not supported, exiting.", file=sys.stderr)
        sys.exit(-1)
    # verify verbose between 0-2:
    if 0 <= arguments.verbose <= 2:
        results['verbose'] = int(arguments.verbose)
    # populate settings tuple
    settings = HashGeneratorSettings(
        hash_algorithms = results['hash_algorithms'],
        parallel = results['parallel'],
        separator = results['separator'],
        input_file = results['input_file'],
        output_file = results['output_file'],
        error_file = results['error_file'],
        temp_directory = results['temp_directory'],
        hash_upper = results['hash_upper'],
        no_header = results['no_header'],
        verbose = results['verbose'],
        quiet = results['quiet'])
    # print verbose details to STDERR to avoid polluting output in STDOUT mode
    if settings.verbose >= 1:
        print(f"VERBOSE ({_function_name}): Parsing argument to settings took " \
              f"{timedelta(seconds=(time.time() - time_start))}\n" \
              f"VERBOSE ({_function_name}): Setting: [{arguments}]\n",
            file=sys.stderr)
    return settings

def hash_string(
        text_string: str,
        settings: HashGeneratorSettings,
        hash_type: str = "sha1"
    ) -> Union[str, HashError]:
    """  Returns a hex hash based on the hash_type and text_string provided """
    # pylint: disable=used-before-assignment
        # false positive
    # verbose output prep
    if settings.verbose == 2:
        # due to high frequency use of this function and inspect's overhead, only call if required
        time_start = time.time()
        _function_name = inspect.currentframe().f_code.co_name
    # produce and return hash
    try:
        # get the byte string from hex value entries
        if text_string[0:5].upper() == '$HEX[' and text_string[-1] == ']':
            try:
                byte_string = bytes.fromhex(text_string[5:-1])
            except (UnboundLocalError, ValueError):
                # invalid hex
                byte_string= False
                if settings.verbose >= 1:
                    print(f"VERBOSE (hash_string): invalid hex string detected [{text_string[5:-1]}] " \
                          f"treating value [{text_string}] as text.",
                        file=sys.stderr)
        else:
            byte_string= False
        if byte_string:
            match hash_type:
                case "sha1":
                    return_value = hashlib.sha1(byte_string).hexdigest()
                case "sha224":
                    return_value = hashlib.sha224(byte_string).hexdigest()
                case "sha256":
                    return_value = hashlib.sha256(byte_string).hexdigest()
                case "sha384":
                    return_value = hashlib.sha384(byte_string).hexdigest()
                case "sha512":
                    return_value = hashlib.sha512(byte_string).hexdigest()
                case "sha3_224":
                    return_value = hashlib.sha3_224(byte_string).hexdigest()
                case "sha3_256":
                    return_value = hashlib.sha3_256(byte_string).hexdigest()
                case "sha3_384":
                    return_value = hashlib.sha3_384(byte_string).hexdigest()
                case "sha3_512":
                    return_value = hashlib.sha3_512(byte_string).hexdigest()
                case "blake2b":
                    return_value = hashlib.blake2b(byte_string).hexdigest()
                case "blake2s":
                    return_value = hashlib.blake2s(byte_string).hexdigest()
                case "md5":
                    return_value = hashlib.md5(byte_string).hexdigest()
                case _:
                    print(f"hash type: {hash_type}, not supported, exiting.")
                    sys.exit(-1)
        else:
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
        # print verbose details to STDERR to avoid polluting output in STDOUT mode
        if settings.verbose == 2: # specify -vv or --verbose --verbose
            print(f"VERBOSE ({_function_name}): hashing took {timedelta(seconds=(time.time() - time_start))} | " \
                  f"{hash_type}[{text_string}] = [{return_value}] ",
                file=sys.stderr)
        # return hash
        if settings.hash_upper:
            return return_value.upper()
        else:
            return return_value
    except OSError as error:
        error_return = HashError(
            error_name = type(error).__name__,
            error_details = error,
            message = f"ERROR: An error occurred performing {hash_type} hash on [{text_string}]:")
        return error_return

def hash_file_segment(
        segment: FileSegment,
        settings: dict
    ) -> Union[SegmentResults, int]:
    """ Open input file and create & populate temporary files with results """
    try:
        # verbose output prep
        time_start = time.time()
        _function_name = inspect.currentframe().f_code.co_name
        # define variables
        settings = HashGeneratorSettings(**settings) # convert back to named tuple (multiprocessing limitation)
        counter_success = 0
        counter_warning = 0
        temp_directory = settings.temp_directory
        # open files
        os.makedirs(temp_directory, exist_ok=True)
        input_file_path = os.path.abspath(segment.file_name)
        # create 'unique' temp file prefix
        file_prefix = f'_hg_{int(time.time())}_'
        # open files and process segment
        with open(input_file_path, mode='r', encoding='UTF-8', errors='strict') \
             as file_input, \
             open(f"{temp_directory}/{file_prefix}{segment.segment_number}.dat", mode='w', encoding='UTF-8') \
             as file_temp:
            # record temp files absolute paths
            temp_file_path = os.path.abspath(file_temp.name)
            temp_err_file_path = f"{temp_directory}/{file_prefix}_{segment.segment_number}.err"
            # process chunk lines
            segment_start = segment.segment_start
            file_input.seek(segment_start)
            for input_line in file_input:
                try:
                    segment_start += len(input_line)
                    if segment_start > segment.segment_end: # exit at end of chunk
                        break
                    result_line=""
                    for hash_name in settings.hash_algorithms:
                        hash_hex = hash_string(input_line[0:-1], settings, hash_name)
                        if isinstance(hash_hex,str):
                            result_line += hash_hex + settings.separator
                        elif isinstance(hash_hex, dict): # error
                            raise ValueError("Hashing Error")
                    result_line += input_line[0:-1]
                    print(result_line, file=file_temp)
                    counter_success += 1
                except ValueError:
                    if settings.verbose >= 1:
                        print(f"VERBOSE ({_function_name}): {hash_hex['message']}", file=sys.stderr)
                        print(f"VERBOSE ({_function_name}): {hash_hex['name']} - {hash_hex['details']}",
                            file=sys.stderr)
                    if settings.error_file:
                        log_errored_line(error_file=temp_err_file_path, line=input_line, settings=settings)
                    counter_warning += 1
        results = SegmentResults(
            segment_number = segment.segment_number,
            temp_file_path = temp_file_path,
            temp_err_file_path = temp_err_file_path,
            counter_success = counter_success,
            counter_warning = counter_warning,
            time_elapsed = timedelta(seconds=time.time() - time_start),
            time_processor = time.process_time())
        return results
    except OSError as error:
        print(f"ERROR: An error occurred processing segment [{segment.segment_number}]:\n" \
            f"    Segment temp file: {temp_file_path}" \
            f"    Source file range: {input_file_path} [{segment.segment_start} to {segment.segment_end}]" \
            f"{type(error).__name__} - {error}",
            file=sys.stderr
        )
        return False

def log_errored_line(
        error_file: str,
        line: str,
        settings: HashGeneratorSettings = None
    ) -> bool:
    """ log the line producing an error to a file """
    try:
        # verbose output prep
        time_start = time.time()
        _function_name = inspect.currentframe().f_code.co_name
        # log error
        error_file_path = os.path.abspath(error_file)
        with open(file=error_file_path, mode='a', encoding="utf-8", errors='strict') as file_error:
            if line[-1] == '\n':
                file_error.write(line)
            else:
                print(line, file=file_error)
        # print verbose details to STDERR to avoid polluting output in STDOUT mode
        if settings:
            if settings.verbose == 2: # specify -vv or --verbose --verbose
                print(f"VERBOSE ({_function_name}): Logging error line took: " \
                      f"{timedelta(seconds=(time.time() - time_start))}" \
                      f" | File: [{error_file_path}] - line[{line[0:-1]}]",
                    file=sys.stderr)
        return True
    except OSError as error:
        print(f"ERROR: An error occurred logging an unprocessed line to error file [{error_file_path}]:\n" \
              f"    line: {line}\n" \
              f"{type(error).__name__} - {error}",
            file=sys.stderr)
        return False

def segment_file(
        file_name: str,
        segments: int = 1,
        settings: HashGeneratorSettings = None
    ) -> list:
    """
    Scan a file to identifying the start and end position of the defined number of
    segments, aligning each segment to the nearest line break.
        REF: https://nurdabolatov.com/parallel-processing-large-file-in-python
    """
    try:
        # verbose output prep
        time_start = time.time()
        _function_name = inspect.currentframe().f_code.co_name
        # segment file
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
                segment = FileSegment(
                    segment_number = segment_number,
                    file_name = file_name,
                    segment_start = segment_start,
                    segment_end = segment_end)
                segment_number +=1
                segment_parts.append(segment)
                # Move to the next chunk
                segment_start = segment_end
        # print verbose details to STDERR to avoid polluting output in STDOUT mode
        if settings:
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Segmenting took: {timedelta(seconds=(time.time() - time_start))} " \
                      f"File: [{file_path}]\nVERBOSE ({_function_name}): Segment details:",
                    file=sys.stderr)
                print(*segment_parts, sep='\n')
        return segment_parts
    except OSError as error:
        print(f"ERROR: An error occurred defining file segments in file [{file_path}]:\n" \
              f"{type(error).__name__} - {error}",
            file=sys.stderr)
        sys.exit(-1)

def track_jobs(
        job_pool: multiprocessing.Pool,
        update_interval: int = 1,
        message_prefix: str = "Tasks remaining: ",
        settings: HashGeneratorSettings = None
    ) -> None:
    """ Track the status of running multi-process async pools printing status at [update_interval] """
    # pylint: disable=protected-access
    # (referencing functions prefixed with _)
    try:
        # verbose output prep
        time_start = time.time()
        thread_time_start = time.thread_time()
        _function_name = inspect.currentframe().f_code.co_name
        # track jobs
        while job_pool._number_left > 0:
            print(f"\r{message_prefix}{job_pool._number_left : < {len(message_prefix) + 10}}", end="")
            time.sleep(update_interval)
        print(f"\r{message_prefix}{0 : < {len(message_prefix) + 10}}")
        # print verbose details to STDERR to avoid polluting output in STDOUT mode
        if settings:
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): job execution took: " \
                      f"{timedelta(seconds=(time.time() - time_start))}\n" \
                      f"VERBOSE ({_function_name}): job tracking used: " \
                      f"{timedelta(seconds=(time.thread_time() - thread_time_start))} processor time",
                    file=sys.stderr)
    except OSError as error:
        print("ERROR: An error occurred tracking child processes, exiting.  Temp files may persist:\n" \
            f"{type(error).__name__} - {error}",
            file=sys.stderr)
        sys.exit(-1)

def process_multi(
        settings: HashGeneratorSettings
    ) -> int:
    """ Process via multi_processing """
    # verbose output prep
    time_start = time.time()
    _function_name = inspect.currentframe().f_code.co_name
    # count lines in source file
    try:
        input_file_base_name = os.path.basename(settings.input_file)
        print(f"Counting lines in '{input_file_base_name}': ", end='', flush=True)
        input_file_lines = count_lines(file_name=os.path.abspath(settings.input_file), settings=settings)
        print(input_file_lines)
        if not isinstance(input_file_lines,int) or input_file_lines < 1:
            print(f"ERROR: Unable to count lines in file: {os.path.abspath(settings.input_file)}, exiting.",
                file=sys.stderr)
            sys.exit(-1)
    except OSError:
        print(f"ERROR: Unable to count lines in file: {os.path.abspath(settings.input_file)}, exiting.",
            file=sys.stderr)
        sys.exit(-1)
    # determine file segment details: errors handled by segment_file()
    if input_file_lines >= settings.parallel * 1000:
        segment_list = segment_file(file_name=settings.input_file, segments=settings.parallel, settings=settings)
    else:
        # less than 1000 lines assigned to a segment (core) adjusting.
        if settings.verbose:
            print(f"VERBOSE ({_function_name}):  input file contains " \
                  f"{input_file_lines} lines, adjusting to {input_file_lines // 1000} worker(s).",
                file=sys.stderr)
        segment_count = input_file_lines // 1000
        segment_list = segment_file(file_name=settings.input_file, segments=segment_count, settings=settings)
    # merge segment list with settings into a 2 item list matching hash_file_segment() arguments
    hash_file_segment_args = []
    for segment in segment_list:
        # convert settings to dict: namedtuple not supported by multiprocessing.Pool (pickle limitation)
        # https://docs.python.org/3/library/pickle.html#what-can-be-pickled-and-unpickled
        hash_file_segment_args.append([segment, settings._asdict()])
    # start and monitor child processes: errors handled by track_jobs()
    try:
        with multiprocessing.Pool(settings.parallel) as process_pool:
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Creating process pool with {len(hash_file_segment_args)} workers.",
                    file=sys.stderr)
            pool_start_time = time.time()
            pool_results = process_pool.starmap_async(
                func=hash_file_segment,
                iterable=hash_file_segment_args,
                chunksize = 1)
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Tracking jobs to completion",
                    file=sys.stderr)
            track_jobs(pool_results, message_prefix="Creating hashes - Jobs remaining: ", settings=settings)
            segment_results = pool_results.get()
            pool_end_time = time.time()
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Segment result details:", file=sys.stderr)
                print(*segment_results, sep='\n')
                process_pool_cpu_time = 0
                for segment in segment_results:
                    process_pool_cpu_time += segment.time_processor
    except OSError as error:
        print("ERROR: An error occurred starting child jobs, exiting.  Temp files may persist.:\n" \
              f"{type(error).__name__} - {error}",
            file=sys.stderr)
        sys.exit(-1)
   # create output file(s)
    try:
        # start clock for temp file I/O
        time_start_io = time.time()
        # create output directory if needed
        output_file_path = os.path.abspath(settings.output_file)
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        if settings.verbose >= 1:
            print(f"VERBOSE ({_function_name}): Created output file path, if required " \
                  f"[{os.path.dirname(output_file_path)}]",
                file=sys.stderr)
        if settings.error_file:
            output_error_file_path = os.path.abspath(settings.error_file)
            os.makedirs(os.path.dirname(output_error_file_path), exist_ok=True)
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Created error file path, if required " \
                      f"[{os.path.dirname(output_file_path)}]",
                    file=sys.stderr)
        # output header
        if not settings.no_header:
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Added header line to output file " \
                      f"[{os.path.dirname(output_file_path)}]",
                    file=sys.stderr)
            with open(output_file_path, mode='w', encoding='UTF-8', errors='strict') as file_output:
                print(*settings.hash_algorithms, "cleartext", sep=settings.separator, file=file_output)
        else:
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Output header skipped, setting [no_header] = False",
                    file=sys.stderr)
        # merge and output results temp files
        for i, result in enumerate(segment_results):
            print(f"\rMerging temporary files: {len(segment_results) - i} remaining          ", end="")
            if not append_files(from_file=result.temp_file_path, to_file=settings.output_file, settings=settings):
                print(f"ERROR: error appending {result.temp_file_path} to {settings.output_file}, exiting: " /
                      f"temp files (prefixed with '_hg_' may still exist in [{settings.temp_directory}]",
                    file=sys.stderr)
                sys.exit(-1)
            # delete temp file after merge
            if os.access(result.temp_file_path, os.W_OK):
                if settings.verbose >= 1:
                    print(f"VERBOSE ({_function_name}): Deleting temp file [{result.temp_file_path}]", file=sys.stderr)
                os.remove(result.temp_file_path)
            else:
                if settings.verbose >= 1:
                    print(f"VERBOSE ({_function_name}): Unable to delete temp file (no write access) " \
                          f"[{result.temp_file_path}]",
                        file=sys.stderr)
        print("\rMerging temporary files: 0 remaining          ")
        # merge and output results temp error files
        if settings.error_file:
            for i, result in enumerate(segment_results):
                print(f"\rMerging temporary error files: {len(segment_results) - i} remaining          ", end="")
                if not append_files(
                    from_file=result.temp_err_file_path,
                    to_file=output_error_file_path,
                    settings=settings
                ):
                    print(f"ERROR: error appending {result.temp_file_path} to {settings.output_file}, exiting: " \
                          f"temp files (prefixed with '_hashgen_'may still exist in [{settings.temp_directory}]",
                        file=sys.stderr)
                    sys.exit(-1)
                if os.access(result.temp_err_file_path, os.W_OK): # temp error file
                    if settings.verbose >= 1:
                        print(f"VERBOSE ({_function_name}): Deleting temp error file [{result.temp_err_file_path}]",
                            file=sys.stderr)
                    os.remove(result.temp_err_file_path)
                else:
                    if settings.verbose >= 1:
                        print(f"VERBOSE ({_function_name}): Unable to delete temp error file (no write access) " \
                              f"[{result.temp_err_file_path}]",
                            file=sys.stderr)
            print("\rMerging temporary error files: 0 remaining          ")
        # delete temp directory if not PWD or not empty
        temp_path = os.path.abspath(settings.temp_directory)
        if not temp_path == os.path.abspath(os.getcwd()):
            if len(os.listdir(temp_path)) == 0: # empty temp directory
                if settings.verbose >= 1:
                    print(f"VERBOSE ({_function_name}): Deleting empty temp directory [{temp_path}]",
                        file=sys.stderr)
                os.rmdir(temp_path)
            else:
                if settings.verbose >= 1:
                    print(f"VERBOSE ({_function_name}): Temp directory not empty, skipping deletion [{temp_path}]",
                        file=sys.stderr)
        else:
            # temp path == CWD
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Temp directory is CWD, skipping deletion [{temp_path}]",
                    file=sys.stderr)
    except OSError as error:
        print("ERROR: An error occurred merging temp files, exiting.  Temp files may persist.:\n" \
              f"{type(error).__name__} - {error}",
            file=sys.stderr)
        sys.exit(-1)
    # show results
    success_lines = 0
    warning_lines = 0
    for segment in segment_results:
        success_lines += segment.counter_success
        warning_lines += segment.counter_warning
    # print verbose details to STDERR to avoid polluting output in STDOUT mode
    if settings.verbose >= 1: # specify -vv or --verbose --verbose
        # calculate timing / performance info
        time_process_pool = timedelta(seconds = process_pool_cpu_time)
        time_avg_process = timedelta(seconds = process_pool_cpu_time / len(hash_file_segment_args))
        time_elapsed = timedelta(seconds = pool_end_time - pool_start_time)
        pool_gain = round(process_pool_cpu_time /(pool_end_time - pool_start_time), 2)
        pool_efficiency = round(
            ((process_pool_cpu_time / (pool_end_time - pool_start_time))  / len(hash_file_segment_args)) * 100,
            2)
        time_io = timedelta(seconds = time.time() - time_start_io)
        time_pool_loop = timedelta(seconds = time.time() - time_start)
        print(f"\nVERBOSE ({_function_name}): Total process pool cpu time: {time_process_pool}\n" \
              f"VERBOSE ({_function_name}):    Average process cpu time: {time_avg_process}\n" \
              f"VERBOSE ({_function_name}):                Elapsed time: {time_elapsed}\n" \
              f"VERBOSE ({_function_name}):     Process pool speed gain: {pool_gain}x\n" \
              f"VERBOSE ({_function_name}):          Process efficiency: {pool_efficiency}%\n" \
              f"VERBOSE ({_function_name}):          Temp File I/O time: {time_io}\n" \
              f"VERBOSE ({_function_name}):      Process Pool loop time: {time_pool_loop}\n",
            file=sys.stderr)
    print("Results:")
    print(f"      Input lines: {input_file_lines}")
    print(f"    skipped lines: {warning_lines}")
    print(f"     Output lines: {success_lines}")
    if success_lines != input_file_lines:
        print("======================================================")
        print("WARNING: Result count does not match input file lines!")
        if success_lines > input_file_lines:
            print(f"Note: {success_lines - input_file_lines} more output lines than input file lines:")
            print("      Your input file may contain UTF-8 characters causing duplicate result lines")
            print("      such as control characters, line endings, or right-to-left printing ex: arabic")
            print("      Consider processing without multithreading (--parallel=1 / -p 1)")
            print("      Alternately clean input file or remove duplicate lines from output file. ex:")
            print("         [sort --unique] sorted deduplicated output")
            print("         [rli or rling] unsorted deduplicated output")
    return 0

def process_single(
        settings: HashGeneratorSettings
    ) -> int:
    """ Process via main thread (single-threaded) """
    # verbose output prep
    time_start = time.time()
    _function_name = inspect.currentframe().f_code.co_name
    # prepare counters
    counter_success = 0
    counter_warning = 0
    if settings.output_file:
        # output to file
        try:
            if isinstance(settings.input_file, str) and len(settings.input_file) > 0:
                # file input NOT <STDIN>
                # count lines in source file
                try:
                    input_file_base_name = os.path.basename(settings.input_file)
                    if settings.verbose >= 1:
                        print(f"VERBOSE ({_function_name}): File based input [{os.path.abspath(settings.input_file)}]",
                            file=sys.stderr)
                    print(f"Counting lines in '{input_file_base_name}': ", end='', flush=True)
                    input_file_lines = count_lines(file_name=os.path.abspath(settings.input_file), settings=settings)
                    print(input_file_lines)
                    if not isinstance(input_file_lines,int) or input_file_lines < 1:
                        print(f"ERROR: Unable to count lines in file: {os.path.abspath(settings.input_file)}, exiting.",
                            file=sys.stderr)
                        sys.exit(-1)
                except OSError:
                    print(f"ERROR: Unable to count lines in file: {os.path.abspath(settings.input_file)}, exiting.",
                        file=sys.stderr)
                    sys.exit(-1)
                # process source file
                update_interval = input_file_lines // 100 # ~1% progress
                output_file_path = os.path.abspath(settings.output_file)
                if settings.verbose >= 1:
                    print(f"VERBOSE ({_function_name}): File based output [{output_file_path}]\n" \
                          f"VERBOSE ({_function_name}): Update progress every [{update_interval}] lines.",
                        file=sys.stderr)
                print(f"Processing file [{input_file_base_name}]: 0% complete          ", end="")
                with open(file=output_file_path, mode='w', encoding="utf-8", errors='strict') as file_output:
                    # print header
                    if not settings.no_header:
                        print(*settings.hash_algorithms, "cleartext", sep=settings.separator, file=file_output)
                    line_number: int  = 1
                    # process lines
                    for input_line in fileinput.input(files=settings.input_file):
                        try:
                            result_line=""
                            for hash_name in settings.hash_algorithms:
                                hash_hex = hash_string(input_line[0:-1], settings, hash_name)
                                if isinstance(hash_hex,str):
                                    result_line += hash_hex + settings.separator
                                elif isinstance(hash_hex, dict): # error
                                    raise ValueError("Hashing Error")
                            result_line += input_line[0:-1]
                            print(result_line, file=file_output)
                            counter_success += 1
                            if line_number % update_interval == 0: # update progress
                                print(f"\rProcessing file '{input_file_base_name}': " \
                                        f"{round((line_number / input_file_lines) * 100)}% complete          ",
                                        end="")
                            line_number += 1
                        except ValueError:
                            if settings.verbose >= 1:
                                print(f"VERBOSE ({_function_name}): {hash_hex['message']}", file=sys.stderr)
                                print(f"VERBOSE ({_function_name}): {hash_hex['name']} - {hash_hex['details']}",
                                    file=sys.stderr)
                            if settings.error_file:
                                log_errored_line(error_file=settings.error_file, line=input_line, settings=settings)
                            counter_warning += 1
                        except IOError as error:
                            if settings.verbose >= 1:
                                print(f"ERROR: line #{str(fileinput.lineno())} generated an error:\n" \
                                      f"    line: {input_line[0:-1]}\n" \
                                      f"{type(error).__name__} - {error}",
                                    file=sys.stderr)
                            if settings.error_file:
                                log_errored_line(settings.error_file, input_line, settings=settings)
                            counter_errors += 1
                    print(f"\rProcessing file '{input_file_base_name}': 100% complete          ")
                    if settings.verbose >= 1:
                        print(f"VERBOSE ({_function_name}): Total file process time: " \
                              f"{timedelta(seconds=time.time() - time_start)}\n",
                            file=sys.stderr)
                    # show results
                    print("Results:")
                    print(f"      Input lines: {input_file_lines}")
                    print(f"    skipped lines: {counter_warning}")
                    print(f"     Output lines: {counter_success}")
                    if counter_success != input_file_lines:
                        print("======================================================")
                        print("WARNING: Result count does not match input file lines!")
                        if counter_success > input_file_lines:
                            lines_extra = counter_success - input_file_lines
                            print(f"Note: {lines_extra} more output lines than input file lines:")
                            print("    Your input file may contain UTF-8 characters causing duplicate result lines")
                            print("    such as control characters, line endings, or right-to-left printing ex: arabic")
                            print("    Consider processing without multithreading (--parallel / -r)")
                            print("    Alternately clean input file or remove duplicate lines from output file. ex:")
                            print("       [sort --unique] sorted deduplicated output")
                            print("       [rli or rling] unsorted deduplicated output")
            else:
                # input is <STDIN>
                output_file_path = os.path.abspath(settings.output_file)
                if settings.verbose >= 1:
                    print(f"VERBOSE ({_function_name}): <STDIN> based input", file=sys.stderr)
                    print(f"VERBOSE ({_function_name}): file based output [{output_file_path}]", file=sys.stderr)
                with open(file=output_file_path, mode='w', encoding="utf-8", errors='strict') as file_output:
                    input_file_lines: int = 0
                    # print header
                    if not settings.no_header:
                        print(*settings.hash_algorithms, "cleartext", sep=settings.separator, file=file_output)
                    # process lines
                    for input_line in fileinput.input(files=settings.input_file):
                        try:
                            input_file_lines += 1
                            result_line=""
                            for hash_name in settings.hash_algorithms:
                                hash_hex = hash_string(input_line[0:-1], settings, hash_name)
                                if isinstance(hash_hex,str):
                                    result_line += hash_hex + settings.separator
                                elif isinstance(hash_hex, dict): # error
                                    raise ValueError("Hashing Error")
                            result_line += input_line[0:-1]
                            print(result_line, file=file_output)
                            counter_success += 1
                        except ValueError:
                            if settings.verbose >= 1:
                                print(f"VERBOSE ({_function_name}): {hash_hex['message']}", file=sys.stderr)
                                print(f"VERBOSE ({_function_name}): {hash_hex['name']} - {hash_hex['details']}",
                                    file=sys.stderr)
                            if settings.error_file:
                                log_errored_line(error_file=settings.error_file, line=input_line, settings=settings)
                            counter_warning += 1
                        except IOError as error:
                            if settings.verbose >= 1:
                                print(f"ERROR: line #{str(fileinput.lineno())} generated an error:\n" \
                                        f"    line: {input_line[0:-1]}\n" \
                                        f"{type(error).__name__} - {error}",
                                        file=sys.stderr)
                            if settings.error_file:
                                log_errored_line(settings.error_file, input_line, settings=settings)
                            counter_errors += 1
                if settings.verbose >= 1:
                    print(f"VERBOSE ({_function_name}): Total file process time: " \
                          f"{timedelta(seconds=time.time() - time_start)}\n",
                        file=sys.stderr)
                print("Results:")
                print(f"  Input lines <STDIN>: {input_file_lines}")
                print(f"        skipped lines: {counter_warning}")
                print(f"         Output lines: {counter_success}")

        except OSError as error:
            print(f"ERROR: An error occurred processing hashes to file [{output_file_path}]:\n" \
                f"{type(error).__name__} - {error}",
                file=sys.stderr)
        if settings.verbose >= 1:
            print(f"VERBOSE ({_function_name}): Total file process time: " \
                  f"{timedelta(seconds=time.time() - time_start)}\n",
                file=sys.stderr)
        return 0
    else:
        # output to STDOUT
        try:
            input_file_lines: int = 0
            # print header
            if not settings.no_header:
                print(*settings.hash_algorithms, "cleartext", sep=settings.separator)
            # process lines
            for input_line in fileinput.input(files=settings.input_file):
                if input_file_lines == 0:
                    if settings.verbose:
                        if fileinput.isstdin():
                            print(f"VERBOSE ({_function_name}): input is <STDIN>", file=sys.stderr)
                        else:
                            print(f"VERBOSE ({_function_name}): input is ({settings.input_file})", file=sys.stderr)
                input_file_lines += 1
                try:
                    result_line=""
                    for hash_name in settings.hash_algorithms:
                        hash_hex = hash_string(input_line[0:-1], settings, hash_name)
                        if isinstance(hash_hex,str):
                            result_line += hash_hex + settings.separator
                        elif isinstance(hash_hex, dict): # error
                            raise ValueError("Hashing Error")
                    result_line += input_line[0:-1]
                    print(result_line)
                    counter_success += 1
                except ValueError:
                    if settings.verbose >= 1:
                        print(f"VERBOSE ({_function_name}): {hash_hex['message']}", file=sys.stderr)
                        print(f"VERBOSE ({_function_name}): {hash_hex['name']} - {hash_hex['details']}",
                            file=sys.stderr)
                    if settings.error_file:
                        log_errored_line(error_file=settings.error_file, line=input_line, settings=settings)
                    counter_warning += 1
                except IOError as error:
                    if settings.verbose >= 1:
                        print(f"ERROR: line #{str(fileinput.lineno())} generated an error:\n" \
                                f"    line: {input_line[0:-1]}\n" \
                                f"{type(error).__name__} - {error}",
                                file=sys.stderr)
                    if settings.error_file:
                        log_errored_line(settings.error_file, input_line, settings=settings)
                    counter_errors += 1
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Total file process time: " \
                      f"{timedelta(seconds=time.time() - time_start)}",
                    file=sys.stderr)
                print(f"VERBOSE ({_function_name}): Results:", file=sys.stderr)
                print(f"VERBOSE ({_function_name}):   Input lines <STDIN>: {input_file_lines}", file=sys.stderr)
                print(f"VERBOSE ({_function_name}):         skipped lines: {counter_warning}", file=sys.stderr)
                print(f"VERBOSE ({_function_name}):          Output lines: {counter_success}", file=sys.stderr)
        except OSError as error:
            print(f"ERROR: An error occurred processing hashes to file [{output_file_path}]:\n" \
                f"{type(error).__name__} - {error}",
                file=sys.stderr)

def main() -> int:
    """ collect arguments, parse settings and init based on threading selection """
    # verbose output prep
    time_start = time.time()
    _function_name = inspect.currentframe().f_code.co_name
    time_init = time.process_time()
    # collect shell arguments and process settings
    arg_parser = parse_arguments()
    settings = parse_settings(arguments=arg_parser.parse_args())
    # check if scripts expects data over <STDIN> and return help screen if TTY detected
    if not isinstance(settings.input_file, str) and sys.stdin.isatty():
        arg_parser.print_help()
        sys.exit(0)
    # process job based on processes (single vs multi)
    if settings.parallel > 1:
        # multi-process mode
        if len(settings.input_file) > 0 and settings.output_file:
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Parallel execution selected with file based input.",
                    file=sys.stderr)
            process_multi(settings=settings)
        else:
            # fallback to single process mode for stdin
            if settings.verbose >= 1:
                print(f"VERBOSE ({_function_name}): Parallel not supported with <STDIN> or <STDOUT>,\n" \
                       "Specify both input and output files (ref: -i & -o), using single threaded.",
                    file=sys.stderr)
            process_single(settings=settings)
    elif settings.parallel == 1:
        # single process mode
        if settings.verbose >= 1:
            print(f"VERBOSE ({_function_name}): Single threaded selected",
                file=sys.stderr)
        process_single(settings=settings)
    else:
        # unable to determine threading
        print("ERROR: Unable to determine a threading strategy, exiting.",
                file=sys.stderr,)
        return -1
    # print verbose details to STDERR to avoid polluting output in STDOUT mode
    if settings.verbose >= 1:
        print(f"VERBOSE ({_function_name}): Python init time time: {timedelta(seconds=time_init)}",
            file=sys.stderr)
        print(f"VERBOSE ({_function_name}): Total execution time: {timedelta(seconds=(time.time() - time_start))}",
            file=sys.stderr)
        print(f"VERBOSE ({_function_name}): Total processor time: {timedelta(seconds=time.process_time())}",
            file=sys.stderr)


# auto start if called directly
if __name__ == '__main__':
    sys.exit(main())
