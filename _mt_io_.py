"""
mod docstring
"""
import os

def chunk_file(file_name: str, segments: int = 1) -> list:
    """
    Scan a file to identifying the start and end position of the defined number of 'chunks'
    aligning to the nearest line break.

    refactored from: https://nurdabolatov.com/parallel-processing-large-file-in-python

    """
    chunk_number = 1
    file_size = os.path.getsize(file_name)
    chunk_size = file_size // segments
    chunk_parts = []

    with open(file_name, 'r', encoding="utf8", errors="surrogateescape") as file:
        def is_start_of_line(position):
            if position == 0:
                return True
            # Check whether the previous character is EOL
            file.seek(position - 1)
            return file.read(1) == '\n'

        def get_next_line_position(position):
            # Read the current line until the end
            file.seek(position)
            file.readline()
            # Return a position after reading the line
            return file.tell()

        chunk_start = 0
        # Iterate over all chunks and construct arguments for `process_chunk`
        while chunk_start < file_size:
            if chunk_number == segments:
                # grow the last chunk to be larger honoring # of segments
                chunk_end = file_size
            else:
                chunk_end = min(file_size, chunk_start + chunk_size)
            # Make sure the chunk ends at the beginning of the next line
            while not is_start_of_line(chunk_end):
                chunk_end -= 1
            # Handle the case when a line is too long to fit the chunk size
            if chunk_start == chunk_end:
                chunk_end = get_next_line_position(chunk_end)
            # Save `process_chunk` arguments
            args = [chunk_number, file_name, chunk_start, chunk_end]
            chunk_number +=1
            chunk_parts.append(args)
            # Move to the next chunk
            chunk_start = chunk_end
    return chunk_parts
