import struct
import os
import sys
import zlib
from pathlib import Path
from ctypes import *

FILE_SIGNATURE = b'FCRA'
ZLIB_HEADER = b'\x78\xDA'

class FileStruct(LittleEndianStructure):
    _fields_ = [
        ('hashed_name', c_uint64),
        ('unknown', c_uint32),
        ('decompressed_size', c_uint32),
        ('data_offset', c_uint64)
    ]

class FCRAUnpack:
    def __init__(self, filepath):
        with open(filepath, 'rb') as file:
            assert file.read(4) == FILE_SIGNATURE
            file.read(4)

            file_count  = struct.unpack('<Q', file.read(8))[0]
            print(f"Log: Extracting {file_count} files..")
            file_structs= self.get_file_structures(file_count, file)
            uncompressed_data = self.get_file_data(file_structs, file)
            folder_name = Path(filepath).stem
            
            print("Log: Creating extracted files..")
            os.makedirs(folder_name, exist_ok=True)
            os.chdir(folder_name)
            for hashed_name in uncompressed_data:
                file_name = hashed_name
                file_data = uncompressed_data[hashed_name]
                file_extension = file_data[:4].decode('utf-8').strip().lower()
                self.create_file(file_name, file_data, file_extension)

            print(f"Log: Finished a new folder was created called {folder_name}." )


    def get_file_structures(self, file_count, file):
        file_structures = []
        for _ in range(file_count):
            file_struct = FileStruct()
            file.readinto(file_struct)
            file_structures.append(file_struct)
        return file_structures
    
    def get_file_data(self, file_structs, file):
        uncompressed_files = {}
        for file_struct in file_structs:
            file.seek(file_struct.data_offset)
            
            chunk_count = (file_struct.decompressed_size >> 15) & 0xFFFF
            if (file_struct.decompressed_size & 0xFFFF != 0):
                chunk_count += 1

            compressed_sizes  = self.get_compressed_sizes(file, chunk_count)
            uncompressed_data = b''
            for size in compressed_sizes:
                uncompressed_data += zlib.decompress(file.read(size))

            uncompressed_files[file_struct.hashed_name] = uncompressed_data

        return uncompressed_files
        
    def create_file(self, file_name, file_data, file_extension):
        with open(f'{file_name}.{file_extension}', 'wb') as file:
            file.write(file_data)

    def get_compressed_sizes(self, file, chunk_count):
        compressed_sizes = []
        for _ in range(chunk_count):
            compressed_size = file.read(4)
            compressed_sizes.append(struct.unpack('<I', compressed_size)[0])
        return compressed_sizes

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Error: Please specify a target .arc file")
        exit()

    FCRAUnpack(sys.argv[1])
    