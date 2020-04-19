'''Provide the `PE` class to parse and modify PE files.
'''


import os
import sys
import mmap


SIZE_BYTE = 1
SIZE_WORD = 2
SIZE_DWORD = 4
SIZE_QWORD = 8
SIGNATURE_DOS_STUB = b'MZ'
SIGNATURE_PE = b'PE\0\0'
MAGIC_PE32PLUS = 0x20b


def b2i(b):
    # Integers are always little endian in PE files.
    return int.from_bytes(b, 'little')


def null_str(raw):
    return raw.rstrip(b'\0').decode('utf-8')


class BadPEFile(Exception): pass


class Struct:
    '''Binary data struct auto-parsing class.'''

    FIELDS = (
        # (offset, length, name, convert function),
    )

    def __init__(self, pe):
        self._data = {}
        self.pe = pe
        self.parse()
    
    def parse(self):
        self.parse_field_set(self.FIELDS)
    
    def parse_field_set(self, field_set):
        for offset, length, name, convert in field_set:
            self[name] = self.pe.read_at(self.file_base + offset, length, convert)
    
    @property
    def file_base(self):
        '''Calculate where in the file is the start of this struct. Must be overridden.
        '''
        raise Exception('This method must be overridden.')
    
    @property
    def size(self):
        return sum(length for _, length, _, _ in self.FIELDS)
    
    @property
    def file_end(self):
        return self.file_base + self.size
    
    def __setitem__(self, name, value):
        self._data[name] = self.__dict__[name] = value
    
    def __getitem__(self, name):
        return self._data[name]
    
    def __repr__(self):
        return '{}(offset={} size={})'.format(self.__class__.__name__, hex(self.file_base), hex(self.size))


class BitFlag:
    '''Bit flag auto-parsing class.
    
    By default the flag bits are considered next to each other, i.e. 0x01, 0x02, 0x04, 0x08, 0x10, and so on.
    '''

    FLAGS = (
        # (bit, name),
        # or just names, to use the default pattern.
    )
    def __init__(self, raw):
        self._data = {}
        self.raw = b2i(raw)
        self.parse()

    def parse(self):
        if isinstance(self.FLAGS[0], str):
            bit = 1
            for name in self.FLAGS:
                self[name] = self.raw & bit != 0
                bit <<= 1
        else:
            for bit, name in self.FLAGS:
                self[name] = self.raw & bit != 0


    def __setitem__(self, key, value):
        self._data[key] = self.__dict__[key] = value
    

class COFFCharacteristics(BitFlag):
    FLAGS = (
        'IMAGE_FILE_RELOCS_STRIPPED',
        'IMAGE_FILE_EXECUTABLE_IMAGE',
        'IMAGE_FILE_LINE_NUMS_STRIPPED',
        'IMAGE_FILE_LOCAL_SYMS_STRIPPED',
        'IMAGE_FILE_AGGRESSIVE_WS_TRIM',
        'IMAGE_FILE_LARGE_ADDRESS_AWARE',
        '', # Reserved
        'IMAGE_FILE_BYTES_REVERSED_LO',
        'IMAGE_FILE_32BIT_MACHINE',
        'IMAGE_FILE_DEBUG_STRIPPED',
        'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',
        'IMAGE_FILE_NET_RUN_FROM_SWAP',
        'IMAGE_FILE_SYSTEM',
        'IMAGE_FILE_DLL',
        'IMAGE_FILE_UP_SYSTEM_ONLY',
        'IMAGE_FILE_BYTES_REVERSED_HI',
    )


class DLLCharacteristics(BitFlag):
    FLAGS = (
        '',
        '',
        '',
        '',
        'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA',
        'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',
        'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',
        'IMAGE_DLLCHARACTERISTICS_NX_COMPAT',
        'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',
        'IMAGE_DLLCHARACTERISTICS_NO_SEH',
        'IMAGE_DLLCHARACTERISTICS_NO_BIND',
        'IMAGE_DLLCHARACTERISTICS_APPCONTAINER',
        'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',
        'IMAGE_DLLCHARACTERISTICS_GUARD_CF',
        'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE',
    )


class COFFHeader(Struct):
    '''Object presenting the COFF header of a PE file.'''

    FIELDS = (
        (0, 2, 'Machine', b2i),
        (2, 2, 'NumberOfSections', b2i),
        (4, 4, 'TimeDateStamp', b2i),
        (8, 4, 'PointerToSymbolTable', b2i),
        (12, 4, 'NumberOfSymbols', b2i),
        (16, 2, 'SizeOfOptionalHeader', b2i),
        (18, 2, 'Characteristics', COFFCharacteristics),
    )

    @property
    def file_base(self):
        return self.pe.pe_sig_offset + len(SIGNATURE_PE)


class DataDirectory(Struct):
    FIELDS = (
        (0, SIZE_DWORD, 'VirtualAddress', b2i),
        (SIZE_DWORD, SIZE_DWORD, 'Size', b2i),
    )

    def __init__(self, optional_header, id):
        self.optional_header = optional_header
        self.id = id
        super().__init__(optional_header.pe)
    
    @property
    def file_base(self):
        if self.optional_header.pe32plus:
            return self.optional_header.file_base + self.optional_header.DATA_DIRECTORY_OFFSET_PE32PLUS + self.id * self.size
        else:
            return self.optional_header.file_base + self.optional_header.DATA_DIRECTORY_OFFSET_PE32 + self.id * self.size


class OptionalHeader(Struct):
    COMMON_FIELDS = (
        (0, 2, 'Magic', b2i),
        (2, 1, 'MajorLinkerVersion', b2i),
        (3, 1, 'MinorLinkerVersion', b2i),
        (4, 4, 'SizeOfCode', b2i),
        (8, 4, 'SizeOfInitializedData', b2i),
        (12, 4, 'SizeOfUninitializedData', b2i),
        (16, 4, 'AddressOfEntryPoint', b2i),
        (20, 4, 'BaseOfCode', b2i),

        (32, 4, 'SectionAlignment', b2i),
        (36, 4, 'FileAlignment', b2i),
        (40, 2, 'MajorOperatingSystemVersion', b2i),
        (42, 2, 'MinorOperatingSystemVersion', b2i),
        (44, 2, 'MajorImageVersion', b2i),
        (46, 2, 'MinorImageVersion', b2i),
        (48, 2, 'MajorSubsystemVersion', b2i),
        (50, 2, 'MinorSubsystemVersion', b2i),
        (52, 4, 'Win32VersionValue', b2i),
        (56, 4, 'SizeOfImage', b2i),
        (60, 4, 'SizeOfHeaders', b2i),
        (64, 4, 'CheckSum', b2i),
        (68, 4, 'Subsystem', b2i),
        (70, 2, 'DllCharacteristics', DLLCharacteristics),
    )

    PE32_FIELDS = (
        (28, 4, 'ImageBase', b2i),
        (72, 4, 'SizeOfStackReserve', b2i),
        (76, 4, 'SizeOfStackCommit', b2i),
        (80, 4, 'SizeOfHeapReserve', b2i),
        (84, 4, 'SizeOfHeapCommit', b2i),
        (88, 4, 'LoaderFlags', b2i),
        (92, 4, 'NumberOfRvaAndSizes', b2i),
    )

    PE32PLUS_FIELDS = (
        (24, 4, 'BaseOfData', b2i),

        (24, 8, 'ImageBase', b2i),
        (72, 8, 'SizeOfStackReserve', b2i),
        (80, 8, 'SizeOfStackCommit', b2i),
        (88, 8, 'SizeOfHeapReserve', b2i),
        (96, 8, 'SizeOfHeapCommit', b2i),
        (104, 4, 'LoaderFlags', b2i),
        (108, 4, 'NumberOfRvaAndSizes', b2i),
    )

    DATA_DIRECTORY_OFFSET_PE32 = 96
    DATA_DIRECTORY_OFFSET_PE32PLUS = 112

    def parse(self):
        self.parse_field_set(self.COMMON_FIELDS)
        self.pe32plus = self.Magic == MAGIC_PE32PLUS
        if self.pe32plus:
            self.parse_field_set(self.PE32PLUS_FIELDS)
        else:
            self.parse_field_set(self.PE32_FIELDS)   

        self.data_directories = []
        for i in range(self.NumberOfRvaAndSizes):
            self.data_directories.append(DataDirectory(self, i))

    @property
    def file_base(self):
        # At this time, the COFF header should have been parsed.
        return self.pe.coff_header.file_end

    @property
    def size(self):
        if self.pe32plus:
            return self.DATA_DIRECTORY_OFFSET_PE32PLUS + self.NumberOfRvaAndSizes * SIZE_DWORD * 2
        else:
            return self.DATA_DIRECTORY_OFFSET_PE32 + self.NumberOfRvaAndSizes * SIZE_DWORD * 2


class DataTables:
        class ExportTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class ImportTable:
            class ImportEntry(Struct):
                FIELDS = (
                    (0, 4, 'ImportLookupTableRVA', b2i),
                    (4, 4, 'TimeDateStamp', b2i),
                    (8, 4, 'ForwarderChain', b2i),
                    (12, 4, 'NameRVA', b2i),
                    (16, 4, 'ImportAddressTableRVA', b2i),
                )

                def __init__(self, table, id):
                    self.table = table
                    self.id = id
                    super().__init__(table.pe)
                
                @property
                def name(self):
                    return self.pe.read_till_zero(self.pe.file_offset_from_rva(self.NameRVA), null_str)

                @property
                def file_base(self):
                    return self.table.file_base + self.id * self.size
                
                def __repr__(self):
                    return '{}<{}>(offset={} size={})'.format(self.__class__.__name__, self.name, hex(self.file_base), hex(self.size))


            def __init__(self, pe, data_directory):
                self.pe = pe
                self.data_directory = data_directory

                self.entries = []

                if data_directory.VirtualAddress == 0:
                    return
                
                entry = None
                i = 0
                while True:
                    entry = self.ImportEntry(self, i)
                    if entry.NameRVA == 0:
                        return
                    self.entries.append(entry)
                    i += 1
                

            @property
            def file_base(self):
                return self.pe.file_offset_from_rva(self.data_directory.VirtualAddress)
        
        class ResourceTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class ExceptionTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class CertificateTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class BaseRelocationTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class Debug:
            def __init__(self, *args, **kwargs):
                pass
        
        class Architecture:
            def __init__(self, *args, **kwargs):
                pass
        
        class GlobalPointer:
            def __init__(self, *args, **kwargs):
                pass
        
        class TLSTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class LoadConfigTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class BoundImport:
            def __init__(self, *args, **kwargs):
                pass
        
        class ImportAddressTable:
            def __init__(self, *args, **kwargs):
                pass
        
        class DelayImportDescriptor:
            def __init__(self, *args, **kwargs):
                pass
        
        class CLRRuntimeHeader:
            def __init__(self, *args, **kwargs):
                pass
        
        class Reserved:
            def __init__(self, *args, **kwargs):
                pass


DATA_TABLE_ENTRIES = (
    DataTables.ExportTable,
    DataTables.ImportTable,
    DataTables.ResourceTable,
    DataTables.ExceptionTable,
    DataTables.CertificateTable,
    DataTables.BaseRelocationTable,
    DataTables.Debug,
    DataTables.Architecture,
    DataTables.GlobalPointer,
    DataTables.TLSTable,
    DataTables.LoadConfigTable,
    DataTables.BoundImport,
    DataTables.ImportAddressTable,
    DataTables.DelayImportDescriptor,
    DataTables.CLRRuntimeHeader,
    DataTables.Reserved,
)


class SectionFlags(BitFlag):
    FLAGS = (
        '',
        '',
        '',
        'IMAGE_SCN_TYPE_NO_PAD',
        'IMAGE_SCN_CNT_CODE',
        'IMAGE_SCN_CNT_INITIALIZED_DATA',
        'IMAGE_SCN_CNT_UNINITIALIZED_DATA',
        'IMAGE_SCN_LNK_OTHER',
        'IMAGE_SCN_LNK_INFO',
        '',
        'IMAGE_SCN_LNK_REMOVE',
        'IMAGE_SCN_LNK_COMDAT',
        'IMAGE_SCN_GPREL',
        'IMAGE_SCN_MEM_PURGEABLE',
        '',
        # TODO: Fill remaining flags (or need we?)
    )


class SectionHeader(Struct):
    FIELDS = (
        (0, 8, 'Name', null_str),
        (8, 4, 'VirtualSize', b2i),
        (12, 4, 'VirtualAddress', b2i),
        (16, 4, 'SizeOfRawData', b2i),
        (20, 4, 'PointerToRawData', b2i),
        (24, 4, 'PointerToRelocations', b2i),
        (28, 4, 'PointerToLinenumbers', b2i),
        (32, 2, 'PointerToRelocations', b2i),
        (34, 2, 'PointerToLinenumbers', b2i),
        (36, 4, 'Characteristics', SectionFlags),
    )

    def __init__(self, section, id):
        self.section = section
        self.id = id
        super().__init__(section.pe)

    @property
    def file_base(self):
        return self.pe.optional_header.file_end + self.id * self.size


class Section:
    def __init__(self, pe, id):
        self.pe = pe
        self.id = id
        self.header = SectionHeader(self, id)
    
    def contains_rva(self, rva):
        return self.header.VirtualAddress <= rva <= self.header.VirtualAddress + self.header.VirtualSize

    def __getattr__(self, name):
        return self.header[name]
    
    def __getitem__(self, name):
        return self.__getattr__(name)


class PE:
    '''Object representing a PE file.

    Since `.pyd`s are DLLs, and DLLs are image files, we don't consider object files here.

    :param source: PE file to load. Can be a path string, path-like object, or a file-like object.
    '''

    def __init__(self, source):
        self.load(source)
        self.parse_verify_coff_header()
        self.optional_header = OptionalHeader(self)

        self.sections = []
        for i in range(self.coff_header.NumberOfSections):
            self.sections.append(Section(self, i))

        self.data_tables = []
        for i, data_directory in enumerate(self.optional_header.data_directories):
            self.data_tables.append(DATA_TABLE_ENTRIES[i](self, data_directory))
    
    def load(self, source):
        # Given a path.
        if isinstance(source, (str, os.PathLike)):
            file = open(source, 'rb')
            if sys.platform.startswith('win32'):
                self.data = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_COPY)
            else:
                self.data = mmap.mmap(file.fileno(), 0, flags=mmap.MAP_PRIVATE)
            file.close()
        # A file-like object. We need `read`,`seek` and `tell` to properly handle the file.
        elif callable(getattr(source, 'read', None)) and callable(getattr(source, 'seek', None)) and callable(getattr(source, 'tell', None)):
            self.data = source
    
    def parse_verify_coff_header(self):
        if self.read_at(0, len(SIGNATURE_DOS_STUB)) != SIGNATURE_DOS_STUB:
            raise BadPEFile('Bad DOS stub')
        self.pe_sig_offset = self.read_at(0x3c, SIZE_DWORD, b2i)
        if self.read_at(self.pe_sig_offset, len(SIGNATURE_PE)) != SIGNATURE_PE:
            raise BadPEFile('Bad PE signature')

        self.coff_header = COFFHeader(self)
        if not self.coff_header.Characteristics.IMAGE_FILE_EXECUTABLE_IMAGE:
            raise BadPEFile('Not an executable')
        if not self.coff_header.Characteristics.IMAGE_FILE_DLL:
            raise BadPEFile('Not a DLL')

    def read_at(self, position, length, convert=None):
        self.data.seek(position)
        if convert:
            return convert(self.data.read(length))
        else:
            return self.data.read(length)

    def read_till_zero(self, start, convert=None):
        self.data.seek(start)
        while self.data.read(1) != b'\0':
            continue
        end = self.data.tell()
        return self.read_at(start, end - start, convert)

    def file_offset_from_rva(self, rva):
        for section in self.sections:
            if section.contains_rva(rva):
                return rva - section.header.VirtualAddress + section.header.PointerToRawData
