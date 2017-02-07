using System;
using System.Collections.Generic;
using System.Reflection;

namespace Ratchet.Runtime.Debugger
{
    /// <summary>
    /// Tools for Windows apps debugging
    /// </summary>
    public static partial class Windows
    {
        /// <summary>
        /// Tools to inspect PE files
        /// </summary>
        unsafe class PEReader
        {
            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            struct EXPORT_TABLE_DATA
            {
                public uint Characteristic;
                public uint Timestamp;
                public ushort MajorVersion;
                public ushort MinorVersion;
                public uint Name;
                public uint Base;
                public uint NumberOfFunction;
                public uint NumberOfName;
                public uint AddressOfFunctions;
                public uint AddressOfNames;
                public uint AddressOfNameOrdinal;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            struct IMAGE_SECTION_HEADER
            {
                public ulong Name;
                public uint Misc;
                public uint VirtualAddress;
                public uint SizeOfRawData;
                public uint PointerToRawData;
                public uint PointerToRelocations;
                public ushort NumberOfRelocations;
                public ushort NumberOfLinenumbers;
                public uint Characteristics;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            struct IMAGE_DATA_DIRECTORY
            {
                public uint VirtualAddress;
                public uint Size;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            struct IMAGE_OPTIONAL_HEADER32
            {
                public ushort Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public uint ImageBase;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public ushort Subsystem;
                public ushort DllCharacteristics;
                public uint SizeOfStackReserve;
                public uint SizeOfStackCommit;
                public uint SizeOfHeapReserve;
                public uint SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;
                public IMAGE_DATA_DIRECTORY exportTable;
                public IMAGE_DATA_DIRECTORY importTable;
                public IMAGE_DATA_DIRECTORY resourceTable;
                public IMAGE_DATA_DIRECTORY certificateTable;
                public IMAGE_DATA_DIRECTORY baseRelocationTable;
                public IMAGE_DATA_DIRECTORY debugInfoTable;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            struct IMAGE_OPTIONAL_HEADER64
            {
                public ushort Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public ulong ImageBase;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public ushort Subsystem;
                public ushort DllCharacteristics;
                public ulong SizeOfStackReserve;
                public ulong SizeOfStackCommit;
                public ulong SizeOfHeapReserve;
                public ulong SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;
                public IMAGE_DATA_DIRECTORY exportTable;
                public IMAGE_DATA_DIRECTORY importTable;
                public IMAGE_DATA_DIRECTORY resourceTable;
                public IMAGE_DATA_DIRECTORY certificateTable;
                public IMAGE_DATA_DIRECTORY baseRelocationTable;
                public IMAGE_DATA_DIRECTORY debugInfoTable;
            }

            static string ReadASCIIString(Module module, IntPtr ptr)
            {
                try
                {
                    int n = 0;
                    byte[] data = new byte[1];
                    string text = "";
                    while (1 == module.ReadMemory(new IntPtr(ptr.ToInt64() + n), data, 1) && data[0] != 0) { text += (char)data[0]; n++; }
                    return text;
                }
                catch { return ""; }
            }

            public static void ParsePE(Module module)
            {
                // Check the DOS header
                byte[] Magick = new byte[2];
                if (Magick.Length != module.ReadMemory(new IntPtr(0), Magick, 2))
                {
                    throw new Exception("Invalid PE file loaded");
                }
                if (Magick[0] != 0x4D && Magick[1] != 0x5A)
                {
                    throw new Exception("Invalid PE file loaded");
                }

                // We are at least debugging a 32 Bits Exe jump on the new header
                byte[] newHeaderOffset = new byte[4];
                if (newHeaderOffset.Length != module.ReadMemory(new IntPtr((16 + 14) * 2), newHeaderOffset, newHeaderOffset.Length))
                {
                    throw new Exception("Invalid PE file loaded");
                }
                uint offset = BitConverter.ToUInt32(newHeaderOffset, 0);
                ParseNewPE(module, offset);
            }

            static IntPtr FindAddressFromRVA(Module Module, ulong Address)
            {
                foreach (Module.Section section in Module.Sections)
                {
                    ulong baseAddr = (ulong)(section.BaseAddress.ToInt64() - Module.BaseAddress.ToInt64());
                    if (Address >= baseAddr && Address < baseAddr + section.Size)
                    {
                        return new IntPtr(section.BaseAddress.ToInt64() + (long)(Address - baseAddr) - Module.BaseAddress.ToInt64());
                    }
                }
                return new IntPtr(0);
            }

            static IntPtr FindAddressInSectionFromRVA(Module Module, ulong Address, out Module.Section Section)
            {
                foreach (Module.Section section in Module.Sections)
                {
                    ulong baseAddr = (ulong)(section.BaseAddress.ToInt64() - Module.BaseAddress.ToInt64());
                    if (Address >= baseAddr && Address < baseAddr + section.Size)
                    {
                        Section = section;
                        return new IntPtr((long)Address - (long)baseAddr);
                    }
                }
                Section = null;
                return new IntPtr(0);
            }

            static void ParseNewPE(Module module, uint Offset)
            {
                byte[] Magick = new byte[4];
                if (Magick.Length != module.ReadMemory(new IntPtr(Offset), Magick, 4))
                {
                    throw new Exception("Invalid PE file loaded");
                }
                if (Magick[0] != 0x50 && Magick[1] != 0x45 && Magick[2] != 0x00 && Magick[3] != 0x00)
                {
                    throw new Exception("Invalid PE file loaded");
                }
                Offset += 4; // Skip the magik number

                byte[] NTHeader = new byte[20];
                if (NTHeader.Length != module.ReadMemory(new IntPtr(Offset), NTHeader, 20))
                {
                    throw new Exception("Invalid PE file loaded");
                }

                uint SectionCount = (uint)NTHeader[2] + (uint)NTHeader[3] * 0x100;
                uint SymbolsTable = (uint)NTHeader[8] + (uint)NTHeader[9] * 0x100 + (uint)NTHeader[10] * 0x10000 + (uint)NTHeader[11] * 0x1000000;
                uint SymbolsCount = (uint)NTHeader[12] + (uint)NTHeader[13] * 0x100 + (uint)NTHeader[14] * 0x10000 + (uint)NTHeader[15] * 0x1000000;
                uint SizeOfOptionalHeader = (uint)NTHeader[16] + (uint)NTHeader[17] * 0x100;
                uint Charateristic = (uint)NTHeader[18] + (uint)NTHeader[19] * 0x100;

                ParseSectionsPE(module, Offset + 20 + SizeOfOptionalHeader, SectionCount);
                ParseNewPEOptionalHeader(module, Offset + 20, SizeOfOptionalHeader);
            }

            static void ParseNewPEOptionalHeader(Module module, uint Offset, uint Size)
            {
                bool _64Bits = false;
                byte[] headerData = new byte[Size];
                if (headerData.Length != module.ReadMemory(new IntPtr(Offset), headerData, headerData.Length)) { return; }


                if (headerData[0] == 0x0B && headerData[1] == 0x02) { _64Bits = true; }
                else if (headerData[0] == 0x0B && headerData[1] == 0x01) { _64Bits = false; }
                else { return; }

                fixed (void* ptr = &headerData[0])
                {
                    if (_64Bits)
                    {
                        IMAGE_OPTIONAL_HEADER64* header = (IMAGE_OPTIONAL_HEADER64*)ptr;
                        ParseExportTable(module, FindAddressFromRVA(module, header->exportTable.VirtualAddress), (int)header->exportTable.Size);
                    }
                    else
                    {
                        IMAGE_OPTIONAL_HEADER32* header = (IMAGE_OPTIONAL_HEADER32*)ptr; 
                    }
                }
            }

            static void ParseExportTable(Module module, IntPtr Address, int Size)
            {
                if (Address.ToInt64() == 0) { return; }
                byte[] Buffer = new byte[Size];
                if (Buffer.Length != module.ReadMemory(Address, Buffer, Size)){ return; }
                fixed (void* ptr = &Buffer[0])
                {
                    EXPORT_TABLE_DATA* exportTableData = (EXPORT_TABLE_DATA*)ptr;
                    IntPtr addressOfFunctions = FindAddressFromRVA(module, exportTableData->AddressOfFunctions);
                    IntPtr addressOfNames = FindAddressFromRVA(module, exportTableData->AddressOfNames);

                    byte[] namePointers = new byte[4 * exportTableData->NumberOfName];
                    module.ReadMemory(addressOfNames, namePointers, namePointers.Length);
                    byte[] functionsPointers = new byte[4 * exportTableData->NumberOfFunction];
                    module.ReadMemory(addressOfFunctions, functionsPointers, functionsPointers.Length);


                    if (exportTableData->NumberOfName > exportTableData->NumberOfFunction)
                    {
                        exportTableData->NumberOfName = exportTableData->NumberOfFunction;
                    }

                    for (int n = 0; n < exportTableData->NumberOfName; n++)
                    {
                        Module.Symbol symbol = new Module.Symbol();
                        Module.Section parent = null;
                        IntPtr namePointer = FindAddressFromRVA(module, BitConverter.ToUInt32(namePointers, n * 4));
                        IntPtr functionPointer = FindAddressInSectionFromRVA(module, BitConverter.ToUInt32(functionsPointers, n * 4), out parent);
                        string name = ReadASCIIString(module, namePointer);
                        symbol._BaseAddress = new IntPtr(functionPointer.ToInt64() + parent.BaseAddress.ToInt64());
                        symbol._Name = name;
                        parent._Symbols.Add(symbol);
                        parent._Parent = module._Parent;
                    }

                }
            }

            static void ParseSectionsPE(Module module, uint Offset, uint Count)
            {
                while (Count > 0)
                {
                    Module.Section section = ParseSectionPE(module, Offset);
                    if (section != null) { module._Sections.Add(section); }
                    Offset += 40;
                    Count--;
                }
            }

            static Module.Section ParseSectionPE(Module module, uint Offset)
            {
                byte[] sectionData = new byte[40];
                if (sectionData.Length != module.ReadMemory(new IntPtr(Offset), sectionData, sectionData.Length))
                {
                    return null;
                }

                Module.Section Section = new Module.Section(module._Parent);
                string name = "";
                for (int n = 0; n < 8; n++) { if (sectionData[n] != 0) { name += (char)sectionData[n]; } }

                fixed (void* ptr = &sectionData[0])
                {
                    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)ptr;
                    Section._Name = name;
                    Section._BaseAddress = new IntPtr(module.BaseAddress.ToInt64() + (long)sectionHeader->VirtualAddress);
                    Section._Size = sectionHeader->SizeOfRawData;
                }

                return Section;
            }
        }
    }
}
