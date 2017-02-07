/*                                                                           *
 * Copyright © 2017, Raphaël Boissel                                         *
 * Permission is hereby granted, free of charge, to any person obtaining     *
 * a copy of this software and associated documentation files, to deal in    *
 * the Software without restriction, including without limitation the        *
 * rights to use, copy, modify, merge, publish, distribute, sublicense,      *
 * and/or sell copies of the Software, and to permit persons to whom the     *
 * Software is furnished to do so, subject to the following conditions:      *
 *                                                                           *
 * - The above copyright notice and this permission notice shall be          *
 *   included in all copies or substantial portions of the Software.         *
 * - The Software is provided "as is", without warranty of any kind,         *
 *   express or implied, including but not limited to the warranties of      *
 *   merchantability, fitness for a particular purpose and noninfringement.  *
 *   In no event shall the authors or copyright holders. be liable for any   *
 *   claim, damages or other liability, whether in an action of contract,    *
 *   tort or otherwise, arising from, out of or in connection with the       *
 *   software or the use or other dealings in the Software.                  *
 * - Except as contained in this notice, the name of Raphaël Boissel shall   *
 *   not be used in advertising or otherwise to promote the sale, use or     *
 *   other dealings in this Software without prior written authorization     *
 *   from Raphaël Boissel.                                                   *
 *                                                                           */

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
        /// Represent a module loaded by the debuggee
        /// </summary>
        public unsafe partial class Module
        {
            [System.Runtime.InteropServices.DllImport("Kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
            static extern uint GetFinalPathNameByHandle(void* hFile, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPTStr)] System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

            [System.Runtime.InteropServices.DllImport("Kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
            static extern uint GetFileSize(void* hFile, out uint lpFileSizeHigh);

            internal List<Section> _Sections = new List<Section>();
            public IReadOnlyCollection<Section> Sections { get { return _Sections.AsReadOnly(); } }

            IntPtr _Handle = new IntPtr(0);
            public IntPtr Handle { get { return _Handle; } }

            string _Path = "";
            public string Path
            {
                get
                {
                    lock (this)
                    {
                        try
                        {
                            if (_Path == "" && _Handle.ToInt64() != 0)
                            {
                                System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder(4096);
                                ulong size = GetFinalPathNameByHandle(_Handle.ToPointer(), stringBuilder, 4096, 0);
                                _Path = stringBuilder.ToString();
                                if (_Path.StartsWith("\\\\?\\")) { _Path = _Path.Substring("\\\\?\\".Length); }
                            }
                        }
                        catch { }
                        return _Path;

                    }
                }
            }

            IntPtr _BaseAddress = new IntPtr(0);
            public IntPtr BaseAddress { get { return _BaseAddress; } }

            internal Session _Parent = null;

            public int ReadMemory(IntPtr Address, byte[] Buffer, int Length)
            {
                return _Parent.ReadMemory(new IntPtr(_BaseAddress.ToInt64() + Address.ToInt64()), Buffer, Length);
            }

            public int WriteMemory(IntPtr Address, byte[] Buffer)
            {
                return WriteMemory(Address, Buffer, Buffer.Length);
            }

            public int WriteMemory(IntPtr Address, byte[] Buffer, int Length)
            {
                return _Parent.WriteMemory(new IntPtr(_BaseAddress.ToInt64() + Address.ToInt64()), Buffer, Length);
            }

            internal Module(Session Session, IntPtr Handle, IntPtr BaseAddress)
            {
                _Handle = Handle;
                _BaseAddress = BaseAddress;
                _Parent = Session;
                _ReadImage();
            }

            void _ReadImage()
            {
                byte[] Magick = new byte[2];
                if (Magick.Length == ReadMemory(new IntPtr(0), Magick, 2))
                {
                    if (Magick[0] == 0x4D && Magick[1] == 0x5A)
                    {
                        // This looks like a PE jump on the PE reader
                        try { PEReader.ParsePE(this); } catch { }
                    }
                }
            }

            public override string ToString()
            {
                return "module: " + (Path == "" ? "<unknown " + _BaseAddress.ToInt64().ToString("X2") + ">" : Path);
            }
        }
    }
}