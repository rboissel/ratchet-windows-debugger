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
    public static partial class Windows
    {
        public unsafe partial class Module
        {
            public unsafe class Section
            {
                internal string _Name = "";
                public string Name { get { return _Name; } }
                internal IntPtr _BaseAddress = new IntPtr(0);
                public IntPtr BaseAddress { get { return _BaseAddress; } }
                internal ulong _Size = 0;
                public ulong Size { get { return _Size; } }
                internal List<Symbol> _Symbols = new List<Symbol>();
                public System.Collections.ObjectModel.ReadOnlyCollection<Symbol> Symbols { get { return _Symbols.AsReadOnly(); } }

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

                public void FlushInstructionCache()
                {
                    _Parent.FlushInstructionCache(_BaseAddress, (int)_Size);
                }

                internal Section(Session Parent) { _Parent = Parent; }

                public override string ToString()
                {
                    return "section: " + (_Name == "" ? "0x" + _BaseAddress.ToInt64().ToString("X2") : _Name);
                }
            }
        }
    }
}
