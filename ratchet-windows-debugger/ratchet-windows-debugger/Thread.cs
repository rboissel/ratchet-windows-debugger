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
        public unsafe class Thread
        {
            public enum CONTEXT_FLAGS : uint
            {
                CONTEXT_i386 = 0x10000,
                CONTEXT_i486 = 0x10000,
                CONTEXT_AMD64 = 0x100000,

                CONTEXT_CONTROL_AMD64 = CONTEXT_AMD64 | 0x01,
                CONTEXT_INTEGER_AMD64 = CONTEXT_AMD64 | 0x02,
                CONTEXT_SEGMENTS_AMD64 = CONTEXT_AMD64 | 0x04,
                CONTEXT_FLOATING_POINT_AMD64 = CONTEXT_AMD64 | 0x08,
                CONTEXT_DEBUG_REGISTERS_AMD64 = CONTEXT_AMD64 | 0x10,
                CONTEXT_FULL_AMD64 = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64 | CONTEXT_FLOATING_POINT_AMD64,
                CONTEXT_ALL_AMD64 = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64 | CONTEXT_SEGMENTS_AMD64 | CONTEXT_FLOATING_POINT_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64,

                CONTEXT_CONTROL_i386 = CONTEXT_i386 | 0x01,
                CONTEXT_INTEGER_i386 = CONTEXT_i386 | 0x02,
                CONTEXT_SEGMENTS_i386 = CONTEXT_i386 | 0x04,
                CONTEXT_FLOATING_POINT_i386 = CONTEXT_i386 | 0x08,
                CONTEXT_DEBUG_REGISTERS_i386 = CONTEXT_i386 | 0x10,
                CONTEXT_EXTENDED_REGISTERS_i386 = CONTEXT_i386 | 0x20,
                CONTEXT_FULL_i386 = CONTEXT_CONTROL_i386 | CONTEXT_INTEGER_i386 | CONTEXT_SEGMENTS_i386,
                CONTEXT_ALL_i386 = CONTEXT_CONTROL_i386 | CONTEXT_INTEGER_i386 | CONTEXT_SEGMENTS_i386 | CONTEXT_FLOATING_POINT_i386 | CONTEXT_DEBUG_REGISTERS_i386 | CONTEXT_EXTENDED_REGISTERS_i386
            }


            [System.Runtime.InteropServices.DllImport("Kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
            static extern uint GetThreadId(void* Thread);

            [System.Runtime.InteropServices.DllImport("Kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
            static extern uint GetThreadContext(void* hThread, void* lpContext);

            [System.Runtime.InteropServices.DllImport("Kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
            static extern uint SetThreadContext(void* hThread, void* lpContext);


            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 1)]
            struct M128A
            {
                ulong a;
                ulong b;
            }
            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 16 )]
            struct NTCONTEXT_x86_64
            {
                ulong P1Home;
                ulong P2Home;
                ulong P3Home;
                ulong P4Home;
                ulong P5Home;
                ulong P6Home;
                public uint ContextFlags;
                uint MxCsr;
                short SegCs;
                short SegDs;
                short SegEs;
                short SegFs;
                short SegGs;
                short SegSs;
                uint EFlags;
                ulong Dr0;
                ulong Dr1;
                ulong Dr2;
                ulong Dr3;
                ulong Dr6;
                ulong Dr7;
                public ulong Rax;
                public ulong Rcx;
                public ulong Rdx;
                public ulong Rbx;
                public ulong Rsp;
                public ulong Rbp;
                public ulong Rsi;
                public ulong Rdi;
                public ulong R8;
                public ulong R9;
                public ulong R10;
                public ulong R11;
                public ulong R12;
                public ulong R13;
                public ulong R14;
                public ulong R15;
                public ulong Rip;

                M128A Header_0;
                M128A Header_1;

                M128A Legacy_0;
                M128A Legacy_1;
                M128A Legacy_2;
                M128A Legacy_3;
                M128A Legacy_4;
                M128A Legacy_5;
                M128A Legacy_6;
                M128A Legacy_7;

                M128A Xmm0;
                M128A Xmm1;
                M128A Xmm2;
                M128A Xmm3;
                M128A Xmm4;
                M128A Xmm5;
                M128A Xmm6;
                M128A Xmm7;
                M128A Xmm8;
                M128A Xmm9;
                M128A Xmm10;
                M128A Xmm11;
                M128A Xmm12;
                M128A Xmm13;
                M128A Xmm14;
                M128A Xmm15;
                M128A VectorRegister_0;
                M128A VectorRegister_1;
                M128A VectorRegister_2;
                M128A VectorRegister_3;
                M128A VectorRegister_4;
                M128A VectorRegister_5;
                M128A VectorRegister_6;
                M128A VectorRegister_7;
                M128A VectorRegister_8;
                M128A VectorRegister_9;
                M128A VectorRegister_10;
                M128A VectorRegister_11;
                M128A VectorRegister_12;
                M128A VectorRegister_13;
                M128A VectorRegister_14;
                M128A VectorRegister_15;
                M128A VectorRegister_16;
                M128A VectorRegister_17;
                M128A VectorRegister_18;
                M128A VectorRegister_19;
                M128A VectorRegister_20;
                M128A VectorRegister_21;
                M128A VectorRegister_22;
                M128A VectorRegister_23;
                M128A VectorRegister_24;
                M128A VectorRegister_25;
                ulong VectorControl;
                ulong DebugControl;
                ulong LastBranchToRip;
                ulong LastBranchFromRip;
                ulong LastExceptionToRip;
                ulong LastExceptionFromRip;
            }

            public IntPtr InstructionPointer
            {
                get
                {
                    NTCONTEXT_x86_64* context = (NTCONTEXT_x86_64*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                    context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_AMD64;
                    GetThreadContext(_Handle.ToPointer(), context);
                    ulong rip = context->Rip;
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(context));
                    return new IntPtr((long)rip);
                }
                set
                {
                    NTCONTEXT_x86_64* context = (NTCONTEXT_x86_64*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                    context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_AMD64;
                    GetThreadContext(_Handle.ToPointer(), context);
                    context->Rip = (ulong)value.ToInt64();
                    SetThreadContext(_Handle.ToPointer(), context);
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(context));
                }
            }            

            uint _Id = 0;
            public uint ID { get { return _Id; } }

            IntPtr _Handle;
            public IntPtr Handle { get { return _Handle; } }


            internal Thread(Session Session, IntPtr Handle)
            {
                _Handle = Handle;
                _Id = GetThreadId(_Handle.ToPointer());
                uint access = 0;
            }

            public override string ToString()
            {
                return "thread: 0x" + ID.ToString("X2");
            }
        }
    }
}
