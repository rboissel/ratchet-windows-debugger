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

            public abstract class IntRegisters
            {
                public abstract ulong this[uint Index]
                {
                    get; set;
                }
            }

            internal class IntRegisters_x86 : IntRegisters
            {
                IntPtr _Handle;
                internal IntRegisters_x86(IntPtr Handle)
                {
                    _Handle = Handle;
                }

                public override ulong this[uint Index]
                {

                    get
                    {
                        NTCONTEXT_x86* pContext = (NTCONTEXT_x86*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        pContext->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_i386;
                        GetThreadContext(_Handle.ToPointer(), pContext);
                        ulong result = 0;
                        switch (Index)
                        {
                            case 0: result = pContext->Eax; break;
                            case 1: result = pContext->Ecx; break;
                            case 2: result = pContext->Edx; break;
                            case 3: result = pContext->Ebx; break;
                            case 4: result = pContext->Esp; break;
                            case 5: result = pContext->Ebp; break;
                            case 6: result = pContext->Esi; break;
                            case 7: result = pContext->Edi; break;
                        }
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(pContext));

                        return result;
                    }

                    set
                    {
                        NTCONTEXT_x86* pContext = (NTCONTEXT_x86*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        pContext->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_i386;
                        GetThreadContext(_Handle.ToPointer(), pContext);

                        switch (Index)
                        {
                            case 0: pContext->Eax = (uint)value; break;
                            case 1: pContext->Ecx = (uint)value; break;
                            case 2: pContext->Edx = (uint)value; break;
                            case 3: pContext->Ebx = (uint)value; break;
                            case 4: pContext->Esp = (uint)value; break;
                            case 5: pContext->Ebp = (uint)value; break;
                            case 6: pContext->Esi = (uint)value; break;
                            case 7: pContext->Edi = (uint)value; break;
                            default:
                                System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(pContext));
                                throw new Exception("Invalid register index");
                        }

                        SetThreadContext(_Handle.ToPointer(), pContext);
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(pContext));
                    }
                }
            }

            internal class IntRegisters_x86_64 : IntRegisters
            {
                IntPtr _Handle;
                internal IntRegisters_x86_64(IntPtr Handle)
                {
                    _Handle = Handle;
                }

                public override ulong this[uint Index]
                {

                    get
                    {
                        NTCONTEXT_x86_64* pContext = (NTCONTEXT_x86_64*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        pContext->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_AMD64;
                        GetThreadContext(_Handle.ToPointer(), pContext);
                        ulong result = 0;
                        switch (Index)
                        {
                            case 0: result = pContext->Rax; break;
                            case 1: result = pContext->Rcx; break;
                            case 2: result = pContext->Rdx; break;
                            case 3: result = pContext->Rbx; break;
                            case 4: result = pContext->Rsp; break;
                            case 5: result = pContext->Rbp; break;
                            case 6: result = pContext->Rsi; break;
                            case 7: result = pContext->Rdi; break;
                            case 8: result = pContext->R8; break;
                            case 9: result = pContext->R9; break;
                            case 10: result = pContext->R10; break;
                            case 11: result = pContext->R11; break;
                            case 12: result = pContext->R12; break;
                            case 13: result = pContext->R13; break;
                            case 14: result = pContext->R14; break;
                            case 15: result = pContext->R15; break;
                            default:
                                System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(pContext));
                                throw new Exception("Invalid register index");


                        }
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(pContext));
                        return result;
                    }

                    set
                    {
                        NTCONTEXT_x86_64* pContext = (NTCONTEXT_x86_64*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        pContext->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_AMD64;
                        GetThreadContext(_Handle.ToPointer(), pContext);

                        switch (Index)
                        {
                            case 0: pContext->Rax = value; break;
                            case 1: pContext->Rcx = value; break;
                            case 2: pContext->Rdx = value; break;
                            case 3: pContext->Rbx = value; break;
                            case 4: pContext->Rsp = value; break;
                            case 5: pContext->Rbp = value; break;
                            case 6: pContext->Rsi = value; break;
                            case 7: pContext->Rdi = value; break;
                            case 8: pContext->R8 = value; break;
                            case 9: pContext->R9 = value; break;
                            case 10: pContext->R10 = value; break;
                            case 11: pContext->R11 = value; break;
                            case 12: pContext->R12 = value; break;
                            case 13: pContext->R13 = value; break;
                            case 14: pContext->R14 = value; break;
                            case 15: pContext->R15 = value; break;
                            default:
                                System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(pContext));
                                throw new Exception("Invalid register index");
                        }

                        SetThreadContext(_Handle.ToPointer(), pContext);
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(pContext));
                    }
                }
            }

            public abstract class Context
            {
                public abstract Thread Thread { get; }
                public abstract void Load();
            }

            class Context_x86_64 : Context
            {
                internal NTCONTEXT_x86_64* _Context;
                internal Thread _Thread;
                internal Context_x86_64(NTCONTEXT_x86_64* pContext, Thread Thread) { _Context = pContext; _Thread = Thread; }
                ~Context_x86_64() { System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(_Context)); }
                public override Thread Thread { get { return _Thread; } }
                public override void Load() { SetThreadContext(Thread._Handle.ToPointer(), _Context); }
            }

            class Context_x86 : Context
            {
                internal NTCONTEXT_x86* _Context;
                internal Thread _Thread;
                internal Context_x86(NTCONTEXT_x86* pContext, Thread Thread) { _Context = pContext; _Thread = Thread; }
                ~Context_x86() { System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(_Context)); }
                public override Thread Thread { get { return _Thread; } }
                public override void Load() { SetThreadContext(Thread._Handle.ToPointer(), _Context); }
            }

            public unsafe Context SaveContext()
            {
                if (sizeof(void*) == 4)
                {
                    NTCONTEXT_x86* context = (NTCONTEXT_x86*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                    context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_i386;
                    GetThreadContext(_Handle.ToPointer(), context);
                    return new Context_x86(context, this);
                }
                else
                {
                    NTCONTEXT_x86_64* context = (NTCONTEXT_x86_64*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                    context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_AMD64;
                    GetThreadContext(_Handle.ToPointer(), context);
                    return new Context_x86_64(context, this);
                }
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 8)]
            struct NTCONTEXT_x86
            {
                public uint ContextFlags;
                uint Dr0;
                uint Dr1;
                uint Dr2;
                uint Dr3;
                uint Dr6;
                uint Dr7;

                /* FLOATING_SAVE_AREA */
                uint ControlWord;
                uint StatusWord;
                uint TagWord;
                uint ErrorOffset;
                uint ErrorSelector;
                uint DataOffset;
                uint DataSelector;
                uint RegisterArea_0;
                uint RegisterArea_1;
                uint RegisterArea_2;
                uint RegisterArea_3;
                uint RegisterArea_4;
                uint RegisterArea_5;
                uint RegisterArea_6;
                uint RegisterArea_7;
                uint RegisterArea_8;
                uint RegisterArea_9;
                uint RegisterArea_10;
                uint RegisterArea_11;
                uint RegisterArea_12;
                uint RegisterArea_13;
                uint RegisterArea_14;
                uint RegisterArea_15;
                uint RegisterArea_16;
                uint RegisterArea_17;
                uint RegisterArea_18;
                uint RegisterArea_19;
                uint Cr0NpxState;

                uint SegGs;
                uint SegFs;
                uint SegEs;
                uint SegDs;

                public uint Edi;
                public uint Esi;
                public uint Ebx;
                public uint Edx;
                public uint Ecx;
                public uint Eax;
                public uint Ebp;
                public uint Eip;
                uint SegCs;
                uint EFlags;
                public uint Esp;
                uint SegSs;
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

            public unsafe IntPtr InstructionPointer
            {
                get
                {
                    if (sizeof(void*) == 4)
                    {
                        NTCONTEXT_x86* context = (NTCONTEXT_x86*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_i386;
                        GetThreadContext(_Handle.ToPointer(), context);
                        ulong eip = context->Eip;
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(context));
                        return new IntPtr((long)eip);
                    }
                    else
                    {
                        NTCONTEXT_x86_64* context = (NTCONTEXT_x86_64*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_AMD64;
                        GetThreadContext(_Handle.ToPointer(), context);
                        ulong rip = context->Rip;
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(context));
                        return new IntPtr((long)rip);
                    }
                }
                set
                {
                    if (sizeof(void*) == 4)
                    {
                        NTCONTEXT_x86* context = (NTCONTEXT_x86*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_i386;
                        GetThreadContext(_Handle.ToPointer(), context);
                        context->Eip = (uint)value.ToInt64();
                        SetThreadContext(_Handle.ToPointer(), context);
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(context));
                    }
                    else
                    {
                        NTCONTEXT_x86_64* context = (NTCONTEXT_x86_64*)System.Runtime.InteropServices.Marshal.AllocHGlobal(4096 * 2).ToPointer();
                        context->ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL_AMD64;
                        GetThreadContext(_Handle.ToPointer(), context);
                        context->Rip = (ulong)value.ToInt64();
                        SetThreadContext(_Handle.ToPointer(), context);
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(new IntPtr(context));
                    }
                }
            }


            public int ReadStack(byte[] Stack, int Size)
            {
                ulong pointer = _IntRegisters[4];
                return _Session.ReadMemory(new IntPtr((long)(pointer - (ulong)Size)), Stack, Size);
            }

            Session _Session;

            uint _Id = 0;
            public uint ID { get { return _Id; } }

            IntPtr _Handle;
            public IntPtr Handle { get { return _Handle; } }

            [System.Runtime.InteropServices.DllImport("Kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
            static extern uint ResumeThread(IntPtr hThread);
            public void Resume()
            {
                ResumeThread(_Handle);
            }


            IntRegisters _IntRegisters;
            public IntRegisters IntegerRegisters
            {
                get { return _IntRegisters; }
            }

            internal Thread(Session Session, IntPtr Handle)
            {
                _Session = Session;
                _Handle = Handle;
                if (sizeof(void*) == 4)
                {
                    _IntRegisters = new IntRegisters_x86(Handle);
                }
                else
                {
                    _IntRegisters = new IntRegisters_x86_64(Handle);
                }
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
