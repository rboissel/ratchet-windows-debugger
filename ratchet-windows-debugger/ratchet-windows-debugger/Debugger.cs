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
        public enum Protection
        {
            None = 0x0,
            Read = 0x1,
            Write = 0x2,
            Execute = 0x4,
        }

        internal static int toNtProtection(Protection Protection)
        {

            const int PAGE_EXECUTE = 0x10;
            const int PAGE_EXECUTE_READ = 0x20;
            const int PAGE_EXECUTE_READWRITE = 0x40;
            const int PAGE_EXECUTE_WRITECOPY = 0x40;
            const int PAGE_NOACCESS = 0x01;
            const int PAGE_READONLY = 0x02;
            const int PAGE_READWRITE = 0x04;
            const int PAGE_WRITECOPY = 0x08;

            int NtProtection = 0;
            switch (Protection)
            {
                case Protection.Read | Protection.Write | Protection.Execute: NtProtection = PAGE_EXECUTE_READWRITE; break;
                case Protection.Read | Protection.Execute: NtProtection = PAGE_EXECUTE_READ; break;
                case Protection.Execute: NtProtection = PAGE_EXECUTE; break;
                case Protection.Read: NtProtection = PAGE_READONLY; break;
                case Protection.Read | Protection.Write: NtProtection = PAGE_READWRITE; break;
                case Protection.None: NtProtection = PAGE_READONLY; break;
                default: throw new Exception("Unsupported allocation flags"); break;
            }

            return NtProtection;
        }

        /// <summary>
        /// Represent a debugger session.
        /// </summary>
        public unsafe class Session
        {

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            extern static void* VirtualAllocEx(void* hProcess, void* lpBaseAddress, IntPtr dwSize, int flAllocationType, int flProtect);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            extern static bool VirtualProtectEx(void* hProcess, void* lpBaseAddress, IntPtr dwSize, int flNewProtect, int* flOldProtect);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            extern static bool ReadProcessMemory(void* hProcess, void* lpBaseAddress, [System.Runtime.InteropServices.Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            extern static bool WriteProcessMemory(void* hProcess, void* lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            extern static bool FlushInstructionCache(void* hProcess, void* lpBaseAddress, int dwSize);


            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            extern static bool DebugBreakProcess(void* handle);

            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            extern static bool DebugActiveProcess(int ProcessId);

            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            extern static bool DebugSetProcessKillOnExit(bool KillOnExit);

            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            extern static bool WaitForDebugEvent(void* lpDebugEvent, int dwMilliseconds);

            internal const uint DBG_CONTINUE = 0x00010002;
            internal const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            extern static bool ContinueDebugEvent(int ProcessId, int ThreadId, uint dwContinueStatus);


            public void Break()
            {
                try
                {
                    DebugBreakProcess(_hProcess);
                }
                catch { }
            }


            internal bool _Attach(int ProcessId)
            {
                bool result = DebugActiveProcess(ProcessId);
                if (result)
                {
                    DebugSetProcessKillOnExit(false);
                }
                return result;
            }

            /// <summary>
            /// Read directly to the debuggee memory
            /// </summary>
            /// <param name="Address">The address where he debugger will start reading</param>
            /// <param name="Buffer">The buffer that will be filled</param>
            /// <param name="Length">The number of byte to read</param>
            /// <returns>return the number of bytes that has been read</returns>
            public int ReadMemory(IntPtr Address, byte[] Buffer, int Length)
            {
                if (Length > Buffer.Length) { throw new Exception("Buffer is too small"); }
                try
                {
                    IntPtr size;
                    bool result = ReadProcessMemory(_hProcess, Address.ToPointer(), Buffer, Length, out size);
                    if (!result)
                    {
                        return 0;
                    }
                    return size.ToInt32();

                }
                catch { return 0; }
            }

            /// <summary>
            /// Write directly to the debuggee memory
            /// </summary>
            /// <param name="Address">The address where the buffer is written</param>
            /// <param name="Buffer">The buffer containing the data to be written</param>
            /// <returns>return the number of bytes that has been written</returns>
            public int WriteMemory(IntPtr Address, byte[] Buffer)
            {
                return WriteMemory(Address, Buffer, Buffer.Length);
            }

            /// <summary>
            /// Write directly to the debuggee memory
            /// </summary>
            /// <param name="Address">The address where the buffer is written</param>
            /// <param name="Buffer">The buffer containing the data to be written</param>
            /// <param name="Length">The number of data to be written</param>
            /// <returns>return the number of bytes that has been written</returns>
            public int WriteMemory(IntPtr Address, byte[] Buffer, int Length)
            {
                if (Length > Buffer.Length) { throw new Exception("Buffer is too small"); }
                try
                {
                    IntPtr size = new IntPtr(0);
                    bool result = WriteProcessMemory(_hProcess, Address.ToPointer(), Buffer, Length, out size);
                    if (!result)
                    {
                        return 0;
                    }
                    return size.ToInt32();

                }
                catch { return 0; }
            }

            /// <summary>
            /// After patching the instruction this function must be called to invalide the instruction cache.
            /// </summary>
            /// <param name="Address">Address of the block to invalidate</param>
            /// <param name="Size">Size of the block to invalidate</param>
            public void FlushInstructionCache(IntPtr Address, int Size)
            {
                if (!FlushInstructionCache(_hProcess, Address.ToPointer(), Size))
                {
                    throw new Exception("Error while flushing instruction cache for memory [" + Address.ToInt64() + ", " + (Address.ToInt64() + Size) + "[");
                }
            }

            /// <summary>
            /// Allocate memory into the debuggee process.
            /// </summary>
            /// <param name="Address">The address where the memory should be allocated (or 0 to let the os decide)</param>
            /// <param name="Size">The size of the block to allocate</param>
            /// <param name="Protection">The protection of the memory block that will be allocated</param>
            /// <returns>The location of the allocated block</returns>
            public IntPtr AllocateMemory(IntPtr Address, int Size, Protection Protection)
            {
                const int MEM_COMMIT = 0x00001000;
                const int MEM_RESERVE = 0x00002000;

                return new IntPtr(VirtualAllocEx(_hProcess, Address.ToPointer(), new IntPtr(Size), MEM_COMMIT | MEM_RESERVE, toNtProtection(Protection)));
            }

            /// <summary>
            /// Change the memory protection of a memory chunk in the debuggee process.
            /// </summary>
            /// <param name="Address">The address where the memory protection should be changed</param>
            /// <param name="Size">The size of the memory block</param>
            /// <param name="Protection">The new protection of the memory block that will be allocated</param>
            /// <returns>True if the protection has been changed false otherwise</returns>
            public bool ChangeMemoryProtection(IntPtr Address, int Size, Protection Protection)
            {
                int flOldProtect = 0;
                return VirtualProtectEx(_hProcess, Address.ToPointer(), new IntPtr(Size), toNtProtection(Protection), &flOldProtect);
            }

            Dictionary<ulong, Breakpoint> _Breakpoint = new Dictionary<ulong, Breakpoint>();
            public Breakpoint AddBreakpoint(IntPtr Address)
            {
                return AddBreakpoint((ulong)Address.ToInt64());
            }
            public Breakpoint AddBreakpoint(ulong address)
            {
                Breakpoint breakpoint = new Breakpoint(this, new IntPtr((long)address), new byte[] { 0xCC });
                lock (this)
                {
                    if (_Breakpoint.ContainsKey(address)) { throw new Exception("Breakpoint already defined"); }
                    _Breakpoint.Add(address, breakpoint);
                }
                return breakpoint;
            }

            internal struct NTUnionDebugEventInfo
            {
                void* _1;
                void* _2;
                void* _3;
                void* _4;
                void* _5;
                void* _6;
                void* _7;
                void* _8;
                void* _9;
                void* _10;
                void* _11;
                void* _12;
                void* _13;
                void* _14;
                void* _15;
                void* _16;
                void* _17;
                void* _18;
                void* _19;
                void* _20;
                void* _21;
            }

            internal struct NTExceptionRecord
            {
                internal Int32 ExceptionCode;
                internal Int32 ExceptionFlags;
                internal void* ExceptionRecord;
                internal void* ExceptionAddress;
                internal Int32 NumberParameters;
                internal void* ExceptionInformation0;
                void* ExceptionInformation1;
                void* ExceptionInformation2;
                void* ExceptionInformation3;
                void* ExceptionInformation4;
                void* ExceptionInformation5;
                void* ExceptionInformation6;
                void* ExceptionInformation7;
                void* ExceptionInformation8;
                void* ExceptionInformation9;
                void* ExceptionInformation10;
                void* ExceptionInformation11;
                void* ExceptionInformation12;
                void* ExceptionInformation13;
                void* ExceptionInformation14;
            }

            internal struct NTExceptionDebugInfo
            {
                internal NTExceptionRecord ExceptionRecord;
                internal Int32 dwFirstChance;
            }

            struct NTCreateThreadDebugInfo
            {
                internal void* hThread;
                internal void* lpThreadLocalBase;
                internal void* lpStartAddress;
            }

            internal struct NTCreateProcessDebugInfo
            {
                internal void* hFile;
                internal void* hProcess;
                internal void* hThread;
                internal void* lpBaseOfImage;
                internal Int32 dwDebugInfoFileOffset;
                internal Int32 nDebugInfoSize;
                internal void* lpThreadLocalBase;
                internal void* lpStartAddress;
                internal void* lpImageName;
                internal Int16 fUnicode;
            }

            internal struct NTExitThreadDebugInfo
            {
                internal Int32 dwExitCode;
            }

            internal struct NTExitProcessDebugInfo
            {
                internal Int32 dwExitCode;
            }

            internal struct NTLoadDllDebugInfo
            {
                internal void* hFile;
                internal void* lpBaseOfDll;
                internal Int32 dwDebugInfoFileOffset;
                internal Int32 nDebugInfoSize;
                internal void* lpImageName;
                internal Int16 fUnicode;
            }

            internal struct NTUnloadDllDebugInfo
            {
                internal void* lpBaseOfDll;
            }

            internal struct NTOutputStringDebugInfo
            {
                internal void* lpDebugStringData;
                internal Int16 fUnicode;
                internal Int16 nDebugStringLength;
            }

            internal struct NTDebugEvent
            {
                internal Int32 dwDebugEventCode;
                internal Int32 dwProcessId;
                internal Int32 dwThreadId;
                internal NTUnionDebugEventInfo u;
            }

            public class DebuggerEventArgs : EventArgs
            {
                internal Session _Parent;
                internal int _PID;

                internal Thread _Thread;
                internal bool _FakeEvent = false;

                public Thread Thread
                {
                    get { return _Thread; }
                }

                internal DebuggerEventArgs(Session Parent, int PID, Thread Thread)
                {
                    _Parent = Parent;
                    _PID = PID;
                    _Thread = Thread;
                }

                public void Continue()
                {
                    if (!_FakeEvent)
                    {
                        ContinueDebugEvent(_PID, (int)_Thread.ID, DBG_CONTINUE);
                    }
                }
            }

            public class CreateProcessEventArgs : DebuggerEventArgs
            {
                Module _Module = null;
                public Module Module { get { return _Module; } }

                internal CreateProcessEventArgs(Session Parent, int PID, Thread Thread, Module Module) : base(Parent, PID, Thread)
                {
                    _Module = Module;
                }
            }

            public class ExitProcessEventArgs : DebuggerEventArgs
            {
                int _ExitCode = 0;
                public int ExitCode { get { return _ExitCode; } }
                internal ExitProcessEventArgs(Session Parent, int PID, Thread Thread, int ExitCode) : base(Parent, PID, Thread) { }
            }

            public class CreateThreadEventArgs : DebuggerEventArgs
            {
                internal CreateThreadEventArgs(Session Parent, int PID, Thread Thread) : base(Parent, PID, Thread) { }
            }

            public class ExitThreadEventArgs : DebuggerEventArgs
            {
                int _ExitCode = 0;
                public int ExitCode { get { return _ExitCode; } }
                internal ExitThreadEventArgs(Session Parent, int PID, Thread Thread, int ExitCode) : base(Parent, PID, Thread)
                {
                    _ExitCode = ExitCode;
                }
            }

            public class BreakpointEventArgs : DebuggerEventArgs
            {
                IntPtr _Address = new IntPtr(0);
                public IntPtr Address { get { return _Address; } }

                internal BreakpointEventArgs(Session Parent, int PID, Thread Thread, IntPtr Address) : base(Parent, PID, Thread)
                {
                    _Address = Address;
                }
            }

            public class ExceptionEventArgs : DebuggerEventArgs
            {
                bool _FirstChance = false;
                public bool FirstChance { get { return _FirstChance; } }

                IntPtr _Address = new IntPtr(0);
                public IntPtr Address { get { return _Address; } }

                internal ExceptionEventArgs(Session Parent, int PID, Thread Thread, bool FirstChance, IntPtr Address) : base(Parent, PID, Thread)
                {
                    _FirstChance = FirstChance;
                    _Address = Address;
                }

                public void ExceptionNotHandled()
                {
                    ContinueDebugEvent(_PID, (int)_Thread.ID, DBG_EXCEPTION_NOT_HANDLED);
                }
            }

            public class LoadModuleEventArgs : DebuggerEventArgs
            {
                Module _Module = null;
                public Module Module { get { return _Module; } }

                internal LoadModuleEventArgs(Session Parent, int PID, Thread Thread, Module Module) : base(Parent, PID, Thread)
                {
                    _Module = Module;
                }
            }

            public class UnloadModuleEventArgs : DebuggerEventArgs
            {
                Module _Module = null;
                public Module Module { get { return _Module; } }

                internal UnloadModuleEventArgs(Session Parent, int PID, Thread Thread, Module Module) : base(Parent, PID, Thread)
                {
                    _Module = Module;
                }
            }

            public class OutputDebugStringEventArgs : DebuggerEventArgs
            {
                string _Message = "";
                public string Message { get { return _Message; } }
                internal OutputDebugStringEventArgs(Session Parent, int PID, Thread Thread, string Message) : base(Parent, PID, Thread)
                {
                    _Message = Message;
                }
            }

            internal Thread _GetThread(ulong threadId)
            {
                Thread thread;
                lock (this)
                {
                    if (!_Threads.TryGetValue(threadId, out thread))
                    {
                        throw new Exception("Thread not registered");
                    }
                }
                return thread;
            }

            internal void _CreateProcessDebugEvent(NTDebugEvent ntevent)
            {
                NTCreateProcessDebugInfo info = *(NTCreateProcessDebugInfo*)(&ntevent.u);
                lock (this)
                {
                    if (_hProcess == null) { _hProcess = info.hProcess; }
                }

                Thread thread;
                lock (this)
                {
                    if (!_Threads.TryGetValue((ulong)info.hThread, out thread))
                    {
                        thread = new Thread(this, new IntPtr(info.hThread));
                        _Threads.Add(thread.ID, thread);
                    }
                }

                lock (this)
                {
                    if (_ResumeMainThreadAtStartup && ntevent.dwThreadId == _TID)
                    {
                        thread.Resume();
                        _ResumeMainThreadAtStartup = false;
                    }
                }

                Module module = new Module(this, new IntPtr(info.hFile), new IntPtr(info.lpBaseOfImage));

                while (OnCreateProcess == null) { System.Threading.Thread.Sleep(0); }

                OnCreateProcess(this, new CreateProcessEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId), module));
            }

            internal void _CreateThreadDebugEvent(NTDebugEvent ntevent)
            {
                NTCreateThreadDebugInfo info = *(NTCreateThreadDebugInfo*)(&ntevent.u);
                Thread thread;
                lock (this)
                {
                    if (!_Threads.TryGetValue((ulong)info.hThread, out thread))
                    {
                        thread = new Thread(this, new IntPtr(info.hThread));
                        _Threads.Add(thread.ID, thread);
                    }
                }
                CreateThreadEventArgs args = new CreateThreadEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId));

                lock (this)
                {
                    if (_ResumeMainThreadAtStartup && ntevent.dwThreadId == _TID)
                    {
                        thread.Resume();
                        _ResumeMainThreadAtStartup = false;
                    }
                }

                if (OnCreateThread != null)
                {
                    OnCreateThread(this, args);
                }
                else
                {
                    args.Continue();
                }


            }

            internal void _CreateExceptionDebugEvent(NTDebugEvent ntevent)
            {
                unchecked
                {
                    NTExceptionDebugInfo info = *(NTExceptionDebugInfo*)(&ntevent.u);

                    if ((uint)info.ExceptionRecord.ExceptionCode == 0x80000003)
                    {
                        lock (this)
                        {
                            if (_Breakpoint.ContainsKey((ulong)info.ExceptionRecord.ExceptionAddress))
                            {
                                _Breakpoint[(ulong)info.ExceptionRecord.ExceptionAddress].hit(this, new BreakpointEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId), new IntPtr(info.ExceptionRecord.ExceptionAddress)));
                                return;
                            }
                        }
                        while (OnBreakpoint == null) { System.Threading.Thread.Sleep(0); }
                        OnBreakpoint(this, new BreakpointEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId), new IntPtr(info.ExceptionRecord.ExceptionAddress)));
                    }
                    else
                    {
                        ExceptionEventArgs excpetion = new ExceptionEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId), info.dwFirstChance != 0, new IntPtr(info.ExceptionRecord.ExceptionAddress));
                        if (OnException != null)
                        {
                            OnException(this, excpetion);
                        }
                        else
                        {
                            excpetion.ExceptionNotHandled();
                        }
                    }
                }
            }

            internal void _CreateOutputDebugStringDebugEvent(NTDebugEvent ntevent)
            {
                NTOutputStringDebugInfo info = *(NTOutputStringDebugInfo*)(&ntevent.u);
                Thread thread = _GetThread((ulong)ntevent.dwThreadId);
                string message = "";
                try
                {
                    int sizeofChar = (info.fUnicode) == 0 ? 1 : 2;
                    int length = sizeofChar * info.nDebugStringLength;
                    byte[] buffer = new byte[length];
                    int finalSize = ReadMemory(new IntPtr(info.lpDebugStringData), buffer, buffer.Length);
                    if (info.fUnicode == 0)
                    {
                        message = System.Text.Encoding.UTF8.GetString(buffer, 0, finalSize);
                    }
                    else
                    {
                        message = System.Text.Encoding.Unicode.GetString(buffer, 0, finalSize);
                    }
                }
                catch { }

                OutputDebugStringEventArgs args = new OutputDebugStringEventArgs(this, ntevent.dwProcessId, thread, message);

                if (OnOutputDebugString != null)
                {
                    OnOutputDebugString(this, args);
                }
                else
                {
                    args.Continue();
                }
            }

            internal void _CreateExitProcessDebugEvent(NTDebugEvent ntevent)
            {
                NTExitProcessDebugInfo info = *(NTExitProcessDebugInfo*)(&ntevent.u);
                Thread thread = _GetThread((ulong)ntevent.dwThreadId);
                try
                {
                    lock (this)
                    {
                        _Threads.Remove(thread.ID);
                    }
                }
                catch { }

                ExitProcessEventArgs args = new ExitProcessEventArgs(this, ntevent.dwProcessId, thread, info.dwExitCode);

                if (OnExitProcess != null)
                {
                    OnExitProcess(this, args);
                }
                else
                {
                    args.Continue();
                }
            }

            internal void _CreateExitThreadDebugEvent(NTDebugEvent ntevent)
            {
                NTExitThreadDebugInfo info = *(NTExitThreadDebugInfo*)(&ntevent.u);
                Thread thread = _GetThread((ulong)ntevent.dwThreadId);
                try
                {
                    lock (this)
                    {
                        _Threads.Remove(thread.ID);
                    }
                }
                catch { }

                ExitThreadEventArgs args = new ExitThreadEventArgs(this, ntevent.dwProcessId,thread, info.dwExitCode);

                if (OnExitThread != null)
                {
                    OnExitThread(this, args);
                }
                else
                {
                    args.Continue();
                }
            }

            internal void _CreateLoadDllDebugEvent(NTDebugEvent ntevent)
            {
                NTLoadDllDebugInfo info = *(NTLoadDllDebugInfo*)(&ntevent.u);
                Module module = new Module(this, new IntPtr(info.hFile), new IntPtr(info.lpBaseOfDll));

                LoadModuleEventArgs args = new LoadModuleEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId), module);

                try
                {
                    lock (this)
                    {
                        _Modules.Add((ulong)module.BaseAddress.ToPointer(), module);
                    }
                }
                catch
                {
                    lock (this)
                    {
                        _Modules.Remove((ulong)module.BaseAddress.ToPointer());
                    }
                    if (OnUnloadModule != null)
                    {
                        UnloadModuleEventArgs unloadArgs = new UnloadModuleEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId), module);
                        unloadArgs._FakeEvent = true;
                        OnUnloadModule(this, unloadArgs);
                    }
                    lock (this)
                    {
                        _Modules.Add((ulong)module.BaseAddress.ToPointer(), module);
                    }
                }

                if (OnLoadModule != null)
                {
                    OnLoadModule(this, args);
                }
                else
                {
                    args.Continue();
                }
            }
            internal void _CreateRIPDebugEvent(NTDebugEvent ntevent)
            {
            }
            internal void _CreateUnloadDllDebugEvent(NTDebugEvent ntevent)
            {
                NTUnloadDllDebugInfo info = *(NTUnloadDllDebugInfo*)(&ntevent.u);
                Module module = null;
                lock (this)
                {
                    if (!_Modules.TryGetValue((ulong)info.lpBaseOfDll, out module))
                    {
                        ContinueDebugEvent(ntevent.dwProcessId, ntevent.dwThreadId, DBG_CONTINUE);
                        return;
                    }
                }
                UnloadModuleEventArgs args = new UnloadModuleEventArgs(this, ntevent.dwProcessId, _GetThread((ulong)ntevent.dwThreadId), module);
                if (OnUnloadModule != null)
                {
                    OnUnloadModule(this, args);
                }
                else
                {
                    args.Continue();
                }
            }
            internal void _CreateEvent(NTDebugEvent ntevent)
            {
                ContinueDebugEvent(ntevent.dwProcessId, ntevent.dwThreadId, DBG_CONTINUE);
            }

            internal bool _WaitForEvent(int Timeout)
            {
                NTDebugEvent dgbevent;
                if (WaitForDebugEvent(&dgbevent, Timeout))
                {
                    switch (dgbevent.dwDebugEventCode)
                    {
                        case 3: _CreateProcessDebugEvent(dgbevent); break;
                        case 2: _CreateThreadDebugEvent(dgbevent); break;
                        case 1: _CreateExceptionDebugEvent(dgbevent); break;
                        case 5: _CreateExitProcessDebugEvent(dgbevent); return false;
                        case 4: _CreateExitThreadDebugEvent(dgbevent); break;
                        case 6: _CreateLoadDllDebugEvent(dgbevent); break;
                        // case 9: return _CreateRIPDebugEvent(dgbevent);
                        case 7: _CreateUnloadDllDebugEvent(dgbevent); break;
                        case 8: _CreateOutputDebugStringDebugEvent(dgbevent); break;
                        default: _CreateEvent(dgbevent); break;
                    }
                }
                return true;
            }

            internal int _PID = 0;
            internal int _TID = 0;
            internal bool _ResumeMainThreadAtStartup = false;

            internal void* _hProcess = null;

            public IntPtr ProcessHandle { get { return new IntPtr(_hProcess); } }

            internal void _EventLoop()
            {
                _Attach(_PID);
                while (_WaitForEvent(-1)) ;
            }

            internal void _StartEventLoop()
            {
                _Thread = new System.Threading.Thread(_EventLoop);
                _Thread.Start();
            }

            System.Threading.Thread _Thread;

            public delegate void CreateProcessEventHandler(object sender, CreateProcessEventArgs e);
            /// <summary>
            /// Raised when the new process is created.
            /// </summary>
            public event CreateProcessEventHandler OnCreateProcess;
            public delegate void ExitProcessEventHandler(object sender, ExitProcessEventArgs e);
            /// <summary>
            /// Raised when the process has exited. Once this event is recieved the debugger is no longer attached.
            /// </summary>
            public event ExitProcessEventHandler OnExitProcess;
            public delegate void CreateThreadEventHandler(object sender, CreateThreadEventArgs e);
            /// <summary>
            /// Raised when a new thread is created. The thread has already been added from the active thread list before this event.
            /// </summary>
            public event CreateThreadEventHandler OnCreateThread;
            public delegate void ExitThreadEventHandler(object sender, ExitThreadEventArgs e);
            /// <summary>
            /// Raised when a thread exit. The thread has already been removed from the active thread list before this event.
            /// </summary>
            public event ExitThreadEventHandler OnExitThread;
            public delegate void BreakpointEventHandler(object sender, BreakpointEventArgs e);
            /// <summary>
            /// Occurs when a breakpoint is reached. This event must be set and the debugger will wait at the first breakpoint until this event is set.
            /// </summary>
            public event BreakpointEventHandler OnBreakpoint;
            public delegate void ExceptionEventHandler(object sender, ExceptionEventArgs e);
            /// <summary>
            /// Raised when an exception occurs in the program.
            /// </summary>
            public event ExceptionEventHandler OnException;
            public delegate void OnLoadModuleEventHandler(object sender, LoadModuleEventArgs e);
            /// <summary>
            /// Raised when a new module is loaded by the debuggee. The module has already been added from the active module list before this event.
            /// </summary>
            public event OnLoadModuleEventHandler OnLoadModule;
            public delegate void OnUnloadModuleEventHandler(object sender, UnloadModuleEventArgs e);
            /// <summary>
            ///  Raised when a new module is unloaded by the debuggee. The module has already been removed from the active module list before this event.
            /// </summary>
            public event OnUnloadModuleEventHandler OnUnloadModule;
            public delegate void OnOutputDebugStringEventHandler(object sender, OutputDebugStringEventArgs e);
            /// <summary>
            /// Raised when the debuggee print a debug string.
            /// </summary>
            public event OnOutputDebugStringEventHandler OnOutputDebugString;
            Dictionary<ulong, Module> _Modules = new Dictionary<ulong, Module>();
            /// <summary>
            /// A read only collection of all the current modules.
            /// </summary>
            public System.Collections.ObjectModel.ReadOnlyCollection<Module> Modules { get { lock (this) { return new List<Module>(_Modules.Values).AsReadOnly(); } } }
            Dictionary<ulong, Thread> _Threads = new Dictionary<ulong, Thread>();
            /// <summary>
            /// A read only collection of all the current threads.
            /// </summary>
            public System.Collections.ObjectModel.ReadOnlyCollection<Thread> Threads { get { lock (this) { return new List<Thread>(_Threads.Values).AsReadOnly(); } } }

            internal static Session CreateSession(int PID, int TID, bool ResumeThread)
            {
                Session session = new Session();
                session._PID = PID;
                session._TID = TID;
                session._ResumeMainThreadAtStartup = ResumeThread;
                session._StartEventLoop();
                return session;
            }
        }

        /// <summary>
        /// Attach a new debugger and return a new debug session for an already started process.
        /// The process must already be running.
        /// </summary>
        /// <param name="Process"></param>
        /// <returns></returns>
        public static Session CreateSession(System.Diagnostics.Process Process)
        {
            return Session.CreateSession(Process.Id, 0, false);
        }

        internal struct NTExitThreadDebugInfo
        {
            internal Int32 dwExitCode;
        }
        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        internal struct NTStartupInfo
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct NTSecurityAttributes
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

        internal struct NTProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static unsafe internal extern bool CreateProcess(string lpApplicationName, string lpCommandLine, NTSecurityAttributes* lpProcessAttributes, NTSecurityAttributes* lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, NTStartupInfo* lpStartupInfo, NTProcessInformation* lpProcessInformation);

        /// <summary>
        /// Attach a new debugger and return a new debug session for an already started process.
        /// </summary>
        /// <param name="Process"></param>
        /// <returns></returns>
        public unsafe static Session CreateSession(System.Diagnostics.ProcessStartInfo ProcessStartInfo, out System.Diagnostics.Process Process)
        {
            const int CREATE_SUSPENDED = 0x4;

            NTProcessInformation processInfo = new NTProcessInformation();
            NTStartupInfo startupInfo = new NTStartupInfo(); ;
            startupInfo.cb = sizeof(NTStartupInfo);
            if (!CreateProcess(ProcessStartInfo.FileName, ProcessStartInfo.Arguments, null, null, false, CREATE_SUSPENDED, new IntPtr(0), ProcessStartInfo.WorkingDirectory, &startupInfo, &processInfo))
            {
                throw new Exception("Failed to start process " + ProcessStartInfo.FileName);
            }

            Process = System.Diagnostics.Process.GetProcessById(processInfo.dwProcessId);

            return Session.CreateSession(processInfo.dwProcessId, processInfo.dwThreadId, true);
        }
    }
}
