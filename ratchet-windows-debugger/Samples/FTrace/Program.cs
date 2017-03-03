using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ftrace
{
    class Program
    {
        static Ratchet.Runtime.Debugger.Windows.Session session;
        static void Main(string[] args)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "notepad.exe";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.WorkingDirectory = "C:/";
            process.Start();
            session = Ratchet.Runtime.Debugger.Windows.CreateSession(process);
            session.OnLoadModule += Session_OnLoadModule;
            session.OnBreakpoint += Session_OnBreakpoint;
            session.OnCreateProcess += Session_OnCreateProcess;
            session.OnException += Session_OnException;
            process.WaitForExit();

            Console.WriteLine("The debuggee has exited. Press any key to quit");
            Console.ReadKey();
        }

        private static void Session_OnCreateThread(object sender, Ratchet.Runtime.Debugger.Windows.Session.CreateThreadEventArgs e)
        {
            e.Continue();
        }

        private static void Session_OnException(object sender, Ratchet.Runtime.Debugger.Windows.Session.ExceptionEventArgs e)
        {
            e.ExceptionNotHandled();
        }

        private static void Session_OnCreateProcess(object sender, Ratchet.Runtime.Debugger.Windows.Session.CreateProcessEventArgs e)
        {
            e.Continue();
        }

        private static void Session_OnLoadModule(object sender, Ratchet.Runtime.Debugger.Windows.Session.LoadModuleEventArgs e)
        {
            foreach (Ratchet.Runtime.Debugger.Windows.Module.Section section in e.Module.Sections)
            {
                foreach (Ratchet.Runtime.Debugger.Windows.Module.Symbol symbol in section.Symbols)
                {
                    if (section.Name != ".text") { continue; }
                    byte[] opcode = new byte[8];
                    symbol.ReadMemory(new IntPtr(0), opcode, 8);
                    int opcodeSize = 0;
                    long bpaddress = 0;
                    bool isJumpPatch = false;

                    // This is a very basic chunk of code to detect common first instructions in system libraries
                    // They are hardcodded. In a true tracert you will write an ASM decodder
                    if (opcode[0] == 0x48 && opcode[1] == 0x89 && opcode[2] == 0x5C && opcode[3] == 0x24) { opcodeSize = 5; bpaddress = symbol.BaseAddress.ToInt64() + (long)opcodeSize; }
                    if (opcode[0] == 0xFF && opcode[1] == 0x25)
                    {
                        int offset = BitConverter.ToInt32(opcode, 2);
                        opcodeSize = 6;
                        bpaddress = symbol.BaseAddress.ToInt64() + (long)offset - opcodeSize;
                        isJumpPatch = true;
                    }
                    if (opcodeSize != 0)
                    {
                        if (isJumpPatch)
                        {
                            try
                            {
                                // This function is a trampoline just trampoline within the debugger
                                Ratchet.Runtime.Debugger.Windows.Breakpoint breakpoint1 = symbol.AddBreakpoint(new IntPtr(0));
                                breakpoint1.OnHit += (object s, Ratchet.Runtime.Debugger.Windows.Session.BreakpointEventArgs bp) =>
                                {

                                    Console.WriteLine(symbol.Name + " at " + symbol.BaseAddress.ToInt64().ToString("X"));

                                    section.FlushInstructionCache();
                                    bp.Thread.InstructionPointer = new IntPtr(bpaddress);

                                    bp.Continue();
                                };
                            }
                            catch { }
                        }
                        else
                        {
                            try
                            {
                                // Use a toggle system with two breakpoint for tracing. This is bad a true tracert will allocate a jump slot
                                // And patch the instruction into a jump (injecting a trampoline)
                                Ratchet.Runtime.Debugger.Windows.Breakpoint breakpoint1 = symbol.AddBreakpoint(new IntPtr(0));
                                Ratchet.Runtime.Debugger.Windows.Breakpoint breakpoint2 = session.AddBreakpoint(new IntPtr(bpaddress));

                                breakpoint1.OnHit += (object s, Ratchet.Runtime.Debugger.Windows.Session.BreakpointEventArgs bp) =>
                                {
                                    breakpoint1.Enabled = false;
                                    breakpoint2.Enabled = true;

                                    Console.WriteLine(symbol.Name + " at " + symbol.BaseAddress.ToInt64().ToString("X"));

                                    section.FlushInstructionCache();
                                    bp.Thread.InstructionPointer = bp.Address;

                                    bp.Continue();
                                };

                                breakpoint2.OnHit += (object s, Ratchet.Runtime.Debugger.Windows.Session.BreakpointEventArgs bp) =>
                                {
                                    breakpoint1.Enabled = true;
                                    breakpoint2.Enabled = false;
                                    section.FlushInstructionCache();
                                    bp.Thread.InstructionPointer = bp.Address;

                                    bp.Continue();
                                };

                                breakpoint1.Enabled = true;
                                breakpoint2.Enabled = false;

                            }
                            catch { }
                        }
                    }
                    else
                    {
                    }

                }
            }

            foreach (Ratchet.Runtime.Debugger.Windows.Module.Section section in e.Module.Sections)
            {
                section.FlushInstructionCache();
            }
            e.Continue();
        }

        private static void Session_OnBreakpoint(object sender, Ratchet.Runtime.Debugger.Windows.Session.BreakpointEventArgs e)
        {
            e.Continue();
        }
    }
}
