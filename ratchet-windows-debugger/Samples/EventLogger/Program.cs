using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ratchet.Runtime.Debugger;

namespace EventLogger
{
    class Program
    {
        static void Main(string[] args)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "notepad.exe";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.WorkingDirectory = "C:/";
            process.Start();
            Ratchet.Runtime.Debugger.Windows.Session session = Ratchet.Runtime.Debugger.Windows.CreateSession(process);
            session.OnLoadModule += Session_OnLoadModule;
            session.OnCreateThread += Session_OnCreateThread;
            session.OnExitThread += Session_OnExitThread;
            session.OnBreakpoint += Session_OnBreakpoint;
            session.OnCreateProcess += Session_OnCreateProcess;
            session.OnException += Session_OnException;
            session.OnUnloadModule += Session_OnUnloadModule;
            session.OnExitProcess += Session_OnExitProcess;
            session.OnOutputDebugString += Session_OnOutputDebugString;
            process.WaitForExit();

            Console.WriteLine("The debuggee has exited. Press any key to quit");
            Console.ReadKey();
        }

        private static void Session_OnOutputDebugString(object sender, Ratchet.Runtime.Debugger.Windows.Session.OutputDebugStringEventArgs e)
        {
            Console.WriteLine("Debug message (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + "): " + e.Message);
            e.Continue();
        }

        private static void Session_OnExitProcess(object sender, Ratchet.Runtime.Debugger.Windows.Session.ExitProcessEventArgs e)
        {
            Console.WriteLine("ExitProcess (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + ") with code " + e.ExitCode);
            e.Continue();
        }

        private static void Session_OnExitThread(object sender, Ratchet.Runtime.Debugger.Windows.Session.ExitThreadEventArgs e)
        {
            Console.WriteLine("ExitThread (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + ") with code " + e.ExitCode);
            e.Continue();
        }

        private static void Session_OnCreateThread(object sender, Ratchet.Runtime.Debugger.Windows.Session.CreateThreadEventArgs e)
        {
            Console.WriteLine("CreateThread (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + ")");
            e.Continue();
        }

        private static void Session_OnLoadModule(object sender, Ratchet.Runtime.Debugger.Windows.Session.LoadModuleEventArgs e)
        {
            Console.WriteLine("Load module '" + e.Module.Path + "' (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + ")");
            e.Continue();
        }

        private static void Session_OnUnloadModule(object sender, Ratchet.Runtime.Debugger.Windows.Session.UnloadModuleEventArgs e)
        {
            Console.WriteLine("Unload module '" + e.Module.Path + "' (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + ")");
            e.Continue();
        }


        private static void Session_OnException(object sender, Ratchet.Runtime.Debugger.Windows.Session.ExceptionEventArgs e)
        {
            Console.WriteLine("Exception  (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + ") (at: 0x" + e.Address.ToString("X2") + ")");
            e.ExceptionNotHandled();
        }

        private static void Session_OnCreateProcess(object sender, Ratchet.Runtime.Debugger.Windows.Session.CreateProcessEventArgs e)
        {
            Console.WriteLine("CreateProcess");
            e.Continue();
        }

        private static void Session_OnBreakpoint(object sender, Ratchet.Runtime.Debugger.Windows.Session.BreakpointEventArgs e)
        {
            Console.WriteLine("Breakpoint (thread id: " + (e.Thread == null ? "unk" : e.Thread.ID.ToString()) + ") (at: 0x" + e.Address.ToString("X2") + ")");

            e.Continue();
        }
    }
}
