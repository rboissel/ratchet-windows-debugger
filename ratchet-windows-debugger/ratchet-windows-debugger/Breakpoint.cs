using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ratchet.Runtime.Debugger
{
    public static partial class Windows
    {
        public class Breakpoint
        {
            Session _Parent;
            IntPtr _Address;
            byte[] _OldCode = new byte[0];
            byte[] _BreakpointCode = new byte[0];

            bool _Enabled = false;
            public bool Enabled
            {
                get { return _Enabled; }
                set
                {
                    bool oldValue = _Enabled;
                    _Enabled = value;
                    if (_Enabled != oldValue)
                    {
                        if (_Enabled)
                        {
                            _OldCode = new byte[_BreakpointCode.Length];
                            _Parent.ReadMemory(_Address, _OldCode, _OldCode.Length);
                            _Parent.WriteMemory(_Address, _BreakpointCode, _BreakpointCode.Length);
                        }
                        else
                        {
                            _Parent.WriteMemory(_Address, _OldCode, _OldCode.Length);
                        }
                    }
                }
            }

            public Breakpoint(Session Parent, IntPtr Address, byte[] BreakpointCode)
            {
                _Parent = Parent;
                _Address = Address;
                _BreakpointCode = BreakpointCode;
            }

            internal void hit(object sender, Windows.Session.BreakpointEventArgs args)
            {
                if (OnHit != null && _Enabled)
                {
                    OnHit(sender, args);
                }
                else
                {
                    args.Continue();
                }
            }
            public event Windows.Session.BreakpointEventHandler OnHit;
        }
    }
}
