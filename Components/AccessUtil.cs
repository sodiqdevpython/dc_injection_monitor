using System;
using System.Collections.Generic;

namespace dc_injection_monitor.Components
{
    public static class AccessUtil
    {
        public static bool IsStrongInjectionAccess(uint a)
        {
            const uint PROCESS_CREATE_THREAD = 0x0002;
            const uint PROCESS_VM_WRITE = 0x0020;

            return (a & PROCESS_CREATE_THREAD) != 0
                && (a & PROCESS_VM_WRITE) != 0;
        }

        public static string ToText(uint a)
        {
            var flags = new List<string>();

            if ((a & 0x0002) != 0) flags.Add("CREATE_THREAD");
            if ((a & 0x0008) != 0) flags.Add("VM_OPERATION");
            if ((a & 0x0010) != 0) flags.Add("VM_READ");
            if ((a & 0x0020) != 0) flags.Add("VM_WRITE");
            if ((a & 0x0040) != 0) flags.Add("DUP_HANDLE");
            if ((a & 0x0400) != 0) flags.Add("QUERY_INFORMATION");
            if ((a & 0x1000) != 0) flags.Add("QUERY_LIMITED_INFORMATION");

            return flags.Count == 0 ? "-" : string.Join(" | ", flags);
        }
    }
}
