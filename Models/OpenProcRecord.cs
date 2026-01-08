using System;

namespace dc_injection_monitor.Models
{
    public class OpenProcRecord
    {
        public DateTime Time { get; set; }

        public int CallerPid { get; set; }
        public string CallerPath { get; set; }

        public int TargetPid { get; set; }
        public uint DesiredAccess { get; set; }
    }
}
