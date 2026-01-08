using System;
using System.Collections.Generic;

namespace dc_injection_monitor.Models
{
    public class DllInjectionAlert
    {
        public DateTime Time { get; set; }

        public int VictimPid { get; set; }
        public string VictimProcessPath { get; set; }

        public string DllPath { get; set; }

        public List<AttackerInfo> Attackers { get; set; } = new List<AttackerInfo>();
    }
}
