using System;

namespace dc_injection_monitor.Models
{
    public class AttackerInfo
    {
        public int Pid { get; set; }
        public DateTime Time { get; set; }

        public string ImagePath { get; set; }

        public uint DesiredAccess { get; set; }
        public string AccessText { get; set; }
    }
}
