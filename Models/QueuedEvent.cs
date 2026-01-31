using System;

namespace dc_injection_monitor.Models
{
    public enum EventType { ApiCall, ImageLoad }

    public class QueuedEvent
    {
        public EventType Type;
        public DateTime Timestamp;

        // ApiCall uchun
        public int CallerPid;
        public string CallerPath;
        public int TargetPid;
        public uint Access;

        // ImageLoad uchun
        public int VictimPid;

        // OLDIN: public string VictimPath; 
        // TUZATILDI:
        public string VictimProcessPath;

        public string DllPath;
    }
}