using System;
using dc_injection_monitor.Components;
using dc_injection_monitor.Models;

namespace dc_injection_monitor
{
    internal static class Program
    {
        static void Main()
        {

            using (var mon = new DllMonitor(maxPerList: 2000))
            {
                mon.Alert += Print;

                mon.Start();
                Console.WriteLine("Ishga tushdi...");
                Console.ReadLine();

                mon.Stop();
            }
        }

        static void Print(DllInjectionAlert a)
        {
            Console.WriteLine("\n[{0:HH:mm:ss.fff}] PID={1} Proc={2} DLL={3}",
                a.Time, a.VictimPid, a.VictimProcessPath, a.DllPath);

            if (a.Attackers == null || a.Attackers.Count == 0)
            {
                Console.WriteLine("Openprocess: (null)");
                return;
            }

            Console.WriteLine("OpenProcess qilganlar:");
            foreach (var x in a.Attackers)
            {
                Console.WriteLine("PID={0} Time={1:HH:mm:ss.fff} Access=0x{2:X8}",
                    x.Pid, x.Time, x.DesiredAccess);

                Console.WriteLine("Path : {0}", x.ImagePath);
                Console.WriteLine("Flags: {0}", x.AccessText);
            }
        }
    }
}
