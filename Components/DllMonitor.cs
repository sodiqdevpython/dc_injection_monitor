using dc_injection_monitor.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
//using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace dc_injection_monitor.Components
{
    public sealed class DllMonitor : IDisposable
    {
        private int _started;// 0 yoki 1 qilib ishlataman

        private static readonly Guid KernelAuditApiCallsGuid =
            new Guid("E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23");

        private readonly int _maxAttackersToShow;
        private readonly RingBuffer<OpenProcRecord> _openFifo;

        private readonly Dictionary<int, string> _pidToPath = new Dictionary<int, string>(4096);
        private readonly object _pidLock = new object();

        private TraceEventSession _session;
        private Task _worker;
        private CancellationTokenSource _cts;

        public event Action<DllInjectionAlert> Alert;

        public DllMonitor(int maxPerList = 2000, int maxAttackersToShow = 100)
        {
            _openFifo = new RingBuffer<OpenProcRecord>(maxPerList);
            _maxAttackersToShow = maxAttackersToShow;
        }

        public void Start()
        {
            if (Interlocked.CompareExchange(ref _started, 1, 0) != 0) // faqat 1 martta ishga tushira olish uchun
                return;

            if (_session != null) return;

            SeedProcessCache();

            string name = Environment.OSVersion.Version.Build >= 9200
                ? "DllMonitor"
                : KernelTraceEventParser.KernelSessionName;

            _session = new TraceEventSession(name) { StopOnDispose = true };
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad);

            _session.EnableProvider(KernelAuditApiCallsGuid, TraceEventLevel.Informational, ulong.MaxValue);

            HookEvents(_session.Source);

            _cts = new CancellationTokenSource();
            _worker = Task.Factory.StartNew(() =>
            {
                try { _session.Source.Process(); }
                catch {  }
            }, _cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public void Stop()
        {
            if (Interlocked.CompareExchange(ref _started, 0, 1) != 1)
                return;

            if (_session == null) return;

            try
            {
                _cts?.Cancel();
                _session.Source?.StopProcessing();
            }
            catch { }

            try { _session.Dispose(); } catch { }

            try { _worker?.Wait(1500); } catch { }

            _worker = null;
            _cts = null;
            _session = null;
        }

        public void Dispose()
        {
            Stop();
        }

        private void HookEvents(TraceEventSource source)
        {
            source.Kernel.ProcessStart += e =>
            {
                string path = SafeGetProcessPath(e.ProcessID);
                if (string.IsNullOrWhiteSpace(path))
                    path = e.ProcessName ?? e.ImageFileName ?? "";

                lock (_pidLock) _pidToPath[e.ProcessID] = path;
            };

            source.Kernel.ProcessStop += e =>
            {
                lock (_pidLock) _pidToPath.Remove(e.ProcessID);
            };

            source.Kernel.ImageLoad += e =>
            {
                var dll = e.FileName;
                if (string.IsNullOrWhiteSpace(dll)) return;
                if (!dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;
                if (PathUtil.IsWhiteListed(dll)) return;

                int victimPid = e.ProcessID;

                var alert = new DllInjectionAlert
                {
                    Time = e.TimeStamp,
                    VictimPid = victimPid,
                    VictimProcessPath = GetProcPathCached(victimPid),
                    DllPath = dll
                };

                alert.Attackers.AddRange(FindAttackers(victimPid, _maxAttackersToShow));

                Alert?.Invoke(alert);
            };

            source.Dynamic.All += ev =>
            {
                if (ev.ProviderGuid != KernelAuditApiCallsGuid) return;
                if ((int)ev.ID != 5) return;

                uint rc = ReadU32(ev, "ReturnCode");
                if (rc != 0) return;

                int callerPid = ev.ProcessID;
                int targetPid = (int)ReadU32(ev, "TargetProcessId");
                uint access = ReadU32(ev, "DesiredAccess");

                if (callerPid <= 0 || targetPid <= 0) return;
                if (callerPid == targetPid) return;

                if (!AccessUtil.IsStrongInjectionAccess(access)) return;

                var rec = new OpenProcRecord
                {
                    Time = ev.TimeStamp,
                    CallerPid = callerPid,
                    CallerPath = GetProcPathCached(callerPid),
                    TargetPid = targetPid,
                    DesiredAccess = access
                };

                _openFifo.Add(rec);
            };
        }

        private List<AttackerInfo> FindAttackers(int victimPid, int take)
        {
            var list = new List<AttackerInfo>(take);
            var seen = new HashSet<int>();

            _openFifo.ScanNewest(
                predicate: r => r.TargetPid == victimPid,
                onHit: r =>
                {
                    if (seen.Contains(r.CallerPid)) return;
                    seen.Add(r.CallerPid);

                    list.Add(new AttackerInfo
                    {
                        Pid = r.CallerPid,
                        Time = r.Time,
                        ImagePath = r.CallerPath,
                        DesiredAccess = r.DesiredAccess,
                        AccessText = AccessUtil.ToText(r.DesiredAccess)
                    });
                },
                shouldStop: () => list.Count >= take
            );

            return list;
        }

        private void SeedProcessCache()
        {
            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    string path = SafeGetProcessPath(p.Id);
                    if (string.IsNullOrWhiteSpace(path))
                        path = p.ProcessName;

                    lock (_pidLock) _pidToPath[p.Id] = path ?? "";
                }
            }
            catch { }
        }

        private string GetProcPathCached(int pid)
        {
            lock (_pidLock)
            {
                string v;
                if (_pidToPath.TryGetValue(pid, out v) && !string.IsNullOrWhiteSpace(v))
                    return v;
            }

            var path = SafeGetProcessPath(pid);
            return string.IsNullOrWhiteSpace(path) ? ("pid=" + pid) : path;
        }

        private static string SafeGetProcessPath(int pid)
        {
            try
            {
                using (var p = Process.GetProcessById(pid))
                    return p.MainModule != null ? p.MainModule.FileName : "";
            }
            catch { return ""; }
        }

        private static uint ReadU32(TraceEvent ev, string name)
        {
            try
            {
                object o = ev.PayloadByName(name);
                if (o == null) return 0;

                if (o is uint) return (uint)o;
                if (o is int) return (uint)(int)o;

                uint v;
                return uint.TryParse(o.ToString(), out v) ? v : 0;
            }
            catch { return 0; }
        }
    }
}
