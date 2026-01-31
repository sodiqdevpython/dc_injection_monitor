using dc_injection_monitor.Models;
using dc_injection_monitor.Utils;
using etw_manager;
using etw_manager.Monitors;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace dc_injection_monitor.Components
{
    public sealed class DllMonitor : IDisposable
    {
        private int _started;
        private readonly int _maxAttackersToShow;
        private readonly RingBuffer<OpenProcRecord> _openFifo;

        private ApiCallMonitor _apiMonitor;
        private ImageLoadMonitor _imageMonitor;

        private readonly Dictionary<int, string> _pidToPath = new Dictionary<int, string>(4096);
        private readonly object _pidLock = new object();

        private readonly Dictionary<string, DateTime> _alertHistory = new Dictionary<string, DateTime>();
        private readonly object _historyLock = new object();

        private BlockingCollection<QueuedEvent> _eventQueue;
        private CancellationTokenSource _cts;
        private Task _workerTask;

        public event Action<DllInjectionAlert> Alert;

        public DllMonitor(int maxPerList = 2000, int maxAttackersToShow = 100)
        {
            _openFifo = new RingBuffer<OpenProcRecord>(maxPerList);
            _maxAttackersToShow = maxAttackersToShow;

            _eventQueue = new BlockingCollection<QueuedEvent>();
        }

        public void Start()
        {
            if (Interlocked.CompareExchange(ref _started, 1, 0) != 0) return;

            SeedProcessCache();

            _cts = new CancellationTokenSource();
            _workerTask = Task.Factory.StartNew(ProcessQueueLoop, TaskCreationOptions.LongRunning);

            _apiMonitor = new ApiCallMonitor();
            _apiMonitor.ApiCallEvent += OnApiCall;
            _apiMonitor.Start();

            _imageMonitor = new ImageLoadMonitor();
            _imageMonitor.ImageLoadEvent += OnImageLoad;
            _imageMonitor.Start();
        }

        public void Stop()
        {
            if (Interlocked.CompareExchange(ref _started, 0, 1) != 1) return;

            try
            {
                _apiMonitor?.Stop();
                _imageMonitor?.Stop();

                _eventQueue.CompleteAdding();
                _cts.Cancel();
                try { _workerTask.Wait(1000); } catch { }
            }
            catch { }
        }

        public void Dispose() => Stop();

        private void OnApiCall(ApiAuditInfo info)
        {
            if (info.ProcessId == Process.GetCurrentProcess().Id) return;

            int callerPid = (int)info.ProcessId;
            int targetPid = (int)info.TargetProcessId;

            if (callerPid <= 0 || targetPid <= 0 || callerPid == targetPid) return;
            if (!AccessUtil.IsStrongInjectionAccess((uint)info.DesiredAccess)) return;

            UpdateProcessPathCache(callerPid, info.ProcessName);
            if (!string.IsNullOrEmpty(info.TargetProcessName))
                UpdateProcessPathCache(targetPid, info.TargetProcessName);

            string callerPath = GetProcPathCached(callerPid);

            if (!HasPathSeparators(callerPath)) return;

            _eventQueue.Add(new QueuedEvent
            {
                Type = EventType.ApiCall,
                Timestamp = DateTime.Now,
                CallerPid = callerPid,
                CallerPath = callerPath,
                TargetPid = targetPid,
                Access = (uint)info.DesiredAccess
            });
        }

        private void OnImageLoad(dynamic data)
        {
            if (data == null) return;

            try { if (data.Opcode == 2) return; } catch { }

            string dll = data.ImagePath;

            if (string.IsNullOrWhiteSpace(dll) || !dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                return;
            if (PathUtil.IsWhiteListed(dll)) return;

            int victimPid = (int)data.ProcessId;
            string victimPath = GetProcPathCached(victimPid);

            _eventQueue.Add(new QueuedEvent
            {
                Type = EventType.ImageLoad,
                Timestamp = DateTime.Now,
                VictimPid = victimPid,
                VictimProcessPath = victimPath,
                DllPath = dll
            });
        }

        private void ProcessQueueLoop()
        {
            foreach (var evt in _eventQueue.GetConsumingEnumerable(_cts.Token))
            {
                try
                {
                    if (evt.Type == EventType.ApiCall)
                    {
                        ProcessApiCall(evt);
                    }
                    else if (evt.Type == EventType.ImageLoad)
                    {
                        ProcessImageLoad(evt);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception) { }
            }
        }

        private void ProcessApiCall(QueuedEvent evt)
        {
            if (SignatureVerifier.IsTrusted(evt.CallerPath)) return;

            _openFifo.Add(new OpenProcRecord
            {
                Time = evt.Timestamp,
                CallerPid = evt.CallerPid,
                CallerPath = evt.CallerPath,
                TargetPid = evt.TargetPid,
                DesiredAccess = evt.Access
            });
        }

        private void ProcessImageLoad(QueuedEvent evt)
        {
            if (SignatureVerifier.IsTrusted(evt.DllPath)) return;

            if (IsDuplicateAlert(evt.VictimPid, evt.DllPath)) return;

            var attackers = FindAttackers(evt.VictimPid, _maxAttackersToShow);

            if (attackers == null || attackers.Count == 0) return;

            Alert?.Invoke(new DllInjectionAlert
            {
                Time = evt.Timestamp,
                VictimPid = evt.VictimPid,
                VictimProcessPath = evt.VictimProcessPath,
                DllPath = evt.DllPath,
                Attackers = attackers
            });
        }


        private bool IsDuplicateAlert(int pid, string dllPath)
        {
            string key = $"{pid}|{dllPath.ToLower()}";
            lock (_historyLock)
            {
                if (_alertHistory.TryGetValue(key, out DateTime lastTime))
                {
                    if ((DateTime.Now - lastTime).TotalSeconds < 5) return true;
                }
                _alertHistory[key] = DateTime.Now;
            }
            return false;
        }

        private bool HasPathSeparators(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            return path.IndexOf(':') >= 0 || path.IndexOf('\\') >= 0 || path.IndexOf('/') >= 0;
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
                    if (SignatureVerifier.IsTrusted(r.CallerPath)) return;

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
            try { foreach (var p in Process.GetProcesses()) UpdateProcessPathCache(p.Id, SafeGetProcessPath(p.Id)); } catch { }
        }
        private void UpdateProcessPathCache(int pid, string pathOrName)
        {
            if (string.IsNullOrEmpty(pathOrName)) return;
            lock (_pidLock) { if (!_pidToPath.ContainsKey(pid)) _pidToPath[pid] = pathOrName; }
        }
        private string GetProcPathCached(int pid)
        {
            lock (_pidLock) { if (_pidToPath.TryGetValue(pid, out string v)) return v; }
            var path = SafeGetProcessPath(pid);
            if (!string.IsNullOrWhiteSpace(path)) { UpdateProcessPathCache(pid, path); return path; }
            return "pid=" + pid;
        }
        private static string SafeGetProcessPath(int pid)
        {
            try { using (var p = Process.GetProcessById(pid)) { try { return p.MainModule?.FileName ?? p.ProcessName; } catch { return p.ProcessName; } } } catch { return ""; }
        }
    }
}