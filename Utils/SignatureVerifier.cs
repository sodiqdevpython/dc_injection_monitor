using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace dc_injection_monitor.Utils
{
    public static class SignatureVerifier
    {
        private static readonly ConcurrentDictionary<string, bool> _cache
            = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        public static bool IsTrusted(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            if (_cache.TryGetValue(path, out bool isTrusted))
            {
                return isTrusted;
            }

            bool result = CheckTrust(path);

            _cache[path] = result;
            return result;
        }

        private static bool CheckTrust(string path)
        {
            if (!File.Exists(path)) return false;

            try
            {
                using (var cert = new X509Certificate2(path))
                {
                    if (cert.Verify()) return true; 
                }
            }
            catch { }
            try
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                if (!string.IsNullOrEmpty(info.CompanyName) && info.CompanyName.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            catch { }

            return false;
        }
    }
}