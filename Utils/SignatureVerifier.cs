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
        // Kesh: Path -> Natija (bool)
        private static readonly ConcurrentDictionary<string, bool> _cache
            = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        public static bool IsTrusted(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            // 1. Agar oldin tekshirgan bo'lsak, keshdan olamiz
            if (_cache.TryGetValue(path, out bool isTrusted))
            {
                return isTrusted;
            }

            // 2. Haqiqiy tekshiruv
            bool result = CheckTrust(path);

            // 3. Natijani keshga yozamiz
            _cache[path] = result;
            return result;
        }

        private static bool CheckTrust(string path)
        {
            if (!File.Exists(path)) return false;

            // --- 1-QADAM: Raqamli Imzo (Embedded Signature) ---
            try
            {
                using (var cert = new X509Certificate2(path))
                {
                    if (cert.Verify()) return true; // Imzo to'g'ri bo'lsa -> Ishonchli
                }
            }
            catch { }

            // --- 2-QADAM: Microsoft fayllari (Catalog Signed) ---
            // Windows tizim fayllari (svchost, csrss) ko'pincha "Embedded Signature"ga ega bo'lmaydi.
            // Ular "Catalog" orqali imzolanadi. C# da buni tekshirish qiyin.
            // Shuning uchun, qo'shimcha "CompanyName" tekshiruvini qilamiz.
            // DIQQAT: Biz fayl qayerda turganiga (Folder) qaramayapmiz, faqat faylning ichiga qarayapmiz.
            try
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                if (!string.IsNullOrEmpty(info.CompanyName) && info.CompanyName.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            catch { }

            // Agar imzo ham yo'q, Microsoft ham emas bo'lsa -> Ishonchsiz
            return false;
        }
    }
}