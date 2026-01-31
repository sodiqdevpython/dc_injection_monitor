using System;
using System.IO;

namespace dc_injection_monitor.Components
{
    public static class PathUtil
    {
        private static readonly string[] WhiteListFolders =
        {
            //@"C:\Windows\System32",
            //@"C:\Program Files",
            //@"C:\Program Files (x86)",
            //@"C:\Windows\",
            //@"C:\ProgramData"
        };

        public static bool IsWhiteListed(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            var fullPath = Normalize(path);

            foreach (var folder in WhiteListFolders)
            {
                if (IsSubPathOf(fullPath, folder))
                    return true;
            }

            return false;
        }

        private static bool IsSubPathOf(string path, string baseDir)
        {
            var normalizedPath = Path.GetFullPath(path)
                .TrimEnd('\\') + "\\";

            var normalizedBase = Path.GetFullPath(baseDir)
                .TrimEnd('\\') + "\\";

            return normalizedPath.StartsWith(
                normalizedBase,
                StringComparison.OrdinalIgnoreCase);
        }

        private static string Normalize(string path)
        {
            path = path.Trim().Replace('/', '\\');

            if (path.StartsWith(@"\\?\") || path.StartsWith(@"\??\"))
                path = path.Substring(4);

            //if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            //{
            //    var systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            //    path = Path.Combine(systemRoot, path.Substring(12));
            //}

            return path;
        }
    }
}
