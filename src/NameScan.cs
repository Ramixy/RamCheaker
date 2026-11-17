using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;

namespace InjectHunter
{
    /// <summary>Раздел «Открытые читы»: быстрый поиск по названиям и размерам из «сайз.txt» —
    /// все файлы и папки на дисках + процессы, установленные программы, автозапуск. Содержимое почти не читается.</summary>
    class NameScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public double Progress;
        public long FilesSeen, BytesSeen, TotalBytes;
        public int Programs;
        HashSet<string> reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        static readonly HashSet<string> weakExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".jar", ".zip", ".rar", ".7z" };

        public void Run(List<string> roots, bool skipService, bool listAllPrograms, CancellationToken ct)
        {
            // 1) программы
            Current = "Процессы, установленные программы, автозапуск";
            RunPrograms(listAllPrograms, ct);
            Progress = 0.05;

            // 2) файлы на дисках
            foreach (string r in roots)
                try { DriveInfo di = new DriveInfo(r); if (di.IsReady) TotalBytes += di.TotalSize - di.TotalFreeSpace; } catch { }
            string[] skip = skipService ? new string[] { "WinSxS", "servicing", "assembly", "Microsoft.NET", "SoftwareDistribution", "System32\\DriverStore", "Installer" }
                                          .Select(x => Path.Combine(Analyzer.WinDir, x)).ToArray() : new string[0];
            foreach (string root in roots)
            {
                if (ct.IsCancellationRequested) break;
                Walk(root, skip, ct);
            }
            Progress = 1;
        }

        void RunPrograms(bool listAll, CancellationToken ct)
        {
            ProgramScanner ps = new ProgramScanner();
            ps.Found += f =>
            {
                Programs++;
                if (f.Severity > 0 || listAll) Emit(f, false);
            };
            try { ps.Run(ct); } catch { }
        }

        void Emit(Finding f, bool finish)
        {
            if (!reported.Add(f.Source + "|" + f.Path)) return;
            if (finish) f.Finish();
            if (Found != null) Found(f);
        }

        void Walk(string root, string[] skip, CancellationToken ct)
        {
            Stack<string> st = new Stack<string>();
            st.Push(root);
            const FileAttributes Recall = (FileAttributes)0x400000 | (FileAttributes)0x40000 | FileAttributes.Offline;
            while (st.Count > 0 && !ct.IsCancellationRequested)
            {
                string dir = st.Pop();
                if (skip.Any(s => dir.Equals(s, StringComparison.OrdinalIgnoreCase))) continue;
                IEnumerator<FileSystemInfo> en;
                try { en = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator(); } catch { continue; }
                while (true)
                {
                    FileSystemInfo it;
                    try { if (!en.MoveNext()) break; it = en.Current; } catch { break; }
                    FileAttributes a;
                    try { a = it.Attributes; } catch { continue; }
                    if ((a & FileAttributes.Directory) != 0)
                    {
                        if ((a & FileAttributes.ReparsePoint) != 0 || (a & Recall) != 0) continue;
                        CheckDir(it.FullName, it.Name);
                        st.Push(it.FullName);
                        continue;
                    }
                    FilesSeen++;
                    if ((a & Recall) != 0) continue;
                    FileInfo fi = it as FileInfo;
                    if (fi == null) continue;
                    long len;
                    try { len = fi.Length; } catch { continue; }
                    BytesSeen += len;
                    if ((FilesSeen & 1023) == 0)
                    {
                        Current = fi.FullName;
                        if (TotalBytes > 0) Progress = Math.Max(Progress, 0.05 + 0.94 * Math.Min(1.0, (double)BytesSeen / TotalBytes));
                    }
                    try { CheckFile(fi, len); } catch { }
                }
            }
        }

        static bool InCache(string p)
        {
            string l = p.ToLowerInvariant();
            return l.Contains("\\cache\\") || l.Contains("\\cache_data\\") || l.Contains("\\code cache\\") || l.Contains("\\gpucache\\") || l.Contains("\\node_modules\\");
        }

        void CheckDir(string path, string name)
        {
            if (Keywords.IsSsTool(name)) return;
            List<Keywords.Kw> hits = Keywords.Match(name).Where(k => k.Strong).ToList();
            if (hits.Count == 0 || InCache(path)) return;
            Finding f = new Finding();
            f.Path = path; f.FileName = name; f.RealType = "DIR · Папка"; f.Source = "Диск";
            try { f.Modified = Directory.GetLastWriteTime(path); } catch { }
            foreach (Keywords.Kw k in hits) f.Add(40, "Папка называется по слову из списка «" + k.Word + "»");
            Emit(f, true);
        }

        void CheckFile(FileInfo fi, long len)
        {
            string name = fi.Name;
            string ext = fi.Extension.ToLowerInvariant();
            if (name.EndsWith(".jar.disabled", StringComparison.OrdinalIgnoreCase)) ext = ".jar";
            List<Keywords.Kw> hits = Keywords.Match(name);
            hits = hits.Where(k => k.Strong || weakExts.Contains(ext)).ToList();
            bool jarSize = ext == ".jar" && SizeRules.JarSizes.Contains(len);
            bool binSize = (ext == ".exe" || ext == ".dll") && SizeRules.BinSizes.Contains(len);
            bool tmplJar = ext == ".jar" && len >= 21 * 1024 && len <= 10L * 1024 * 1024 && fi.FullName.IndexOf("\\libraries\\", StringComparison.OrdinalIgnoreCase) < 0;
            bool tmpl30 = len == 30720 && (ext == ".dll" || ext == ".exe" || ext == ".tmp" || ext == ".dat" || ext == "");
            if (hits.Count == 0 && !jarSize && !binSize && !tmplJar && !tmpl30) return;
            if (InCache(fi.FullName) && hits.Count == 0) return;

            Finding f = new Finding();
            f.Path = fi.FullName; f.FileName = name; f.Size = len; f.Source = "Диск";
            f.RealType = (ext.Length > 1 ? ext.Substring(1).ToUpperInvariant() : "—") + " · Файл";
            try { f.Modified = fi.LastWriteTime; f.Created = fi.CreationTime; } catch { }
            bool mc = fi.FullName.IndexOf("minecraft", StringComparison.OrdinalIgnoreCase) >= 0 || fi.FullName.IndexOf("\\mods\\", StringComparison.OrdinalIgnoreCase) >= 0;
            foreach (Keywords.Kw k in hits)
                f.Add(k.Strong ? 50 : (mc ? 30 : 16), (k.Strong ? "Название из списка: «" : "Частое слово из списка: «") + k.Word + "»");
            if (jarSize) f.Add(35, "Размер " + len.ToString("N0") + " байт точно совпадает с чит-jar из сайз-листа");
            if (binSize) f.Add(30, "Размер " + len.ToString("N0") + " байт точно совпадает с чит-файлом из сайз-листа");
            if (tmplJar && JarTemplate(fi.FullName)) f.Add(60, "Шаблон из сайз-листа: jar с «l.png» и «mcmod.info» (21 КБ–10 МБ)");
            if (tmpl30 && Has30720Strings(fi.FullName)) f.Add(70, "Шаблон из сайз-листа: файл 30 720 байт со строками ClientPlayerEntity и AxisAlignedBB");
            if (f.Score == 0) return;
            if ((ext == ".exe" || ext == ".dll") && f.Score < 100)
            {
                try
                {
                    SigInfo s = Native.CheckSignature(fi.FullName);
                    if (s.Trusted) return; // подтверждён системой — не трогаем
                    f.Sig = s;
                }
                catch { }
            }
            Emit(f, true);
        }

        static bool JarTemplate(string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (ZipArchive za = new ZipArchive(fs, ZipArchiveMode.Read))
                    return za.GetEntry("l.png") != null && za.GetEntry("mcmod.info") != null;
            }
            catch { return false; }
        }

        static bool Has30720Strings(string path)
        {
            try
            {
                byte[] b = File.ReadAllBytes(path);
                string a = Encoding.ASCII.GetString(b);
                string u = Encoding.Unicode.GetString(b);
                bool c1 = a.Contains("ClientPlayerEntity") || u.Contains("ClientPlayerEntity");
                bool c2 = a.Contains("AxisAlignedBB") || u.Contains("AxisAlignedBB");
                return c1 && c2;
            }
            catch { return false; }
        }
    }
}
