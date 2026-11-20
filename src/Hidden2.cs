using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace InjectHunter
{
    /// <summary>Скрытые места, которые смотрят AlternateStreamView и LoadedDllsView:
    /// программы/JAR в альтернативных потоках NTFS и подозрительные DLL в любых процессах.</summary>
    class HiddenExtraScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public int Files, Streams, Modules;
        public double Progress;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_STREAM_DATA { public long Size; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string Name; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstStreamW(string f, int lvl, out WIN32_FIND_STREAM_DATA d, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool FindNextStreamW(IntPtr h, out WIN32_FIND_STREAM_DATA d);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFile(string n, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t);

        static readonly string[] benign = { "zone.identifier", "smartscreen", "com.dropbox", "oecustomproperty", "encryptable", "ms-properties", "afp_afpinfo", "afp_resource",
            "win32app_1", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}", "favicon", "kaspersky", "$cmdtcid", "cachedtiles", "com.apple", "sync", "thumbs", "wofcompresseddata", "appxblockmap" };

        public void Run(CancellationToken ct)
        {
            Current = "Скрытые потоки NTFS";
            List<string> roots = new List<string>();
            string users = Path.Combine(Path.GetPathRoot(Analyzer.WinDir), "Users");
            try
            {
                foreach (string u in Directory.GetDirectories(users))
                {
                    string n = Path.GetFileName(u).ToLowerInvariant();
                    if (n == "default" || n == "default user" || n == "all users") continue;
                    roots.Add(u);
                }
            }
            catch { }
            roots.Add(Path.Combine(Path.GetPathRoot(Analyzer.WinDir), "ProgramData"));
            for (int i = 0; i < roots.Count && !ct.IsCancellationRequested; i++)
            {
                WalkStreams(roots[i], ct);
                Progress = 0.8 * (i + 1) / roots.Count;
            }
            if (!ct.IsCancellationRequested) AllModules(ct);
            Progress = 1;
        }

        void WalkStreams(string root, CancellationToken ct)
        {
            Stack<KeyValuePair<string, int>> st = new Stack<KeyValuePair<string, int>>();
            st.Push(new KeyValuePair<string, int>(root, 0));
            while (st.Count > 0 && !ct.IsCancellationRequested)
            {
                KeyValuePair<string, int> cur = st.Pop();
                string l = cur.Key.ToLowerInvariant();
                if (l.EndsWith("\\node_modules") || l.EndsWith("\\.git") || l.Contains("\\windowsapps")) continue;
                CheckStreams(cur.Key, true);
                try
                {
                    foreach (string d in Directory.EnumerateDirectories(cur.Key))
                    {
                        FileAttributes a;
                        try { a = File.GetAttributes(d); } catch { continue; }
                        if ((a & FileAttributes.ReparsePoint) == 0 && cur.Value < 14) st.Push(new KeyValuePair<string, int>(d, cur.Value + 1));
                    }
                }
                catch { }
                try
                {
                    foreach (string f in Directory.EnumerateFiles(cur.Key))
                    {
                        Files++;
                        if ((Files & 2047) == 0) Current = "Скрытые потоки NTFS · " + Files.ToString("N0") + " · " + f;
                        CheckStreams(f, false);
                    }
                }
                catch { }
            }
        }

        void CheckStreams(string path, bool dir)
        {
            WIN32_FIND_STREAM_DATA d;
            IntPtr h = FindFirstStreamW(path, 0, out d, 0);
            if (h == new IntPtr(-1)) return;
            try
            {
                do
                {
                    string n = d.Name ?? "";
                    if (n == "::$DATA") continue;
                    Streams++;
                    string sn = n.Trim(':').Replace(":$DATA", "");
                    string ln = sn.ToLowerInvariant();
                    if (benign.Any(b => ln.StartsWith(b))) continue;
                    Inspect(path, sn, d.Size, dir);
                }
                while (FindNextStreamW(h, out d));
            }
            finally { FindClose(h); }
        }

        void Inspect(string path, string stream, long size, bool dir)
        {
            byte[] head = new byte[64]; int got = 0;
            try
            {
                using (SafeFileHandle fh = CreateFile(path + ":" + stream, 0x80000000, 7, IntPtr.Zero, 3, dir ? 0x02000000u : 0u, IntPtr.Zero))
                {
                    if (!fh.IsInvalid) using (FileStream fs = new FileStream(fh, FileAccess.Read)) got = fs.Read(head, 0, head.Length);
                }
            }
            catch { }
            string magic = Analyzer.DescribeMagic(head, got);
            bool exec = magic == "PE" || magic == "ZIP/JAR" || magic == "Java class" || magic == "ELF";
            if (!exec && size < 512 * 1024 && Keywords.Match(stream).All(k => !k.Strong)) return;
            Finding f = new Finding();
            f.Path = path + ":" + stream; f.FileName = Path.GetFileName(path) + ":" + stream; f.Source = "Скрытые потоки NTFS";
            f.RealType = "ADS · " + (exec ? magic : "данные") + " · " + DetailsView.FormatSize(size);
            f.Size = size;
            try { f.Modified = File.GetLastWriteTime(path); } catch { }
            if (exec) f.Add(75, "Внутри " + (dir ? "папки" : "файла «" + Path.GetFileName(path) + "»") + " в скрытом потоке «" + stream + "» спрятан " + (magic == "PE" ? "исполняемый файл (EXE/DLL)" : magic == "ELF" ? "исполняемый файл" : "JAR/Java-код") + " — проводник и поиск его не видят");
            else if (size >= 512 * 1024) f.Add(20, "Скрытый поток «" + stream + "» размером " + DetailsView.FormatSize(size) + " — обычно в потоках хранят только мелкие служебные метки");
            foreach (Keywords.Kw k in Keywords.Match(stream).Where(k => k.Strong)) f.Add(40, "Имя потока содержит слово из списка «" + k.Word + "»");
            f.Note("Посмотреть можно в AlternateStreamView (Инструменты) или командой: more < \"" + path + ":" + stream + "\"");
            f.Origin = "Альтернативный поток NTFS (ADS)";
            f.Finish();
            if (f.Severity > 0 && Found != null) Found(f);
        }

        // ---------- DLL во всех процессах (как LoadedDllsView) ----------
        void AllModules(CancellationToken ct)
        {
            Dictionary<string, List<string>> mods = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            Process[] ps = Process.GetProcesses();
            int self = Process.GetCurrentProcess().Id;
            for (int i = 0; i < ps.Length && !ct.IsCancellationRequested; i++)
            {
                Process p = ps[i];
                if (p.Id == self) continue;
                Progress = 0.8 + 0.15 * i / Math.Max(1, ps.Length);
                Current = "DLL во всех процессах · " + p.ProcessName;
                try
                {
                    foreach (ProcessModule m in p.Modules)
                    {
                        string f = m.FileName;
                        if (string.IsNullOrEmpty(f)) continue;
                        Modules++;
                        List<string> l;
                        if (!mods.TryGetValue(f, out l)) mods[f] = l = new List<string>();
                        if (!l.Contains(p.ProcessName)) l.Add(p.ProcessName);
                    }
                }
                catch { }
                finally { try { p.Dispose(); } catch { } }
            }
            foreach (KeyValuePair<string, List<string>> kv in mods)
            {
                if (ct.IsCancellationRequested) return;
                string f = kv.Key, l = f.ToLowerInvariant();
                if (Analyzer.WinDir != null && l.StartsWith(Analyzer.WinDir.ToLowerInvariant() + "\\") && !l.Contains("\\temp\\")) continue;
                bool userPlace = l.Contains("\\downloads\\") || l.Contains("\\desktop\\") || l.Contains("\\$recycle.bin\\") || l.Contains("\\users\\public\\");
                List<Keywords.Kw> kws = Keywords.Match(Path.GetFileName(f)).Where(k => k.Strong).ToList();
                if (!userPlace && kws.Count == 0) continue;
                if (l.EndsWith(".exe") && !userPlace && kws.Count == 0) continue;
                SigInfo sig = null;
                try { sig = Native.CheckSignature(f); } catch { }
                if (sig != null && sig.Trusted) continue;
                Finding fd = new Finding();
                fd.Path = f; fd.FileName = Path.GetFileName(f); fd.Source = "DLL во всех процессах"; fd.Sig = sig;
                fd.RealType = (l.EndsWith(".exe") ? "EXE" : "DLL") + " · загружена в " + string.Join(", ", kv.Value.Take(4));
                try { FileInfo fi = new FileInfo(f); fd.Size = fi.Length; fd.Modified = fi.LastWriteTime; fd.Created = fi.CreationTime; } catch { }
                foreach (Keywords.Kw k in kws) fd.Add(60, "Модуль со словом из списка «" + k.Word + "» загружен в процесс " + string.Join(", ", kv.Value.Take(4)));
                if (userPlace) fd.Add(30, "Неподписанная библиотека прямо из Загрузок/Рабочего стола загружена в " + string.Join(", ", kv.Value.Take(4)) + " — так работают инжекторы");
                if (kv.Value.Any(x => x.Equals("javaw", StringComparison.OrdinalIgnoreCase) || x.Equals("java", StringComparison.OrdinalIgnoreCase))) fd.Add(20, "Загружена в Minecraft (javaw)");
                fd.Finish();
                if (fd.Severity > 0 && Found != null) Found(fd);
            }
        }
    }
}
