using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace InjectHunter
{
    /// <summary>Следы запуска и скачивания: Prefetch, BAM, UserAssist, MuiCache, AppCompat, недавние файлы,
    /// загрузки, папки лаунчеров и выгрузка NirSoft-утилит. Всё сверяется со списком слов.</summary>
    class TraceScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public double Progress;
        public int Entries, Sources;
        HashSet<string> reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public void Run(bool useNirsoft, CancellationToken ct)
        {
            List<KeyValuePair<string, Action>> steps = new List<KeyValuePair<string, Action>>();
            steps.Add(Step("Prefetch", Prefetch));
            steps.Add(Step("BAM (реестр)", Bam));
            steps.Add(Step("UserAssist (реестр)", UserAssist));
            steps.Add(Step("MuiCache (реестр)", MuiCache));
            steps.Add(Step("AppCompat Store (реестр)", AppCompat));
            steps.Add(Step("Недавние файлы", Recent));
            steps.Add(Step("Загрузки и рабочий стол", Downloads));
            steps.Add(Step("Папки лаунчеров Minecraft", Launchers));
            if (useNirsoft)
                foreach (ToolInfo t in Tools.All.Where(x => x.NirArgs != null))
                {
                    ToolInfo tt = t;
                    steps.Add(Step("NirSoft: " + t.Title, () => Nirsoft(tt)));
                }
            for (int i = 0; i < steps.Count; i++)
            {
                if (ct.IsCancellationRequested) break;
                Current = steps[i].Key;
                try { steps[i].Value(); Sources++; } catch { }
                Progress = (i + 1.0) / steps.Count;
            }
        }

        static KeyValuePair<string, Action> Step(string n, Action a) { return new KeyValuePair<string, Action>(n, a); }

        // ---------- проверка одной записи ----------
        void Check(string source, string badge, string text, string shortName, DateTime time, bool executed, string extra)
        {
            Entries++;
            if (string.IsNullOrEmpty(text)) return;
            List<Keywords.Kw> hits = Keywords.Match((badge == "MC" || badge == "DL") && !string.IsNullOrEmpty(shortName) ? shortName : text);
            bool deletedExe = false;
            if (executed && text.Length > 3 && text[1] == ':' && text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                string l = text.ToLowerInvariant();
                bool userPlace = l.Contains("\\downloads\\") || l.Contains("\\desktop\\") || l.Contains("\\temp\\") || l.Contains("\\appdata\\") || l.Contains("\\$recycle.bin\\");
                try { deletedExe = userPlace && !File.Exists(text); } catch { }
            }
            // частые слова — только в записях о запуске программ и только в имени exe/jar/prefetch
            string nameOnly = SafeName(string.IsNullOrEmpty(shortName) ? text : shortName).ToLowerInvariant();
            bool fileLike = nameOnly.EndsWith(".exe") || nameOnly.EndsWith(".jar") || nameOnly.EndsWith(".zip") || nameOnly.EndsWith(".rar") || badge == "PF";
            hits = hits.Where(k => k.Strong || (executed && fileLike)).ToList();
            if (hits.Count == 0) return;
            // программа подтверждена системой (подписана) — не трогаем
            if (text.Length > 3 && text[1] == ':' && (text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || text.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
            {
                try { if (File.Exists(text) && Native.CheckSignature(text).Trusted) return; } catch { }
            }
            string key = source + "|" + text;
            if (!reported.Add(key)) return;

            Finding f = new Finding();
            f.Path = text;
            f.FileName = string.IsNullOrEmpty(shortName) ? SafeName(text) : shortName;
            f.RealType = badge + " · " + source;
            f.Source = source;
            f.Modified = time;
            foreach (Keywords.Kw k in hits)
            {
                if (k.Strong) f.Add(executed ? 65 : 45, "Слово «" + k.Word + "» из списка" + (executed ? " — программа ЗАПУСКАЛАСЬ" : ""));
                else f.Add(executed ? 20 : 16, "Частое слово «" + k.Word + "» из списка — проверь вручную");
            }
            if (deletedExe) f.Add(15, "Файла уже нет на диске — удалён после запуска");
            if (time.Year > 1990) f.Note("Время: " + time.ToString("dd.MM.yyyy HH:mm:ss"));
            if (!string.IsNullOrEmpty(extra)) f.Note(extra);
            f.Finish();
            if (f.Severity > 0 && Found != null) Found(f);
        }

        static string SafeName(string t)
        {
            try
            {
                string s = t.TrimEnd('\\', '/');
                int i = Math.Max(s.LastIndexOf('\\'), s.LastIndexOf('/'));
                return i >= 0 ? s.Substring(i + 1) : s;
            }
            catch { return t; }
        }

        // ---------- источники ----------
        void Prefetch()
        {
            string dir = Path.Combine(Analyzer.WinDir, "Prefetch");
            foreach (string f in Directory.GetFiles(dir, "*.pf"))
            {
                string n = Path.GetFileNameWithoutExtension(f);
                int dash = n.LastIndexOf('-');
                if (dash > 0) n = n.Substring(0, dash);
                Check("Prefetch", "PF", n, n, File.GetLastWriteTime(f), true, "Последний запуск ≈ время изменения .pf");
            }
        }

        void Bam()
        {
            foreach (string root in new string[] { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", @"SYSTEM\CurrentControlSet\Services\bam\UserSettings" })
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(root))
                {
                    if (k == null) continue;
                    foreach (string sid in k.GetSubKeyNames())
                        using (RegistryKey u = k.OpenSubKey(sid))
                        {
                            if (u == null) continue;
                            foreach (string v in u.GetValueNames())
                            {
                                if (!v.StartsWith("\\")) continue;
                                DateTime t = DateTime.MinValue;
                                byte[] b = u.GetValue(v) as byte[];
                                if (b != null && b.Length >= 8) try { t = DateTime.FromFileTime(BitConverter.ToInt64(b, 0)); } catch { }
                                Check("BAM", "BAM", Native.DevicePathToDos(v), null, t, true, null);
                            }
                        }
                }
            }
        }

        static string Rot13(string s)
        {
            StringBuilder sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
                else if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
                else sb.Append(c);
            }
            return sb.ToString();
        }

        void UserAssist()
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"))
            {
                if (k == null) return;
                foreach (string g in k.GetSubKeyNames())
                    using (RegistryKey c = k.OpenSubKey(g + "\\Count"))
                    {
                        if (c == null) continue;
                        foreach (string v in c.GetValueNames())
                        {
                            string name = Rot13(v);
                            DateTime t = DateTime.MinValue;
                            byte[] b = c.GetValue(v) as byte[];
                            if (b != null && b.Length >= 68) try { long ft = BitConverter.ToInt64(b, 60); if (ft > 0) t = DateTime.FromFileTime(ft); } catch { }
                            Check("UserAssist", "UA", ExpandKnownFolder(name), null, t, true, null);
                        }
                    }
            }
        }

        static string ExpandKnownFolder(string s)
        {
            // {GUID}\path -> путь (основные known folders)
            Dictionary<string, Environment.SpecialFolder> m = new Dictionary<string, Environment.SpecialFolder>(StringComparer.OrdinalIgnoreCase) {
                { "{6D809377-6AF0-444B-8957-A3773F02200E}", Environment.SpecialFolder.ProgramFiles },
                { "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", Environment.SpecialFolder.ProgramFilesX86 },
                { "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", Environment.SpecialFolder.System },
                { "{F38BF404-1D43-42F2-9305-67DE0B28FC23}", Environment.SpecialFolder.Windows },
            };
            foreach (KeyValuePair<string, Environment.SpecialFolder> kv in m)
                if (s.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
                    return Environment.GetFolderPath(kv.Value) + s.Substring(kv.Key.Length);
            return s;
        }

        void MuiCache()
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"))
            {
                if (k == null) return;
                foreach (string v in k.GetValueNames())
                {
                    string p = v;
                    int dot = p.LastIndexOf(".FriendlyAppName", StringComparison.OrdinalIgnoreCase);
                    if (dot < 0) dot = p.LastIndexOf(".ApplicationCompany", StringComparison.OrdinalIgnoreCase);
                    if (dot > 0) p = p.Substring(0, dot);
                    object desc = k.GetValue(v);
                    Check("MuiCache", "MUI", p, null, DateTime.MinValue, true, desc != null ? "Описание: " + desc : null);
                }
            }
        }

        void AppCompat()
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"))
            {
                if (k == null) return;
                foreach (string v in k.GetValueNames()) Check("AppCompat Store", "APC", v, null, DateTime.MinValue, true, null);
            }
        }

        void Recent()
        {
            string dir = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            foreach (string f in Directory.GetFiles(dir, "*.lnk"))
            {
                string n = Path.GetFileNameWithoutExtension(f);
                Check("Недавние файлы", "LNK", n, n, File.GetLastWriteTime(f), false, "Ярлык: " + f);
            }
        }

        void Downloads()
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            foreach (string d in new string[] { Path.Combine(home, "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.Desktop) })
                Walk(d, 3, 20000, "Загрузки/Рабочий стол", "DL");
        }

        void Launchers()
        {
            string ad = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] dirs = {
                Path.Combine(ad, ".minecraft"), Path.Combine(ad, ".tlauncher"), Path.Combine(ad, ".feather"), Path.Combine(ad, "PrismLauncher"),
                Path.Combine(ad, "PolyMC"), Path.Combine(ad, "MultiMC"), Path.Combine(ad, "ATLauncher"), Path.Combine(ad, "CurseForge"),
                Path.Combine(ad, ".lunarclient"), Path.Combine(home, ".lunarclient"), Path.Combine(ad, "ModrinthApp"), Path.Combine(ad, "com.modrinth.theseus"),
                Path.Combine(ad, "Badlion Client"), Path.Combine(la, "Packages"), Path.Combine(ad, "GDLauncher"), Path.Combine(ad, ".minecraft_tlauncher")
            };
            foreach (string d in dirs)
                if (Directory.Exists(d) && !d.EndsWith("Packages")) Walk(d, 6, 60000, "Лаунчер Minecraft", "MC");
        }

        void Walk(string root, int maxDepth, int limit, string source, string badge)
        {
            if (!Directory.Exists(root)) return;
            Stack<KeyValuePair<string, int>> st = new Stack<KeyValuePair<string, int>>();
            st.Push(new KeyValuePair<string, int>(root, 0));
            int n = 0;
            while (st.Count > 0 && n < limit)
            {
                KeyValuePair<string, int> cur = st.Pop();
                string[] files = new string[0], dirs = new string[0];
                try { files = Directory.GetFiles(cur.Key); } catch { }
                try { dirs = Directory.GetDirectories(cur.Key); } catch { }
                foreach (string f in files)
                {
                    n++;
                    string ext = Path.GetExtension(f).ToLowerInvariant();
                    if (ext == ".png" || ext == ".ogg" || ext == ".json" && !f.Contains("versions") || ext == ".nbt" || ext == ".mca" || ext == ".dat" || ext == ".log" || ext == ".gz") continue;
                    DateTime t = DateTime.MinValue;
                    try { t = File.GetLastWriteTime(f); } catch { }
                    Check(source, badge, f, Path.GetFileName(f), t, false, null);
                }
                if (cur.Value < maxDepth)
                    foreach (string d in dirs)
                    {
                        string dn = Path.GetFileName(d).ToLowerInvariant();
                        if (dn == "assets" || dn == "saves" || dn == "resourcepacks" || dn == "screenshots" || dn == "logs" || dn == "crash-reports" || dn == "shaderpacks") continue;
                        Check(source, badge, d, Path.GetFileName(d), DateTime.MinValue, false, "Папка");
                        st.Push(new KeyValuePair<string, int>(d, cur.Value + 1));
                    }
            }
        }

        void Nirsoft(ToolInfo t)
        {
            List<string[]> rows = Tools.RunNirsoft(t, 90000);
            if (rows.Count == 0) return;
            foreach (string[] r in rows)
            {
                string joined = string.Join(" | ", r.Where(x => !string.IsNullOrEmpty(x)));
                string first = r.Length > 0 ? r[0] : joined;
                string path = r.FirstOrDefault(x => x.Length > 3 && x[1] == ':' && x[2] == '\\') ?? first;
                DateTime time = DateTime.MinValue;
                foreach (string x in r)
                {
                    DateTime d;
                    if (x.Length >= 10 && x.Length <= 25 && DateTime.TryParse(x, out d) && d.Year > 2000) { time = d; break; }
                }
                Entries++;
                List<Keywords.Kw> hits = Keywords.Match(joined);
                if (hits.Count == 0) continue;
                string text = Keywords.Match(path).Count > 0 ? path : joined;
                Check("NirSoft " + t.Title, "NS", text, SafeName(first), time, t.Title.Contains("Prefetch") || t.Title.Contains("Executed") || t.Title.Contains("Activity"), "Строка выгрузки: " + (joined.Length > 400 ? joined.Substring(0, 400) + "…" : joined));
                Entries--;
            }
        }
    }
}
