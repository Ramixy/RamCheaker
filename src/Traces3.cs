using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace InjectHunter
{
    /// <summary>BAM Parser, ExecutedProgramsList, LastActivityView, RecentFilesView, RegScanner — их логика внутри чекера.</summary>
    partial class TraceScanner
    {
        class ExecInfo { public string Path; public DateTime Last; public List<string> Sources = new List<string>(); }
        Dictionary<string, ExecInfo> execs = new Dictionary<string, ExecInfo>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Запись о запуске программы без слов из списка — копим, потом проверяем файл (как BAM Parser).</summary>
        void Executed(string source, string path, DateTime t)
        {
            ExecInfo e;
            if (!execs.TryGetValue(path, out e)) execs[path] = e = new ExecInfo { Path = path };
            string src = source.Split(' ')[0];
            if (!e.Sources.Contains(src)) e.Sources.Add(src);
            if (t > e.Last) e.Last = t;
        }

        static string Place(string l)
        {
            if (l.Contains("\\downloads\\") || l.Contains("\\загрузки\\")) return "Загрузок";
            if (l.Contains("\\desktop\\")) return "Рабочего стола";
            if (l.Contains("\\documents\\")) return "Документов";
            if (l.Contains("\\$recycle.bin\\")) return "Корзины";
            if (l.Contains("\\users\\public\\")) return "общей папки Public";
            if (Regex.IsMatch(l, @"^[a-z]:\\[^\\]+\.exe$")) return "корня диска";
            return null;
        }

        void EmitExecuted()
        {
            foreach (ExecInfo e in execs.Values)
            {
                string l = e.Path.ToLowerInvariant();
                string place = Place(l);
                if (place == null) continue;
                string fn = SafeName(e.Path).ToLowerInvariant();
                if (fn.StartsWith("ramixycheaker") || fn.StartsWith("ramcheaker") || (Analyzer.SelfPath != null && e.Path.Equals(Analyzer.SelfPath, StringComparison.OrdinalIgnoreCase))) continue;
                bool exists = false;
                try { exists = File.Exists(e.Path); } catch { }
                SigInfo sig = null;
                if (exists) { try { sig = Native.CheckSignature(e.Path); } catch { } if (sig == null || sig.Trusted) continue; }
                if (!reported.Add("exec|" + e.Path)) continue;
                Finding f = new Finding();
                f.Path = e.Path; f.FileName = SafeName(e.Path); f.Source = "Запущенные программы"; f.Sig = sig;
                f.RealType = "EXE · " + (exists ? "без подписи" : "удалён") + " · " + string.Join(", ", e.Sources);
                f.Modified = e.Last;
                if (!exists) f.Add(15, "Запускалась из " + place + " и уже удалена — проверь, что это было (имя, время)");
                else f.Add(15, "Неподписанная программа запускалась из " + place + " — проверь, что это");
                f.Note("Где видно запуск: " + string.Join(", ", e.Sources));
                if (e.Last.Year > 2000) f.Note("Последний запуск: " + e.Last.ToString("dd.MM.yyyy HH:mm:ss"));
                if (exists) { try { FileInfo fi = new FileInfo(e.Path); f.Size = fi.Length; f.Created = fi.CreationTime; } catch { } }
                f.Finish();
                if (f.Severity > 0 && Found != null) Found(f);
            }
        }

        // ---------- ExecutedProgramsList: режимы совместимости ----------
        void Layers()
        {
            foreach (RegistryKey hive in new RegistryKey[] { Registry.CurrentUser, Registry.LocalMachine })
                using (RegistryKey k = hive.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"))
                {
                    if (k == null) continue;
                    foreach (string v in k.GetValueNames()) Check("Layers", "APC", v, null, DateTime.MinValue, true, "Режим совместимости: " + k.GetValue(v));
                }
        }

        // ---------- RecentFilesView: куда ведут ярлыки ----------
        static List<string> LnkTargets(string lnk)
        {
            List<string> res = new List<string>();
            byte[] b = ReadShared(lnk, 1024 * 1024);
            if (b == null) return res;
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string s in Utf16Strings(b, 4)) foreach (string p in Paths(s)) if (seen.Add(p)) res.Add(p);
            foreach (Match m in Regex.Matches(Encoding.Default.GetString(b), @"[A-Za-z]:\\[^\x00-\x1F""<>|]{2,259}"))
                if (seen.Add(m.Value)) res.Add(m.Value);
            return res;
        }

        // ---------- LastActivityView: события Windows ----------
        void EventLogs()
        {
            DateTime since = DateTime.Now.AddDays(-60);
            string ts = since.ToUniversalTime().ToString("o");
            // падения программ: javaw упал на чужом модуле — частый след инжекта
            Query("Application", "*[System[(EventID=1000 or EventID=1001 or EventID=1026) and TimeCreated[@SystemTime>='" + ts + "']]]", 3000, (e, d) =>
            {
                Check("События: падения программ", "EVT", d, null, e.TimeCreated ?? DateTime.MinValue, true, "Событие " + e.Id + " в журнале Application");
                if (e.Id != 1000) return;
                List<string> props = e.Properties.Select(p => Convert.ToString(p.Value)).ToList();
                string app = props.Count > 0 ? props[0] : "", module = props.Count > 3 ? props[3] : "";
                string modPath = props.FirstOrDefault(x => x.Length > 3 && x[1] == ':' && x.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !x.Equals(props.ElementAtOrDefault(10) ?? "", StringComparison.Ordinal)) ?? "";
                if (!app.StartsWith("java", StringComparison.OrdinalIgnoreCase)) return;
                string ml = (modPath.Length > 0 ? modPath : module).ToLowerInvariant();
                bool foreign = module.Length > 0 && !ml.Contains("\\windows\\") && !ml.Contains("\\java") && !ml.Contains("\\jre") && !ml.Contains("\\runtime\\") && !Regex.IsMatch(module, @"^(jvm|java|awt|net|nio|zip|ntdll|kernelbase|ucrtbase|vcruntime|msvcp|lwjgl|opengl|glfw|openal|nvoglv|atio|ig[0-9a-z]+|amd|nv|jna|jemalloc|libsodium)", RegexOptions.IgnoreCase);
                if (!foreign || !reported.Add("crash|" + module)) return;
                Finding f = new Finding();
                f.Path = modPath.Length > 0 ? modPath : module; f.FileName = module; f.Source = "События: падения программ";
                f.RealType = "EVT · падение " + app; f.Modified = e.TimeCreated ?? DateTime.MinValue;
                f.Add(25, "Minecraft (" + app + ") упал на постороннем модуле «" + module + "» — так бывает, когда в javaw внедряют DLL");
                f.Origin = d.Length > 1200 ? d.Substring(0, 1200) : d;
                f.Finish();
                if (Found != null) Found(f);
            });
            // установки программ (MsiInstaller)
            Query("Application", "*[System[Provider[@Name='MsiInstaller'] and (EventID=11707 or EventID=1033 or EventID=11724 or EventID=1034) and TimeCreated[@SystemTime>='" + ts + "']]]", 2000, (e, d) =>
                Check("События: установка программ", "EVT", d, null, e.TimeCreated ?? DateTime.MinValue, false, (e.Id == 11724 || e.Id == 1034 ? "Удаление" : "Установка") + " программы (журнал Application)"));
            // включения/выключения и сон — для сверки со временем проверки
            int boots = 0;
            Query("System", "*[System[(EventID=6005 or EventID=6006 or EventID=42 or EventID=1) and TimeCreated[@SystemTime>='" + DateTime.Now.AddDays(-2).ToUniversalTime().ToString("o") + "']]]", 200, (e, d) => { boots++; Entries++; });
        }

        void Query(string log, string xpath, int max, Action<EventRecord, string> on)
        {
            try
            {
                EventLogQuery q = new EventLogQuery(log, PathType.LogName, xpath); q.ReverseDirection = true;
                using (EventLogReader r = new EventLogReader(q))
                {
                    EventRecord e; int n = 0;
                    while (n++ < max && (e = r.ReadEvent()) != null)
                        using (e)
                        {
                            string d = null;
                            try { d = e.FormatDescription(); } catch { }
                            if (string.IsNullOrEmpty(d)) d = string.Join(" | ", e.Properties.Select(p => Convert.ToString(p.Value)));
                            try { on(e, d); } catch { }
                        }
                }
            }
            catch { }
        }

        // ---------- RegScanner: значения реестра ----------
        int regValues;
        void RegistryValues()
        {
            regValues = 0;
            ScanValues(Registry.CurrentUser, "Software", 5);
            ScanValues(Registry.CurrentUser, @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", 1);
            ScanValues(Registry.LocalMachine, "SOFTWARE", 4);
            ScanValues(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services", 2);
        }

        void ScanValues(RegistryKey hive, string path, int depth)
        {
            if (regValues > 3000000) return;
            RegistryKey k = null;
            try { k = hive.OpenSubKey(path); } catch { }
            if (k == null) return;
            using (k)
            {
                string[] names = new string[0];
                try { names = k.GetValueNames(); } catch { }
                foreach (string v in names)
                {
                    regValues++;
                    object o = null;
                    try { o = k.GetValue(v, null, RegistryValueOptions.DoNotExpandEnvironmentNames); } catch { }
                    string data = o as string ?? (o is string[] ? string.Join(" ", (string[])o) : null);
                    string text = (v + " " + (data ?? "")).Trim();
                    if (text.Length < 3 || Keywords.Match(text).All(kw => !kw.Strong)) continue;
                    Check("Реестр: значения", "REGV", hive.Name + "\\" + path + " → " + (v.Length == 0 ? "(по умолчанию)" : v) + (data != null ? " = " + (data.Length > 200 ? data.Substring(0, 200) : data) : ""), null, DateTime.MinValue, false, "Значение реестра");
                }
                if ((regValues & 0x3FFF) == 0) Current = "Реестр: значения · " + regValues.ToString("N0") + " · " + path;
                if (depth <= 0) return;
                string[] subs = new string[0];
                try { subs = k.GetSubKeyNames(); } catch { }
                foreach (string s in subs)
                {
                    string ls = s.ToLowerInvariant();
                    if (path == "SOFTWARE" && (ls == "classes" || ls == "wow6432node")) continue;
                    if (ls == "classes" && path == "Software") { ScanValues(hive, path + "\\" + s, 2); continue; }
                    ScanValues(hive, path + "\\" + s, depth - 1);
                }
            }
        }
    }
}
