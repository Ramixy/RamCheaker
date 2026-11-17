using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace InjectHunter
{
    /// <summary>База legit-читов: автокликеры, макро-программы, ghost-клиенты.</summary>
    static class LegitDb
    {
        public enum Kind { Clicker, Macro, Ghost, MouseSoft }
        public class Entry { public string Token, Label; public Kind Kind; public int Weight; }
        public static readonly List<Entry> All = new List<Entry>();

        static void A(Kind k, int w, string label, params string[] toks)
        {
            foreach (string t in toks) { Entry e = new Entry(); e.Token = Norm(t); e.Label = label; e.Kind = k; e.Weight = w; All.Add(e); }
        }

        static LegitDb()
        {
            A(Kind.Clicker, 60, "Автокликер", "autoclicker", "auto clicker", "autoclick", "op auto clicker", "gs auto clicker", "speed autoclicker",
                "fastclicker", "fast clicker", "clickermann", "murgee", "auto mouse click", "automouseclick", "mouse clicker", "jitterclick",
                "jitter click", "butterflyclick", "butterfly click", "dragclick", "drag click", "rapidclick", "cps booster", "cpsbooster",
                "clickcrystal", "ghostclicker", "legitclicker", "clicker.exe", "clickerx", "auto-clicker", "auto_clicker", "autoclickextreme",
                "mineclicker", "zenithclicker", "zenith clicker", "kuroclicker", "clickz");
            A(Kind.Macro, 45, "Программа макросов", "tinytask", "pulover", "macro creator", "jitbit", "macro recorder", "macrorecorder",
                "mini mouse macro", "minimousemacro", "macro toolworks", "perfect automation", "xmousebuttoncontrol", "x-mouse button control", "xmbc");
            A(Kind.Macro, 30, "AutoHotkey", "autohotkey", "autohotkeyu64", "autohotkeyu32", "autohotkeya32");
            A(Kind.Ghost, 70, "Ghost-клиент", "vapelite", "vape lite", "vape v4", "vapev4", "vapeclient", "driplite", "drip lite", "dripclient",
                "entropyclient", "koidclient", "whiteoutclient", "slinkyclient", "itamiclient", "ravenbplus", "raven b+", "doomsday", "cortexclient",
                "ghostclient", "ghost client", "legitclient", "injectclient");
            A(Kind.MouseSoft, 30, "ПО мыши с макросами (Bloody/Oscar)", "bloody7", "bloody6", "bloody5", "bloodyx", "bloody mouse", "oscar editor",
                "oscareditor", "x7 oscar", "a4tech", "redragon");
        }

        public static string Norm(string s)
        {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder(s.Length);
            foreach (char c in s.ToLowerInvariant()) if (c != ' ' && c != '_' && c != '-') sb.Append(c);
            return sb.ToString();
        }

        public static List<Entry> Match(string text)
        {
            string n = Norm(text);
            List<Entry> res = new List<Entry>();
            if (n.Length == 0 || Keywords.IsSsTool(text)) return res;
            HashSet<string> labels = new HashSet<string>();
            foreach (Entry e in All)
                if (n.Contains(e.Token) && labels.Add(e.Label + e.Kind)) res.Add(e);
            return res;
        }
    }

    /// <summary>Общие помощники: процессы через WMI, установленные программы, автозапуск.</summary>
    static class SysInfo
    {
        public class Proc { public int Pid; public string Name, Path, CommandLine, Title; }
        public class App { public string Name, Publisher, Version, Location, Date, Key; }

        public static List<Proc> Processes()
        {
            Dictionary<int, Proc> d = new Dictionary<int, Proc>();
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process"))
                    foreach (ManagementObject o in s.Get())
                    {
                        Proc p = new Proc();
                        p.Pid = Convert.ToInt32(o["ProcessId"]);
                        p.Name = o["Name"] as string ?? "";
                        p.Path = o["ExecutablePath"] as string;
                        p.CommandLine = o["CommandLine"] as string;
                        d[p.Pid] = p;
                    }
            }
            catch { }
            try
            {
                foreach (Process pr in Process.GetProcesses())
                {
                    Proc p;
                    if (!d.TryGetValue(pr.Id, out p)) { p = new Proc(); p.Pid = pr.Id; p.Name = pr.ProcessName + ".exe"; d[pr.Id] = p; }
                    try { string t = pr.MainWindowTitle; if (!string.IsNullOrEmpty(t)) p.Title = t; } catch { }
                }
            }
            catch { }
            return d.Values.Where(x => x.Pid > 4).ToList();
        }

        public static List<App> Installed()
        {
            List<App> res = new List<App>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            RegistryKey[] roots = { Registry.LocalMachine, Registry.CurrentUser };
            string[] paths = { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" };
            foreach (RegistryKey root in roots)
                foreach (string p in paths)
                    using (RegistryKey k = root.OpenSubKey(p))
                    {
                        if (k == null) continue;
                        foreach (string sub in k.GetSubKeyNames())
                            using (RegistryKey a = k.OpenSubKey(sub))
                            {
                                if (a == null) continue;
                                string name = a.GetValue("DisplayName") as string;
                                if (string.IsNullOrEmpty(name)) continue;
                                if (a.GetValue("SystemComponent") is int && (int)a.GetValue("SystemComponent") == 1) continue;
                                if (!seen.Add(name + "|" + (a.GetValue("DisplayVersion") as string))) continue;
                                App app = new App();
                                app.Name = name;
                                app.Publisher = a.GetValue("Publisher") as string;
                                app.Version = a.GetValue("DisplayVersion") as string;
                                app.Location = a.GetValue("InstallLocation") as string;
                                app.Date = a.GetValue("InstallDate") as string;
                                app.Key = sub;
                                if (string.IsNullOrEmpty(app.Location))
                                {
                                    string icon = a.GetValue("DisplayIcon") as string;
                                    if (!string.IsNullOrEmpty(icon)) app.Location = icon.Split(',')[0].Trim('"');
                                }
                                res.Add(app);
                            }
                    }
            return res;
        }

        public static List<KeyValuePair<string, string>> Autoruns()
        {
            List<KeyValuePair<string, string>> res = new List<KeyValuePair<string, string>>();
            RegistryKey[] roots = { Registry.CurrentUser, Registry.LocalMachine };
            string[] paths = { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" };
            foreach (RegistryKey root in roots)
                foreach (string p in paths)
                    using (RegistryKey k = root.OpenSubKey(p))
                    {
                        if (k == null) continue;
                        foreach (string v in k.GetValueNames())
                            res.Add(new KeyValuePair<string, string>(v, Convert.ToString(k.GetValue(v))));
                    }
            foreach (string dir in new string[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
                try { foreach (string f in Directory.GetFiles(dir)) res.Add(new KeyValuePair<string, string>(Path.GetFileName(f), f)); } catch { }
            return res;
        }

        public static string ExeFromCommand(string cmd)
        {
            if (string.IsNullOrEmpty(cmd)) return null;
            cmd = Environment.ExpandEnvironmentVariables(cmd.Trim());
            if (cmd.StartsWith("\"")) { int e = cmd.IndexOf('"', 1); return e > 1 ? cmd.Substring(1, e - 1) : null; }
            int x = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return x > 0 ? cmd.Substring(0, x + 4) : cmd.Split(' ')[0];
        }
    }

    /// <summary>Раздел «Программы»: весь список запущенных, установленных и автозапуска — с поиском и флагами.</summary>
    class ProgramScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public double Progress;
        public int Count;

        public void Run(CancellationToken ct)
        {
            Current = "Запущенные процессы";
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (SysInfo.Proc p in SysInfo.Processes())
            {
                if (ct.IsCancellationRequested) return;
                string key = p.Path ?? p.Name;
                if (!seen.Add(key + "|" + p.Title)) continue;
                Finding f = New(p.Name, p.Path ?? p.Name, "PRC · Процесс · PID " + p.Pid, "Процессы");
                if (!string.IsNullOrEmpty(p.Title)) f.Note("Окно: «" + p.Title + "»");
                if (!string.IsNullOrEmpty(p.CommandLine) && p.CommandLine.Length < 600) f.Note("Команда: " + p.CommandLine);
                Rate(f, p.Name + " " + p.Path + " " + p.Title, p.Path, true);
                Emit(f);
            }
            Progress = 0.4;
            Current = "Установленные программы";
            foreach (SysInfo.App a in SysInfo.Installed())
            {
                if (ct.IsCancellationRequested) return;
                Finding f = New(a.Name, string.IsNullOrEmpty(a.Location) ? a.Name : a.Location, "APP · Установлено" + (a.Version != null ? " · " + a.Version : ""), "Установленные");
                if (!string.IsNullOrEmpty(a.Publisher)) f.Note("Издатель: " + a.Publisher);
                DateTime d;
                if (a.Date != null && DateTime.TryParseExact(a.Date, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out d)) f.Modified = d;
                Rate(f, a.Name + " " + a.Location, null, false);
                Emit(f);
            }
            Progress = 0.8;
            Current = "Автозапуск";
            foreach (KeyValuePair<string, string> r in SysInfo.Autoruns())
            {
                string exe = SysInfo.ExeFromCommand(r.Value);
                Finding f = New(r.Key, r.Value, "RUN · Автозапуск", "Автозапуск");
                Rate(f, r.Key + " " + r.Value, exe, false);
                Emit(f);
            }
            Progress = 1;
        }

        static Finding New(string name, string path, string type, string source)
        {
            Finding f = new Finding();
            f.FileName = name; f.Path = path ?? name; f.RealType = type; f.Source = source;
            return f;
        }

        /// <summary>Оценка программы: слова из списка + база legit-читов. Подписанные файлы не трогаем.</summary>
        public static void Rate(Finding f, string text, string exePath, bool running)
        {
            List<Keywords.Kw> kws = Keywords.Match(text).Where(k => k.Strong).ToList();
            List<LegitDb.Entry> legit = LegitDb.Match(text);
            if (kws.Count == 0 && legit.Count == 0) return;
            if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
            {
                SigInfo sig = Native.CheckSignature(exePath);
                f.Sig = sig;
                if (sig.Trusted) { f.Note(sig + " — подтверждён системой, не считается подозрительным"); return; }
            }
            foreach (Keywords.Kw k in kws) f.Add(running ? 60 : 45, "Слово «" + k.Word + "» из списка" + (running ? " — запущено сейчас" : ""));
            foreach (LegitDb.Entry e in legit) f.Add(running ? e.Weight + 15 : e.Weight, e.Label + " («" + e.Token + "»)" + (running ? " — запущено сейчас" : ""));
        }

        void Emit(Finding f) { f.Finish(); Count++; if (Found != null) Found(f); }
    }

    /// <summary>Раздел «Legit-читы»: автокликеры, макросы, ПО мышек, Java-агенты в javaw, скрипты AHK и G HUB.</summary>
    class LegitScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public double Progress;
        public int Checked;
        HashSet<string> reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        static readonly string[] safeAgents = { "authlib-injector", "authlibinjector", "lunar", "feather", "badlion", "labymod", "jacoco", "idea_rt",
            "yourkit", "jprofiler", "theseus", "modrinth", "essential", "tlauncher", "legacylauncher", "mixin" };

        public void Run(CancellationToken ct)
        {
            Step(0.10, "Процессы и окна", Processes);
            if (ct.IsCancellationRequested) return;
            Step(0.25, "Аргументы javaw", JavaArgs);
            Step(0.40, "Установленные программы", Installed);
            Step(0.55, "История запусков (Prefetch, BAM)", History);
            if (ct.IsCancellationRequested) return;
            Step(0.75, "Файлы в папках пользователя", () => Files(ct));
            Step(0.90, "Скрипты макросов (AutoHotkey, Logitech)", Scripts);
            Progress = 1;
        }

        void Step(double p, string name, Action a)
        {
            Current = name;
            try { a(); } catch { }
            Progress = p;
        }

        void Emit(Finding f)
        {
            if (!reported.Add(f.Source + "|" + f.Path)) return;
            f.Finish();
            if (f.Severity > 0 && Found != null) Found(f);
        }

        void Processes()
        {
            foreach (SysInfo.Proc p in SysInfo.Processes())
            {
                Checked++;
                Finding f = new Finding();
                f.FileName = p.Name; f.Path = p.Path ?? p.Name; f.RealType = "PRC · Запущен · PID " + p.Pid; f.Source = "Процессы";
                if (!string.IsNullOrEmpty(p.Title)) f.Note("Окно: «" + p.Title + "»");
                ProgramScanner.Rate(f, p.Name + " " + p.Path + " " + p.Title, p.Path, true);
                Emit(f);
            }
        }

        void JavaArgs()
        {
            foreach (SysInfo.Proc p in SysInfo.Processes())
            {
                string n = (p.Name ?? "").ToLowerInvariant();
                if (n != "javaw.exe" && n != "java.exe" || string.IsNullOrEmpty(p.CommandLine)) continue;
                Checked++;
                string cmd = p.CommandLine;
                foreach (Match m in Regex.Matches(cmd, "-(javaagent|agentpath|agentlib):(\"[^\"]+\"|\\S+)", RegexOptions.IgnoreCase))
                {
                    string kind = m.Groups[1].Value.ToLowerInvariant();
                    string val = m.Groups[2].Value.Trim('"');
                    string file = val.Split('=')[0];
                    if (kind == "agentlib" && file.StartsWith("jdwp")) { Add(p, "Java запущен с отладчиком (-agentlib:jdwp) — к игре можно подключаться извне", 25, file); continue; }
                    string lf = file.ToLowerInvariant();
                    bool safe = safeAgents.Any(s => lf.Contains(s));
                    if (safe) continue;
                    int w = kind == "javaagent" ? 55 : 65;
                    string what = kind == "javaagent" ? "Java-агент (-javaagent)" : "нативный агент (-" + kind + ")";
                    Finding f = Add(p, "javaw запущен с " + what + ": " + file + " — так подгружаются legit/инжект-читы", w, file);
                    try
                    {
                        if (File.Exists(file))
                        {
                            Finding deep = Analyzer.AnalyzeFile(new FileInfo(file), new ScanOptions(), true);
                            if (deep != null) foreach (string r in deep.Reasons) f.Reasons.Add(r);
                            if (deep != null) f.Score += deep.Score;
                        }
                        else f.Add(15, "Файла агента уже нет на диске");
                    }
                    catch { }
                    Emit(f);
                }
                if (Regex.IsMatch(cmd, @"-Xbootclasspath/[ap]:", RegexOptions.IgnoreCase))
                    Emit(Add(p, "javaw запущен с -Xbootclasspath — подмена системных классов Java", 35, null));
            }
        }

        Finding Add(SysInfo.Proc p, string reason, int w, string file)
        {
            Finding f = new Finding();
            f.FileName = file != null ? Path.GetFileName(file) : p.Name;
            f.Path = file ?? (p.Path ?? p.Name);
            f.RealType = "AGT · Аргументы javaw · PID " + p.Pid; f.Source = "javaw";
            f.Add(w, reason);
            f.Note("Команда: " + (p.CommandLine.Length > 500 ? p.CommandLine.Substring(0, 500) + "…" : p.CommandLine));
            return f;
        }

        void Installed()
        {
            foreach (SysInfo.App a in SysInfo.Installed())
            {
                Checked++;
                List<LegitDb.Entry> hits = LegitDb.Match(a.Name);
                if (hits.Count == 0) continue;
                Finding f = new Finding();
                f.FileName = a.Name; f.Path = string.IsNullOrEmpty(a.Location) ? a.Name : a.Location; f.RealType = "APP · Установлено"; f.Source = "Установленные";
                foreach (LegitDb.Entry e in hits) f.Add(e.Weight - 10, e.Label + " установлен(а) («" + e.Token + "»)");
                if (!string.IsNullOrEmpty(a.Publisher)) f.Note("Издатель: " + a.Publisher);
                Emit(f);
            }
        }

        void History()
        {
            string pf = Path.Combine(Analyzer.WinDir, "Prefetch");
            try
            {
                foreach (string f in Directory.GetFiles(pf, "*.pf"))
                {
                    Checked++;
                    string n = Path.GetFileNameWithoutExtension(f);
                    int dash = n.LastIndexOf('-'); if (dash > 0) n = n.Substring(0, dash);
                    HistoryHit("Prefetch", n, n, File.GetLastWriteTime(f));
                }
            }
            catch { }
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"))
                    if (k != null)
                        foreach (string sid in k.GetSubKeyNames())
                            using (RegistryKey u = k.OpenSubKey(sid))
                                if (u != null)
                                    foreach (string v in u.GetValueNames())
                                    {
                                        if (!v.StartsWith("\\")) continue;
                                        Checked++;
                                        DateTime t = DateTime.MinValue;
                                        byte[] b = u.GetValue(v) as byte[];
                                        if (b != null && b.Length >= 8) try { t = DateTime.FromFileTime(BitConverter.ToInt64(b, 0)); } catch { }
                                        string path = Native.DevicePathToDos(v);
                                        HistoryHit("BAM", Path.GetFileName(path), path, t);
                                    }
            }
            catch { }
        }

        void HistoryHit(string src, string name, string path, DateTime t)
        {
            List<LegitDb.Entry> hits = LegitDb.Match(name);
            if (hits.Count == 0) return;
            if (path.Length > 3 && path[1] == ':' && File.Exists(path)) { try { if (Native.CheckSignature(path).Trusted) return; } catch { } }
            Finding f = new Finding();
            f.FileName = name; f.Path = path; f.RealType = (src == "BAM" ? "BAM" : "PF") + " · " + src; f.Source = src; f.Modified = t;
            foreach (LegitDb.Entry e in hits) f.Add(e.Weight, e.Label + " запускался («" + e.Token + "»)");
            if (t.Year > 1990) f.Note("Последний запуск: " + t.ToString("dd.MM.yyyy HH:mm:ss"));
            if (path.Length > 3 && path[1] == ':' && !File.Exists(path)) f.Add(10, "Файла уже нет — удалён после запуска");
            Emit(f);
        }

        void Files(CancellationToken ct)
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[][] roots = {
                new string[] { Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "4" },
                new string[] { Path.Combine(home, "Downloads"), "4" },
                new string[] { Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "3" },
                new string[] { Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "3" },
                new string[] { Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "2" },
                new string[] { Path.GetTempPath(), "2" },
                new string[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "1" },
                new string[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "1" },
            };
            foreach (string[] r in roots)
            {
                if (ct.IsCancellationRequested) return;
                Walk(r[0], int.Parse(r[1]), ct);
            }
        }

        void Walk(string root, int maxDepth, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return;
            Stack<KeyValuePair<string, int>> st = new Stack<KeyValuePair<string, int>>();
            st.Push(new KeyValuePair<string, int>(root, 0));
            int n = 0;
            while (st.Count > 0 && n < 80000 && !ct.IsCancellationRequested)
            {
                KeyValuePair<string, int> cur = st.Pop();
                string[] files = new string[0], dirs = new string[0];
                try { files = Directory.GetFiles(cur.Key); } catch { }
                try { dirs = Directory.GetDirectories(cur.Key); } catch { }
                foreach (string f in files)
                {
                    n++; Checked++;
                    string ext = Path.GetExtension(f).ToLowerInvariant();
                    if (ext == ".ahk") { CheckAhk(f); continue; }
                    if (ext != ".exe" && ext != ".jar" && ext != ".zip" && ext != ".rar" && ext != ".7z" && ext != ".lnk" && ext != ".bat") continue;
                    string name = Path.GetFileName(f);
                    List<LegitDb.Entry> hits = LegitDb.Match(name);
                    if (hits.Count == 0) continue;
                    if (ext == ".exe") { try { if (Native.CheckSignature(f).Trusted) continue; } catch { } }
                    Finding fd = new Finding();
                    fd.FileName = name; fd.Path = f; fd.RealType = ext.TrimStart('.').ToUpperInvariant() + " · Файл"; fd.Source = "Файлы";
                    try { FileInfo fi = new FileInfo(f); fd.Size = fi.Length; fd.Modified = fi.LastWriteTime; fd.Created = fi.CreationTime; } catch { }
                    foreach (LegitDb.Entry e in hits) fd.Add(e.Weight - 5, e.Label + " — файл на диске («" + e.Token + "»)");
                    Emit(fd);
                }
                foreach (string d in dirs)
                {
                    string dn = Path.GetFileName(d);
                    List<LegitDb.Entry> hits = LegitDb.Match(dn);
                    if (hits.Count > 0 && hits.Any(h => h.Kind != LegitDb.Kind.Macro || h.Weight >= 45))
                    {
                        Finding fd = new Finding();
                        fd.FileName = dn; fd.Path = d; fd.RealType = "DIR · Папка"; fd.Source = "Файлы";
                        foreach (LegitDb.Entry e in hits) fd.Add(e.Weight - 15, e.Label + " — папка («" + e.Token + "»)");
                        Emit(fd);
                    }
                    if (cur.Value < maxDepth)
                    {
                        string l = dn.ToLowerInvariant();
                        if (l == "node_modules" || l == "cache" || l == ".git" || l == "assets" || l == "packages" || l.StartsWith("microsoft") || l == "google" || l == "mozilla") continue;
                        st.Push(new KeyValuePair<string, int>(d, cur.Value + 1));
                    }
                }
            }
        }

        static readonly Regex rxAhkClick = new Regex(@"\b(Click|MouseClick|SendInput\s*\{?\s*(L|R)Button|Send\s*\{?\s*(L|R)Button|ControlClick)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex rxAhkLoop = new Regex(@"\b(Loop|SetTimer|While)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        void CheckAhk(string f)
        {
            string text;
            try { if (new FileInfo(f).Length > 2 * 1024 * 1024) return; text = File.ReadAllText(f); } catch { return; }
            bool click = rxAhkClick.IsMatch(text), loop = rxAhkLoop.IsMatch(text);
            if (!click) return;
            Finding fd = new Finding();
            fd.FileName = Path.GetFileName(f); fd.Path = f; fd.RealType = "AHK · Скрипт AutoHotkey"; fd.Source = "Скрипты";
            try { FileInfo fi = new FileInfo(f); fd.Size = fi.Length; fd.Modified = fi.LastWriteTime; } catch { }
            if (loop) fd.Add(60, "Скрипт AutoHotkey с повторяющимися кликами мыши (цикл/таймер + Click) — автокликер");
            else fd.Add(30, "Скрипт AutoHotkey, который нажимает кнопки мыши");
            if (Regex.IsMatch(text, @"Random\s*,", RegexOptions.IgnoreCase)) fd.Add(10, "Случайные задержки между кликами — маскировка под человека (jitter)");
            if (text.IndexOf("javaw", StringComparison.OrdinalIgnoreCase) >= 0 || text.IndexOf("Minecraft", StringComparison.OrdinalIgnoreCase) >= 0)
                fd.Add(15, "Скрипт привязан к окну Minecraft/javaw");
            Emit(fd);
        }

        void Scripts()
        {
            string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            // Logitech G HUB: скрипты хранятся в settings.db
            foreach (string db in new string[] { Path.Combine(la, "LGHUB", "settings.db"), Path.Combine(la, "LGHUB", "settings.json") })
                CheckLuaBlob(db, "Logitech G HUB");
            // Старое Logitech Gaming Software: профили xml
            string lgs = Path.Combine(la, "Logitech", "Logitech Gaming Software", "profiles");
            try { if (Directory.Exists(lgs)) foreach (string f in Directory.GetFiles(lgs, "*.xml")) CheckLuaBlob(f, "Logitech Gaming Software"); } catch { }
        }

        void CheckLuaBlob(string path, string product)
        {
            if (!File.Exists(path)) return;
            Checked++;
            string text;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length > 200L * 1024 * 1024) return;
                    byte[] b = new byte[fs.Length]; int got = 0;
                    while (got < b.Length) { int r = fs.Read(b, got, b.Length - got); if (r <= 0) break; got += r; }
                    text = Encoding.UTF8.GetString(b, 0, got);
                }
            }
            catch { return; }
            bool press = text.Contains("PressMouseButton") || text.Contains("PressAndReleaseMouseButton");
            bool loop = Regex.IsMatch(text, @"\b(while|repeat|for)\b") && text.Contains("Sleep");
            if (!press) return;
            Finding fd = new Finding();
            fd.FileName = product + " — Lua-макрос"; fd.Path = path; fd.RealType = "LUA · Макрос мыши"; fd.Source = "Скрипты";
            fd.Add(loop ? 60 : 30, loop ? "В " + product + " есть Lua-скрипт с циклическим нажатием кнопок мыши — автокликер/джиттер"
                                         : "В " + product + " есть Lua-скрипт, нажимающий кнопки мыши");
            if (text.Contains("IsMouseButtonPressed")) fd.Add(10, "Срабатывает при зажатой кнопке мыши (типично для кликер-макросов)");
            Emit(fd);
        }
    }
}
