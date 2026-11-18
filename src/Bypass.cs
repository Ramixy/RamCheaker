using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace InjectHunter
{
    /// <summary>Раздел «Обходы проверки»: следы того, что проверку пытались сломать или спрятать от неё следы —
    /// блокировка сайтов и программ, очистка журналов, отключённый Prefetch, удалённый USN-журнал и т.п.
    /// Только поиск, в системе ничего не меняется.</summary>
    class BypassScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public double Progress;
        public int Checks;
        DateTime boot = DateTime.MinValue;

        public void Run(CancellationToken ct)
        {
            try { boot = DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount & int.MaxValue); } catch { }
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))
                    foreach (ManagementObject o in s.Get()) boot = ManagementDateTimeConverter.ToDateTime((string)o["LastBootUpTime"]);
            }
            catch { }
            List<KeyValuePair<string, Action>> steps = new List<KeyValuePair<string, Action>> {
                Step("Файл hosts", Hosts),
                Step("Заблокированные сайты (зоны IE)", RestrictedZones),
                Step("Блокировка сайтов в браузерах", UrlBlocklist),
                Step("Запрет запуска программ (DisallowRun)", DisallowRun),
                Step("Подмена запуска программ (IFEO)", Ifeo),
                Step("taskkill в автозапуске и AutoRun CMD", TaskkillAutorun),
                Step("Ограничения групповой политики", Gpo),
                Step("Prefetch выключен или изменён", PrefetchParams),
                Step("Prefetch-файлы только для чтения", PrefetchReadOnly),
                Step("Служба SysMain", SysMain),
                Step("Фильтр FileInfo", FileInfoSvc),
                Step("USN-журнал", UsnJournal),
                Step("Очистка журналов событий", EventLogs),
                Step("Перевод системного времени", TimeChanges),
                Step("История WinRAR (стеганография)", WinRar),
                Step("История диалогов «Открыть/Сохранить»", NotFileMru),
                Step("Отключённые USB-устройства", UsbDisabled),
                Step("Скрытые страницы Параметров", SettingsVisibility),
                Step("Smart App Control (блок утилит)", SmartAppControl),
                Step("Заблокированные сертификаты", DisallowedCerts),
                Step("Невидимый текст в CMD", CmdColor),
            };
            for (int i = 0; i < steps.Count; i++)
            {
                if (ct.IsCancellationRequested) break;
                Current = steps[i].Key;
                try { steps[i].Value(); } catch { }
                Checks++;
                Progress = (i + 1.0) / steps.Count;
            }
        }

        static KeyValuePair<string, Action> Step(string n, Action a) { return new KeyValuePair<string, Action>(n, a); }

        void Report(string what, string path, int pts, string reason, params string[] notes)
        {
            Finding f = new Finding();
            f.Path = path; f.FileName = what; f.RealType = "ОБХОД · " + what; f.Source = "Обходы проверки";
            f.Origin = "—";
            f.Add(pts, reason);
            foreach (string n in notes) if (!string.IsNullOrEmpty(n)) f.Note(n);
            f.Finish();
            if (f.Severity > 0 && Found != null) Found(f);
        }

        static RegistryKey Open(RegistryHive hive, string path)
        {
            try { return RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(path); } catch { return null; }
        }

        static object Val(RegistryHive hive, string path, string name)
        {
            using (RegistryKey k = Open(hive, path)) { try { return k == null ? null : k.GetValue(name); } catch { return null; } }
        }

        static int? Int(RegistryHive hive, string path, string name)
        {
            object v = Val(hive, path, name);
            if (v is int) return (int)v;
            int r; if (v != null && int.TryParse(v.ToString(), out r)) return r;
            return null;
        }

        static readonly RegistryHive[] Both = { RegistryHive.CurrentUser, RegistryHive.LocalMachine };
        static string HiveName(RegistryHive h) { return h == RegistryHive.CurrentUser ? "HKCU" : "HKLM"; }

        static readonly string[] ssDomains = {
            "github", "githubusercontent", "discord", "telegram", "t.me", "virustotal", "nirsoft", "google", "microsoft", "windowsupdate",
            "modrinth", "curseforge", "anydesk", "teamviewer", "rustdesk", "spokwn", "echo.ac", "paladin", "avenge", "ocean", "sysinternals",
            "ericzimmerman", "hybrid-analysis", "any.run", "jotti", "mediafire", "mega.nz", "gofile", "dropbox", "pastebin", "youtube"
        };

        // ---------------- проверки ----------------
        void Hosts()
        {
            string p = Path.Combine(Analyzer.Sys32, "drivers\\etc\\hosts");
            if (!File.Exists(p)) return;
            List<string> bad = new List<string>(), other = new List<string>();
            foreach (string raw in File.ReadAllLines(p))
            {
                string l = raw.Trim();
                int c = l.IndexOf('#'); if (c >= 0) l = l.Substring(0, c).Trim();
                if (l.Length == 0) continue;
                string[] parts = Regex.Split(l, @"\s+");
                if (parts.Length < 2) continue;
                for (int i = 1; i < parts.Length; i++)
                {
                    string h = parts[i].ToLowerInvariant();
                    if (h == "localhost" || h.EndsWith(".localhost") || h == "localhost.localdomain") continue;
                    if (ssDomains.Any(d => h.Contains(d))) bad.Add(parts[0] + " → " + h); else other.Add(parts[0] + " → " + h);
                }
            }
            if (bad.Count > 0)
                Report("Файл hosts", p, 60, "В hosts заблокированы сайты, нужные для проверки: " + string.Join(", ", bad.Take(6)) + (bad.Count > 6 ? " и ещё " + (bad.Count - 6) : ""),
                       "Изменён: " + File.GetLastWriteTime(p).ToString("dd.MM.yyyy HH:mm"));
            else if (other.Count > 0)
                Report("Файл hosts", p, 15, "В hosts есть перенаправления: " + string.Join(", ", other.Take(6)) + (other.Count > 6 ? " и ещё " + (other.Count - 6) : "") + ". Часто это блокировка рекламы — проверь вручную.",
                       "Изменён: " + File.GetLastWriteTime(p).ToString("dd.MM.yyyy HH:mm"));
        }

        void RestrictedZones()
        {
            foreach (RegistryHive h in Both)
                foreach (string root in new string[] { "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains",
                                                       "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\EscDomains",
                                                       "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains" })
                    using (RegistryKey k = Open(h, root))
                    {
                        if (k == null) continue;
                        List<string> blocked = new List<string>();
                        Walk(k, "", blocked, 0);
                        if (blocked.Count > 0)
                            Report("Опасная зона IE", HiveName(h) + "\\" + root, blocked.Any(b => ssDomains.Any(d => b.Contains(d))) ? 55 : 30,
                                   "Сайты принудительно занесены в «Опасные» (зона 4) — их нельзя открыть или скачать с них: " + string.Join(", ", blocked.Take(8)));
                    }
        }

        static void Walk(RegistryKey k, string name, List<string> res, int depth)
        {
            try
            {
                foreach (string v in k.GetValueNames())
                {
                    object o = k.GetValue(v);
                    if (o is int && (int)o == 4) { res.Add(name.Length > 0 ? name : "?"); break; }
                }
                if (depth < 3)
                    foreach (string s in k.GetSubKeyNames())
                        using (RegistryKey c = k.OpenSubKey(s)) if (c != null) Walk(c, s + (name.Length > 0 ? "." + name : ""), res, depth + 1);
            }
            catch { }
        }

        void UrlBlocklist()
        {
            string[] browsers = { "Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave", "Vivaldi", "YandexBrowser", "Chromium" };
            foreach (RegistryHive h in Both)
                foreach (string b in browsers)
                    using (RegistryKey k = Open(h, "Software\\Policies\\" + b + "\\URLBlocklist"))
                    {
                        if (k == null) continue;
                        List<string> urls = new List<string>();
                        foreach (string v in k.GetValueNames()) { object o = k.GetValue(v); if (o != null) urls.Add(o.ToString()); }
                        if (urls.Count == 0) continue;
                        bool all = urls.Contains("*");
                        Report("Блокировка в браузере", HiveName(h) + "\\Software\\Policies\\" + b + "\\URLBlocklist", all || urls.Any(u => ssDomains.Any(d => u.Contains(d))) ? 55 : 30,
                               (all ? "Браузеру разрешены только сайты из белого списка" : "В браузере заблокированы сайты: " + string.Join(", ", urls.Take(8))) + " (" + b.Split('\\').Last() + ")");
                    }
        }

        void DisallowRun()
        {
            foreach (RegistryHive h in Both)
            {
                string p = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
                int? on = Int(h, p, "DisallowRun");
                List<string> list = new List<string>();
                using (RegistryKey k = Open(h, p + "\\DisallowRun"))
                    if (k != null) foreach (string v in k.GetValueNames()) { object o = k.GetValue(v); if (o != null) list.Add(o.ToString()); }
                if (on == 1 && list.Count > 0)
                    Report("Запрет запуска программ", HiveName(h) + "\\" + p + "\\DisallowRun", 60, "Windows запрещено запускать программы: " + string.Join(", ", list.Take(10)));
                else if (list.Count > 0)
                    Report("Запрет запуска программ", HiveName(h) + "\\" + p + "\\DisallowRun", 20, "Есть список запрещённых программ (сейчас выключен): " + string.Join(", ", list.Take(10)));
            }
        }

        void Ifeo()
        {
            string p = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
            using (RegistryKey k = Open(RegistryHive.LocalMachine, p))
            {
                if (k == null) { Report("IFEO", "HKLM\\" + p, 40, "Ключ Image File Execution Options не читается — права на него могли отобрать, чтобы скрыть подмену программ"); }
                else
                    foreach (string s in k.GetSubKeyNames())
                        using (RegistryKey c = k.OpenSubKey(s))
                        {
                            if (c == null) continue;
                            object dbg = c.GetValue("Debugger");
                            if (dbg != null && dbg.ToString().Trim().Length > 0)
                            {
                                string d = dbg.ToString();
                                bool legit = d.IndexOf("vsjitdebugger", StringComparison.OrdinalIgnoreCase) >= 0 || d.IndexOf("procexp", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                             d.IndexOf("systemsettings", StringComparison.OrdinalIgnoreCase) >= 0;
                                Report("Подмена запуска (IFEO)", "HKLM\\" + p + "\\" + s, legit ? 10 : 55,
                                       "При запуске «" + s + "» вместо неё открывается «" + d + "» — так ломают утилиты проверки");
                            }
                            object gf = c.GetValue("GlobalFlag");
                            if (gf is int && ((int)gf & 0x200) != 0)
                                Report("Подмена запуска (IFEO)", "HKLM\\" + p + "\\" + s, 40, "У «" + s + "» включён тихий выход (GlobalFlag 0x200) — программа может молча закрываться");
                        }
            }
            using (RegistryKey nt = Open(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"))
                if (nt != null)
                    foreach (string s in nt.GetSubKeyNames())
                        if (s.IndexOf("Image File Execution", StringComparison.OrdinalIgnoreCase) >= 0 && s != "Image File Execution Options")
                            Report("Копия ключа IFEO", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" + s, 45, "Найдена переименованная копия ключа IFEO «" + s + "» — так прячут подмену программ");
        }

        void TaskkillAutorun()
        {
            foreach (RegistryHive h in Both)
                foreach (string p in new string[] { "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" })
                    using (RegistryKey k = Open(h, p))
                    {
                        if (k == null) continue;
                        foreach (string v in k.GetValueNames())
                        {
                            string d = (k.GetValue(v) ?? "").ToString();
                            if (Regex.IsMatch(d, @"\b(taskkill|tskill)\b", RegexOptions.IgnoreCase))
                                Report("taskkill в автозапуске", HiveName(h) + "\\" + p + "\\" + v, 55, "При входе в Windows убиваются процессы: " + d);
                        }
                    }
            foreach (RegistryHive h in Both)
            {
                object ar = Val(h, "Software\\Microsoft\\Command Processor", "AutoRun");
                if (ar != null && ar.ToString().Trim().Length > 0)
                    Report("AutoRun в CMD", HiveName(h) + "\\Software\\Microsoft\\Command Processor", Regex.IsMatch(ar.ToString(), "taskkill|exit|cls|del ", RegexOptions.IgnoreCase) ? 55 : 25,
                           "При каждом открытии командной строки выполняется: " + ar);
            }
        }

        void Gpo()
        {
            var checks = new[] {
                new { P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", N = "DisableTaskMgr", T = "Диспетчер задач запрещён" },
                new { P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", N = "DisableRegistryTools", T = "Редактор реестра запрещён" },
                new { P = "Software\\Policies\\Microsoft\\Windows\\System", N = "DisableCMD", T = "Командная строка запрещена" },
                new { P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", N = "NoRun", T = "Окно «Выполнить» (Win+R) отключено" },
                new { P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", N = "NoControlPanel", T = "Панель управления запрещена" },
                new { P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", N = "NoFolderOptions", T = "Параметры папок скрыты (нельзя показать скрытые файлы)" },
                new { P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", N = "NoFind", T = "Поиск Windows отключён" },
                new { P = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", N = "NoDispCPL", T = "Настройки экрана запрещены" },
                new { P = "Software\\Policies\\Microsoft\\Windows\\PowerShell", N = "EnableScripts", T = "" },
            };
            foreach (RegistryHive h in Both)
                foreach (var c in checks)
                {
                    int? v = Int(h, c.P, c.N);
                    if (v == null) continue;
                    if (c.N == "EnableScripts") { if (v == 0) Report("Групповая политика", HiveName(h) + "\\" + c.P, 40, "Скрипты PowerShell полностью запрещены"); continue; }
                    if (v.Value != 0) Report("Групповая политика", HiveName(h) + "\\" + c.P + "\\" + c.N, 45, c.T + " (" + c.N + ")");
                }
            foreach (RegistryHive h in Both)
            {
                object ep = Val(h, "Software\\Policies\\Microsoft\\Windows\\PowerShell", "ExecutionPolicy");
                if (ep != null && (ep.ToString() == "Restricted" || ep.ToString() == "AllSigned"))
                    Report("Групповая политика", HiveName(h) + "\\Software\\Policies\\Microsoft\\Windows\\PowerShell", 30, "Политика PowerShell принудительно «" + ep + "» — скрипты проверки не запустятся");
            }
        }

        void PrefetchParams()
        {
            string p = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters";
            int? en = Int(RegistryHive.LocalMachine, p, "EnablePrefetcher");
            if (en != null && en.Value != 3)
                Report("Prefetch выключен", "HKLM\\" + p, en.Value == 0 ? 60 : 45,
                       "EnablePrefetcher = " + en + " (норма 3) — Windows " + (en.Value == 0 ? "вообще не записывает" : "не полностью записывает") + " историю запуска программ");
            DateTime lw = RegTime.LastWrite(RegistryHive.LocalMachine, p);
            if (lw > DateTime.MinValue && boot > DateTime.MinValue && lw > boot.AddSeconds(15))
                Report("Prefetch изменён", "HKLM\\" + p, 35, "Ключ PrefetchParameters менялся уже после включения ПК (" + lw.ToString("dd.MM.yyyy HH:mm:ss") + ", загрузка " + boot.ToString("HH:mm:ss") + ")");
        }

        void PrefetchReadOnly()
        {
            string d = Path.Combine(Analyzer.WinDir, "Prefetch");
            if (!Directory.Exists(d)) return;
            List<string> ro = new List<string>();
            int total = 0;
            try
            {
                foreach (string f in Directory.EnumerateFiles(d, "*.pf"))
                {
                    total++;
                    try { if ((File.GetAttributes(f) & FileAttributes.ReadOnly) != 0) ro.Add(Path.GetFileName(f)); } catch { }
                }
            }
            catch { return; }
            if (ro.Count > 0)
                Report("Prefetch только для чтения", d, 55, "Файлы Prefetch помечены «только чтение» — Windows не может обновить историю запуска: " + string.Join(", ", ro.Take(8)) + (ro.Count > 8 ? " и ещё " + (ro.Count - 8) : ""));
            else if (total == 0)
                Report("Prefetch пуст", d, 40, "Папка Prefetch пуста — история запуска программ удалена или не пишется");
        }

        void SysMain()
        {
            try
            {
                using (ServiceController sc = new ServiceController("SysMain"))
                {
                    if (sc.Status != ServiceControllerStatus.Running)
                        Report("Служба SysMain", "Служба SysMain", 45, "Служба SysMain не работает (" + sc.Status + ") — без неё Prefetch не записывается");
                }
            }
            catch { }
            int? st = Int(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Services\\SysMain", "Start");
            if (st == 4) Report("Служба SysMain", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysMain", 45, "Служба SysMain отключена (Start = 4)");
        }

        void FileInfoSvc()
        {
            int? st = Int(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Services\\FileInfo", "Start");
            if (st == 4) Report("Фильтр FileInfo", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\FileInfo", 45, "Драйвер FileInfo отключён — Prefetch и SuperFetch не видят запуски");
            try
            {
                EventLogQuery q = new EventLogQuery("System", PathType.LogName, "*[System[Provider[@Name='Microsoft-Windows-FilterManager'] and (EventID=1)]]");
                using (EventLogReader r = new EventLogReader(q))
                    for (EventRecord e = r.ReadEvent(); e != null; e = r.ReadEvent())
                        using (e)
                        {
                            string m = "";
                            try { m = e.FormatDescription() ?? ""; } catch { }
                            if (m.IndexOf("FileInfo", StringComparison.OrdinalIgnoreCase) >= 0 && e.TimeCreated > boot)
                                Report("Фильтр FileInfo", "Журнал System · FilterManager 1", 50, "Фильтр FileInfo выгружали в этом сеансе (" + e.TimeCreated.Value.ToString("dd.MM HH:mm:ss") + ")");
                        }
            }
            catch { }
        }

        void UsnJournal()
        {
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try { if (!d.IsReady || d.DriveType != DriveType.Fixed || d.DriveFormat != "NTFS") continue; } catch { continue; }
                string letter = d.Name.TrimEnd('\\');
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo("fsutil", "usn queryjournal " + letter);
                    psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; psi.CreateNoWindow = true;
                    using (Process p = Process.Start(psi))
                    {
                        string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit(10000);
                        if (p.ExitCode != 0 && Regex.IsMatch(o, "0x8007049[dD]|not active|не активен|не включ", RegexOptions.IgnoreCase))
                            Report("USN-журнал удалён", "Диск " + letter, 60, "USN-журнал на " + letter + " выключен или удалён — история изменений файлов стёрта");
                    }
                }
                catch { }
            }
            try
            {
                EventLogQuery q = new EventLogQuery("Microsoft-Windows-Ntfs/Operational", PathType.LogName, "*[System[(EventID=501)]]");
                using (EventLogReader r = new EventLogReader(q))
                    for (EventRecord e = r.ReadEvent(); e != null; e = r.ReadEvent())
                        using (e)
                        {
                            if (e.TimeCreated == null || e.TimeCreated < boot.AddMinutes(2)) continue;
                            Report("USN-журнал удалён", "Журнал Ntfs/Operational · 501", 55, "USN-журнал удаляли (" + e.TimeCreated.Value.ToString("dd.MM.yyyy HH:mm:ss") + ")");
                        }
            }
            catch { }
            EventsSince("Application", "*[System[(EventID=3079)]]", "Удаление USN-журнала", 55, "Событие удаления USN-журнала (3079)");
        }

        void EventsSince(string log, string xpath, string what, int pts, string text)
        {
            try
            {
                EventLogQuery q = new EventLogQuery(log, PathType.LogName, xpath);
                using (EventLogReader r = new EventLogReader(q))
                    for (EventRecord e = r.ReadEvent(); e != null; e = r.ReadEvent())
                        using (e)
                        {
                            if (e.TimeCreated == null || e.TimeCreated < boot) continue;
                            string m = "";
                            try { m = e.FormatDescription() ?? ""; } catch { }
                            Report(what, "Журнал " + log + " · " + e.Id, pts, text + " — " + e.TimeCreated.Value.ToString("dd.MM.yyyy HH:mm:ss"), m.Length > 300 ? m.Substring(0, 300) + "…" : m);
                        }
            }
            catch { }
        }

        void EventLogs()
        {
            EventsSince("Security", "*[System[(EventID=1102)]]", "Журнал очищен", 60, "Журнал безопасности очищали в этом сеансе");
            EventsSince("System", "*[System[(EventID=104)]]", "Журнал очищен", 55, "Журнал событий очищали в этом сеансе");
        }

        void TimeChanges()
        {
            try
            {
                EventLogQuery q = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4616)]]");
                using (EventLogReader r = new EventLogReader(q))
                    for (EventRecord e = r.ReadEvent(); e != null; e = r.ReadEvent())
                        using (e)
                        {
                            if (e.TimeCreated == null || e.TimeCreated < boot.AddMinutes(3)) continue;
                            DateTime a = DateTime.MinValue, b = DateTime.MinValue; string proc = "";
                            try
                            {
                                foreach (EventProperty p in e.Properties)
                                {
                                    if (p.Value is DateTime) { if (a == DateTime.MinValue) a = (DateTime)p.Value; else b = (DateTime)p.Value; }
                                    else if (p.Value is string && ((string)p.Value).EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) proc = (string)p.Value;
                                }
                            }
                            catch { }
                            if (a == DateTime.MinValue || b == DateTime.MinValue || Math.Abs((b - a).TotalSeconds) <= 30) continue;
                            if (proc.EndsWith("svchost.exe", StringComparison.OrdinalIgnoreCase)) continue;
                            Report("Перевод времени", "Журнал Security · 4616", 40, "Системное время переводили вручную: " + a.ToLocalTime().ToString("dd.MM HH:mm:ss") + " → " + b.ToLocalTime().ToString("dd.MM HH:mm:ss") +
                                   " — так путают даты в истории", proc.Length > 0 ? "Процесс: " + proc : null);
                        }
            }
            catch { }
        }

        void WinRar()
        {
            using (RegistryKey k = Open(RegistryHive.CurrentUser, "Software\\WinRAR\\ArcHistory"))
            {
                if (k == null) return;
                List<string> odd = new List<string>();
                foreach (string v in k.GetValueNames())
                {
                    string p = (k.GetValue(v) ?? "").ToString();
                    string ext = Path.GetExtension(p).ToLowerInvariant();
                    if (ext.Length > 0 && !Regex.IsMatch(ext, @"^\.(rar|zip|7z|tar|gz|tgz|bz2|xz|cab|iso|jar|r\d\d|\d\d\d|z\d\d|arj|lzh|uue|zipx)$")) odd.Add(p);
                }
                if (odd.Count > 0)
                    Report("WinRAR открывал не архив", "HKCU\\Software\\WinRAR\\ArcHistory", 40, "WinRAR открывал файлы, которые не являются архивами — так прячут чит внутри картинки или другого файла: " + string.Join(", ", odd.Take(6)));
            }
        }

        void NotFileMru()
        {
            foreach (string p in new string[] { "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ComDlg32", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32" })
                foreach (RegistryHive h in Both)
                {
                    if (Int(h, p, "NoFileMru") == 1 || Int(h, p, "NotFileMru") == 1)
                        Report("История «Открыть/Сохранить» отключена", HiveName(h) + "\\" + p, 45, "Windows не запоминает файлы, открытые через окно «Открыть/Сохранить» (NoFileMru)");
                }
        }

        void UsbDisabled()
        {
            foreach (string root in new string[] { "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "SYSTEM\\CurrentControlSet\\Enum\\USB" })
                using (RegistryKey k = Open(RegistryHive.LocalMachine, root))
                {
                    if (k == null) continue;
                    foreach (string dev in k.GetSubKeyNames())
                        using (RegistryKey d = k.OpenSubKey(dev))
                        {
                            if (d == null) continue;
                            foreach (string inst in d.GetSubKeyNames())
                                using (RegistryKey i = d.OpenSubKey(inst))
                                {
                                    object cf = i == null ? null : i.GetValue("ConfigFlags");
                                    if (cf is int && ((int)cf & 1) != 0)
                                    {
                                        string name = (i.GetValue("FriendlyName") ?? i.GetValue("DeviceDesc") ?? dev).ToString();
                                        if (name.Contains(";")) name = name.Substring(name.LastIndexOf(';') + 1);
                                        Report("Отключённое USB-устройство", "HKLM\\" + root + "\\" + dev, root.EndsWith("USBSTOR") ? 35 : 15,
                                               "Устройство «" + name + "» вручную отключено — отключённую флешку не видно в списках устройств");
                                    }
                                }
                        }
                }
        }

        void SettingsVisibility()
        {
            foreach (RegistryHive h in Both)
            {
                object v = Val(h, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "SettingsPageVisibility");
                if (v != null && v.ToString().Length > 0)
                    Report("Скрытые страницы Параметров", HiveName(h) + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 30, "Часть страниц «Параметров Windows» скрыта: " + v);
            }
        }

        void SmartAppControl()
        {
            int? sac = Int(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", "VerifiedAndReputablePolicyState");
            if (sac == 1) Report("Smart App Control", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", 15, "Smart App Control включён — он может не дать запустить утилиты проверки");
            object aic = Val(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", "AicEnabled");
            if (aic != null && aic.ToString().IndexOf("StoreOnly", StringComparison.OrdinalIgnoreCase) >= 0)
                Report("Только приложения из Store", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", 40, "Windows разрешает ставить программы только из Microsoft Store — утилиты проверки не запустятся");
        }

        void DisallowedCerts()
        {
            string[] who = { "github", "nir sofer", "nirsoft", "discord", "telegram", "virustotal", "eric zimmerman", "anydesk", "spokwn" };
            foreach (StoreLocation loc in new StoreLocation[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
                try
                {
                    X509Store st = new X509Store("Disallowed", loc);
                    st.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    foreach (X509Certificate2 c in st.Certificates)
                    {
                        string s = c.Subject.ToLowerInvariant();
                        string w = who.FirstOrDefault(x => s.Contains(x));
                        if (w != null)
                            Report("Заблокированный сертификат", "Хранилище Disallowed (" + loc + ")", 55, "Сертификат «" + c.GetNameInfo(X509NameType.SimpleName, false) + "» внесён в недоверенные — сайты или программы этой компании перестанут работать",
                                   "Отпечаток: " + c.Thumbprint);
                    }
                    st.Close();
                }
                catch { }
        }

        void CmdColor()
        {
            int? c = Int(RegistryHive.CurrentUser, "Software\\Microsoft\\Command Processor", "DefaultColor");
            if (c != null && c.Value != 0 && ((c.Value >> 4) & 0xF) == (c.Value & 0xF))
                Report("Невидимый текст в CMD", "HKCU\\Software\\Microsoft\\Command Processor", 40, "Цвет текста в командной строке совпадает с фоном — вывод команд не видно");
            using (RegistryKey k = Open(RegistryHive.CurrentUser, "Console"))
                if (k != null)
                {
                    object a = k.GetValue("ScreenColors");
                    if (a is int && (int)a != 0 && (((int)a >> 4) & 0xF) == ((int)a & 0xF))
                        Report("Невидимый текст в консоли", "HKCU\\Console", 40, "Цвет текста консоли совпадает с фоном — вывод команд не видно");
                }
        }
    }

    static class RegTime
    {
        [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int options, int sam, out UIntPtr result);
        [System.Runtime.InteropServices.DllImport("advapi32.dll")]
        static extern int RegQueryInfoKey(UIntPtr hKey, IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, out long lastWrite);
        [System.Runtime.InteropServices.DllImport("advapi32.dll")]
        static extern int RegCloseKey(UIntPtr hKey);

        public static DateTime LastWrite(RegistryHive hive, string path)
        {
            UIntPtr root = hive == RegistryHive.LocalMachine ? new UIntPtr(0x80000002u) : new UIntPtr(0x80000001u);
            UIntPtr k;
            if (RegOpenKeyEx(root, path, 0, 0x20019 | 0x0100, out k) != 0) return DateTime.MinValue;
            try
            {
                long ft;
                if (RegQueryInfoKey(k, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft) != 0) return DateTime.MinValue;
                return DateTime.FromFileTime(ft);
            }
            finally { RegCloseKey(k); }
        }
    }
}
