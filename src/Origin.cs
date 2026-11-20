using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace InjectHunter
{
    /// <summary>Откуда файл появился на ПК. Браузеры, Telegram, Discord и почта ставят метку Mark-of-the-Web
    /// (поток Zone.Identifier) — в ней адрес страницы и прямая ссылка скачивания.</summary>
    static class Origin
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);

        public class Info
        {
            public string Zone, Referrer, Host, App, Domain;
            public string Text;
        }

        /// <summary>Слова, по которым узнаём сайты читов в домене. Плюс весь список ключевых слов.</summary>
        static readonly string[] siteWords = {
            "doomsday", "cortexclient", "cortexcheat", "vapeclient", "novoware", "nursultan", "wexside", "celka", "neverhook", "deadcode", "akrien",
            "rusherhack", "thunderhack", "moonhack", "nightware", "liquidbounce", "wurstclient", "meteorclient", "aristois", "impactclient",
            "futureclient", "konasclient", "bleachhack", "argonclient", "dlclient", "systemclient",
            "wildclient", "richclient", "fuzeclient", "hachclient", "exloader", "troxill", "extazyy", "arbuzclient", "winstonclient",
            "debuda", "hackclient", "injector", "ghostclient", "autoclicker", "cheatclient", "spoofer"
        };
        /// <summary>Короткие и общие слова — только отдельной частью домена (cortex.com, my-hack.net), не подстрокой.</summary>
        static readonly string[] genericWords = {
            "cortex", "vape", "wurst", "cheat", "cheats", "hack", "hacks", "clicker", "bypass", "crack", "cracked", "leak", "leaks", "nulled", "skid", "inject", "cheating"
        };

        static readonly string[] fileHosts = {
            "mediafire.com", "mega.nz", "mega.io", "gofile.io", "anonfiles", "dropbox.com", "dropboxusercontent.com", "drive.google.com",
            "drive.usercontent.google.com", "cdn.discordapp.com", "media.discordapp.net", "t.me", "telegram", "yadi.sk",
            "disk.yandex", "workupload.com", "pixeldrain.com", "catbox.moe", "sendspace.com", "files.fm", "uploadhaven.com",
            "krakenfiles.com", "qiwi.gg", "buzzheavier.com", "transfer.sh", "wetransfer.com", "1drv.ms", "onedrive.live.com",
            "github.com", "githubusercontent.com", "gitlab.com", "anonymfile", "upload.ee", "fex.net"
        };

        /// <summary>Сайты, где слово из списка — обычное дело (поисковики, видео, магазины).</summary>
        static readonly string[] neutralHosts = {
            "google.", "youtube.", "yandex.ru", "ya.ru", "bing.com", "duckduckgo", "wikipedia.org", "microsoft.com", "live.com", "msn.com",
            "apple.com", "amazon.", "steampowered", "twitch.tv", "vk.com", "ok.ru", "mail.ru", "gstatic", "googleapis", "cloudflare"
        };

        public const string NoMark = "Нет метки скачивания: файл создан на этом ПК, скопирован с флешки, распакован архиватором или метку стёрли.";

        public static Info Read(string path)
        {
            string text = null;
            try
            {
                using (SafeFileHandle h = CreateFile(path + ":Zone.Identifier", 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid) return null;
                    using (FileStream fs = new FileStream(h, FileAccess.Read))
                    {
                        byte[] b = new byte[Math.Min(fs.Length, 16384)];
                        int n = fs.Read(b, 0, b.Length);
                        text = Encoding.UTF8.GetString(b, 0, n);
                    }
                }
            }
            catch { return null; }
            if (text == null) return null;
            Info i = new Info();
            foreach (string raw in text.Split('\n'))
            {
                string l = raw.Trim(); int e = l.IndexOf('=');
                if (e < 0) continue;
                string k = l.Substring(0, e), v = l.Substring(e + 1).Trim('\0', ' ', '\r', '\t');
                if (k == "ZoneId") i.Zone = v; else if (k == "ReferrerUrl") i.Referrer = v;
                else if (k == "HostUrl") i.Host = v; else if (k == "LastWriterPackageFamilyName") i.App = v;
            }
            if (i.Host == "about:internet") i.Host = null;
            i.Domain = HostOf(i.Host) ?? HostOf(i.Referrer);
            StringBuilder sb = new StringBuilder();
            sb.Append(i.Domain != null ? "Сайт: " + i.Domain : "Зона: " + ZoneName(i.Zone));
            if (!string.IsNullOrEmpty(i.Referrer)) sb.Append("\nСтраница: " + Cut(i.Referrer));
            if (!string.IsNullOrEmpty(i.Host)) sb.Append("\nСсылка: " + Cut(i.Host));
            if (!string.IsNullOrEmpty(i.App)) sb.Append("\nПриложение: " + AppName(i.App));
            if (i.Domain == null) sb.Append("\nАдрес не сохранён (инкогнито, мессенджер или его стёрли)");
            i.Text = sb.ToString();
            return i;
        }

        static string Cut(string s) { return s.Length > 300 ? s.Substring(0, 300) + "…" : s; }

        static string AppName(string pkg)
        {
            string l = pkg.ToLowerInvariant();
            if (l.Contains("telegram")) return "Telegram";
            if (l.Contains("discord")) return "Discord";
            if (l.Contains("whatsapp")) return "WhatsApp";
            return pkg;
        }

        public static string HostOf(string url)
        {
            if (string.IsNullOrEmpty(url)) return null;
            Match m = Regex.Match(url, @"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?([^/:?#]+)", RegexOptions.IgnoreCase);
            if (!m.Success) return null;
            string h = m.Groups[1].Value.ToLowerInvariant();
            if (h.StartsWith("www.")) h = h.Substring(4);
            return h.Length > 0 ? h : null;
        }

        static string ZoneName(string z)
        {
            switch (z)
            {
                case "0": return "этот компьютер";
                case "1": return "локальная сеть";
                case "2": return "доверенные сайты";
                case "3": return "интернет";
                case "4": return "опасные сайты";
                default: return z ?? "?";
            }
        }

        /// <summary>Похож ли домен на сайт чита. Возвращает найденное слово или null.</summary>
        public static string CheatSite(string urlOrHost)
        {
            if (string.IsNullOrEmpty(urlOrHost) || Keywords.IsSsTool(urlOrHost)) return null;
            string host = HostOf(urlOrHost) ?? urlOrHost.ToLowerInvariant();
            // поисковики, Discord, Google, ВК и т.п.: сам сайт обычный, но в адресе может быть название чита (google.com/search?q=nursultan)
            if (neutralHosts.Any(n => host.Contains(n))) return PathWord(urlOrHost);
            string[] labels = host.Split(new char[] { '.', '-' }, StringSplitOptions.RemoveEmptyEntries);
            string joined = host.Replace(".", "").Replace("-", "");
            foreach (string w in siteWords)
                if (w.Length >= 5 ? joined.Contains(w) : labels.Contains(w)) return w;
            foreach (string w in genericWords)
                if (labels.Contains(w)) return w;
            // остальные слова из списка — только сильные (частые слова вроде delta/future дают ложные срабатывания)
            foreach (Keywords.Kw k in Keywords.Match(string.Join(" ", labels)))
                if (k.Kind == Keywords.KwKind.Token && k.Strong && labels.Any(l => l == k.Word || (k.Word.Length >= 7 && l.Contains(k.Word)))) return k.Word;
            // файлообменники и GitHub: сайт обычный, поэтому смотрим путь (github.com/кто-то/doomsday-client)
            if (FileHost(urlOrHost) != null) return PathWord(urlOrHost);
            return null;
        }

        /// <summary>Обычный сайт (поисковик, видео, соцсеть) — слово чита там значит «искали/смотрели», а не «зашли на сайт чита».</summary>
        public static bool IsNeutral(string urlOrHost)
        {
            string host = HostOf(urlOrHost) ?? (urlOrHost ?? "").ToLowerInvariant();
            return neutralHosts.Any(n => host.Contains(n));
        }

        /// <summary>Название чита в пути или запросе адреса (github.com/x/doomsday-client, google.com/search?q=nursultan).</summary>
        static string PathWord(string url)
        {
            int ds = url.IndexOf("//", StringComparison.Ordinal);
            if (ds < 0) return null;
            int sl = url.IndexOfAny(new char[] { '/', '?' }, ds + 2);
            if (sl <= 0 || Keywords.IsSsTool(url)) return null;
            string path;
            try { path = Uri.UnescapeDataString(url.Substring(sl).Replace('+', ' ')).ToLowerInvariant(); } catch { path = url.Substring(sl).ToLowerInvariant(); }
            string pj = Regex.Replace(path, "[^a-z0-9]", "");
            foreach (string w in siteWords) if (w.Length >= 6 && pj.Contains(w)) return w;
            string[] toks = Regex.Split(path, "[^a-z0-9]+");
            foreach (string w in new string[] { "cortex", "vape", "wurst" }) if (toks.Contains(w)) return w;
            foreach (Keywords.Kw k in Keywords.Match(path)) if (k.Kind == Keywords.KwKind.Token && k.Strong && !Keywords.IsSsTool(path)) return k.Word;
            return null;
        }

        /// <summary>Анонимные файлообменники — оттуда обычно качают читы (GitHub, Discord, Google Диск — слишком частые для обычных файлов, их не считаем).</summary>
        static readonly string[] anonHosts = {
            "mediafire.com", "mega.nz", "mega.io", "gofile.io", "anonfiles", "pixeldrain.com", "catbox.moe", "workupload.com", "sendspace.com",
            "krakenfiles.com", "qiwi.gg", "buzzheavier.com", "uploadhaven.com", "files.fm", "transfer.sh", "anonymfile", "upload.ee", "fex.net"
        };

        public static string AnonHost(string url)
        {
            string h = HostOf(url);
            if (h == null) return null;
            foreach (string f in anonHosts) if (h == f || h.EndsWith("." + f) || (f.IndexOf('.') < 0 && h.Contains(f))) return h;
            return null;
        }

        public static string FileHost(string url)
        {
            string h = HostOf(url);
            if (h == null) return null;
            foreach (string f in fileHosts) if (h == f || h.EndsWith("." + f) || (f.IndexOf('.') < 0 && h.Contains(f))) return h;
            return null;
        }

        static readonly HashSet<string> runnable = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".exe", ".dll", ".jar", ".zip", ".rar", ".7z", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".sys", ".bin", ".dat", ".ahk", ".lua", ".disabled"
        };

        /// <summary>Всё, что известно о происхождении файла.</summary>
        public class Explained
        {
            public Info Mark;
            public DlRecord Dl;          // запись в истории загрузок браузера (по пути)
            public DlRecord DlByName;    // скачивался файл с таким же именем (переименован/перемещён)
            public string Guess;         // догадка по папке (Telegram, архив, флешка…)
            public string Copied;        // признак копирования
            public string Domain, Site, Short, Text;
        }

        public static Explained Explain(string path)
        {
            Explained e = new Explained();
            e.Mark = Read(path);
            try { e.Dl = DownloadHistory.ForPath(path); } catch { }
            if (e.Dl == null) try { DlRecord n = DownloadHistory.ForName(Path.GetFileName(path)); if (n != null && n.Url != null) e.DlByName = n; } catch { }
            e.Guess = Guess(path);
            if (e.Guess != null && e.Guess.StartsWith("Лежит в «Загрузках»") && (e.Mark != null || e.Dl != null)) e.Guess = null;
            try
            {
                FileInfo fi = new FileInfo(path);
                if (fi.Exists && fi.CreationTime > fi.LastWriteTime.AddMinutes(2))
                    e.Copied = "Появился здесь " + fi.CreationTime.ToString("dd.MM.yyyy HH:mm") + ", а изменён раньше (" + fi.LastWriteTime.ToString("dd.MM.yyyy HH:mm") + ") — файл скопирован или перемещён сюда из другого места";
            }
            catch { }

            DlRecord dl = e.Dl ?? e.DlByName;
            string url = e.Mark != null ? (e.Mark.Host ?? e.Mark.Referrer) : null;
            if (url == null && dl != null) url = dl.Url ?? dl.Page;
            e.Domain = e.Mark != null && e.Mark.Domain != null ? e.Mark.Domain : dl != null ? (HostOf(dl.Url) ?? HostOf(dl.Page)) : null;
            foreach (string u in new string[] { e.Mark != null ? e.Mark.Host : null, e.Mark != null ? e.Mark.Referrer : null, dl != null ? dl.Url : null, dl != null ? dl.FirstUrl : null, dl != null ? dl.Page : null, dl != null ? dl.Referrer : null })
                if (e.Site == null && u != null && !IsNeutral(u)) e.Site = CheatSite(u);

            StringBuilder sb = new StringBuilder();
            if (e.Mark != null) sb.Append(e.Mark.Text);
            if (e.Dl != null)
            {
                if (sb.Length > 0) sb.Append("\n");
                sb.Append("История загрузок " + e.Dl.Browser + (e.Dl.Time.Year > 2000 ? " · " + e.Dl.Time.ToString("dd.MM.yyyy HH:mm") : ""));
                if (e.Mark == null || e.Dl.Url != e.Mark.Host) sb.Append("\nСсылка: " + Cut(e.Dl.Url ?? "?"));
                if (!string.IsNullOrEmpty(e.Dl.Page) && (e.Mark == null || e.Dl.Page != e.Mark.Referrer)) sb.Append("\nСтраница: " + Cut(e.Dl.Page));
                if (!string.IsNullOrEmpty(e.Dl.FirstUrl) && e.Dl.FirstUrl != e.Dl.Url) sb.Append("\nПервая ссылка (до переадресаций): " + Cut(e.Dl.FirstUrl));
            }
            else if (e.DlByName != null)
            {
                if (sb.Length > 0) sb.Append("\n");
                sb.Append("Файл с таким же именем скачивался в " + e.DlByName.Browser + (e.DlByName.Time.Year > 2000 ? " " + e.DlByName.Time.ToString("dd.MM.yyyy HH:mm") : "") +
                          ": " + Cut(e.DlByName.Url) + "\nСохранялся как: " + e.DlByName.Path);
            }
            if (e.Guess != null) { if (sb.Length > 0) sb.Append("\n"); sb.Append(e.Guess); }
            if (e.Copied != null) { if (sb.Length > 0) sb.Append("\n"); sb.Append(e.Copied); }
            if (e.Mark == null && dl == null) sb.Insert(0, sb.Length > 0 ? "Метки скачивания нет.\n" : NoMark);
            e.Text = sb.ToString();

            if (e.Domain != null) e.Short = "Скачан с " + e.Domain + (dl != null ? " (" + dl.Browser + (dl.Time.Year > 2000 ? ", " + dl.Time.ToString("dd.MM.yyyy") : "") + ")" : "");
            else if (e.Mark != null && e.Mark.App != null) e.Short = "Получен через " + AppName(e.Mark.App);
            else if (e.Mark != null) e.Short = "Скачан из интернета (адрес не сохранён)";
            else if (e.Guess != null) e.Short = e.Guess;
            else e.Short = "Нет метки скачивания";
            return e;
        }

        /// <summary>Откуда файл, если метки нет: по папке, где он лежит.</summary>
        public static string Guess(string path)
        {
            string l = path.ToLowerInvariant();
            Match m;
            if (l.Contains("\\telegram desktop\\")) return "Лежит в папке «Telegram Desktop» — получен через Telegram";
            if (l.Contains("\\appdata\\local\\temp\\rar$")) return "Открыт из архива в WinRAR (временная папка Rar$…)";
            if (Regex.IsMatch(l, @"\\temp\\7z[a-z0-9]+\\")) return "Открыт из архива в 7-Zip (временная папка 7z…)";
            if ((m = Regex.Match(path, @"\\Temp\\Temp\d+_([^\\]+)\\", RegexOptions.IgnoreCase)).Success) return "Открыт проводником из архива «" + m.Groups[1].Value + "»";
            if (l.Contains("\\discord\\") && l.Contains("cache")) return "Кэш Discord — файл открывали из Discord";
            if (l.Contains("\\inetcache\\") || l.Contains("\\content.ie5\\")) return "Кэш браузера";
            if (l.Contains("\\.minecraft\\") && l.Contains("\\mods\\")) return "Папка модов Minecraft";
            if (l.Contains("\\steamapps\\")) return "Установлен через Steam";
            if (l.Contains("\\downloads\\") || l.Contains("\\загрузки\\")) return "Лежит в «Загрузках» — скачан, но метку скачивания стёрли или скачан не браузером";
            if (l.Contains("\\desktop\\")) return "Лежит на рабочем столе";
            try
            {
                string root = Path.GetPathRoot(path);
                if (root != null && root.Length >= 2 && new DriveInfo(root).DriveType == DriveType.Removable) return "Лежит на флешке / съёмном диске " + root.TrimEnd('\\');
            }
            catch { }
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if ((pf.Length > 0 && l.StartsWith(pf.ToLowerInvariant() + "\\")) || (pf86.Length > 0 && l.StartsWith(pf86.ToLowerInvariant() + "\\"))) return "Установленная программа (Program Files)";
            if (Analyzer.WinDir != null && l.StartsWith(Analyzer.WinDir.ToLowerInvariant() + "\\")) return "Папка Windows";
            return null;
        }

        /// <summary>Дописывает в находку, откуда взялся файл. Сайт чита — сильный признак.</summary>
        public static void Apply(Finding f)
        {
            if (f.Origin != null || string.IsNullOrEmpty(f.Path) || f.Path.Length < 4 || f.Path[1] != ':') return;
            try { if (!File.Exists(f.Path)) return; } catch { return; }
            Explained e = Explain(f.Path);
            f.Origin = e.Text;
            string ext = Path.GetExtension(f.Path);
            DlRecord dl = e.Dl ?? e.DlByName;
            if (e.Site != null) f.Add(55, "Скачан с сайта читов: " + (e.Domain ?? e.Site) + " (в адресе «" + e.Site + "»)");
            else if (e.Mark != null && FileHost(e.Mark.Host ?? e.Mark.Referrer) != null && runnable.Contains(ext)) f.Note("Скачан с файлообменника " + e.Domain + " — читы часто раздают так");
            else f.Note(e.Short);
        }
    }

    /// <summary>Файлы в папках пользователей, скачанные с сайтов читов или с файлообменников (по метке Zone.Identifier).</summary>
    class DownloadOriginScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public int Checked, WithMark;

        static readonly HashSet<string> exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".exe", ".dll", ".jar", ".zip", ".rar", ".7z", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".ahk", ".lua", ".disabled", ".bin", ".dat", ".sys"
        };

        public void Run(CancellationToken ct)
        {
            List<string> roots = new List<string>();
            string users = Path.Combine(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)), "Users");
            try
            {
                foreach (string u in Directory.GetDirectories(users))
                {
                    string n = Path.GetFileName(u).ToLowerInvariant();
                    if (n == "public" || n == "default" || n == "default user" || n == "all users") continue;
                    foreach (string sub in new string[] { "Downloads", "Desktop", "Documents", "OneDrive", "Pictures", "Videos", "Music", "AppData\\Roaming", "AppData\\Local\\Temp" })
                    {
                        string d = Path.Combine(u, sub);
                        if (Directory.Exists(d)) roots.Add(d);
                    }
                }
            }
            catch { }
            foreach (string r in roots)
            {
                if (ct.IsCancellationRequested) return;
                Walk(r, ct);
            }
            if (!ct.IsCancellationRequested) History(ct);
        }

        void Walk(string root, CancellationToken ct)
        {
            Stack<KeyValuePair<string, int>> st = new Stack<KeyValuePair<string, int>>();
            st.Push(new KeyValuePair<string, int>(root, 0));
            while (st.Count > 0 && !ct.IsCancellationRequested)
            {
                KeyValuePair<string, int> cur = st.Pop();
                string l = cur.Key.ToLowerInvariant();
                if (l.Contains("\\cache") || l.Contains("\\node_modules") || l.EndsWith("\\microsoft") || l.Contains("\\packages\\")) continue;
                try
                {
                    foreach (string d in Directory.EnumerateDirectories(cur.Key))
                    {
                        FileAttributes a = File.GetAttributes(d);
                        if ((a & FileAttributes.ReparsePoint) == 0 && cur.Value < 8) st.Push(new KeyValuePair<string, int>(d, cur.Value + 1));
                    }
                }
                catch { }
                try
                {
                    foreach (string file in Directory.EnumerateFiles(cur.Key))
                    {
                        if (ct.IsCancellationRequested) return;
                        if (!exts.Contains(Path.GetExtension(file))) continue;
                        Checked++;
                        if ((Checked & 255) == 0) Current = file;
                        CheckFile(file);
                    }
                }
                catch { }
            }
        }

        void CheckFile(string file)
        {
            Origin.Explained e = Origin.Explain(file);
            if (e.Mark == null && e.Dl == null) return;
            WithMark++;
            string url = e.Mark != null ? (e.Mark.Host ?? e.Mark.Referrer) : (e.Dl.Url ?? e.Dl.Page);
            string fh = e.Site == null ? (Origin.FileHost(url) ?? Origin.AnonHost(url)) : null;
            string app = e.Site == null && fh == null && e.Mark != null && e.Mark.App != null ? e.Mark.App : null;
            if (e.Site == null && fh == null && app == null) return;
            string ext = Path.GetExtension(file).ToLowerInvariant();
            bool anon = fh != null && Origin.AnonHost(url) != null;
            if (e.Site == null)
            {
                // файлообменник / Discord / Telegram / GitHub / Google Диск — только программы, моды и архивы, и не подписанные
                if (ext != ".exe" && ext != ".jar" && ext != ".dll" && ext != ".zip" && ext != ".rar" && ext != ".7z" && ext != ".msi" && ext != ".bat" && ext != ".scr") return;
                if (ext == ".exe" || ext == ".dll" || ext == ".msi")
                    try { if (Native.CheckSignature(file).Trusted) return; } catch { }
            }
            Finding f = new Finding();
            f.Path = file; f.FileName = Path.GetFileName(file); f.Source = "Откуда скачано";
            f.RealType = ext.TrimStart('.').ToUpperInvariant() + " · " + (e.Domain ?? "скачан");
            try { FileInfo fi = new FileInfo(file); f.Size = fi.Length; f.Modified = fi.LastWriteTime; f.Created = fi.CreationTime; } catch { }
            f.Origin = e.Text;
            if (e.Site != null) f.Add(60, "Скачан с сайта читов: " + (e.Domain ?? e.Site) + " (в адресе «" + e.Site + "»)");
            else if (anon) f.Add(15, "Скачан с анонимного файлообменника " + e.Domain + " — проверь, что это за файл");
            else
            {
                string what = ext == ".zip" || ext == ".rar" || ext == ".7z" ? "архив — проверь, что внутри" : ext == ".jar" ? "мод/Java-программа — проверь в «Моды и файлы»" : "программа без подписи — проверь, что это";
                f.Add(15, (fh != null ? "Скачан с " + e.Domain : "Получен через " + app) + ": " + what);
            }
            foreach (Keywords.Kw k in Keywords.Match(f.FileName).Where(k => k.Strong)) f.Add(30, "В названии слово из списка «" + k.Word + "»");
            f.Finish();
            if (f.Severity > 0 && Found != null) Found(f);
        }

        /// <summary>Загрузки с сайтов читов из истории браузеров — даже если файл уже удалён.</summary>
        public void History(CancellationToken ct)
        {
            Current = "история загрузок браузеров";
            foreach (DlRecord d in DownloadHistory.All)
            {
                if (ct.IsCancellationRequested) return;
                string site = null;
                foreach (string u in new string[] { d.Url, d.FirstUrl, d.Page, d.Referrer }) if (site == null && u != null && !Origin.IsNeutral(u)) site = Origin.CheatSite(u);
                List<Keywords.Kw> kws = string.IsNullOrEmpty(d.Path) ? new List<Keywords.Kw>() : Keywords.Match(Path.GetFileName(d.Path)).Where(k => k.Strong).ToList();
                if (site == null && kws.Count == 0) continue;
                bool exists = false;
                try { exists = !string.IsNullOrEmpty(d.Path) && File.Exists(d.Path); } catch { }
                if (exists) continue; // существующие файлы уже проверены по метке
                Finding f = new Finding();
                f.Path = string.IsNullOrEmpty(d.Path) ? d.Url : d.Path; f.FileName = string.IsNullOrEmpty(d.Path) ? (Origin.HostOf(d.Url) ?? "загрузка") : Path.GetFileName(d.Path);
                f.Source = "История загрузок " + d.Browser;
                f.RealType = "Загрузка · " + d.Browser + " · файл удалён";
                f.Modified = d.Time; f.Size = d.Bytes;
                f.Origin = "Ссылка: " + d.Url + (d.Page != null ? "\nСтраница: " + d.Page : "") + "\nСохранялся как: " + d.Path + "\nФайла на диске уже нет";
                if (site != null) f.Add(60, "Скачивался с сайта читов " + (Origin.HostOf(d.Url) ?? site) + " (в адресе «" + site + "») — файл уже удалён");
                foreach (Keywords.Kw k in kws) f.Add(40, "Скачивался файл со словом «" + k.Word + "» в названии — файл уже удалён");
                f.Finish();
                if (f.Severity > 0 && Found != null) Found(f);
            }
        }
    }

    /// <summary>Сайты читов в истории браузеров и в DNS-кэше Windows (остаются, даже если файл удалили).</summary>
    static class WebTraces
    {
        public static List<KeyValuePair<string, string>> HistoryFiles()
        {
            List<KeyValuePair<string, string>> res = new List<KeyValuePair<string, string>>();
            string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string ad = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string[][] chromium = {
                new[] { "Chrome", Path.Combine(la, "Google\\Chrome\\User Data") },
                new[] { "Edge", Path.Combine(la, "Microsoft\\Edge\\User Data") },
                new[] { "Brave", Path.Combine(la, "BraveSoftware\\Brave-Browser\\User Data") },
                new[] { "Яндекс", Path.Combine(la, "Yandex\\YandexBrowser\\User Data") },
                new[] { "Vivaldi", Path.Combine(la, "Vivaldi\\User Data") },
                new[] { "Chromium", Path.Combine(la, "Chromium\\User Data") },
                new[] { "Opera", Path.Combine(ad, "Opera Software") },
            };
            foreach (string[] c in chromium)
            {
                if (!Directory.Exists(c[1])) continue;
                try
                {
                    foreach (string f in Directory.GetFiles(c[1], "History", SearchOption.AllDirectories))
                        if (f.IndexOf("\\Snapshots\\", StringComparison.OrdinalIgnoreCase) < 0) res.Add(new KeyValuePair<string, string>(c[0], f));
                }
                catch { }
            }
            string ff = Path.Combine(ad, "Mozilla\\Firefox\\Profiles");
            if (Directory.Exists(ff))
                try { foreach (string f in Directory.GetFiles(ff, "places.sqlite", SearchOption.AllDirectories)) res.Add(new KeyValuePair<string, string>("Firefox", f)); } catch { }
            return res;
        }

        static readonly Regex urlRx = new Regex(@"https?://[\x21-\x7e]{4,600}", RegexOptions.Compiled);

        /// <summary>Достаёт адреса из файла истории (база читается как поток байт — работает и при открытом браузере).</summary>
        public static List<string> Urls(string file)
        {
            HashSet<string> seen = new HashSet<string>();
            List<string> res = new List<string>();
            foreach (string part in new string[] { file, file + "-wal", file + "-journal" })
            {
                byte[] b = null;
                try
                {
                    if (!File.Exists(part)) continue;
                    using (FileStream fs = new FileStream(part, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        long len = Math.Min(fs.Length, 512L * 1024 * 1024);
                        b = new byte[len];
                        int off = 0, n;
                        while (off < len && (n = fs.Read(b, off, (int)Math.Min(len - off, 1 << 20))) > 0) off += n;
                    }
                }
                catch { }
                if (b == null) continue;
                foreach (string u in UrlsFromBytes(b)) if (seen.Add(u)) res.Add(u);
            }
            return res;
        }

        /// <summary>Адреса из произвольных байтов (ASCII и UTF-16).</summary>
        public static List<string> UrlsFromBytes(byte[] b)
        {
            HashSet<string> seen = new HashSet<string>();
            List<string> res = new List<string>();
            List<string> texts = new List<string> { Encoding.ASCII.GetString(b) };
            if (b.Length < 64 * 1024 * 1024) texts.Add(Encoding.Unicode.GetString(b, 0, b.Length & ~1));
            foreach (string s in texts)
                foreach (Match m in urlRx.Matches(s))
                {
                    string u = m.Value;
                    int cut = u.IndexOfAny(new char[] { '"', '\'', '<', '>', '`', '{', '}', '|', '\\', '^' });
                    if (cut > 0) u = u.Substring(0, cut);
                    if (seen.Add(u)) res.Add(u);
                }
            return res;
        }

        /// <summary>Домены из DNS-кэша (ipconfig /displaydns). Не зависит от языка Windows.</summary>
        public static List<string> DnsCache()
        {
            List<string> res = new List<string>();
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("ipconfig", "/displaydns");
                psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(15000);
                    HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (Match m in Regex.Matches(o, @"(?<![\w.-])([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,24})(?![\w-])", RegexOptions.IgnoreCase))
                    {
                        string d = m.Groups[1].Value.ToLowerInvariant();
                        if (d.EndsWith(".arpa")) continue;
                        if (seen.Add(d)) res.Add(d);
                    }
                }
            }
            catch { }
            return res;
        }
    }
}
