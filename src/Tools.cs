using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

namespace InjectHunter
{
    class ToolInfo
    {
        public string Resource, FileName, Title, Desc, Group, Exe, NirArgs;
        public bool Zip, Installer;
        public long Size;
        public SigInfo Sig;
    }

    /// <summary>Вшитые в exe программы для проверки: распаковка во временную папку и запуск.</summary>
    static class Tools
    {
        public static List<ToolInfo> All = new List<ToolInfo>();
        public static string Root = Path.Combine(Path.GetTempPath(), "RamCheaker", "tools");

        // file -> title | описание | группа
        static readonly string[,] meta = {
            { "BAMParser.exe", "BAM Parser", "Какие программы запускались (BAM), с датами — в том числе уже удалённые", "SS-утилиты" },
            { "JournalTrace.exe", "JournalTrace", "USN-журнал NTFS: удалённые и переименованные файлы (фильтр .jar / .exe)", "SS-утилиты" },
            { "PathsParser.exe", "Paths Parser", "Проверяет список путей: существует ли файл, подпись, подозрительность", "SS-утилиты" },
            { "CachedProgramsList.exe", "Cached Programs List", "Программы из системных кэшей запуска Windows", "SS-утилиты" },
            { "MinecraftVersionChecker.exe", "Minecraft Version Checker", "Версии и сборки Minecraft на компьютере", "SS-утилиты" },
            { "MeowDoomsdayFucker.exe", "Meow Doomsday", "Поиск Doomsday в памяти javaw (сторонняя утилита)", "SS-утилиты" },
            { "shellbag_analyzer_cleaner.exe", "ShellBag Analyzer", "ShellBags: какие папки открывались в проводнике", "SS-утилиты" },
            { "winprefetchview-x64.zip", "WinPrefetchView", "Prefetch: запуски программ и файлы, которые они открывали", "NirSoft" },
            { "executedprogramslist.zip", "ExecutedProgramsList", "Список когда-либо запускавшихся программ", "NirSoft" },
            { "lastactivityview.zip", "LastActivityView", "Хронология действий: запуски, установки, выключения", "NirSoft" },
            { "recentfilesview.zip", "RecentFilesView", "Недавно открытые файлы", "NirSoft" },
            { "browserdownloadsview.zip", "BrowserDownloadsView", "Что скачивалось через браузеры", "NirSoft" },
            { "USBDeview..zip", "USBDeview", "Какие USB-устройства подключались", "NirSoft" },
            { "OpenedFilesView.exe.zip", "OpenedFilesView", "Файлы, открытые процессами прямо сейчас", "NirSoft" },
            { "installedpackagesview-x64.zip", "InstalledPackagesView", "Установленные программы и пакеты", "NirSoft" },
            { "regscanner-x64.zip", "RegScanner", "Поиск по реестру", "NirSoft" },
            { "Everything-1.4.1.1026.x86-Setup.exe", "Everything", "Мгновенный поиск файлов по имени и размеру", "Установщики" },
            { "processhacker-2.39-setup.exe", "Process Hacker", "Процессы, модули, строки в памяти", "Установщики" },
            { "systeminformer-3.2.25011-release-setup.exe", "System Informer", "Новая версия Process Hacker", "Установщики" },
            { "rcsetup155.exe", "Recuva", "Восстановление удалённых файлов", "Установщики" },
        };

        // NirSoft-утилиты, которые RamCheaker запускает сам (только с подписью Nir Sofer) и проверяет их выгрузку
        static readonly Dictionary<string, string> nirAuto = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "winprefetchview-x64.zip", "WinPrefetchView.exe" },
            { "executedprogramslist.zip", "ExecutedProgramsList.exe" },
            { "lastactivityview.zip", "LastActivityView.exe" },
            { "recentfilesview.zip", "RecentFilesView.exe" },
            { "USBDeview..zip", "USBDeview.exe" },
        };

        public static void Load()
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            foreach (string r in asm.GetManifestResourceNames())
            {
                if (!r.StartsWith("tool:")) continue;
                ToolInfo t = new ToolInfo();
                t.Resource = r;
                t.FileName = r.Substring(5);
                t.Zip = t.FileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
                t.Title = Path.GetFileNameWithoutExtension(t.FileName);
                t.Desc = "";
                t.Group = "Другое";
                for (int i = 0; i < meta.GetLength(0); i++)
                    if (meta[i, 0].Equals(t.FileName, StringComparison.OrdinalIgnoreCase))
                    { t.Title = meta[i, 1]; t.Desc = meta[i, 2]; t.Group = meta[i, 3]; }
                t.Installer = t.Group == "Установщики";
                string nir;
                if (nirAuto.TryGetValue(t.FileName, out nir)) t.NirArgs = nir;
                try { using (Stream s = asm.GetManifestResourceStream(r)) t.Size = s.Length; } catch { }
                All.Add(t);
            }
            string[] order = { "SS-утилиты", "NirSoft", "Установщики", "Другое" };
            All = All.OrderBy(x => Array.IndexOf(order, x.Group)).ThenBy(x => x.Title).ToList();
        }

        /// <summary>Распаковывает программу и возвращает путь к её exe.</summary>
        public static string Extract(ToolInfo t)
        {
            Directory.CreateDirectory(Root);
            Assembly asm = Assembly.GetExecutingAssembly();
            if (!t.Zip)
            {
                string dst = Path.Combine(Root, t.FileName);
                if (!File.Exists(dst) || new FileInfo(dst).Length != t.Size)
                    using (Stream s = asm.GetManifestResourceStream(t.Resource))
                    using (FileStream fs = File.Create(dst)) s.CopyTo(fs);
                t.Exe = dst;
                return dst;
            }
            string dir = Path.Combine(Root, Path.GetFileNameWithoutExtension(t.FileName).TrimEnd('.'));
            Directory.CreateDirectory(dir);
            using (Stream s = asm.GetManifestResourceStream(t.Resource))
            using (ZipArchive za = new ZipArchive(s, ZipArchiveMode.Read))
            {
                foreach (ZipArchiveEntry e in za.Entries)
                {
                    if (string.IsNullOrEmpty(e.Name)) continue;
                    string dst = Path.GetFullPath(Path.Combine(dir, e.FullName));
                    if (!dst.StartsWith(Path.GetFullPath(dir), StringComparison.OrdinalIgnoreCase)) continue; // защита от ../
                    Directory.CreateDirectory(Path.GetDirectoryName(dst));
                    if (File.Exists(dst) && new FileInfo(dst).Length == e.Length) continue;
                    using (Stream es = e.Open()) using (FileStream fs = File.Create(dst)) es.CopyTo(fs);
                }
            }
            string exe = Directory.GetFiles(dir, "*.exe").FirstOrDefault();
            t.Exe = exe;
            return exe;
        }

        public static void Launch(ToolInfo t)
        {
            string exe = Extract(t);
            if (exe == null) throw new FileNotFoundException("В архиве нет .exe");
            ProcessStartInfo psi = new ProcessStartInfo(exe);
            psi.UseShellExecute = true;
            psi.WorkingDirectory = Path.GetDirectoryName(exe);
            Process.Start(psi);
        }

        public static void CheckSignatures()
        {
            foreach (ToolInfo t in All)
            {
                try { string exe = Extract(t); if (exe != null) t.Sig = Native.CheckSignature(exe); } catch { }
            }
        }

        /// <summary>Тихо запускает подписанную NirSoft-утилиту с /scomma и возвращает строки CSV.</summary>
        public static List<string[]> RunNirsoft(ToolInfo t, int timeoutMs)
        {
            List<string[]> rows = new List<string[]>();
            string exe = Extract(t);
            if (exe == null) return rows;
            SigInfo sig = Native.CheckSignature(exe);
            if (sig.State != SigState.Embedded || sig.Signer == null || sig.Signer.IndexOf("Nir Sofer", StringComparison.OrdinalIgnoreCase) < 0)
                throw new InvalidOperationException("нет подписи Nir Sofer — автозапуск пропущен");
            string csv = Path.Combine(Root, Path.GetFileNameWithoutExtension(exe) + "_" + DateTime.Now.Ticks + ".csv");
            ProcessStartInfo psi = new ProcessStartInfo(exe, "/scomma \"" + csv + "\"");
            psi.UseShellExecute = false; psi.CreateNoWindow = true;
            psi.WorkingDirectory = Path.GetDirectoryName(exe);
            using (Process p = Process.Start(psi))
            {
                if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } }
            }
            if (!File.Exists(csv)) return rows;
            foreach (string line in File.ReadAllLines(csv, System.Text.Encoding.Default))
                if (line.Length > 0) rows.Add(SplitCsv(line));
            try { File.Delete(csv); } catch { }
            return rows;
        }

        static string[] SplitCsv(string line)
        {
            List<string> r = new List<string>();
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            bool q = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (q)
                {
                    if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else if (c == '"') q = false;
                    else sb.Append(c);
                }
                else if (c == '"') q = true;
                else if (c == ',') { r.Add(sb.ToString()); sb.Length = 0; }
                else sb.Append(c);
            }
            r.Add(sb.ToString());
            return r.ToArray();
        }
    }
}
