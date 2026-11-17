using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace InjectHunter
{
    class Finding
    {
        public string Path;
        public string FileName;
        public string Ext;
        public string RealType = "—";
        public long Size;
        public DateTime Modified;
        public DateTime Created;
        public int Score;
        public int Severity;
        public string Source = "Диск";
        public SigInfo Sig;
        public string Sha256;
        public List<string> Reasons = new List<string>();
        public bool ManySigs;

        public void Add(int pts, string reason)
        {
            Score += pts;
            Reasons.Add((pts > 0 ? "+" + pts : pts.ToString()) + "  " + reason);
        }
        public void Note(string reason) { Reasons.Add("·  " + reason); }

        public string Summary
        {
            get
            {
                string best = null; int bestPts = -1;
                foreach (string r in Reasons)
                {
                    int sp = r.IndexOf("  ");
                    int pts;
                    if (sp > 1 && r[0] == '+' && int.TryParse(r.Substring(1, sp - 1), out pts) && pts > bestPts)
                    { bestPts = pts; best = r.Substring(sp + 2); }
                }
                return best ?? (Reasons.Count > 0 ? Reasons[0] : "");
            }
        }

        public static string SevName(int s)
        {
            return s >= 3 ? "КРИТИЧНО" : s == 2 ? "ПОДОЗРИТЕЛЬНО" : s == 1 ? "ВНИМАНИЕ" : "ОК";
        }

        public void Finish()
        {
            if (Score < 0) Score = 0;
            Severity = Score >= 60 ? 3 : Score >= 30 ? 2 : Score >= 15 ? 1 : 0;
        }
    }

    class ScanOptions
    {
        public List<string> Roots = new List<string>();
        public bool SkipServiceDirs = true;
        public bool DisguiseExt = true;
        public bool AllFiles = false;
        public bool ScanExe = true;
        public bool ScanJars = true;
        public bool SystemSigCheck = true;
        public bool DeepContent = true;
        public long MaxContent = 64L * 1024 * 1024;
    }

    static class Analyzer
    {
        public static string WinDir, Sys32, SysWow, SelfPath;
        static HashSet<string> systemNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static ConcurrentDictionary<string, bool> javaDirCache = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        static byte[] lowerTab = new byte[256];

        [ThreadStatic] static byte[] tBuf;
        [ThreadStatic] static byte[] tUtf;
        const int BUF = 4 * 1024 * 1024;

        public static readonly HashSet<string> PeExts = Set(".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi", ".ax", ".acm",
            ".node", ".pyd", ".mui", ".tlb", ".winmd", ".ime", ".rll", ".fon", ".com", ".xll", ".vst", ".vst3", ".aex", ".8bf", ".asi",
            ".flt", ".api", ".bpl", ".dat_old", ".mun", ".olb", ".tsp", ".iec", ".cmd_", ".lex", ".plugin", ".exe_", ".dll_", ".so",
            ".x3d", ".wlx", ".wcx", ".wdx", ".spi", ".arx", ".crx3", ".dbx", ".zap", ".icl", ".ppi", ".msstyles", ".tsk", ".ds", ".resources");

        public static readonly HashSet<string> ZipExts = Set(".zip", ".jar", ".apk", ".aar", ".war", ".ear", ".docx", ".xlsx", ".pptx",
            ".odt", ".ods", ".odp", ".epub", ".nupkg", ".vsix", ".whl", ".xpi", ".crx", ".mcpack", ".mcworld", ".mrpack", ".appx", ".msix",
            ".appxbundle", ".msixbundle", ".kmz", ".3mf", ".xps", ".oxps", ".ipa", ".litemod", ".sketch", ".fig", ".mcaddon", ".mctemplate",
            ".pak", ".pk3", ".pk4", ".cbz", ".egg", ".sb3", ".gadget", ".vsdx", ".dotx", ".xltx", ".potx", ".jmod", ".ja", ".hpi", ".kra",
            ".ora", ".xd", ".usdz", ".ggb", ".unitypackage", ".zipx", ".cfa", ".bundle", ".mtz", ".lck", ".mca");

        public static readonly HashSet<string> FakeExts = Set(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".txt", ".log",
            ".json", ".ini", ".cfg", ".conf", ".config", ".dat", ".tmp", ".temp", ".bin", ".db", ".sqlite", ".mp3", ".mp4", ".ogg", ".wav",
            ".ttf", ".otf", ".xml", ".yml", ".yaml", ".properties", ".lang", ".nbt", ".lock", ".bak", ".old", ".cache", ".pf", ".dmp",
            ".toml", ".csv", ".md", ".html", ".htm", ".css", ".js", ".lnk", ".url", ".bat", ".cmd", ".ps1", ".vbs", ".zip", ".rar", ".7z",
            ".pdf", ".doc", ".mkv", ".avi", ".res", ".pack", ".idx", ".etl", ".evtx", ".blf", ".regtrans-ms", ".class", ".mcmeta", ".sk", ".ldb", ".map");

        static HashSet<string> Set(params string[] a) { return new HashSet<string>(a, StringComparer.OrdinalIgnoreCase); }

        public static void Init()
        {
            for (int i = 0; i < 256; i++) lowerTab[i] = (byte)((i >= 'A' && i <= 'Z') ? i + 32 : i);
            WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            Sys32 = System.IO.Path.Combine(WinDir, "System32");
            SysWow = System.IO.Path.Combine(WinDir, "SysWOW64");
            try { SelfPath = System.Reflection.Assembly.GetExecutingAssembly().Location; } catch { SelfPath = ""; }
            foreach (string d in new string[] { Sys32, SysWow })
            {
                try
                {
                    foreach (string f in Directory.EnumerateFiles(d))
                    {
                        string e = System.IO.Path.GetExtension(f);
                        if (e.Equals(".dll", StringComparison.OrdinalIgnoreCase) || e.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                            systemNames.Add(System.IO.Path.GetFileName(f));
                    }
                }
                catch { }
            }
            hidingDirs = hidingRel.Select(r => System.IO.Path.Combine(WinDir, r)).ToArray();
            LoadHashList();
            Keywords.Load();
            SizeRules.Load();
            int dummy = Signatures.All.Count; // принудительная инициализация сигнатур
        }

        public static bool IsUnder(string path, string dir)
        {
            return path.Length > dir.Length && path.StartsWith(dir, StringComparison.OrdinalIgnoreCase) && path[dir.Length] == '\\';
        }

        // Папки Windows, где у Microsoft НЕТ своих программ, но читеры прячут файлы (найдено: System32\Recovery\Settings.ini)
        static readonly string[] hidingRel = {
            "System32\\Recovery", "SysWOW64\\Recovery", "System32\\Tasks", "SysWOW64\\Tasks", "Tasks", "System32\\spool\\drivers\\color",
            "System32\\spool\\PRINTERS", "System32\\spool\\SERVERS", "Debug", "Tracing", "Temp", "Help", "Cursors", "Media", "Web", "Resources",
            "System32\\drivers\\etc", "System32\\LogFiles", "System32\\wbem\\Repository", "System32\\Com\\dmp", "System32\\FxsTmp",
            "System32\\Tasks_Migrated", "SysWOW64\\Tasks_Migrated", "System32\\config", "SysWOW64\\config", "Registration\\CRMLog",
            "PLA", "Prefetch", "Logs", "ServiceState", "Vss", "schemas", "L2Schemas", "Offline Web Pages", "Downloaded Program Files",
            "System32\\Microsoft\\Crypto\\RSA\\MachineKeys", "System32\\catroot2", "SysWOW64\\catroot2", "IME", "INF", "Fonts"
        };
        static string[] hidingDirs;

        /// <summary>Файл лежит в «тайнике» внутри Windows (папка, где обычно нет программ)?</summary>
        public static string HidingSpot(string path)
        {
            if (hidingDirs == null) return null;
            foreach (string d in hidingDirs)
                if (IsUnder(path, d)) return d;
            return null;
        }

        public static Dictionary<string, string> KnownBad = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "8f4b2ec622dc8aa2c71e600bd2ca04d150e430b8fb043afbddc0d77db647ad91", "чит-лоадер «Settings.ini» из System32\\Recovery (найден на проверке)" }
        };

        static void LoadHashList()
        {
            try
            {
                string f = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(SelfPath) ?? "", "hashes.txt");
                if (!File.Exists(f)) return;
                foreach (string line in File.ReadAllLines(f))
                {
                    string t = line.Trim();
                    if (t.Length < 64 || t.StartsWith("#")) continue;
                    string h = t.Substring(0, 64);
                    if (!Regex.IsMatch(h, "^[0-9a-fA-F]{64}$")) continue;
                    string label = t.Substring(64).Trim().TrimStart(';', ',', '|', '-').Trim();
                    KnownBad[h] = label.Length > 0 ? label : "из списка hashes.txt";
                }
            }
            catch { }
        }

        public static string Sha256(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16))
            using (System.Security.Cryptography.SHA256 h = System.Security.Cryptography.SHA256.Create())
                return BitConverter.ToString(h.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
        }

        static readonly HashSet<string> ConfigExts = Set(".ini", ".cfg", ".conf", ".config", ".txt", ".log", ".json", ".xml", ".yml", ".yaml",
            ".properties", ".toml", ".dat", ".db", ".lock", ".tmp", ".etl", ".evtx", ".blf", ".pf", ".mui", ".cat", ".inf", ".pnf", ".ttf", ".png", ".ico");

        // Кэши браузеров/мессенджеров: там лежат скачанные программы без расширения — это не маскировка
        static bool IsCacheDir(string p)
        {
            string l = p.ToLowerInvariant();
            return l.Contains("\\cache\\") || l.Contains("\\cache_data\\") || l.Contains("\\cache2\\") || l.Contains("\\code cache\\") ||
                   l.Contains("\\gpucache\\") || l.Contains("\\inetcache\\") || l.Contains("\\service worker\\") || l.Contains("\\webcache") ||
                   l.Contains("\\temporary internet files\\") || l.Contains("\\deliveryoptimization\\") || l.Contains("\\package cache\\");
        }

        // Библиотеки, которые программы постоянно кладут к себе (часто без подписи) — совпадение имени с System32 не подозрительно
        static readonly HashSet<string> CommonBundled = Set("vulkan-1.dll", "onnxruntime.dll", "directml.dll", "d3dcompiler_47.dll", "libegl.dll",
            "libglesv2.dll", "ffmpeg.dll", "opencl.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll", "ucrtbase.dll", "concrt140.dll",
            "msvcp140_1.dll", "msvcp140_2.dll", "vccorlib140.dll", "dbghelp.dll", "dbgcore.dll", "webview2loader.dll", "libcrypto-3-x64.dll",
            "libssl-3-x64.dll", "zlib1.dll", "sqlite3.dll", "nvapi64.dll", "nvapi.dll", "openal32.dll", "xinput1_3.dll", "d3dx9_43.dll", "msvcr120.dll",
            "msvcp120.dll", "msvcr100.dll", "msvcp100.dll", "msvcr110.dll", "msvcp110.dll", "mfc140u.dll", "libiomp5md.dll", "cudart64_12.dll");

        static bool IsSuspiciousLocation(string p)
        {
            string l = p.ToLowerInvariant();
            return l.Contains("\\temp\\") || l.Contains("\\appdata\\") || l.Contains("\\downloads\\") || l.Contains("\\desktop\\") ||
                   l.Contains("\\$recycle.bin\\") || l.Contains("\\programdata\\") || l.Contains("\\public\\");
        }

        /// <summary>Каталог входит в установку Java (JDK/JRE/рантайм лаунчера)?</summary>
        public static bool IsJavaRuntimeDir(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return false;
            bool v;
            if (javaDirCache.TryGetValue(dir, out v)) return v;
            v = false;
            try
            {
                string d = dir;
                for (int i = 0; i < 4 && !string.IsNullOrEmpty(d); i++)
                {
                    if (File.Exists(System.IO.Path.Combine(d, "java.exe")) || File.Exists(System.IO.Path.Combine(d, "jvm.dll")) ||
                        File.Exists(System.IO.Path.Combine(d, "bin\\java.exe")) || File.Exists(System.IO.Path.Combine(d, "server\\jvm.dll")) ||
                        File.Exists(System.IO.Path.Combine(d, "bin\\server\\jvm.dll")))
                    { v = true; break; }
                    d = System.IO.Path.GetDirectoryName(d);
                }
            }
            catch { }
            javaDirCache[dir] = v;
            return v;
        }

        public static bool ShouldAnalyze(string path, string ext, ScanOptions o)
        {
            if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)) return true;
            if (ext.Equals(".jar", StringComparison.OrdinalIgnoreCase)) return o.ScanJars;
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) return o.ScanExe && (!IsUnder(path, WinDir) || HidingSpot(path) != null);
            if (HidingSpot(path) != null && !ZipExts.Contains(ext)) return true; // в «тайниках» Windows смотрим ЛЮБЫЕ файлы
            if (ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".jar.disabled" || ext == ".disabled")
                return Keywords.HasStrong(System.IO.Path.GetFileName(path));
            if (PeExts.Contains(ext) || ZipExts.Contains(ext)) return false;
            if (o.AllFiles) return true;
            if (o.DisguiseExt && (ext.Length == 0 || FakeExts.Contains(ext))) return true;
            return false;
        }

        public static byte[] Buf() { if (tBuf == null) tBuf = new byte[BUF]; return tBuf; }
        static byte[] UBuf() { if (tUtf == null) tUtf = new byte[BUF]; return tUtf; }

        /// <summary>Сканирует кусок: ASCII (регистронезависимо) + извлечённые UTF-16 строки.</summary>
        public static void ScanChunk(byte[] buf, int len, int[] counts, ref int st1, ref int st2)
        {
            byte[] u = UBuf();
            if (u.Length < len) { tUtf = u = new byte[len]; }
            int ul = 0;
            int i = 0;
            while (i + 1 < len)
            {
                byte b = buf[i];
                if (buf[i + 1] == 0 && b >= 0x20 && b < 0x7f) { u[ul++] = lowerTab[b]; i += 2; }
                else { if (ul > 0 && u[ul - 1] != 0) u[ul++] = 0; i++; }
            }
            for (int k = 0; k < len; k++) buf[k] = lowerTab[buf[k]];
            Signatures.Matcher.Search(buf, 0, len, ref st1, counts);
            Signatures.Matcher.Search(u, 0, ul, ref st2, counts);
        }

        public static int[] ScanStream(Stream s, long limit)
        {
            int[] counts = new int[Signatures.All.Count];
            byte[] buf = Buf();
            int st1 = 0, st2 = 0;
            long total = 0;
            s.Position = 0;
            while (total < limit)
            {
                int want = (int)Math.Min(buf.Length, limit - total);
                int r = s.Read(buf, 0, want);
                if (r <= 0) break;
                total += r;
                ScanChunk(buf, r, counts, ref st1, ref st2);
            }
            return counts;
        }

        static string DescribeMagic(byte[] h, int n)
        {
            if (n >= 4 && h[0] == 'P' && h[1] == 'K' && (h[2] == 3 || h[2] == 5 || h[2] == 7)) return "ZIP/JAR";
            if (n >= 8 && h[0] == 0xCA && h[1] == 0xFE && h[2] == 0xBA && h[3] == 0xBE && h[7] >= 45 && h[7] < 90) return "Java class";
            if (n >= 2 && h[0] == 'M' && h[1] == 'Z') return "PE";
            if (n >= 4 && h[0] == 0x7F && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') return "ELF";
            if (n >= 6 && h[0] == '7' && h[1] == 'z' && h[2] == 0xBC && h[3] == 0xAF) return "7-Zip";
            if (n >= 4 && h[0] == 'R' && h[1] == 'a' && h[2] == 'r' && h[3] == '!') return "RAR";
            if (n >= 4 && h[0] == 0x89 && h[1] == 'P' && h[2] == 'N' && h[3] == 'G') return "PNG";
            if (n >= 3 && h[0] == 0xFF && h[1] == 0xD8 && h[2] == 0xFF) return "JPEG";
            if (n >= 4 && h[0] == '%' && h[1] == 'P' && h[2] == 'D' && h[3] == 'F') return "PDF";
            if (n >= 2 && h[0] == 0x1F && h[1] == 0x8B) return "GZIP";
            if (n == 0) return "пустой";
            int printable = 0;
            for (int i = 0; i < n; i++) if (h[i] == 9 || h[i] == 10 || h[i] == 13 || (h[i] >= 32 && h[i] < 127) || h[i] >= 0xC0) printable++;
            if (printable > n * 0.95) return "текст";
            return "данные";
        }

        static int Levenshtein(string a, string b)
        {
            if (Math.Abs(a.Length - b.Length) > 1) return 99;
            int[] prev = new int[b.Length + 1], cur = new int[b.Length + 1];
            for (int j = 0; j <= b.Length; j++) prev[j] = j;
            for (int i = 1; i <= a.Length; i++)
            {
                cur[0] = i;
                for (int j = 1; j <= b.Length; j++)
                {
                    int c = a[i - 1] == b[j - 1] ? 0 : 1;
                    cur[j] = Math.Min(Math.Min(prev[j] + 1, cur[j - 1] + 1), prev[j - 1] + c);
                }
                int[] t = prev; prev = cur; cur = t;
            }
            return prev[b.Length];
        }

        static string Homoglyph(string s)
        {
            return s.Replace('1', 'l').Replace('0', 'o').Replace('3', 'e').Replace('5', 's').Replace("rn", "m").Replace("vv", "w");
        }

        // ================== главный анализ файла ==================
        public static Finding AnalyzeFile(FileInfo fi, ScanOptions o) { return AnalyzeFile(fi, o, false); }

        /// <summary>keepClean = true — вернуть результат даже для чистого файла (ручная проверка).</summary>
        public static Finding AnalyzeFile(FileInfo fi, ScanOptions o, bool keepClean)
        {
            string path = fi.FullName;
            if (!string.IsNullOrEmpty(SelfPath) && path.Equals(SelfPath, StringComparison.OrdinalIgnoreCase)) return null;
            long size = fi.Length;
            string ext = fi.Extension.ToLowerInvariant();
            Finding f = new Finding();
            f.Path = path; f.FileName = fi.Name; f.Ext = ext; f.Size = size;
            try { f.Modified = fi.LastWriteTime; f.Created = fi.CreationTime; } catch { }

            bool isDllExt = ext == ".dll";
            bool isExeExt = ext == ".exe";
            bool isJarExt = ext == ".jar";
            string dir = System.IO.Path.GetDirectoryName(path) ?? "";
            bool inSysRoot = dir.Equals(Sys32, StringComparison.OrdinalIgnoreCase) || dir.Equals(SysWow, StringComparison.OrdinalIgnoreCase);
            bool inWindows = IsUnder(path, WinDir);
            bool needSig = false;
            bool isPe = false;
            bool disguised = false;
            string hiding = HidingSpot(path);

            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan))
            {
                byte[] head = new byte[64];
                int hn = fs.Read(head, 0, head.Length);
                string magic = DescribeMagic(head, hn);

                if (magic == "PE")
                {
                    isPe = true;
                    PeInfo pe = PeInfo.Parse(fs);
                    f.RealType = pe.Describe();
                    if (pe.Valid)
                    {
                        if (isDllExt && !pe.IsDll && pe.Subsystem != 1)
                            f.Add(60, "Это EXE, а не DLL: у файла .dll нет флага IMAGE_FILE_DLL (запускаемая программа под видом библиотеки)");
                        if (isExeExt && pe.IsDll)
                            f.Add(15, "Это DLL с расширением .exe");
                        bool backup = (ext == ".bak" || ext == ".old" || ext == ".orig" || ext == ".backup") &&
                            Regex.IsMatch(fi.Name, @"\.(dll|exe|sys|jar)\.(bak|old|orig|backup)$", RegexOptions.IgnoreCase);
                        if (backup) f.Note("Резервная копия программы (" + fi.Name + ")");
                        else if (ext.Length == 0 && !inWindows && (IsCacheDir(path) || Regex.IsMatch(fi.Name, "^[0-9a-fA-F]{24,}$")))
                            f.Note("Программа в кэше браузера/приложения (скачанный файл) — не маскировка");
                        else if (!isDllExt && !isExeExt && !PeExts.Contains(ext) && (disguised = true))
                            f.Add(ext == ".bin" && !inWindows ? 20 : ext.Length == 0 || FakeExts.Contains(ext) ? 55 : 35,
                                "Исполняемый PE-файл (" + pe.Describe() + ") замаскирован под расширение «" + (ext.Length == 0 ? "без расширения" : ext) + "»");

                        if (disguised && size >= 1024 * 1024 && ConfigExts.Contains(ext))
                            f.Add(15, "«" + ext + "»-файл весом " + (size / 1048576.0).ToString("0.#") + " МБ, а внутри программа — настоящие " + ext + " такими не бывают");
                        if (inWindows && (disguised || hiding != null)) needSig = true;
                        bool javaDir = IsJavaRuntimeDir(dir);
                        if (!javaDir)
                        {
                            if (pe.ImportDlls.Contains("jvm.dll"))
                                f.Add(35, "Статически импортирует jvm.dll — нативный модуль для работы внутри Java/Minecraft вне папки Java");
                            foreach (string ex in pe.Exports)
                            {
                                if (ex == "Agent_OnAttach" || ex == "Agent_OnLoad")
                                { f.Add(30, "Экспортирует " + ex + " — JVMTI-агент, который можно подгрузить в работающий javaw"); break; }
                            }
                            int javaExports = pe.Exports.Count(x => x.StartsWith("Java_"));
                            if (javaExports > 0)
                            {
                                string first = pe.Exports.First(x => x.StartsWith("Java_"));
                                f.Note("JNI-библиотека: " + javaExports + " экспорт(ов) Java_*, напр. " + first);
                                string pl = first.ToLowerInvariant().Replace('_', '/');
                                int[] c2 = new int[Signatures.All.Count];
                                int s1 = 0;
                                byte[] nb = Encoding.ASCII.GetBytes(pl);
                                Signatures.Matcher.Search(nb, 0, nb.Length, ref s1, c2);
                                ApplyHits(f, c2, false, true);
                            }
                            if (pe.ExportDllName != null && !pe.ExportDllName.Equals(fi.Name, StringComparison.OrdinalIgnoreCase) && pe.Exports.Count > 0)
                                f.Note("Внутреннее имя библиотеки: " + pe.ExportDllName);
                        }

                        if (o.DeepContent && size <= o.MaxContent * 4)
                        {
                            int[] counts = ScanStream(fs, o.MaxContent);
                            ApplyHits(f, counts, true, javaDir);
                        }

                        // Подмена системных DLL
                        if (isDllExt)
                        {
                            string baseName = System.IO.Path.GetFileNameWithoutExtension(fi.Name).ToLowerInvariant();
                            if (!inWindows && systemNames.Contains(fi.Name) && !Signatures.KnownJavaNatives.Contains(fi.Name) && !CommonBundled.Contains(fi.Name))
                            {
                                needSig = true;
                                f.Reasons.Add("?sysname");
                            }
                            else if (!systemNames.Contains(fi.Name) && !Signatures.KnownJavaNatives.Contains(fi.Name))
                            {
                                string hb = Homoglyph(baseName);
                                foreach (string t in Signatures.MimicTargets)
                                {
                                    if (baseName == t) continue;
                                    if (hb == Homoglyph(t) || (baseName.Length >= 5 && Levenshtein(baseName, t) == 1 && !char.IsDigit(baseName[baseName.Length - 1]) == !char.IsDigit(t[t.Length - 1])))
                                    {
                                        f.Add(50, "Имя подделывает системную библиотеку «" + t + ".dll» (опечатка/подмена символов)");
                                        break;
                                    }
                                }
                            }
                            if (inSysRoot && o.SystemSigCheck) { needSig = true; f.Reasons.Add("?sysroot"); }
                        }
                    }
                    else f.Add(20, "Повреждённый PE-заголовок (MZ без корректного PE)");
                }
                else if (magic == "ZIP/JAR")
                {
                    JarInfo ji = new JarInfo();
                    if (!isJarExt && ZipExts.Contains(ext)) { f.RealType = "архив " + ext; goto zipDone; }
                    int[] counts = new int[Signatures.All.Count];
                    try
                    {
                        fs.Position = 0;
                        using (ZipArchive za = new ZipArchive(fs, ZipArchiveMode.Read, true))
                            AnalyzeZip(za, ji, counts, 0);
                        ji.TemplateHit = ji.HasLpng && ji.HasMcmod && size >= 21 * 1024 && size <= 10L * 1024 * 1024;
                    }
                    catch { ji.Broken = true; }
                    f.RealType = ji.Classes > 0 ? "JAR (Java, " + ji.Classes + " классов)" : "ZIP-архив";
                    if (ji.ModName != null) f.RealType += " · " + ji.ModName;
                    bool jarBackup = Regex.IsMatch(fi.Name, @"\.jar\.(bak|old|orig|backup)$", RegexOptions.IgnoreCase);
                    if (jarBackup) f.Note("Резервная копия .jar");
                    else if (ji.Classes > 0 && !isJarExt)
                        f.Add(isDllExt ? 75 : 55, "Java-архив (JAR с " + ji.Classes + " классами) замаскирован под «" + (ext.Length == 0 ? "без расширения" : ext) + "»");
                    else if (ji.Classes == 0 && isDllExt)
                        f.Add(30, "Файл .dll на самом деле ZIP-архив");
                    if (ji.Classes > 0)
                    {
                        ApplyHits(f, counts, false, true);
                        bool mc = counts.Length > 0 && HasToken(counts, "net/minecraft/");
                        bool lib = path.IndexOf("\\libraries\\", StringComparison.OrdinalIgnoreCase) >= 0 || path.IndexOf("\\.gradle\\", StringComparison.OrdinalIgnoreCase) >= 0 || path.IndexOf("\\.m2\\", StringComparison.OrdinalIgnoreCase) >= 0;
                        if (ji.Agent != null && lib) f.Note("Java-агент из библиотек лаунчера/сборщика: " + ji.Agent);
                        else if (ji.Agent != null)
                        {
                            f.Add(12, "Java-агент (" + ji.Agent + ") — может внедряться в уже запущенную JVM");
                            if (mc) f.Add(20, "Агент работает с классами Minecraft — типично для инжект-клиентов");
                        }
                        if (ji.Classes >= 15 && ji.ShortNames >= ji.Classes * 0.6)
                        {
                            f.Add(mc ? 18 : 8, "Сильная обфускация имён классов (" + ji.ShortNames + " из " + ji.Classes + ")");
                        }
                        if (ji.NestedJars > 0) f.Note("Вложенных JAR: " + ji.NestedJars);
                        if (ji.Loader != null) f.Note("Загрузчик: " + ji.Loader);
                    }
                    if (ji.Broken) f.Note("Архив повреждён или зашифрован");
                    if (ji.TemplateHit) f.Add(55, "Совпадает с шаблоном чита из списка: jar 21 КБ–10 МБ с «l.png» и «mcmod.info»");
                zipDone: ;
                }
                else if (magic == "Java class")
                {
                    f.RealType = "Java class (байткод)";
                    if (ext != ".class") f.Add(isDllExt ? 65 : 45, "Скомпилированный Java-класс замаскирован под «" + ext + "»");
                    int[] counts = ScanStream(fs, o.MaxContent);
                    ApplyHits(f, counts, false, true);
                }
                else
                {
                    f.RealType = magic;
                    if (isDllExt && size > 0 && magic != "пустой")
                        f.Add(magic == "ELF" || magic == "7-Zip" || magic == "RAR" || magic == "GZIP" ? 30 : 15,
                            "Файл .dll не является библиотекой Windows (содержимое: " + magic + ")");
                    else if (isExeExt && magic != "пустой" && size > 0)
                        f.Add(10, "Файл .exe не является программой Windows (содержимое: " + magic + ")");
                }
            }

            // ---- правила из списка: точные размеры и шаблоны ----
            if (isJarExt && SizeRules.JarSizes.Contains(size))
                f.Add(30, "Размер " + size.ToString("N0") + " байт точно совпадает с известным чит-jar из списка");
            else if ((isPe || isDllExt || isExeExt) && SizeRules.BinSizes.Contains(size))
                f.Add(25, "Размер " + size.ToString("N0") + " байт точно совпадает с известным чит-файлом из списка");
            if (size == 30720 && f.Reasons.Any(r => r.Contains("net/minecraft/")))
                f.Add(60, "Шаблон из списка: файл 30 720 байт со строками классов Minecraft (ClientPlayerEntity/AxisAlignedBB) — инжект-модуль");
            // ---- запрещённые слова в имени файла/папки ----
            {
                List<Keywords.Kw> nameHits = Keywords.Match(fi.Name);
                List<Keywords.Kw> dirHits = Keywords.Match(dir).Where(k => k.Strong && !nameHits.Contains(k)).ToList();
                bool mcContext = isJarExt || path.IndexOf("minecraft", StringComparison.OrdinalIgnoreCase) >= 0 || path.IndexOf("launcher", StringComparison.OrdinalIgnoreCase) >= 0 || path.IndexOf("\\mods", StringComparison.OrdinalIgnoreCase) >= 0;
                foreach (Keywords.Kw k in nameHits)
                {
                    if (k.Strong) f.Add(isJarExt || isExeExt || isDllExt ? 50 : 40, "Имя файла содержит запрещённое слово «" + k.Word + "»");
                    else if (mcContext || isExeExt) f.Add(16, "Имя содержит слово из списка «" + k.Word + "» (частое слово — проверь вручную)");
                }
                foreach (Keywords.Kw k in dirHits.Take(2))
                    f.Add(30, "Лежит в папке со словом из списка «" + k.Word + "»");
            }

            // ---- проверка цифровой подписи ----
            bool sysName = f.Reasons.Remove("?sysname");
            bool sysRoot = f.Reasons.Remove("?sysroot");
            bool signedOk = false, knownBad = false;
            if (isPe && (f.Score > 0 || needSig || keepClean))
            {
                f.Sig = Native.CheckSignature(path);
                if (f.Sig.Trusted)
                {
                    signedOk = true;
                    int before = f.Score;
                    int after = f.Sig.IsMicrosoft ? before / 8 : before / 5;
                    if (before > 0) f.Add(after - before, f.Sig.ToString() + " — оценка снижена");
                    else f.Note(f.Sig.ToString());
                }
                else
                {
                    if (f.Sig.State == SigState.Invalid) f.Add(25, "Цифровая подпись недействительна — файл изменён после подписания");
                    if (sysName) f.Add(22, "Имя совпадает с системной библиотекой Windows («" + fi.Name + "»), но файл лежит вне Windows и НЕ подписан");
                    bool oldMs = false;
                    if (sysRoot)
                    {
                        try
                        {
                            System.Diagnostics.FileVersionInfo vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
                            oldMs = vi.CompanyName != null && vi.CompanyName.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 &&
                                    (DateTime.Now - f.Modified).TotalDays > 365 && (DateTime.Now - f.Created).TotalDays > 30;
                        }
                        catch { }
                        if (oldMs) f.Note("Старая библиотека Microsoft без подписи (" + f.Modified.Year + ") — обычный старый рантайм");
                    }
                    if (sysRoot && !oldMs)
                    {
                        f.Add(30, "Неподписанная библиотека прямо в " + dir + " — Windows такие не ставит");
                        if ((DateTime.Now - f.Modified).TotalDays < 30) f.Add(10, "Изменена недавно: " + f.Modified.ToString("dd.MM.yyyy HH:mm"));
                        if (systemNames.Contains(fi.Name) && f.Sig.State == SigState.Unsigned) f.Note("Возможна ПОДМЕНА системного файла");
                    }
                    if (inWindows && disguised)
                        f.Add(40, "Спрятан ВНУТРИ папки Windows (" + dir + ") под видом «" + ext + "» и без подписи — Windows так не делает, это приём читов/лоадеров");
                    else if (hiding != null)
                        f.Add(45, "Неподписанная программа в папке Windows, где программ быть не должно (" + hiding.Substring(WinDir.Length + 1) + ")");
                    if (f.Score >= 15) f.Note(f.Sig.ToString());
                }
            }
            if (isPe && (disguised || hiding != null) && f.Score >= 15)
            {
                try
                {
                    FileAttributes a = fi.Attributes;
                    if ((a & (FileAttributes.Hidden | FileAttributes.System)) != 0)
                        f.Add(10, "У файла атрибуты " + ((a & FileAttributes.Hidden) != 0 ? "«скрытый» " : "") + ((a & FileAttributes.System) != 0 ? "«системный»" : "") + " — прячут от проводника");
                }
                catch { }
            }
            if ((isPe || disguised || f.Score >= 15) && size <= 512L * 1024 * 1024)
            {
                try
                {
                    f.Sha256 = Sha256(path);
                    string lbl;
                    if (KnownBad.TryGetValue(f.Sha256, out lbl)) { f.Add(150, "ИЗВЕСТНЫЙ ЧИТ по хэшу SHA-256: " + lbl); knownBad = true; }
                }
                catch { }
            }
            // Файл подтверждён системой (действительная цифровая подпись) — не трогаем
            if (signedOk && !knownBad)
            {
                if (!keepClean) return null;
                f.Score = 0; f.Reasons.Clear();
                f.Note(f.Sig.ToString() + " — файл подтверждён системой, не считается подозрительным");
                f.Finish();
                return f;
            }
            if (f.Score >= 15 && f.Score < 60 && IsSuspiciousLocation(path) && !f.ManySigs && (f.Sig == null || !f.Sig.Trusted))
                f.Add(8, "Расположение типично для читов/лоадеров (Temp/AppData/Downloads/.minecraft)");

            f.Finish();
            if (f.Severity == 0 && keepClean && f.Reasons.Count == 0) f.Note("Признаков чита не найдено");
            return f.Severity > 0 || keepClean ? f : null;
        }

        class JarInfo
        {
            public int Classes, ShortNames, NestedJars;
            public string Agent, ModName, Loader;
            public bool Broken, TemplateHit;
            public bool HasLpng, HasMcmod;
        }

        static readonly Regex rxName = new Regex("\"name\"\\s*:\\s*\"([^\"]{1,80})\"", RegexOptions.Compiled);
        static readonly Regex rxToml = new Regex("displayName\\s*=\\s*\"([^\"]{1,80})\"", RegexOptions.Compiled);

        static void AnalyzeZip(ZipArchive za, JarInfo ji, int[] counts, int depth)
        {
            StringBuilder names = new StringBuilder();
            long budget = 48L * 1024 * 1024;
            byte[] buf = Buf();
            foreach (ZipArchiveEntry e in za.Entries)
            {
                string n = e.FullName.Replace('\\', '/');
                names.Append(n).Append('\n');
                string ln = n.ToLowerInvariant();
                if (depth == 0 && ln == "l.png") ji.HasLpng = true;
                if (depth == 0 && ln == "mcmod.info") ji.HasMcmod = true;
                if (ln.EndsWith(".class"))
                {
                    ji.Classes++;
                    string simple = n.Substring(n.LastIndexOf('/') + 1);
                    simple = simple.Substring(0, simple.Length - 6);
                    int dollar = simple.IndexOf('$');
                    if (dollar > 0) simple = simple.Substring(0, dollar);
                    if (simple.Length <= 2 || (simple.Length <= 4 && simple.All(ch => ch == 'I' || ch == 'l' || ch == '1' || ch == 'i' || ch == 'O' || ch == '0')))
                        ji.ShortNames++;
                    if (budget > 0 && e.Length > 0 && e.Length <= 1024 * 1024)
                    {
                        int len = ReadEntry(e, buf);
                        if (len > 0)
                        {
                            budget -= len;
                            int a = 0, b = 0;
                            ScanChunk(buf, len, counts, ref a, ref b);
                        }
                    }
                }
                else if (ln == "meta-inf/manifest.mf" && e.Length < 65536)
                {
                    string m = ReadText(e);
                    foreach (string key in new string[] { "Launcher-Agent-Class", "Agent-Class", "Premain-Class" })
                    {
                        Match mm = Regex.Match(m, "^" + key + ":\\s*(\\S+)", RegexOptions.Multiline);
                        if (mm.Success) { ji.Agent = key + ": " + mm.Groups[1].Value; break; }
                    }
                }
                else if ((ln == "fabric.mod.json" || ln == "quilt.mod.json") && e.Length < 262144)
                {
                    Match mm = rxName.Match(ReadText(e));
                    if (mm.Success && ji.ModName == null) ji.ModName = mm.Groups[1].Value;
                    ji.Loader = ln.StartsWith("fabric") ? "Fabric" : "Quilt";
                    ScanTextEntry(e, counts);
                }
                else if (ln == "meta-inf/mods.toml" || ln == "meta-inf/neoforge.mods.toml")
                {
                    Match mm = rxToml.Match(ReadText(e));
                    if (mm.Success && ji.ModName == null) ji.ModName = mm.Groups[1].Value;
                    ji.Loader = ln.Contains("neoforge") ? "NeoForge" : "Forge";
                    ScanTextEntry(e, counts);
                }
                else if (ln == "mcmod.info" && e.Length < 262144)
                {
                    Match mm = rxName.Match(ReadText(e));
                    if (mm.Success && ji.ModName == null) ji.ModName = mm.Groups[1].Value;
                    if (ji.Loader == null) ji.Loader = "Forge (старый)";
                }
                else if (ln.EndsWith(".jar") && depth < 2 && e.Length > 0 && e.Length <= 32L * 1024 * 1024)
                {
                    ji.NestedJars++;
                    try
                    {
                        MemoryStream ms = new MemoryStream();
                        using (Stream es = e.Open()) es.CopyTo(ms);
                        ms.Position = 0;
                        using (ZipArchive inner = new ZipArchive(ms, ZipArchiveMode.Read))
                        {
                            JarInfo sub = new JarInfo();
                            AnalyzeZip(inner, sub, counts, depth + 1);
                        }
                    }
                    catch { }
                }
            }
            byte[] nb = Encoding.UTF8.GetBytes(names.ToString());
            int s1 = 0, s2 = 0;
            for (int i = 0; i < nb.Length; i++) nb[i] = lowerTab[nb[i]];
            Signatures.Matcher.Search(nb, 0, nb.Length, ref s1, counts);
            s2 = 0;
        }

        static void ScanTextEntry(ZipArchiveEntry e, int[] counts)
        {
            byte[] nb = Encoding.UTF8.GetBytes(ReadText(e).ToLowerInvariant());
            int s = 0;
            Signatures.Matcher.Search(nb, 0, nb.Length, ref s, counts);
        }

        static int ReadEntry(ZipArchiveEntry e, byte[] buf)
        {
            try
            {
                using (Stream s = e.Open())
                {
                    int got = 0;
                    while (got < buf.Length)
                    {
                        int r = s.Read(buf, got, buf.Length - got);
                        if (r <= 0) break;
                        got += r;
                    }
                    return got;
                }
            }
            catch { return 0; }
        }

        static string ReadText(ZipArchiveEntry e)
        {
            try { using (StreamReader r = new StreamReader(e.Open(), Encoding.UTF8)) return r.ReadToEnd(); }
            catch { return ""; }
        }

        static bool HasToken(int[] counts, string token)
        {
            for (int i = 0; i < Signatures.All.Count; i++)
                if (counts[i] > 0 && Signatures.All[i].Token == token) return true;
            return false;
        }

        /// <summary>Превращает найденные сигнатуры в баллы и причины.</summary>
        public static void ApplyHits(Finding f, int[] counts, bool nativeCode, bool javaRuntime)
        {
            Dictionary<string, Sig> clients = new Dictionary<string, Sig>();
            SortedSet<string> modules = new SortedSet<string>();
            Dictionary<string, Sig> evasion = new Dictionary<string, Sig>();
            Dictionary<string, Sig> jni = new Dictionary<string, Sig>();
            Dictionary<string, Sig> inj = new Dictionary<string, Sig>();
            bool javaw = false, mc = false;
            SortedSet<string> kws = new SortedSet<string>();
            for (int i = 0; i < counts.Length; i++)
            {
                if (counts[i] == 0) continue;
                Sig s = Signatures.All[i];
                switch (s.Kind)
                {
                    case SigKind.ClientPackage:
                    case SigKind.ClientName:
                        Sig old;
                        if (!clients.TryGetValue(s.Label, out old) || old.Weight < s.Weight) clients[s.Label] = s;
                        break;
                    case SigKind.CheatModule: modules.Add(s.Label); break;
                    case SigKind.Evasion: evasion[s.Label] = s; break;
                    case SigKind.Jni: jni[s.Label] = s; break;
                    case SigKind.Injector: inj[s.Label] = s; break;
                    case SigKind.Keyword: kws.Add(s.Label); break;
                    case SigKind.Context:
                        if (s.Token.StartsWith("javaw")) javaw = true; else if (s.Token == "minecraft") mc = true;
                        break;
                }
            }

            if (kws.Count >= 10 || clients.Count >= 6)
            {
                f.ManySigs = true;
                f.Add(5, "Содержит названия " + clients.Count + " разных читов — похоже на SS-инструмент/античит/базу сигнатур, а не на чит");
                return;
            }
            foreach (Sig s in clients.Values)
            {
                bool already = f.Reasons.Any(r => r.Contains("Сигнатура чита: " + s.Label + " "));
                if (already) continue;
                f.Add(s.Weight, "Сигнатура чита: " + s.Label + " (" + (s.Kind == SigKind.ClientPackage ? "пакет" : "строка") + " «" + s.Token + "»)");
            }
            if (kws.Count > 0)
            {
                if (nativeCode) f.Add(Math.Min(70, 30 + 10 * kws.Count), "Внутри программы найдены слова из списка (" + kws.Count + "): " + string.Join(", ", kws.Take(8)));
                else f.Add(Math.Min(20, 8 * kws.Count), "Упоминает моды/читы из списка (" + kws.Count + "): " + string.Join(", ", kws.Take(8)) + " — часто это просто совместимость, само по себе не чит");
            }
            if (modules.Count >= 3)
                f.Add(Math.Min(60, 15 + 10 * modules.Count), "Модули чита (" + modules.Count + "): " + string.Join(", ", modules));
            else if (modules.Count > 0)
                f.Add(8 * modules.Count, "Возможные модули чита: " + string.Join(", ", modules));
            foreach (Sig s in evasion.Values)
            {
                if (clients.Count > 0 || modules.Count > 0) f.Add(s.Weight, "Анти-SS функция: " + s.Label + " («" + s.Token + "»)");
                else f.Note("Строка «" + s.Token + "» (само по себе не признак)");
            }

            if (nativeCode && !javaRuntime)
            {
                int sum = jni.Values.Sum(x => x.Weight);
                if (sum >= 20)
                {
                    f.Add(Math.Min(70, sum), "Нативный код работает изнутри JVM (признак инжект-клиента): " + string.Join(", ", jni.Keys));
                    if (javaw || mc) f.Add(10, "Упоминает javaw/minecraft");
                }
                if (javaw && inj.Count >= 2)
                    f.Add(60, "Инжектор: ищет javaw.exe и внедряет код (" + string.Join(", ", inj.Keys) + ")");
                else if (inj.Count >= 4)
                    f.Add(Math.Min(25, inj.Values.Sum(x => x.Weight)), "Использует API внедрения кода в чужие процессы: " + string.Join(", ", inj.Keys));
            }
        }
    }
}
