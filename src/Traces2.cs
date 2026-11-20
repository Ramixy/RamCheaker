using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace InjectHunter
{
    /// <summary>Те же источники, что смотрят встроенные программы (WinPrefetchView, JournalTrace, ShellBag Analyzer,
    /// CachedProgramsList, OpenSaveFilesView, RecentFilesView, BrowserDownloadsView, BrowsingHistoryView, RegScanner,
    /// Autoruns, Recuva) — только чекер проверяет их сам и сразу сверяет со списком слов и сайтов читов.</summary>
    partial class TraceScanner
    {
        /// <summary>Источники, где слово ищется только в имени (а не во всём пути) — иначе одна папка со словом даёт сотни строк.</summary>
        static readonly HashSet<string> NameOnly = new HashSet<string> { "MC", "DL", "REG", "SB", "USN", "PFX", "BIN" };

        void AddExtraSteps(List<KeyValuePair<string, Action>> steps)
        {
            steps.Add(Step("Prefetch: какие файлы открывала программа при запуске", PrefetchFiles));
            steps.Add(Step("PCA: журнал запуска программ Windows 11", Pca));
            steps.Add(Step("ShimCache (AppCompatCache)", ShimCache));
            steps.Add(Step("ShellBags: какие папки открывали", ShellBags));
            steps.Add(Step("Окна «Открыть/Сохранить», недавние документы, «Выполнить»", Mru));
            steps.Add(Step("Списки переходов (Jump Lists)", JumpLists));
            steps.Add(Step("Корзина", RecycleBin));
            steps.Add(Step("USN-журнал: созданные, удалённые, переименованные файлы", Usn));
            steps.Add(Step("Реестр: разделы с названиями читов", RegistryKeys));
            steps.Add(Step("История загрузок браузеров", BrowserDownloads));
            steps.Add(Step("Данные браузеров: cookies, логины, закладки, сессии", BrowserData));
            steps.Add(Step("Защитник Windows: найденные угрозы", Defender));
            steps.Add(Step("Автозапуск: задачи планировщика и службы", TasksAndServices));
            steps.Add(Step("Режимы совместимости (Layers)", Layers));
            steps.Add(Step("События Windows: падения программ и установки", EventLogs));
            steps.Add(Step("Реестр: значения со словами читов", RegistryValues));
        }

        // ---------- строки из двоичных данных ----------
        static readonly Regex u16 = new Regex(@"[\u0020-\u007E\u00A0-\u024F\u0400-\u04FF]{3,260}", RegexOptions.Compiled);
        static readonly Regex pathRx = new Regex(@"(?:[A-Za-z]:\\|\\\\\?\\|\\VOLUME\{|\\DEVICE\\)[^\u0000-\u001F""<>|]{2,260}", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>UTF-16 строки из байтов (с обоих выравниваний).</summary>
        static List<string> Utf16Strings(byte[] b, int min)
        {
            List<string> res = new List<string>();
            if (b == null) return res;
            for (int off = 0; off < 2 && off < b.Length; off++)
            {
                string s = Encoding.Unicode.GetString(b, off, (b.Length - off) & ~1);
                foreach (Match m in u16.Matches(s)) if (m.Length >= min) res.Add(m.Value.Trim());
            }
            return res;
        }

        static List<string> Paths(string s)
        {
            List<string> r = new List<string>();
            foreach (Match m in pathRx.Matches(s)) r.Add(m.Value.TrimEnd(' ', '.'));
            return r;
        }

        static byte[] ReadShared(string path, long max)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long len = Math.Min(fs.Length, max);
                    byte[] b = new byte[len]; int off = 0, n;
                    while (off < len && (n = fs.Read(b, off, (int)Math.Min(len - off, 1 << 20))) > 0) off += n;
                    return b;
                }
            }
            catch { return null; }
        }

        static string VolPath(string p)
        {
            Match m = Regex.Match(p, @"^\\VOLUME\{[^}]+\}", RegexOptions.IgnoreCase);
            if (m.Success) return "?:" + p.Substring(m.Length);
            if (p.StartsWith("\\DEVICE\\", StringComparison.OrdinalIgnoreCase)) return Native.DevicePathToDos(p);
            return p;
        }

        // ---------- Prefetch: файлы, которые открывались при запуске (как WinPrefetchView) ----------
        [DllImport("ntdll.dll")] static extern uint RtlGetCompressionWorkSpaceSize(ushort fmt, out uint ws, out uint fws);
        [DllImport("ntdll.dll")] static extern uint RtlDecompressBufferEx(ushort fmt, byte[] dst, int dstSize, byte[] src, int srcSize, out int final, byte[] ws);

        static byte[] PfDecompress(byte[] b)
        {
            if (b == null || b.Length < 8) return null;
            if (b[0] == 'M' && b[1] == 'A' && b[2] == 'M')
            {
                int size = BitConverter.ToInt32(b, 4);
                if (size <= 0 || size > 64 * 1024 * 1024) return null;
                uint ws, fws;
                if (RtlGetCompressionWorkSpaceSize(4, out ws, out fws) != 0) return null;
                byte[] w = new byte[ws], dst = new byte[size];
                byte[] src = new byte[b.Length - 8]; Buffer.BlockCopy(b, 8, src, 0, src.Length);
                int fin;
                return RtlDecompressBufferEx(4, dst, size, src, src.Length, out fin, w) == 0 ? dst : null;
            }
            return b.Length > 8 && b[4] == 'S' && b[5] == 'C' && b[6] == 'C' && b[7] == 'A' ? b : null;
        }

        void PrefetchFiles()
        {
            string dir = Path.Combine(Analyzer.WinDir, "Prefetch");
            string[] pfs;
            try { pfs = Directory.GetFiles(dir, "*.pf"); } catch { Note("Prefetch", "нужны права администратора"); return; }
            foreach (string pf in pfs)
            {
                string exe = Path.GetFileNameWithoutExtension(pf);
                int dash = exe.LastIndexOf('-'); if (dash > 0) exe = exe.Substring(0, dash);
                Current = "Prefetch · " + exe;
                byte[] d = PfDecompress(ReadShared(pf, 32 * 1024 * 1024));
                if (d == null) continue;
                DateTime t = File.GetLastWriteTime(pf);
                foreach (string s in Utf16Strings(d, 6))
                {
                    if (!s.StartsWith("\\VOLUME{", StringComparison.OrdinalIgnoreCase) && !s.StartsWith("\\DEVICE\\", StringComparison.OrdinalIgnoreCase)) continue;
                    string p = VolPath(s);
                    string ext = Path.GetExtension(p).ToLowerInvariant();
                    if (ext == ".mui" || ext == ".nls" || ext == ".ttf" || ext == ".png") continue;
                    Check("Prefetch " + exe, "PFX", p, SafeName(p), t, ext == ".jar" || ext == ".dll" || ext == ".exe",
                          "Файл открывала программа " + exe + " при запуске (Prefetch " + Path.GetFileName(pf) + ")");
                }
            }
        }

        void Note(string src, string why) { Current = src + ": " + why; }

        // ---------- PCA (Windows 11 22H2+) ----------
        void Pca()
        {
            string dir = Path.Combine(Analyzer.WinDir, "appcompat\\pca");
            foreach (string f in new string[] { "PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt" })
            {
                byte[] b = ReadShared(Path.Combine(dir, f), 64 * 1024 * 1024);
                if (b == null) continue;
                string s = b.Length > 1 && b[1] == 0 || (b.Length > 2 && b[0] == 0xFF && b[1] == 0xFE) ? Encoding.Unicode.GetString(b) : Encoding.UTF8.GetString(b);
                foreach (string line in s.Split('\n'))
                {
                    string[] parts = line.Trim('\r', '\uFEFF').Split('|');
                    string path = parts.FirstOrDefault(x => x.Length > 3 && (x[1] == ':' || x.StartsWith("%")));
                    if (path == null) continue;
                    DateTime t = DateTime.MinValue;
                    foreach (string x in parts) { DateTime d; if (x.Length >= 10 && DateTime.TryParse(x, out d) && d.Year > 2000) { t = d; break; } }
                    Check("PCA " + f, "PCA", Environment.ExpandEnvironmentVariables(path), null, t, true, "Журнал запуска программ Windows (" + f + ")");
                }
            }
        }

        // ---------- ShimCache ----------
        void ShimCache()
        {
            byte[] b;
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"))
                b = k == null ? null : k.GetValue("AppCompatCache") as byte[];
            if (b == null || b.Length < 0x40) return;
            int pos = BitConverter.ToInt32(b, 0);
            if (pos < 0x30 || pos > 0x100) pos = 0x34;
            int guard = 0;
            while (pos + 14 < b.Length && guard++ < 100000)
            {
                if (b[pos] != '1' || b[pos + 1] != '0' || b[pos + 2] != 't' || b[pos + 3] != 's') break;
                int entryLen = BitConverter.ToInt32(b, pos + 8);
                int plen = BitConverter.ToUInt16(b, pos + 12);
                if (pos + 14 + plen + 8 > b.Length || entryLen <= 0) break;
                string path = Encoding.Unicode.GetString(b, pos + 14, plen);
                DateTime t = DateTime.MinValue;
                try { long ft = BitConverter.ToInt64(b, pos + 14 + plen); if (ft > 0) t = DateTime.FromFileTime(ft); } catch { }
                Check("ShimCache", "SHIM", path, null, t, false, "Программа была на ПК (кэш совместимости Windows), время — изменение файла");
                pos += 12 + entryLen;
            }
        }

        // ---------- ShellBags ----------
        void ShellBags()
        {
            foreach (string root in new string[] { @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU", @"Software\Microsoft\Windows\Shell\BagMRU" })
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(root))
                    if (k != null) Bags(k, "", 0);
        }

        void Bags(RegistryKey k, string prefix, int depth)
        {
            if (depth > 20) return;
            foreach (string v in k.GetValueNames())
            {
                int idx; if (!int.TryParse(v, out idx)) continue;
                string name = ShellName(k.GetValue(v) as byte[]);
                if (name == null) continue;
                string p = prefix.Length == 0 ? name : prefix.TrimEnd('\\') + "\\" + name;
                Check("ShellBags", "SB", p, name, DateTime.MinValue, false, "Эту папку открывали в проводнике (ShellBags)");
                try { using (RegistryKey sub = k.OpenSubKey(v)) if (sub != null) Bags(sub, p, depth + 1); } catch { }
            }
        }

        static string ShellName(byte[] b)
        {
            if (b == null || b.Length < 4) return null;
            if (b[2] == 0x2F && b.Length > 5) return Encoding.ASCII.GetString(b, 3, 3).TrimEnd('\0');
            string best = null;
            foreach (string s in Utf16Strings(b, 2)) if (best == null || s.Length > best.Length) best = s;
            if (best != null && best.Length >= 2) return best;
            Match m = Regex.Match(Encoding.ASCII.GetString(b), @"[\x20-\x7E]{3,}");
            return m.Success ? m.Value : null;
        }

        // ---------- MRU (OpenSaveFilesView, RecentFilesView, «Выполнить») ----------
        void Mru()
        {
            string ex = @"Software\Microsoft\Windows\CurrentVersion\Explorer\";
            string[] keys = { ex + "ComDlg32\\OpenSavePidlMRU", ex + "ComDlg32\\LastVisitedPidlMRU", ex + "ComDlg32\\CIDSizeMRU", ex + "RecentDocs",
                              ex + "RunMRU", ex + "TypedPaths", ex + "WordWheelQuery", ex + "FeatureUsage\\AppSwitched", ex + "FeatureUsage\\ShowJumpView", ex + "FeatureUsage\\AppLaunch",
                              @"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps", @"Software\WinRAR\ArcHistory", @"Software\WinRAR\DialogEditHistory\ExtrPath", @"Software\7-Zip\FM" };
            foreach (string kp in keys)
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(kp))
                    if (k != null) MruKey(k, kp.Substring(kp.LastIndexOf('\\') + 1), 0);
        }

        void MruKey(RegistryKey k, string label, int depth)
        {
            string src = label == "OpenSavePidlMRU" ? "Окна «Открыть/Сохранить»" : label == "LastVisitedPidlMRU" || label == "CIDSizeMRU" ? "Программы с окнами «Открыть/Сохранить»"
                       : label == "RecentDocs" ? "Недавние документы" : label == "RunMRU" ? "Окно «Выполнить»" : label == "TypedPaths" ? "Адресная строка проводника"
                       : label == "WordWheelQuery" ? "Поиск в проводнике" : label == "ArcHistory" || label == "ExtrPath" ? "WinRAR" : "Реестр · " + label;
            bool exec = label == "AppSwitched" || label == "ShowJumpView" || label == "AppLaunch" || label == "RunMRU" || label == "RecentApps";
            foreach (string v in k.GetValueNames())
            {
                if (v == "MRUList" || v == "MRUListEx") continue;
                object o = k.GetValue(v);
                List<string> items = new List<string>();
                if (exec && v.Length > 3) items.Add(v);
                if (o is string) items.Add((string)o);
                else if (o is byte[]) items.AddRange(Utf16Strings((byte[])o, 3).Where(s => s.Length >= 4));
                foreach (string it in items.Distinct()) Check(src, "MRU", it.TrimEnd('\\').Replace("\\1", ""), null, DateTime.MinValue, exec, "Запись в реестре: " + k.Name);
            }
            if (depth < 3) foreach (string sk in k.GetSubKeyNames()) try { using (RegistryKey s = k.OpenSubKey(sk)) if (s != null) MruKey(s, label, depth + 1); } catch { }
        }

        // ---------- Jump Lists ----------
        void JumpLists()
        {
            string rec = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            foreach (string sub in new string[] { "AutomaticDestinations", "CustomDestinations" })
            {
                string d = Path.Combine(rec, sub);
                if (!Directory.Exists(d)) continue;
                foreach (string f in Directory.GetFiles(d))
                {
                    byte[] b = ReadShared(f, 16 * 1024 * 1024);
                    if (b == null) continue;
                    DateTime t = File.GetLastWriteTime(f);
                    HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string s in Utf16Strings(b, 6))
                        foreach (string p in Paths(s))
                            if (seen.Add(p)) Check("Списки переходов", "JL", p, null, t, false, "Файл открывали недавно (Jump List)");
                }
            }
        }

        // ---------- Корзина ----------
        void RecycleBin()
        {
            foreach (DriveInfo di in DriveInfo.GetDrives())
            {
                try { if (!di.IsReady || di.DriveType != DriveType.Fixed && di.DriveType != DriveType.Removable) continue; } catch { continue; }
                string rb = Path.Combine(di.RootDirectory.FullName, "$Recycle.Bin");
                string[] sids;
                try { sids = Directory.GetDirectories(rb); } catch { continue; }
                foreach (string sid in sids)
                {
                    string[] files;
                    try { files = Directory.GetFiles(sid, "$I*"); } catch { continue; }
                    foreach (string f in files)
                    {
                        byte[] b = ReadShared(f, 8192);
                        if (b == null || b.Length < 28) continue;
                        long ver = BitConverter.ToInt64(b, 0);
                        DateTime t = DateTime.MinValue;
                        try { t = DateTime.FromFileTime(BitConverter.ToInt64(b, 16)); } catch { }
                        string orig = ver == 2 && b.Length > 28 ? Encoding.Unicode.GetString(b, 28, Math.Min(b.Length - 28, BitConverter.ToInt32(b, 24) * 2)) : Encoding.Unicode.GetString(b, 24, Math.Min(520, b.Length - 24));
                        orig = orig.TrimEnd('\0'); int z = orig.IndexOf('\0'); if (z >= 0) orig = orig.Substring(0, z);
                        string r = Path.Combine(sid, "$R" + Path.GetFileName(f).Substring(2));
                        Check("Корзина", "BIN", orig, SafeName(orig), t, false,
                              "Удалён в корзину " + (t.Year > 2000 ? t.ToString("dd.MM.yyyy HH:mm") : "") + (File.Exists(r) || Directory.Exists(r) ? " — файл ещё в корзине: " + r : " — корзину уже очистили"));
                    }
                }
            }
        }

        // ---------- USN-журнал (как JournalTrace) ----------
        [StructLayout(LayoutKind.Sequential)] struct READ_USN { public long Start; public uint Mask; public uint OnlyOnClose; public ulong Timeout; public ulong Bytes; public ulong Journal; }
        [StructLayout(LayoutKind.Sequential)] struct USN_JOURNAL { public ulong Id; public long First; public long Next; public long Lowest; public long Max; public ulong Size; public ulong Delta; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFile(string n, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool DeviceIoControl(SafeFileHandle h, uint code, IntPtr inb, int ins, out USN_JOURNAL outb, int outs, out int ret, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool DeviceIoControl(SafeFileHandle h, uint code, ref READ_USN inb, int ins, IntPtr outb, int outs, out int ret, IntPtr ov);

        class UsnAgg { public string Name; public uint Reasons; public DateTime Last; public string OldName; }

        void Usn()
        {
            foreach (DriveInfo di in DriveInfo.GetDrives())
            {
                try { if (!di.IsReady || di.DriveFormat != "NTFS") continue; } catch { continue; }
                string vol = di.Name.TrimEnd('\\');
                using (SafeFileHandle h = CreateFile(@"\\.\" + vol, 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid) { Note("USN", "нужны права администратора"); return; }
                    USN_JOURNAL j; int ret;
                    if (!DeviceIoControl(h, 0x000900F4, IntPtr.Zero, 0, out j, Marshal.SizeOf(typeof(USN_JOURNAL)), out ret, IntPtr.Zero)) continue;
                    Dictionary<ulong, UsnAgg> byFrn = new Dictionary<ulong, UsnAgg>();
                    Dictionary<ulong, string> renameOld = new Dictionary<ulong, string>();
                    READ_USN r = new READ_USN(); r.Start = j.First; r.Mask = 0xFFFFFFFF; r.Journal = j.Id;
                    const int BUF = 1 << 20; IntPtr buf = Marshal.AllocHGlobal(BUF);
                    int recs = 0;
                    try
                    {
                        while (recs < 5000000 && DeviceIoControl(h, 0x000900BB, ref r, Marshal.SizeOf(typeof(READ_USN)), buf, BUF, out ret, IntPtr.Zero) && ret > 8)
                        {
                            long next = Marshal.ReadInt64(buf);
                            int off = 8;
                            while (off + 60 <= ret)
                            {
                                int len = Marshal.ReadInt32(buf, off); if (len <= 0) break;
                                if (Marshal.ReadInt16(buf, off + 4) == 2)
                                {
                                    ulong frn = (ulong)Marshal.ReadInt64(buf, off + 8);
                                    long ts = Marshal.ReadInt64(buf, off + 32);
                                    uint reason = (uint)Marshal.ReadInt32(buf, off + 40);
                                    int nl = (ushort)Marshal.ReadInt16(buf, off + 56), no = (ushort)Marshal.ReadInt16(buf, off + 58);
                                    string name = Marshal.PtrToStringUni(new IntPtr(buf.ToInt64() + off + no), nl / 2);
                                    recs++;
                                    if ((reason & 0x1000) != 0) renameOld[frn] = name;
                                    string ext = Path.GetExtension(name).ToLowerInvariant();
                                    bool interesting = ext == ".exe" || ext == ".jar" || ext == ".dll" || ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".bat" || ext == ".class" || ext == ".sys" || ext == ".ahk" || ext == ".pf" || ext == ".lnk" || ext == ".disabled";
                                    if (interesting || Keywords.Match(name).Any(k => k.Strong))
                                    {
                                        UsnAgg a; ulong key = frn ^ (ulong)name.GetHashCode();
                                        if (!byFrn.TryGetValue(key, out a)) byFrn[key] = a = new UsnAgg { Name = name };
                                        a.Reasons |= reason;
                                        try { a.Last = DateTime.FromFileTime(ts); } catch { }
                                        string old;
                                        if ((reason & 0x2000) != 0 && renameOld.TryGetValue(frn, out old) && old != name) a.OldName = old;
                                    }
                                }
                                off += len;
                            }
                            if (next == r.Start) break;
                            r.Start = next;
                            if ((recs & 0x3FFF) == 0) Current = "USN " + vol + " · записей " + recs.ToString("N0");
                        }
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                    Entries += recs;
                    foreach (UsnAgg a in byFrn.Values)
                    {
                        string what = ((a.Reasons & 0x100) != 0 ? "создан, " : "") + ((a.Reasons & 0x200) != 0 ? "УДАЛЁН, " : "") +
                                      (a.OldName != null ? "переименован из «" + a.OldName + "», " : "") + ((a.Reasons & 0x2) != 0 ? "изменён, " : "");
                        Check("USN-журнал " + vol, "USN", vol + "\\…\\" + a.Name, a.Name, a.Last, false, "Журнал файловой системы: " + what.TrimEnd(',', ' '));
                        // смена расширения: был .jar/.exe/.dll, стал «картинкой/конфигом» — так прячут читы перед проверкой
                        if (a.OldName != null)
                        {
                            string oe = Path.GetExtension(a.OldName).ToLowerInvariant(), ne = Path.GetExtension(a.Name).ToLowerInvariant();
                            if ((oe == ".jar" || oe == ".exe" || oe == ".dll") && ne != oe && Analyzer.FakeExts.Contains(ne) && reported.Add("usnren|" + a.OldName + "|" + a.Name))
                            {
                                Finding f = new Finding();
                                f.Path = vol + "\\…\\" + a.Name; f.FileName = a.Name; f.RealType = "USN · смена расширения"; f.Source = "USN-журнал " + vol; f.Modified = a.Last;
                                f.Origin = "Журнал файловой системы";
                                f.Add(35, "Файл переименовали из «" + a.OldName + "» в «" + a.Name + "» — программу/мод спрятали под другое расширение");
                                f.Finish();
                                if (Found != null) Found(f);
                            }
                        }
                    }
                }
            }
        }

        // ---------- реестр (как RegScanner) ----------
        void RegistryKeys()
        {
            Walk(Registry.CurrentUser, "Software", 4);
            Walk(Registry.LocalMachine, "SOFTWARE", 2);
            Walk(Registry.LocalMachine, @"SOFTWARE\WOW6432Node", 2);
        }

        void Walk(RegistryKey hive, string path, int depth)
        {
            RegistryKey k = null;
            try { k = hive.OpenSubKey(path); } catch { }
            if (k == null) return;
            using (k)
            {
                string[] subs;
                try { subs = k.GetSubKeyNames(); } catch { return; }
                foreach (string s in subs)
                {
                    string full = path + "\\" + s;
                    Check("Реестр", "REG", hive.Name + "\\" + full, s, DateTime.MinValue, false, "Раздел реестра — программы создают его при установке/запуске");
                    string l = s.ToLowerInvariant();
                    if (depth > 0 && l != "classes" && l != "microsoft" && l != "policies" && l != "wow6432node") Walk(hive, full, depth - 1);
                }
            }
        }

        // ---------- загрузки браузеров (как BrowserDownloadsView) ----------
        void BrowserDownloads()
        {
            foreach (DlRecord d in DownloadHistory.All)
            {
                Entries++;
                string name = string.IsNullOrEmpty(d.Path) ? (d.Url ?? "") : Path.GetFileName(d.Path);
                string extra = "Скачан в " + d.Browser + " · " + d.Url + (d.Page != null ? " · страница " + d.Page : "") + (File.Exists(d.Path ?? "") ? "" : " · файла уже нет");
                Check("Загрузки " + d.Browser, "DL", d.Path ?? d.Url, name, d.Time, false, extra);
                string site = null;
                foreach (string u in new string[] { d.Url, d.FirstUrl, d.Page, d.Referrer }) if (site == null && u != null) site = Origin.CheatSite(u);
                if (site != null) Site("Загрузки " + d.Browser, d.Url ?? d.Page, Origin.HostOf(d.Url ?? d.Page) ?? site, site, 60, "Скачивали файл «" + name + "» с сайта читов");
            }
        }

        // ---------- cookies, логины, закладки, сессии (как BrowsingHistoryView и др.) ----------
        static readonly Regex domRx = new Regex(@"(?<![a-z0-9.-])\.?([a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,62})*\.[a-z]{2,12})(?![a-z0-9-])", RegexOptions.Compiled);

        void BrowserData()
        {
            string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string ad = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string[] names = { "Cookies", "Login Data", "Login Data For Account", "Web Data", "Favicons", "Top Sites", "Shortcuts", "Bookmarks", "Preferences", "Current Session", "Last Session", "Current Tabs", "Last Tabs", "Visited Links", "Network Action Predictor" };
            List<KeyValuePair<string, string>> files = new List<KeyValuePair<string, string>>();
            foreach (KeyValuePair<string, string> h in WebTraces.HistoryFiles())
            {
                string dir = Path.GetDirectoryName(h.Value);
                if (h.Key == "Firefox")
                {
                    foreach (string n in new string[] { "cookies.sqlite", "favicons.sqlite", "formhistory.sqlite", "logins.json", "sessionstore.jsonlz4", "permissions.sqlite" })
                        files.Add(new KeyValuePair<string, string>("Firefox", Path.Combine(dir, n)));
                    continue;
                }
                foreach (string n in names) files.Add(new KeyValuePair<string, string>(h.Key, Path.Combine(dir, n)));
                files.Add(new KeyValuePair<string, string>(h.Key, Path.Combine(dir, "Network\\Cookies")));
                string ses = Path.Combine(dir, "Sessions");
                if (Directory.Exists(ses)) try { foreach (string f in Directory.GetFiles(ses)) files.Add(new KeyValuePair<string, string>(h.Key, f)); } catch { }
            }
            foreach (KeyValuePair<string, string> f in files)
            {
                if (!File.Exists(f.Value)) continue;
                Current = f.Key + " · " + Path.GetFileName(f.Value);
                byte[] b = ReadShared(f.Value, 256L * 1024 * 1024);
                if (b == null) continue;
                string what = Kind(f.Value);
                HashSet<string> seen = new HashSet<string>();
                // адреса
                foreach (string u in WebTraces.UrlsFromBytes(b))
                {
                    Entries++;
                    string w = Origin.CheatSite(u);
                    if (w != null) Site(f.Key + " · " + what, u, Origin.HostOf(u) ?? u, w, 50, what + ": сайт читов " + (Origin.HostOf(u) ?? u));
                }
                // голые домены (cookies, разрешения сайтов)
                string a = Encoding.ASCII.GetString(b).ToLowerInvariant();
                foreach (Match m in domRx.Matches(a))
                {
                    string d = m.Groups[1].Value;
                    if (!seen.Add(d)) continue;
                    Entries++;
                    string w = Origin.CheatSite(d);
                    if (w != null) Site(f.Key + " · " + what, d, d, w, 50, what + ": сайт читов " + d);
                }
            }
        }

        static string Kind(string f)
        {
            string n = Path.GetFileName(f).ToLowerInvariant();
            if (n.Contains("cookie")) return "Cookies — сайт сохранял данные в браузере, даже если историю очистили";
            if (n.Contains("login")) return "Сохранённый логин — на сайте был аккаунт";
            if (n.Contains("favicon")) return "Значок сайта — сайт открывали";
            if (n.Contains("bookmark")) return "Закладка";
            if (n.Contains("top sites") || n.Contains("shortcuts") || n.Contains("predictor")) return "Часто посещаемый сайт";
            if (n.Contains("session") || n.Contains("tabs")) return "Открытая вкладка";
            if (n.Contains("preferences") || n.Contains("permissions")) return "Настройки сайта в браузере";
            if (n.Contains("web data") || n.Contains("formhistory")) return "Автозаполнение формы";
            return "Данные браузера";
        }

        // ---------- Защитник Windows ----------
        void Defender()
        {
            EventLogQuery q = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, "*[System[(EventID=1116 or EventID=1117 or EventID=1006 or EventID=1015)]]");
            q.ReverseDirection = true;
            int n = 0;
            using (EventLogReader r = new EventLogReader(q))
            {
                EventRecord e;
                while ((e = r.ReadEvent()) != null && n++ < 2000)
                    using (e)
                    {
                        string desc = null;
                        try { desc = e.FormatDescription(); } catch { }
                        if (desc == null) desc = string.Join(" | ", e.Properties.Select(pr => Convert.ToString(pr.Value)));
                        Match name = Regex.Match(desc, @"(?:Имя|Name):\s*(.+)");
                        Match path = Regex.Match(desc, @"(?:Путь|Path):\s*(.+)");
                        string threat = name.Success ? name.Groups[1].Value.Trim() : "угроза";
                        string p = path.Success ? path.Groups[1].Value.Trim() : threat;
                        p = Regex.Replace(p, @"^(file|process|regkey)?_?\s*:?_?", "", RegexOptions.IgnoreCase).Trim();
                        string key = "def|" + p + "|" + threat;
                        if (!reported.Add(key)) continue;
                        Finding f = new Finding();
                        f.Path = p; f.FileName = SafeName(p.Split(';')[0]); f.RealType = "DEF · Защитник Windows"; f.Source = "Защитник Windows";
                        f.Modified = e.TimeCreated ?? DateTime.MinValue;
                        string tl = threat.ToLowerInvariant();
                        bool cheatish = tl.Contains("hacktool") || tl.Contains("gamehack") || tl.Contains("cheat") || tl.Contains("injector") || tl.Contains("spoofer");
                        f.Add(cheatish ? 45 : 20, "Защитник Windows нашёл «" + threat + "»" + (cheatish ? " — так он помечает читы и инжекторы" : ""));
                        foreach (Keywords.Kw k in Keywords.Match(p).Where(k => k.Strong)) f.Add(40, "В пути слово из списка «" + k.Word + "»");
                        f.Note((e.Id == 1117 ? "Действие выполнено (удалён/в карантине)" : e.Id == 1116 ? "Обнаружено" : "Событие " + e.Id) + (e.TimeCreated.HasValue ? " " + e.TimeCreated.Value.ToString("dd.MM.yyyy HH:mm") : ""));
                        f.Origin = desc.Length > 1200 ? desc.Substring(0, 1200) : desc;
                        f.Finish();
                        if (f.Severity > 0 && Found != null) Found(f);
                    }
            }
        }

        // ---------- задачи планировщика и службы (как Autoruns) ----------
        void TasksAndServices()
        {
            string tasks = Path.Combine(Analyzer.Sys32, "Tasks");
            try
            {
                foreach (string f in Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories))
                {
                    string x = null;
                    try { x = File.ReadAllText(f); } catch { continue; }
                    foreach (Match m in Regex.Matches(x, @"<Command>([^<]+)</Command>(?:\s*<Arguments>([^<]*)</Arguments>)?"))
                    {
                        string cmd = Environment.ExpandEnvironmentVariables(m.Groups[1].Value.Trim().Trim('"'));
                        AutorunItem("Задача планировщика", cmd, (cmd + " " + m.Groups[2].Value).Trim(), "Задача: " + f.Substring(tasks.Length));
                    }
                }
            }
            catch { }
            using (RegistryKey s = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            {
                if (s == null) return;
                foreach (string n in s.GetSubKeyNames())
                    using (RegistryKey k = s.OpenSubKey(n))
                    {
                        string img = k == null ? null : k.GetValue("ImagePath") as string;
                        if (string.IsNullOrEmpty(img)) continue;
                        string p = Environment.ExpandEnvironmentVariables(img.Trim());
                        if (p.StartsWith("\"")) p = p.Substring(1, Math.Max(0, p.IndexOf('"', 1) - 1));
                        else { int sp = p.IndexOf(".exe ", StringComparison.OrdinalIgnoreCase); if (sp > 0) p = p.Substring(0, sp + 4); }
                        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = Analyzer.WinDir + p.Substring(11);
                        else if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)) p = Path.Combine(Analyzer.WinDir, p);
                        else if (p.StartsWith(@"\??\")) p = p.Substring(4);
                        AutorunItem("Служба/драйвер", p, n + " · " + img, "Служба: " + n);
                    }
            }
        }

        void AutorunItem(string source, string exe, string full, string extra)
        {
            Check(source, "RUN", full, SafeName(exe), DateTime.MinValue, false, extra);
            // драйвер или служба из пользовательской папки без подписи — так ставят спуферы и kernel-читы
            string l = exe.ToLowerInvariant();
            bool userPlace = l.Contains("\\appdata\\") || l.Contains("\\temp\\") || l.Contains("\\downloads\\") || l.Contains("\\desktop\\") || l.Contains("\\users\\public\\");
            if (!userPlace || !File.Exists(exe) || !reported.Add("run|" + exe)) return;
            SigInfo sig = null;
            try { sig = Native.CheckSignature(exe); } catch { }
            if (sig == null || sig.Trusted) return;
            Finding f = new Finding();
            f.Path = exe; f.FileName = SafeName(exe); f.RealType = "RUN · " + source; f.Source = source; f.Sig = sig;
            f.Add(l.EndsWith(".sys") ? 45 : 20, source + " запускает неподписанную программу из папки пользователя" + (l.EndsWith(".sys") ? " — драйвер, так ставят спуферы и kernel-читы" : ""));
            f.Note(extra);
            f.Finish();
            if (f.Severity > 0 && Found != null) Found(f);
        }
    }
}
