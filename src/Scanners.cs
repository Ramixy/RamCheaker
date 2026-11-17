using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace InjectHunter
{
    class DiskScanner
    {
        public event Action<Finding> Found;
        public long FilesSeen, FilesQueued, FilesDone, DirsSeen, BytesSeen, TotalBytes;
        public volatile string Current = "";

        static readonly string[] serviceRel = {
            "WinSxS", "servicing", "assembly", "Microsoft.NET", "SoftwareDistribution", "System32\\DriverStore",
            "System32\\CatRoot", "System32\\catroot2", "Logs", "Panther", "SystemApps", "WinSxS", "Containers", "UUS", "InfusedApps"
        };
        string[] serviceDirs;

        bool IsServiceDir(string dir)
        {
            foreach (string s in serviceDirs) if (dir.Equals(s, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public void Run(ScanOptions o, CancellationToken ct)
        {
            serviceDirs = serviceRel.Select(r => Path.Combine(Analyzer.WinDir, r)).ToArray();
            foreach (string r in o.Roots)
            {
                try { DriveInfo di = new DriveInfo(r); if (di.IsReady) TotalBytes += di.TotalSize - di.TotalFreeSpace; } catch { }
            }
            BlockingCollection<FileInfo> q = new BlockingCollection<FileInfo>(20000);
            int nWorkers = Math.Max(2, Math.Min(6, Environment.ProcessorCount));
            Task[] workers = new Task[nWorkers];
            for (int w = 0; w < nWorkers; w++)
            {
                workers[w] = Task.Factory.StartNew(() =>
                {
                    try
                    {
                        foreach (FileInfo fi in q.GetConsumingEnumerable(ct))
                        {
                            Current = fi.FullName;
                            try
                            {
                                Finding f = Analyzer.AnalyzeFile(fi, o);
                                if (f != null && Found != null) Found(f);
                            }
                            catch { }
                            Interlocked.Increment(ref FilesDone);
                        }
                    }
                    catch (OperationCanceledException) { }
                }, TaskCreationOptions.LongRunning);
            }
            try
            {
                foreach (string root in o.Roots) Walk(root, o, q, ct);
            }
            catch (OperationCanceledException) { }
            finally
            {
                q.CompleteAdding();
                try { Task.WaitAll(workers); } catch { }
            }
        }

        void Walk(string root, ScanOptions o, BlockingCollection<FileInfo> q, CancellationToken ct)
        {
            Stack<string> st = new Stack<string>();
            st.Push(root);
            const FileAttributes Recall = (FileAttributes)0x400000 | (FileAttributes)0x40000 | FileAttributes.Offline;
            while (st.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                string dir = st.Pop();
                Interlocked.Increment(ref DirsSeen);
                if (o.SkipServiceDirs && IsServiceDir(dir)) continue;
                IEnumerator<FileSystemInfo> en;
                try { en = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator(); }
                catch { continue; }
                while (true)
                {
                    FileSystemInfo it;
                    try { if (!en.MoveNext()) break; it = en.Current; }
                    catch { break; }
                    FileAttributes a;
                    try { a = it.Attributes; } catch { continue; }
                    if ((a & FileAttributes.Directory) != 0)
                    {
                        if ((a & FileAttributes.ReparsePoint) == 0 && (a & Recall) == 0) st.Push(it.FullName);
                        continue;
                    }
                    Interlocked.Increment(ref FilesSeen);
                    if ((a & Recall) != 0) continue;
                    FileInfo fi = it as FileInfo;
                    if (fi == null) continue;
                    long len;
                    try { len = fi.Length; } catch { continue; }
                    Interlocked.Add(ref BytesSeen, len);
                    if (len == 0) continue;
                    if (Analyzer.ShouldAnalyze(fi.FullName, fi.Extension, o))
                    {
                        q.Add(fi, ct);
                        Interlocked.Increment(ref FilesQueued);
                    }
                }
            }
        }
    }

    class ProcessScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public double Progress;
        public int ProcCount, ModulesChecked;

        void Emit(Finding f) { f.Finish(); if (f.Severity > 0 && Found != null) Found(f); }

        public void Run(ScanOptions o, bool memScan, CancellationToken ct)
        {
            List<Process> procs = new List<Process>();
            foreach (string n in new string[] { "javaw", "java" })
                try { procs.AddRange(Process.GetProcessesByName(n)); } catch { }
            ProcCount = procs.Count;
            for (int i = 0; i < procs.Count; i++)
            {
                if (ct.IsCancellationRequested) break;
                Process p = procs[i];
                string tag = p.ProcessName + ".exe (PID " + p.Id + ")";
                Current = tag + " — модули";
                HashSet<long> bases = new HashSet<long>();
                try
                {
                    foreach (ProcessModule m in p.Modules)
                    {
                        if (ct.IsCancellationRequested) break;
                        bases.Add(m.BaseAddress.ToInt64());
                        CheckModule(m.FileName, tag, o);
                        ModulesChecked++;
                    }
                }
                catch (Exception ex)
                {
                    Finding f = new Finding();
                    f.Path = tag; f.FileName = tag; f.Source = tag; f.RealType = "процесс";
                    f.Add(15, "Не удалось прочитать список модулей (" + ex.Message + "). Запусти от администратора.");
                    Emit(f);
                }
                Progress = (i + 0.3) / procs.Count;
                if (memScan && !ct.IsCancellationRequested)
                {
                    try { ScanMemory(p, tag, bases, i, procs.Count, ct); } catch { }
                }
                Progress = (i + 1.0) / procs.Count;
            }
            Progress = 1;
        }

        void CheckModule(string path, string tag, ScanOptions o)
        {
            Current = tag + " — " + path;
            Finding f = new Finding();
            f.Path = path; f.FileName = Path.GetFileName(path); f.Ext = Path.GetExtension(path).ToLowerInvariant();
            f.Source = tag;
            if (!File.Exists(path))
            {
                f.RealType = "модуль в памяти";
                f.Add(70, "Модуль загружен в " + tag + ", но файла уже нет на диске — удалён после инжекта");
                Emit(f);
                return;
            }
            string dir = Path.GetDirectoryName(path) ?? "";
            FileInfo fi = new FileInfo(path);
            f.Size = fi.Length; f.Modified = fi.LastWriteTime; f.Created = fi.CreationTime;
            bool inWin = Analyzer.IsUnder(path, Analyzer.WinDir);
            bool javaDir = Analyzer.IsJavaRuntimeDir(dir);
            if (javaDir && !inWin) return; // сам JDK/JRE

            Finding deep = null;
            try { deep = Analyzer.AnalyzeFile(fi, o); } catch { }
            if (deep != null)
            {
                deep.Source = tag;
                deep.Add(15, "Загружена в процесс " + tag);
                Emit(deep);
                return;
            }

            SigInfo sig = Native.CheckSignature(path);
            f.Sig = sig;
            f.RealType = "DLL в javaw";
            if (inWin)
            {
                if (!sig.Trusted)
                {
                    f.Add(45, "Неподписанная библиотека из папки Windows загружена в " + tag + " — так маскируются под системные DLL");
                    f.Note(sig.ToString());
                    Emit(f);
                }
                return;
            }
            bool knownNative = Signatures.KnownJavaNatives.Contains(f.FileName) ||
                               path.IndexOf("lwjgl", StringComparison.OrdinalIgnoreCase) >= 0 ||
                               path.IndexOf("\\natives", StringComparison.OrdinalIgnoreCase) >= 0;
            if (sig.Trusted) return;
            if (knownNative)
            {
                f.Add(10, "Нативная библиотека Minecraft/LWJGL без подписи (обычно норма)");
                f.Note(sig.ToString());
                Emit(f);
                return;
            }
            f.Add(30, "Сторонняя НЕподписанная DLL загружена в " + tag);
            string l = path.ToLowerInvariant();
            if (l.Contains("\\temp\\") || l.Contains("\\appdata\\") || l.Contains("\\downloads\\") || l.Contains("\\desktop\\") || l.Contains("\\$recycle.bin\\"))
                f.Add(20, "Загружена из пользовательской/временной папки");
            f.Note(sig.ToString());
            Emit(f);
        }

        struct Region { public long Base, Size, AllocBase; public uint Type, Protect; }

        static bool Readable(uint p)
        {
            if ((p & Native.PAGE_GUARD) != 0 || (p & Native.PAGE_NOACCESS) != 0) return false;
            return (p & 0xEE) != 0; // READONLY|READWRITE|WRITECOPY|EXECUTE_*
        }
        static bool Exec(uint p)
        {
            return (p & (Native.PAGE_EXECUTE | Native.PAGE_EXECUTE_READ | Native.PAGE_EXECUTE_READWRITE | Native.PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        void ScanMemory(Process p, string tag, HashSet<long> bases, int idx, int total, CancellationToken ct)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_READ, false, p.Id);
            if (h == IntPtr.Zero) return;
            try
            {
                List<Region> regs = new List<Region>();
                long addr = 0, sum = 0;
                Native.MEMORY_BASIC_INFORMATION mbi;
                int mbiSize = Marshal.SizeOf(typeof(Native.MEMORY_BASIC_INFORMATION));
                while (Native.VirtualQueryEx(h, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) != IntPtr.Zero)
                {
                    long b = mbi.BaseAddress.ToInt64(), s = mbi.RegionSize.ToInt64();
                    if (s <= 0) break;
                    if (mbi.State == Native.MEM_COMMIT && Readable(mbi.Protect))
                    {
                        Region r = new Region();
                        r.Base = b; r.Size = s; r.Type = mbi.Type; r.Protect = mbi.Protect; r.AllocBase = mbi.AllocationBase.ToInt64();
                        regs.Add(r);
                        if (r.Type != Native.MEM_IMAGE && s <= 256L * 1024 * 1024) sum += s;
                    }
                    addr = b + s;
                    if (addr <= 0 || addr >= 0x7FFFFFFFFFFFL) break;
                }

                // 1) Скрытые модули (MEM_IMAGE вне списка модулей) и PE в приватной памяти
                HashSet<long> reported = new HashSet<long>();
                byte[] hdr = new byte[0x400];
                foreach (Region r in regs)
                {
                    if (r.Type == Native.MEM_IMAGE && !bases.Contains(r.AllocBase) && reported.Add(r.AllocBase))
                    {
                        StringBuilder sb = new StringBuilder(1024);
                        string file = Native.GetMappedFileName(h, new IntPtr(r.AllocBase), sb, 1024) > 0 ? Native.DevicePathToDos(sb.ToString()) : "?";
                        string lf = file.ToLowerInvariant();
                        if (lf.EndsWith(".dll") || lf.EndsWith(".exe") || file == "?")
                        {
                            Finding f = new Finding();
                            f.Path = file; f.FileName = Path.GetFileName(file); f.Source = tag; f.RealType = "скрытый модуль";
                            f.Add(65, "Образ DLL есть в памяти " + tag + " по адресу 0x" + r.AllocBase.ToString("X") + ", но скрыт из списка модулей (unlink из PEB — приём инжект-читов)");
                            Emit(f);
                        }
                    }
                    else if (r.Type == Native.MEM_PRIVATE && Exec(r.Protect) && r.Base == r.AllocBase)
                    {
                        IntPtr rd;
                        if (Native.ReadProcessMemory(h, new IntPtr(r.Base), hdr, new IntPtr(hdr.Length), out rd) && rd.ToInt64() >= 0x100)
                        {
                            bool mz = hdr[0] == 'M' && hdr[1] == 'Z';
                            int lf = BitConverter.ToInt32(hdr, 0x3C);
                            bool pe = mz && lf > 0 && lf < 0x3F8 && hdr[lf] == 'P' && hdr[lf + 1] == 'E';
                            if (pe)
                            {
                                Finding f = new Finding();
                                f.Path = tag + " @ 0x" + r.Base.ToString("X"); f.FileName = "PE в приватной памяти"; f.Source = tag;
                                f.RealType = "manual-map";
                                f.Add(80, "Исполняемая приватная память с PE-заголовком (0x" + r.Base.ToString("X") + ", " + (r.Size / 1024) + " КБ) — DLL внедрена вручную (manual map), без файла на диске");
                                Emit(f);
                            }
                        }
                    }
                }

                // 2) Поиск строк читов в памяти
                int[] counts = new int[Signatures.All.Count];
                byte[] buf = Analyzer.Buf();
                long done = 0;
                foreach (Region r in regs)
                {
                    if (ct.IsCancellationRequested) break;
                    if (r.Type == Native.MEM_IMAGE || r.Size > 256L * 1024 * 1024) continue;
                    long off = 0;
                    int s1 = 0, s2 = 0;
                    while (off < r.Size)
                    {
                        int want = (int)Math.Min(buf.Length, r.Size - off);
                        IntPtr rd;
                        if (!Native.ReadProcessMemory(h, new IntPtr(r.Base + off), buf, new IntPtr(want), out rd) || rd.ToInt64() == 0) break;
                        Analyzer.ScanChunk(buf, (int)rd.ToInt64(), counts, ref s1, ref s2);
                        off += want;
                        done += want;
                        Current = tag + " — память " + (done >> 20) + " / " + (sum >> 20) + " МБ";
                        if (sum > 0) Progress = (idx + 0.3 + 0.7 * Math.Min(1.0, (double)done / sum)) / total;
                    }
                }
                ReportMemory(counts, tag);
            }
            finally { Native.CloseHandle(h); }
        }

        void ReportMemory(int[] counts, string tag)
        {
            Dictionary<string, Sig> clients = new Dictionary<string, Sig>();
            SortedSet<string> modules = new SortedSet<string>();
            SortedSet<string> evasion = new SortedSet<string>();
            SortedSet<string> kws = new SortedSet<string>();
            for (int i = 0; i < counts.Length; i++)
            {
                if (counts[i] == 0) continue;
                Sig s = Signatures.All[i];
                if (s.Kind == SigKind.ClientName || s.Kind == SigKind.ClientPackage)
                {
                    Sig old;
                    if (!clients.TryGetValue(s.Label, out old) || old.Weight < s.Weight) clients[s.Label] = s;
                }
                else if (s.Kind == SigKind.CheatModule) modules.Add(s.Label);
                else if (s.Kind == SigKind.Evasion) evasion.Add(s.Label);
                else if (s.Kind == SigKind.Keyword) kws.Add(s.Label);
            }
            Finding f = new Finding();
            f.Path = tag + " — оперативная память"; f.FileName = "Память " + tag; f.Source = tag; f.RealType = "RAM";
            if (clients.Count >= 6)
                f.Add(20, "В памяти названия " + clients.Count + " разных читов (" + string.Join(", ", clients.Keys.Take(10)) + "…) — проверь вручную: это может быть список блокировки лаунчера или сам чит");
            else
                foreach (Sig s in clients.Values)
                    f.Add(s.Kind == SigKind.ClientPackage ? 80 : 55, "В памяти найдена сигнатура чита: " + s.Label + " («" + s.Token + "»)");
            if (modules.Count >= 3) f.Add(Math.Min(60, 10 + 8 * modules.Count), "Названия модулей чита в памяти (" + modules.Count + "): " + string.Join(", ", modules));
            else if (modules.Count > 0) f.Add(7 * modules.Count, "Возможные модули чита в памяти: " + string.Join(", ", modules));
            foreach (string e in evasion) f.Add(15, "Анти-SS строка в памяти: " + e);
            if (kws.Count > 0) f.Add(Math.Min(90, 40 + 10 * kws.Count), "В памяти javaw слова из списка (" + kws.Count + "): " + string.Join(", ", kws.Take(12)));
            Emit(f);
        }
    }
}
