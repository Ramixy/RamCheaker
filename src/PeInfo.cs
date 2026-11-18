using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace InjectHunter
{
    /// <summary>Минимальный безопасный разбор PE-заголовков, импорта и экспорта.</summary>
    class PeInfo
    {
        public bool Valid;
        public bool IsDll;
        public bool Is64;
        public bool IsDotNet;
        public ushort Machine;
        public ushort Subsystem;
        public uint TimeStamp;
        public List<string> ImportDlls = new List<string>();
        public HashSet<string> ImportFuncs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public List<string> Exports = new List<string>();
        public string ExportDllName;
        public List<string> SectionNames = new List<string>();

        struct Section { public uint VA, VSize, RawPtr, RawSize; }
        List<Section> sections = new List<Section>();
        Stream s;
        long len;

        public string Describe()
        {
            if (!Valid) return "PE (повреждён)";
            string arch = Machine == 0x8664 ? "x64" : Machine == 0x14c ? "x86" : Machine == 0xAA64 ? "ARM64" : "0x" + Machine.ToString("X");
            string kind = IsDll ? "DLL" : (Subsystem == 1 ? "драйвер/native" : "EXE");
            return (IsDotNet ? ".NET " : "") + kind + " (" + arch + ")";
        }

        byte[] ReadAt(long off, int count)
        {
            if (off < 0 || off >= len) return null;
            if (off + count > len) count = (int)(len - off);
            byte[] b = new byte[count];
            s.Position = off;
            int got = 0;
            while (got < count)
            {
                int r = s.Read(b, got, count - got);
                if (r <= 0) break;
                got += r;
            }
            if (got != count) Array.Resize(ref b, got);
            return b;
        }

        long RvaToOff(uint rva)
        {
            foreach (Section sc in sections)
            {
                uint size = Math.Max(sc.VSize, sc.RawSize);
                if (rva >= sc.VA && rva < sc.VA + size)
                {
                    long off = (long)rva - sc.VA + sc.RawPtr;
                    return off < len ? off : -1;
                }
            }
            return -1;
        }

        string CStr(uint rva, int max)
        {
            long off = RvaToOff(rva);
            if (off < 0) return null;
            byte[] b = ReadAt(off, max);
            if (b == null) return null;
            int n = Array.IndexOf<byte>(b, 0);
            if (n < 0) n = b.Length;
            return Encoding.ASCII.GetString(b, 0, n);
        }

        public static PeInfo Parse(Stream stream)
        {
            PeInfo p = new PeInfo();
            p.s = stream;
            p.len = stream.Length;
            try { p.DoParse(); } catch { }
            return p;
        }

        void DoParse()
        {
            byte[] dos = ReadAt(0, 64);
            if (dos == null || dos.Length < 64 || dos[0] != 'M' || dos[1] != 'Z') return;
            int lfanew = BitConverter.ToInt32(dos, 0x3C);
            if (lfanew <= 0 || lfanew > 0x100000 || lfanew + 24 > len) return;
            byte[] nt = ReadAt(lfanew, 24 + 240);
            if (nt == null || nt.Length < 24 || nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0) return;
            Machine = BitConverter.ToUInt16(nt, 4);
            int nSec = BitConverter.ToUInt16(nt, 6);
            TimeStamp = BitConverter.ToUInt32(nt, 8);
            int optSize = BitConverter.ToUInt16(nt, 20);
            ushort ch = BitConverter.ToUInt16(nt, 22);
            IsDll = (ch & 0x2000) != 0;
            Valid = true;
            if (optSize < 96) return;
            byte[] opt = ReadAt(lfanew + 24, optSize);
            if (opt == null || opt.Length < 96) return;
            ushort magic = BitConverter.ToUInt16(opt, 0);
            Is64 = magic == 0x20b;
            Subsystem = BitConverter.ToUInt16(opt, 68);
            int ddOff = Is64 ? 112 : 96;
            int nDirs = (int)BitConverter.ToUInt32(opt, Is64 ? 108 : 92);
            uint expRva = 0, impRva = 0, clrRva = 0;
            if (nDirs > 0 && ddOff + 8 <= opt.Length) expRva = BitConverter.ToUInt32(opt, ddOff);
            if (nDirs > 1 && ddOff + 16 <= opt.Length) impRva = BitConverter.ToUInt32(opt, ddOff + 8);
            if (nDirs > 14 && ddOff + 14 * 8 + 8 <= opt.Length) clrRva = BitConverter.ToUInt32(opt, ddOff + 14 * 8);
            IsDotNet = clrRva != 0;

            if (nSec > 96) nSec = 96;
            byte[] sec = ReadAt(lfanew + 24 + optSize, nSec * 40);
            if (sec == null) return;
            for (int i = 0; i + 40 <= sec.Length; i += 40)
            {
                Section sc = new Section();
                sc.VSize = BitConverter.ToUInt32(sec, i + 8);
                sc.VA = BitConverter.ToUInt32(sec, i + 12);
                sc.RawSize = BitConverter.ToUInt32(sec, i + 16);
                sc.RawPtr = BitConverter.ToUInt32(sec, i + 20);
                sections.Add(sc);
                int n = 0; while (n < 8 && sec[i + n] != 0) n++;
                SectionNames.Add(Encoding.ASCII.GetString(sec, i, n));
            }

            if (impRva != 0) ParseImports(impRva);
            if (expRva != 0) ParseExports(expRva);
        }

        void ParseImports(uint rva)
        {
            long off = RvaToOff(rva);
            if (off < 0) return;
            int totalFuncs = 0;
            for (int d = 0; d < 512; d++)
            {
                byte[] desc = ReadAt(off + d * 20, 20);
                if (desc == null || desc.Length < 20) break;
                uint oft = BitConverter.ToUInt32(desc, 0);
                uint name = BitConverter.ToUInt32(desc, 12);
                uint ft = BitConverter.ToUInt32(desc, 16);
                if (oft == 0 && name == 0 && ft == 0) break;
                string dll = CStr(name, 256);
                if (!string.IsNullOrEmpty(dll)) ImportDlls.Add(dll.ToLowerInvariant());
                uint thunk = oft != 0 ? oft : ft;
                long toff = RvaToOff(thunk);
                if (toff < 0) continue;
                int tsz = Is64 ? 8 : 4;
                for (int t = 0; t < 4096 && totalFuncs < 20000; t++)
                {
                    byte[] tb = ReadAt(toff + t * tsz, tsz);
                    if (tb == null || tb.Length < tsz) break;
                    ulong v = Is64 ? BitConverter.ToUInt64(tb, 0) : BitConverter.ToUInt32(tb, 0);
                    if (v == 0) break;
                    bool ordinal = Is64 ? (v & 0x8000000000000000UL) != 0 : (v & 0x80000000UL) != 0;
                    if (ordinal) continue;
                    string fn = CStr((uint)(v & 0x7FFFFFFF) + 2, 256);
                    if (!string.IsNullOrEmpty(fn)) { ImportFuncs.Add(fn); totalFuncs++; }
                }
            }
        }

        void ParseExports(uint rva)
        {
            long off = RvaToOff(rva);
            if (off < 0) return;
            byte[] ed = ReadAt(off, 40);
            if (ed == null || ed.Length < 40) return;
            ExportDllName = CStr(BitConverter.ToUInt32(ed, 12), 256);
            int nNames = (int)BitConverter.ToUInt32(ed, 24);
            uint namesRva = BitConverter.ToUInt32(ed, 32);
            if (nNames <= 0) return;
            if (nNames > 8192) nNames = 8192;
            long noff = RvaToOff(namesRva);
            if (noff < 0) return;
            byte[] arr = ReadAt(noff, nNames * 4);
            if (arr == null) return;
            for (int i = 0; i + 4 <= arr.Length; i++)
            {
                if (i % 4 != 0) continue;
                string n = CStr(BitConverter.ToUInt32(arr, i), 256);
                if (!string.IsNullOrEmpty(n)) Exports.Add(n);
            }
        }
    }

    /// <summary>Чем PE-файл отличается от системного: подпись, папка, версия, импорт, упаковщики.</summary>
    static class PeClass
    {
        static readonly HashSet<string> sysProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "svchost.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "smss.exe", "services.exe", "wininit.exe", "explorer.exe", "conhost.exe",
            "dwm.exe", "runtimebroker.exe", "taskhostw.exe", "spoolsv.exe", "sihost.exe", "fontdrvhost.exe", "dllhost.exe", "rundll32.exe",
            "taskmgr.exe", "audiodg.exe", "ctfmon.exe", "searchindexer.exe", "wuauclt.exe", "lsm.exe", "system.exe", "smartscreen.exe"
        };

        /// <summary>Короткая метка: системный / Microsoft / чужая подпись / без подписи.</summary>
        public static string Label(string path, SigInfo sig)
        {
            if (sig == null) return null;
            bool inWin = Analyzer.WinDir != null && path.StartsWith(Analyzer.WinDir + "\\", StringComparison.OrdinalIgnoreCase);
            if (sig.Trusted && sig.IsMicrosoft) return inWin ? "системный файл Windows" : "Microsoft";
            if (sig.Trusted) return "подпись: " + (sig.Signer ?? "есть");
            if (sig.State == SigState.Invalid) return "подпись недействительна";
            return inWin ? "БЕЗ подписи в папке Windows" : "без подписи — сторонняя программа";
        }

        /// <summary>Признаки, которые есть у читов/инжекторов и почти никогда — у системных файлов. Баллы ставятся только неподписанным.</summary>
        public static void Traits(Finding f, PeInfo pe, string path, bool inWindows)
        {
            if (pe == null || !pe.Valid) return;
            HashSet<string> im = pe.ImportFuncs;
            bool alloc = im.Contains("VirtualAllocEx") || im.Contains("NtAllocateVirtualMemory");
            bool write = im.Contains("WriteProcessMemory") || im.Contains("NtWriteVirtualMemory");
            bool thread = im.Contains("CreateRemoteThread") || im.Contains("CreateRemoteThreadEx") || im.Contains("NtCreateThreadEx") || im.Contains("RtlCreateUserThread") || im.Contains("QueueUserAPC");
            if (alloc && write && thread) f.Add(20, "Умеет внедрять код в чужой процесс (VirtualAllocEx + WriteProcessMemory + удалённый поток) — так работают инжекторы");
            else if (write && (im.Contains("OpenProcess") || alloc) && (im.Contains("ReadProcessMemory"))) f.Note("Читает и пишет память других процессов");
            bool click = im.Contains("SendInput") || im.Contains("mouse_event");
            bool keys = im.Contains("GetAsyncKeyState") || im.Contains("SetWindowsHookExA") || im.Contains("SetWindowsHookExW") || im.Contains("RegisterHotKey");
            if (click && keys) f.Add(12, "Нажимает кнопки мыши программно и следит за клавишами — так устроены автокликеры");
            foreach (string s in pe.SectionNames)
            {
                string l = s.ToLowerInvariant();
                if (l.StartsWith(".vmp")) { f.Add(12, "Защищён VMProtect (секция " + s + ") — так прячут код читов и лоадеров"); break; }
                if (l == ".themida" || l == ".winlice") { f.Add(12, "Защищён Themida/WinLicense (секция " + s + ")"); break; }
                if (l.StartsWith(".enigma")) { f.Add(10, "Защищён Enigma Protector (секция " + s + ")"); break; }
                if (l == "upx0" || l == "upx1") { f.Add(6, "Сжат упаковщиком UPX"); break; }
                if (l == ".mpress1" || l == ".aspack" || l == ".petite" || l == ".nsp0") { f.Add(8, "Сжат упаковщиком (секция " + s + ")"); break; }
            }
            string name = System.IO.Path.GetFileName(path);
            if (!inWindows && sysProcs.Contains(name))
                f.Add(45, "Называется как системный процесс Windows («" + name + "»), но лежит не в папке Windows — так маскируют читы в диспетчере задач");
            if (pe.TimeStamp > 0)
            {
                DateTime t = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(pe.TimeStamp);
                if (t > DateTime.UtcNow.AddDays(2) && t.Year < 2100) f.Note("Дата сборки в будущем (" + t.ToString("dd.MM.yyyy") + ") — подделана");
                else if (t > DateTime.UtcNow.AddDays(-30) && t <= DateTime.UtcNow.AddDays(2)) f.Note("Собран недавно: " + t.ToLocalTime().ToString("dd.MM.yyyy HH:mm"));
            }
        }

        /// <summary>Сведения о версии: пустые или выдающие себя за Microsoft.</summary>
        public static void VersionTraits(Finding f, string path, bool inWindows)
        {
            try
            {
                System.Diagnostics.FileVersionInfo vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
                string comp = (vi.CompanyName ?? "").Trim(), prod = (vi.ProductName ?? "").Trim(), orig = (vi.OriginalFilename ?? "").Trim();
                if (comp.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 && !inWindows)
                    f.Add(30, "В сведениях о файле написано «" + comp + "», но подписи Microsoft нет — выдаёт себя за файл Windows");
                if (comp.Length == 0 && prod.Length == 0 && (vi.FileDescription ?? "").Trim().Length == 0)
                    f.Note("Нет сведений о версии (компания, продукт, описание) — у системных и обычных программ они есть");
                else f.Note("О файле: " + string.Join(" · ", new string[] { comp, prod, (vi.FileDescription ?? "").Trim(), vi.FileVersion }.Where(x => !string.IsNullOrEmpty(x)).Distinct().ToArray()));
                string ob = System.IO.Path.GetFileNameWithoutExtension(orig.Replace(".mui", "")), fb = System.IO.Path.GetFileNameWithoutExtension(path);
                if (ob.Length > 0 && !ob.Equals(fb, StringComparison.OrdinalIgnoreCase) && !System.Text.RegularExpressions.Regex.IsMatch(fb, @"^" + System.Text.RegularExpressions.Regex.Escape(ob) + @"[\s_-]*(\(\d+\)|v?[\d.]+)?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    f.Note("Исходное имя файла: «" + orig + "» — файл переименован");
            }
            catch { }
        }
    }

    /// <summary>Aho-Corasick по байтам (DFA) — одновременный поиск всех сигнатур за один проход.</summary>
    class AhoCorasick
    {
        List<int[]> go = new List<int[]>();
        List<List<int>> outs = new List<List<int>>();
        int[][] delta;
        int[][] output;
        public int PatternCount;

        public AhoCorasick() { NewNode(); }

        int NewNode()
        {
            int[] t = new int[256];
            for (int i = 0; i < 256; i++) t[i] = -1;
            go.Add(t);
            outs.Add(new List<int>());
            return go.Count - 1;
        }

        public void Add(byte[] pattern, int id)
        {
            int cur = 0;
            foreach (byte b in pattern)
            {
                if (go[cur][b] == -1) { int n = NewNode(); go[cur][b] = n; }
                cur = go[cur][b];
            }
            outs[cur].Add(id);
            if (id + 1 > PatternCount) PatternCount = id + 1;
        }

        public void Build()
        {
            int n = go.Count;
            int[] fail = new int[n];
            delta = new int[n][];
            for (int i = 0; i < n; i++) delta[i] = (int[])go[i].Clone();
            Queue<int> q = new Queue<int>();
            for (int c = 0; c < 256; c++)
            {
                if (delta[0][c] == -1) delta[0][c] = 0;
                else { fail[delta[0][c]] = 0; q.Enqueue(delta[0][c]); }
            }
            while (q.Count > 0)
            {
                int r = q.Dequeue();
                outs[r].AddRange(outs[fail[r]]);
                for (int c = 0; c < 256; c++)
                {
                    int s = delta[r][c];
                    if (s == -1) { delta[r][c] = delta[fail[r]][c]; continue; }
                    fail[s] = delta[fail[r]][c];
                    q.Enqueue(s);
                }
            }
            output = new int[n][];
            for (int i = 0; i < n; i++) output[i] = outs[i].Count > 0 ? outs[i].ToArray() : null;
        }

        /// <summary>Ищет в data[off..off+count). state переносится между кусками. counts[id]++ при совпадении.</summary>
        public void Search(byte[] data, int off, int count, ref int state, int[] counts)
        {
            int st = state;
            int[][] d = delta;
            int[][] o = output;
            int end = off + count;
            for (int i = off; i < end; i++)
            {
                st = d[st][data[i]];
                int[] hit = o[st];
                if (hit != null)
                    for (int k = 0; k < hit.Length; k++)
                        if (counts[hit[k]] < 1000000) counts[hit[k]]++;
            }
            state = st;
        }
    }
}
