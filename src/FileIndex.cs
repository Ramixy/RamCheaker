using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace InjectHunter
{
    /// <summary>Индекс всех файлов на дисках, как в Everything: с правами администратора читается сразу таблица MFT (секунды),
    /// без прав — обычный обход папок.</summary>
    class FileIndex
    {
        public string[] Names = new string[0], Lower = new string[0];
        public int[] Parent = new int[0];
        public bool[] IsDir = new bool[0];
        public long[] Size = new long[0];
        public long[] Mtime = new long[0];
        public int Count, Files, Dirs;
        public volatile string Current = "";
        public string Method = "";
        public DateTime Built;

        List<string> nl = new List<string>(); List<int> pl = new List<int>(); List<bool> dl = new List<bool>(); List<long> sl = new List<long>(); List<long> ml = new List<long>();
        public volatile int Progress;
        string[] dirPath;

        // ---------- построение ----------
        public void Build(List<string> roots, CancellationToken ct)
        {
            List<string> methods = new List<string>();
            foreach (string r in roots)
            {
                if (ct.IsCancellationRequested) break;
                string root = r.TrimEnd('\\');
                int idx = AddEntry(root, -1, true, 0, 0);
                Current = root;
                bool ok = false;
                try { ok = root.Length == 2 && Mft(root, idx, ct); } catch { ok = false; }
                if (!ok) { Walk(root + "\\", idx, ct); methods.Add(root + " — обход папок"); }
                else methods.Add(root + " — MFT");
            }
            Names = nl.ToArray(); Parent = pl.ToArray(); IsDir = dl.ToArray(); Size = sl.ToArray(); Mtime = ml.ToArray();
            nl = null; pl = null; dl = null; sl = null; ml = null;
            Count = Names.Length;
            Lower = new string[Count];
            for (int i = 0; i < Count; i++) Lower[i] = Names[i].ToLowerInvariant();
            Dirs = IsDir.Count(x => x); Files = Count - Dirs;
            dirPath = new string[Count];
            Method = string.Join(", ", methods);
            Built = DateTime.Now;
        }

        int AddEntry(string name, int parent, bool dir, long size, long mtime)
        {
            nl.Add(name); pl.Add(parent); dl.Add(dir); sl.Add(size); ml.Add(mtime);
            Progress = nl.Count;
            return nl.Count - 1;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MFT_ENUM_DATA_V0 { public ulong Start; public long LowUsn; public long HighUsn; }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        struct BY_HANDLE_FILE_INFORMATION
        {
            public uint Attr; public long Ct, At, Wt; public uint Vol, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(SafeFileHandle h, uint code, ref MFT_ENUM_DATA_V0 inb, int inSize, IntPtr outb, int outSize, out int ret, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

        bool Mft(string drive, int rootIdx, CancellationToken ct)
        {
            try { if (new DriveInfo(drive + "\\").DriveFormat != "NTFS") return false; } catch { return false; }
            ulong rootFrn;
            using (SafeFileHandle rh = CreateFile(drive + "\\", 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero))
            {
                BY_HANDLE_FILE_INFORMATION bi;
                if (rh.IsInvalid || !GetFileInformationByHandle(rh, out bi)) return false;
                rootFrn = ((ulong)bi.IndexHigh << 32) | bi.IndexLow;
            }
            using (SafeFileHandle vol = CreateFile(@"\\.\" + drive, 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero))
            {
                if (vol.IsInvalid) return false;
                List<ulong> frns = new List<ulong>(1 << 20), parents = new List<ulong>(1 << 20);
                List<string> names = new List<string>(1 << 20); List<bool> dirs = new List<bool>(1 << 20);
                MFT_ENUM_DATA_V0 med = new MFT_ENUM_DATA_V0(); med.Start = 0; med.LowUsn = 0; med.HighUsn = long.MaxValue;
                const int BUF = 1 << 20;
                IntPtr buf = Marshal.AllocHGlobal(BUF);
                try
                {
                    int ret;
                    while (!ct.IsCancellationRequested && DeviceIoControl(vol, 0x000900B3, ref med, Marshal.SizeOf(typeof(MFT_ENUM_DATA_V0)), buf, BUF, out ret, IntPtr.Zero))
                    {
                        if (ret <= 8) break;
                        med.Start = (ulong)Marshal.ReadInt64(buf);
                        int off = 8;
                        while (off + 60 <= ret)
                        {
                            int len = Marshal.ReadInt32(buf, off);
                            if (len <= 0) break;
                            short major = Marshal.ReadInt16(buf, off + 4);
                            if (major == 2)
                            {
                                ulong frn = (ulong)Marshal.ReadInt64(buf, off + 8), par = (ulong)Marshal.ReadInt64(buf, off + 16);
                                uint attr = (uint)Marshal.ReadInt32(buf, off + 52);
                                int nlen = (ushort)Marshal.ReadInt16(buf, off + 56), noff = (ushort)Marshal.ReadInt16(buf, off + 58);
                                string name = Marshal.PtrToStringUni(new IntPtr(buf.ToInt64() + off + noff), nlen / 2);
                                frns.Add(frn); parents.Add(par); names.Add(name); dirs.Add((attr & 0x10) != 0);
                            }
                            off += len;
                        }
                        Progress = nl.Count + frns.Count;
                        if ((frns.Count & 0xFFFF) < 2000) Current = drive + " · MFT: " + frns.Count.ToString("N0");
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
                if (frns.Count < 10) return false;
                int baseIdx = nl.Count;
                Dictionary<ulong, int> map = new Dictionary<ulong, int>(frns.Count);
                for (int i = 0; i < frns.Count; i++) map[frns[i]] = baseIdx + i;
                map[rootFrn] = rootIdx;
                for (int i = 0; i < frns.Count; i++)
                {
                    int p;
                    if (!map.TryGetValue(parents[i], out p)) p = -2;
                    nl.Add(names[i]); pl.Add(p); dl.Add(dirs[i]); sl.Add(-1); ml.Add(0);
                }
                Progress = nl.Count;
                return true;
            }
        }

        // обход папок (без прав администратора)
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
        struct WIN32_FIND_DATA
        {
            public uint Attr; public long Ct, At, Wt; public uint SizeHigh, SizeLow, R0, R1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string Alt;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstFileEx(string name, int level, out WIN32_FIND_DATA data, int op, IntPtr filter, int flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool FindNextFile(IntPtr h, out WIN32_FIND_DATA data);
        [DllImport("kernel32.dll")]
        static extern bool FindClose(IntPtr h);

        void Walk(string root, int rootIdx, CancellationToken ct)
        {
            Stack<KeyValuePair<string, int>> st = new Stack<KeyValuePair<string, int>>();
            st.Push(new KeyValuePair<string, int>(root, rootIdx));
            int n = 0;
            while (st.Count > 0 && !ct.IsCancellationRequested)
            {
                KeyValuePair<string, int> cur = st.Pop();
                WIN32_FIND_DATA fd;
                IntPtr h = FindFirstFileEx(cur.Key + "*", 1, out fd, 0, IntPtr.Zero, 2);
                if (h == new IntPtr(-1)) continue;
                try
                {
                    do
                    {
                        if (fd.Name == "." || fd.Name == "..") continue;
                        bool dir = (fd.Attr & 0x10) != 0;
                        int idx = AddEntry(fd.Name, cur.Value, dir, dir ? 0 : ((long)fd.SizeHigh << 32) | fd.SizeLow, fd.Wt);
                        if (dir && (fd.Attr & 0x400) == 0) st.Push(new KeyValuePair<string, int>(cur.Key + fd.Name + "\\", idx));
                        if ((++n & 4095) == 0) Current = cur.Key;
                    }
                    while (FindNextFile(h, out fd));
                }
                finally { FindClose(h); }
            }
        }

        // ---------- пути ----------
        public string PathOf(int i)
        {
            if (i < 0 || i >= Count) return null;
            int p = Parent[i];
            if (p == -1) return Names[i] + "\\";
            if (p < 0) return null;
            string d = DirPath(p);
            return d == null ? null : d + "\\" + Names[i];
        }

        string DirPath(int i)
        {
            string c = dirPath[i];
            if (c != null) return c;
            int p = Parent[i];
            string res;
            if (p == -1) res = Names[i];
            else if (p < 0) res = null;
            else
            {
                if (p == i) return null;
                string pp = DirPath(p);
                res = pp == null ? null : pp + "\\" + Names[i];
            }
            dirPath[i] = res;
            return res;
        }

        // ---------- поиск ----------
        public class Query
        {
            public List<string> Words = new List<string>(), Not = new List<string>(), PathWords = new List<string>();
            public List<Regex> Masks = new List<Regex>();
            public HashSet<string> Exts;
            public bool FilesOnly;
            public bool Empty { get { return Words.Count == 0 && PathWords.Count == 0 && Masks.Count == 0 && Exts == null; } }
        }

        /// <summary>Слова через пробел — все должны быть в имени. *.jar / ext:exe,dll — по расширению. !слово — исключить.
        /// Слово с \ — ищется в полном пути. Маски * и ?.</summary>
        public static Query Parse(string text)
        {
            Query q = new Query();
            foreach (Match m in Regex.Matches(text ?? "", "\"([^\"]+)\"|(\\S+)"))
            {
                string t = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
                if (t.Length == 0) continue;
                if (t.StartsWith("ext:", StringComparison.OrdinalIgnoreCase))
                {
                    if (q.Exts == null) q.Exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string e in t.Substring(4).Split(new char[] { ',', ';', '|' }, StringSplitOptions.RemoveEmptyEntries)) q.Exts.Add("." + e.TrimStart('.', '*'));
                }
                else if (Regex.IsMatch(t, @"^\*\.[\w]+$"))
                {
                    if (q.Exts == null) q.Exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    q.Exts.Add(t.Substring(1));
                }
                else if (t.StartsWith("!") && t.Length > 1) q.Not.Add(t.Substring(1).ToLowerInvariant());
                else if (t.Contains("\\")) q.PathWords.Add(t);
                else if (t.Contains("*") || t.Contains("?"))
                    q.Masks.Add(new Regex("^" + Regex.Escape(t).Replace("\\*", ".*").Replace("\\?", ".") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                else q.Words.Add(t.ToLowerInvariant());
            }
            return q;
        }

        public List<int> Search(Query q, int max, Func<int, bool> extra, out int total, CancellationToken ct)
        {
            List<int> res = new List<int>();
            total = 0;
            if (q.Empty) return res;
            for (int i = 0; i < Count; i++)
            {
                if ((i & 0xFFFF) == 0 && ct.IsCancellationRequested) break;
                if (Parent[i] < 0 && Parent[i] != -1) continue;
                if (q.FilesOnly && IsDir[i]) continue;
                string n = Lower[i];
                bool ok = true;
                foreach (string w in q.Words) if (n.IndexOf(w, StringComparison.Ordinal) < 0) { ok = false; break; }
                if (!ok) continue;
                foreach (string w in q.Not) if (n.IndexOf(w, StringComparison.Ordinal) >= 0) { ok = false; break; }
                if (!ok) continue;
                if (q.Exts != null)
                {
                    if (IsDir[i]) continue;
                    int dot = n.LastIndexOf('.');
                    if (dot < 0 || !q.Exts.Contains(n.Substring(dot))) continue;
                }
                foreach (Regex r in q.Masks) if (!r.IsMatch(n)) { ok = false; break; }
                if (!ok) continue;
                if (q.PathWords.Count > 0)
                {
                    string p = PathOf(i);
                    if (p == null) continue;
                    foreach (string w in q.PathWords) if (p.IndexOf(w, StringComparison.OrdinalIgnoreCase) < 0) { ok = false; break; }
                    if (!ok) continue;
                }
                if (extra != null && !extra(i)) continue;
                total++;
                if (res.Count < max) res.Add(i);
            }
            return res;
        }
    }
}
