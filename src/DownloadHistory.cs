using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace InjectHunter
{
    /// <summary>Минимальное чтение SQLite-базы (только таблицы, только чтение) — для истории загрузок браузеров.
    /// Читается копия байтов, страницы из -wal накладываются поверх — работает при открытом браузере.</summary>
    class MiniSqlite
    {
        byte[] db;
        int pageSize, usable;
        Dictionary<int, byte[]> wal = new Dictionary<int, byte[]>();
        public Dictionary<string, KeyValuePair<int, string>> Tables = new Dictionary<string, KeyValuePair<int, string>>(StringComparer.OrdinalIgnoreCase);

        public static MiniSqlite Open(string path)
        {
            byte[] b = ReadShared(path, 256L * 1024 * 1024);
            if (b == null || b.Length < 512 || Encoding.ASCII.GetString(b, 0, 15) != "SQLite format 3") return null;
            MiniSqlite s = new MiniSqlite();
            s.db = b;
            int ps = (b[16] << 8) | b[17];
            s.pageSize = ps == 1 ? 65536 : ps;
            if (s.pageSize < 512) return null;
            s.usable = s.pageSize - b[20];
            byte[] w = ReadShared(path + "-wal", 128L * 1024 * 1024);
            if (w != null && w.Length > 32)
            {
                int wps = (int)BE32(w, 8);
                if (wps == s.pageSize)
                    for (long off = 32; off + 24 + wps <= w.Length; off += 24 + wps)
                    {
                        int pg = (int)BE32(w, (int)off);
                        if (pg <= 0) continue;
                        byte[] page = new byte[wps];
                        Buffer.BlockCopy(w, (int)off + 24, page, 0, wps);
                        s.wal[pg] = page;
                    }
            }
            try
            {
                foreach (object[] r in s.Rows(1))
                    if (r.Length >= 5 && "table".Equals(r[0] as string) && r[1] is string && r[3] is long)
                        s.Tables[(string)r[1]] = new KeyValuePair<int, string>((int)(long)r[3], r[4] as string ?? "");
            }
            catch { }
            return s;
        }

        static byte[] ReadShared(string path, long max)
        {
            try
            {
                if (!File.Exists(path)) return null;
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long len = Math.Min(fs.Length, max);
                    byte[] b = new byte[len];
                    int off = 0, n;
                    while (off < len && (n = fs.Read(b, off, (int)Math.Min(len - off, 1 << 20))) > 0) off += n;
                    if (off < len) Array.Resize(ref b, off);
                    return b;
                }
            }
            catch { return null; }
        }

        static uint BE32(byte[] b, int o) { return (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]); }

        byte[] Page(int n)
        {
            byte[] p;
            if (wal.TryGetValue(n, out p)) return p;
            long off = (long)(n - 1) * pageSize;
            if (n < 1 || off + pageSize > db.Length) return null;
            p = new byte[pageSize];
            Buffer.BlockCopy(db, (int)off, p, 0, pageSize);
            return p;
        }

        static long Varint(byte[] b, ref int o)
        {
            long v = 0;
            for (int i = 0; i < 9; i++)
            {
                if (o >= b.Length) return v;
                byte c = b[o++];
                if (i == 8) return (v << 8) + c;
                v = (v << 7) + (c & 0x7f);
                if ((c & 0x80) == 0) return v;
            }
            return v;
        }

        /// <summary>Имена колонок из CREATE TABLE.</summary>
        public static List<string> Columns(string sql)
        {
            List<string> res = new List<string>();
            int a = sql.IndexOf('('), z = sql.LastIndexOf(')');
            if (a < 0 || z <= a) return res;
            string body = sql.Substring(a + 1, z - a - 1);
            int depth = 0; StringBuilder cur = new StringBuilder();
            List<string> parts = new List<string>();
            foreach (char c in body)
            {
                if (c == '(') depth++; else if (c == ')') depth--;
                if (c == ',' && depth == 0) { parts.Add(cur.ToString()); cur.Length = 0; } else cur.Append(c);
            }
            parts.Add(cur.ToString());
            foreach (string p in parts)
            {
                string t = p.Trim();
                if (t.Length == 0) continue;
                string u = t.ToUpperInvariant();
                if (u.StartsWith("PRIMARY KEY") || u.StartsWith("UNIQUE") || u.StartsWith("CONSTRAINT") || u.StartsWith("FOREIGN") || u.StartsWith("CHECK")) continue;
                string name = t.Split(new char[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim('"', '`', '[', ']');
                res.Add(name);
            }
            return res;
        }

        /// <summary>Все строки таблицы с корнем root. Первый элемент массива — rowid в конце (последний).</summary>
        public IEnumerable<object[]> Rows(int root)
        {
            Stack<int> st = new Stack<int>();
            HashSet<int> seen = new HashSet<int>();
            st.Push(root);
            while (st.Count > 0)
            {
                int pn = st.Pop();
                if (!seen.Add(pn) || seen.Count > 200000) continue;
                byte[] p = Page(pn);
                if (p == null) continue;
                int h = pn == 1 ? 100 : 0;
                byte type = p[h];
                int nCells = (p[h + 3] << 8) | p[h + 4];
                if (type == 0x05)
                {
                    st.Push((int)BE32(p, h + 8));
                    for (int i = 0; i < nCells; i++)
                    {
                        int co = (p[h + 12 + i * 2] << 8) | p[h + 13 + i * 2];
                        if (co + 4 <= p.Length) st.Push((int)BE32(p, co));
                    }
                }
                else if (type == 0x0D)
                {
                    for (int i = 0; i < nCells; i++)
                    {
                        object[] row = null;
                        try
                        {
                            int co = (p[h + 8 + i * 2] << 8) | p[h + 9 + i * 2];
                            long plen = Varint(p, ref co);
                            long rowid = Varint(p, ref co);
                            byte[] payload = Payload(p, co, plen);
                            if (payload != null) row = Record(payload, rowid);
                        }
                        catch { }
                        if (row != null) yield return row;
                    }
                }
            }
        }

        byte[] Payload(byte[] p, int co, long plen)
        {
            if (plen < 0 || plen > 16 * 1024 * 1024) return null;
            int x = usable - 35;
            if (plen <= x)
            {
                if (co + plen > p.Length) return null;
                byte[] r = new byte[plen]; Buffer.BlockCopy(p, co, r, 0, (int)plen); return r;
            }
            int m = ((usable - 12) * 32 / 255) - 23;
            int k = m + (int)((plen - m) % (usable - 4));
            int local = k <= x ? k : m;
            byte[] res = new byte[plen];
            if (co + local + 4 > p.Length) return null;
            Buffer.BlockCopy(p, co, res, 0, local);
            int got = local;
            int next = (int)BE32(p, co + local);
            int guard = 0;
            while (got < plen && next > 0 && guard++ < 10000)
            {
                byte[] op = Page(next);
                if (op == null) break;
                int n = (int)Math.Min(usable - 4, plen - got);
                Buffer.BlockCopy(op, 4, res, got, n);
                got += n;
                next = (int)BE32(op, 0);
            }
            return got == plen ? res : null;
        }

        static object[] Record(byte[] b, long rowid)
        {
            int o = 0;
            long hlen = Varint(b, ref o);
            List<long> types = new List<long>();
            while (o < hlen && o < b.Length) types.Add(Varint(b, ref o));
            int d = (int)hlen;
            object[] res = new object[types.Count + 1];
            for (int i = 0; i < types.Count; i++)
            {
                long t = types[i];
                if (t == 0) res[i] = null;
                else if (t >= 1 && t <= 6)
                {
                    int n = t == 5 ? 6 : t == 6 ? 8 : (int)t;
                    long v = 0;
                    for (int j = 0; j < n && d + j < b.Length; j++) v = (v << 8) | b[d + j];
                    if (n < 8 && (v & (1L << (n * 8 - 1))) != 0) v -= 1L << (n * 8);
                    res[i] = v; d += n;
                }
                else if (t == 7) { res[i] = 0.0; d += 8; }
                else if (t == 8) res[i] = 0L;
                else if (t == 9) res[i] = 1L;
                else if (t >= 12)
                {
                    int n = (int)((t - (t % 2 == 0 ? 12 : 13)) / 2);
                    if (d + n > b.Length) n = Math.Max(0, b.Length - d);
                    res[i] = t % 2 == 0 ? (object)null : Encoding.UTF8.GetString(b, d, n);
                    d += n;
                }
            }
            res[types.Count] = rowid;
            return res;
        }
    }

    /// <summary>Загрузка из истории браузера: какой файл, откуда, когда.</summary>
    class DlRecord
    {
        public string Browser, Path, Url, FirstUrl, Page, Referrer, Mime;
        public DateTime Time;
        public long Bytes;
    }

    /// <summary>История загрузок Chrome/Edge/Яндекс/Opera/Brave/Vivaldi и Firefox. Работает, даже если метку скачивания стёрли.</summary>
    static class DownloadHistory
    {
        static List<DlRecord> all;
        static Dictionary<string, List<DlRecord>> byPath, byName;
        static readonly object lk = new object();

        public static List<DlRecord> All { get { Ensure(); return all; } }

        public static void Reset() { lock (lk) all = null; }

        static void Ensure()
        {
            lock (lk)
            {
                if (all != null) return;
                List<DlRecord> res = new List<DlRecord>();
                foreach (KeyValuePair<string, string> h in WebTraces.HistoryFiles())
                {
                    try { if (h.Key == "Firefox") ReadFirefox(h.Value, res); else ReadChromium(h.Key, h.Value, res); } catch { }
                }
                byPath = new Dictionary<string, List<DlRecord>>(StringComparer.OrdinalIgnoreCase);
                byName = new Dictionary<string, List<DlRecord>>(StringComparer.OrdinalIgnoreCase);
                foreach (DlRecord r in res)
                {
                    if (string.IsNullOrEmpty(r.Path)) continue;
                    Add(byPath, r.Path, r);
                    string n = System.IO.Path.GetFileName(r.Path);
                    if (!string.IsNullOrEmpty(n)) Add(byName, n, r);
                }
                all = res;
            }
        }

        static void Add(Dictionary<string, List<DlRecord>> d, string k, DlRecord r)
        {
            List<DlRecord> l;
            if (!d.TryGetValue(k, out l)) d[k] = l = new List<DlRecord>();
            l.Add(r);
        }

        public static DlRecord ForPath(string path)
        {
            Ensure();
            List<DlRecord> l;
            return byPath.TryGetValue(path, out l) ? l.OrderByDescending(x => x.Time).First() : null;
        }

        public static DlRecord ForName(string name)
        {
            Ensure();
            List<DlRecord> l;
            return byName.TryGetValue(name, out l) ? l.OrderByDescending(x => x.Time).First() : null;
        }

        static string Col(object[] row, List<string> cols, string name)
        {
            int i = cols.IndexOf(name);
            return i >= 0 && i < row.Length - 1 ? row[i] as string : null;
        }
        static long ColL(object[] row, List<string> cols, string name)
        {
            int i = cols.IndexOf(name);
            if (i < 0 || i >= row.Length - 1) return 0;
            if (row[i] == null && name == "id") return (long)row[row.Length - 1];
            return row[i] is long ? (long)row[i] : 0;
        }

        static void ReadChromium(string browser, string file, List<DlRecord> res)
        {
            MiniSqlite s = MiniSqlite.Open(file);
            if (s == null) return;
            KeyValuePair<int, string> t, tc;
            if (!s.Tables.TryGetValue("downloads", out t)) return;
            List<string> cols = MiniSqlite.Columns(t.Value);
            Dictionary<long, SortedDictionary<long, string>> chains = new Dictionary<long, SortedDictionary<long, string>>();
            if (s.Tables.TryGetValue("downloads_url_chains", out tc))
            {
                List<string> cc = MiniSqlite.Columns(tc.Value);
                foreach (object[] r in s.Rows(tc.Key))
                {
                    long id = ColL(r, cc, "id"), idx = ColL(r, cc, "chain_index");
                    string url = Col(r, cc, "url");
                    if (url == null) continue;
                    SortedDictionary<long, string> ch;
                    if (!chains.TryGetValue(id, out ch)) chains[id] = ch = new SortedDictionary<long, string>();
                    ch[idx] = url;
                }
            }
            foreach (object[] r in s.Rows(t.Key))
            {
                DlRecord d = new DlRecord();
                d.Browser = browser;
                d.Path = Col(r, cols, "target_path");
                if (string.IsNullOrEmpty(d.Path)) d.Path = Col(r, cols, "current_path");
                d.Page = Col(r, cols, "tab_url");
                d.Referrer = Col(r, cols, "referrer");
                if (string.IsNullOrEmpty(d.Referrer)) d.Referrer = Col(r, cols, "tab_referrer_url");
                d.Mime = Col(r, cols, "mime_type");
                d.Bytes = ColL(r, cols, "total_bytes");
                long st = ColL(r, cols, "start_time");
                try { if (st > 0) d.Time = DateTime.FromFileTimeUtc(st * 10).ToLocalTime(); } catch { }
                SortedDictionary<long, string> ch;
                if (chains.TryGetValue(ColL(r, cols, "id"), out ch) && ch.Count > 0) { d.FirstUrl = ch.Values.First(); d.Url = ch.Values.Last(); }
                if (d.Url == null) d.Url = Col(r, cols, "site_url");
                if (string.IsNullOrEmpty(d.Path) && string.IsNullOrEmpty(d.Url)) continue;
                res.Add(d);
            }
        }

        static void ReadFirefox(string file, List<DlRecord> res)
        {
            MiniSqlite s = MiniSqlite.Open(file);
            if (s == null) return;
            KeyValuePair<int, string> tp, ta, tn;
            if (!s.Tables.TryGetValue("moz_annos", out ta) || !s.Tables.TryGetValue("moz_places", out tp) || !s.Tables.TryGetValue("moz_anno_attributes", out tn)) return;
            List<string> cn = MiniSqlite.Columns(tn.Value), ca = MiniSqlite.Columns(ta.Value), cp = MiniSqlite.Columns(tp.Value);
            long dest = -1;
            foreach (object[] r in s.Rows(tn.Key)) if (Col(r, cn, "name") == "downloads/destinationFileURI") dest = ColL(r, cn, "id");
            if (dest < 0) return;
            Dictionary<long, DlRecord> byPlace = new Dictionary<long, DlRecord>();
            foreach (object[] r in s.Rows(ta.Key))
            {
                if (ColL(r, ca, "anno_attribute_id") != dest) continue;
                string uri = Col(r, ca, "content");
                if (uri == null) continue;
                DlRecord d = new DlRecord(); d.Browser = "Firefox";
                try { d.Path = new Uri(uri).LocalPath; } catch { d.Path = uri; }
                long t = ColL(r, ca, "dateAdded");
                try { if (t > 0) d.Time = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddTicks(t * 10).ToLocalTime(); } catch { }
                byPlace[ColL(r, ca, "place_id")] = d;
            }
            if (byPlace.Count == 0) return;
            foreach (object[] r in s.Rows(tp.Key))
            {
                DlRecord d;
                if (byPlace.TryGetValue(ColL(r, cp, "id"), out d)) d.Url = Col(r, cp, "url");
            }
            res.AddRange(byPlace.Values);
        }
    }
}
