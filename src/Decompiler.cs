using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace InjectHunter
{
    /// <summary>Java-декомпилятор CFR (вшит в exe) + поиск java.exe на компьютере.</summary>
    static class Cfr
    {
        static string java, jar;
        static bool searched;

        public static bool Embedded { get { return Assembly.GetExecutingAssembly().GetManifestResourceNames().Contains("lib:cfr.jar"); } }

        public static string Java
        {
            get
            {
                if (!searched) { searched = true; try { java = FindJava(); } catch { } }
                return java;
            }
        }

        static string FindJava()
        {
            List<string> c = new List<string>();
            try
            {
                foreach (Process p in Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")))
                    try { c.Add(Path.Combine(Path.GetDirectoryName(p.MainModule.FileName), "java.exe")); } catch { }
            }
            catch { }
            string jh = Environment.GetEnvironmentVariable("JAVA_HOME");
            if (!string.IsNullOrEmpty(jh)) c.Add(Path.Combine(jh, "bin\\java.exe"));
            foreach (string d in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
                if (d.Trim().Length > 0) try { c.Add(Path.Combine(d.Trim().Trim('"'), "java.exe")); } catch { }
            foreach (string f in c) if (File.Exists(f) && !f.ToLowerInvariant().Contains("\\windows\\")) return f;

            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string ad = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            List<string> roots = new List<string>();
            foreach (string v in new string[] { "Java", "Eclipse Adoptium", "Zulu", "Microsoft", "BellSoft", "Amazon Corretto", "Semeru", "Minecraft Launcher\\runtime" })
                roots.Add(Path.Combine(pf, v));
            roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Minecraft Launcher\\runtime"));
            roots.Add(Path.Combine(ad, ".minecraft\\runtime"));
            roots.Add(Path.Combine(la, "Packages\\Microsoft.4297127D64EC6_8wekyb3d8bbwe\\LocalCache\\Local\\runtime"));
            try { foreach (string d in Directory.GetDirectories(ad)) roots.Add(d); } catch { }
            roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".jdks"));
            foreach (string r in roots)
            {
                string f = Find(r, 0);
                if (f != null) return f;
            }
            return null;
        }

        static string Find(string dir, int depth)
        {
            if (depth > 6 || !Directory.Exists(dir)) return null;
            try
            {
                string f = Path.Combine(dir, "bin\\java.exe");
                if (File.Exists(f)) return f;
                foreach (string d in Directory.GetDirectories(dir))
                {
                    string n = Path.GetFileName(d).ToLowerInvariant();
                    if (depth == 0 && dir.EndsWith("Roaming", StringComparison.OrdinalIgnoreCase) && n != ".minecraft" && n != ".tlauncher" && !n.Contains("launcher") && !n.Contains("client") && !n.Contains("minecraft") && !n.Contains("java")) continue;
                    if (n == "assets" || n == "libraries" || n == "versions" || n == "saves" || n == "resourcepacks" || n == "logs" || n == "screenshots" || n == "mods" || n == "node_modules") continue;
                    string r = Find(d, depth + 1);
                    if (r != null) return r;
                }
            }
            catch { }
            return null;
        }

        static string Jar()
        {
            if (jar != null && File.Exists(jar)) return jar;
            string dst = Path.Combine(Path.GetTempPath(), "RamixyCheaker", "cfr.jar");
            Directory.CreateDirectory(Path.GetDirectoryName(dst));
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("lib:cfr.jar"))
            {
                if (s == null) return null;
                if (!File.Exists(dst) || new FileInfo(dst).Length != s.Length)
                    using (FileStream fs = File.Create(dst)) s.CopyTo(fs);
            }
            return jar = dst;
        }

        /// <summary>Декомпилирует класс className из jarPath (или одиночный .class). Возвращает Java-код или текст ошибки.</summary>
        public static string Decompile(string file, string className, CancellationToken ct)
        {
            string j = Java;
            if (j == null) return null;
            string cj = Jar();
            if (cj == null) return null;
            string args = "-jar \"" + cj + "\" \"" + file + "\" --silent true --comments false";
            if (className != null)
            {
                string outer = className.Replace('/', '.');
                int d = outer.IndexOf('$'); if (d > 0) outer = outer.Substring(0, d);
                args += " --jarfilter \"^" + Regex.Escape(outer).Replace("\"", "") + "$\"";
            }
            ProcessStartInfo psi = new ProcessStartInfo(j, "-Xmx512m -Dfile.encoding=UTF-8 " + args);
            psi.UseShellExecute = false; psi.CreateNoWindow = true; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8; psi.StandardErrorEncoding = Encoding.UTF8;
            using (Process p = Process.Start(psi))
            {
                Task<string> o = p.StandardOutput.ReadToEndAsync(), e = p.StandardError.ReadToEndAsync();
                Stopwatch sw = Stopwatch.StartNew();
                while (!p.WaitForExit(200))
                {
                    if (ct.IsCancellationRequested || sw.ElapsedMilliseconds > 90000) { try { p.Kill(); } catch { } return "// декомпиляция прервана"; }
                }
                string res = o.Result;
                if (res.Trim().Length == 0) res = "// CFR ничего не вывел\n" + e.Result;
                return res;
            }
        }
    }

    /// <summary>Раздел «Декомпилятор»: дерево JAR слева, код справа. Подозрительные классы — красным.</summary>
    class DecompilerView : TableLayoutPanel
    {
        class Item
        {
            public string Name;      // путь внутри архива
            public byte[] Data;
            public Archive Owner;
            public int Weight;       // сумма весов сигнатур
            public string Hits;
        }
        class Archive { public string File; public string Label; public byte[] Bytes; public string TempPath; public List<Item> Items = new List<Item>(); }

        TreeView tree;
        TextBox code;
        Label info;
        SearchBox find;
        PillToggle tCfr, tSusp;
        FlatButton bOpen, bSave;
        Archive root;
        CancellationTokenSource cts;
        public Func<string, bool> Busy;

        public DecompilerView()
        {
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 4; BackColor = Theme.Bg; Margin = Padding.Empty;
            RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(60)));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(30)));
            RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            PageTitle pt = new PageTitle("Декомпилятор", "Разбор модов и программ: что внутри JAR (классы, строки, Java-код) и EXE/DLL (импорт, секции, строки). Ничего не запускается.");
            pt.Dock = DockStyle.Fill; Controls.Add(pt, 0, 0);

            FlowLayoutPanel tb = new FlowLayoutPanel(); tb.AutoSize = true; tb.Dock = DockStyle.Fill; tb.BackColor = Theme.Bg; tb.Margin = new Padding(0, 0, 0, Theme.Px(6));
            bOpen = new FlatButton("Открыть файл…", true, Theme.IcOpen); bOpen.Margin = new Padding(0, 0, Theme.Px(8), 0); tb.Controls.Add(bOpen);
            bSave = new FlatButton("Сохранить текст", false, Theme.IcSave); bSave.Margin = new Padding(0, 0, Theme.Px(16), 0); tb.Controls.Add(bSave);
            find = new SearchBox("Найти класс или строку (Enter)"); find.Size = new Size(Theme.Px(300), Theme.Px(34)); find.Margin = new Padding(0, Theme.Px(2), Theme.Px(12), 0); tb.Controls.Add(find);
            tCfr = new PillToggle("Java-код (CFR)", true); tCfr.Margin = new Padding(0, Theme.Px(3), Theme.Px(8), 0); tb.Controls.Add(tCfr);
            tSusp = new PillToggle("Только подозрительные", false); tSusp.Margin = new Padding(0, Theme.Px(3), Theme.Px(8), 0); tb.Controls.Add(tSusp);
            Controls.Add(tb, 0, 1);

            info = new Label(); info.Dock = DockStyle.Fill; info.ForeColor = Theme.Muted; info.BackColor = Theme.Bg; info.Font = Theme.Font(8.5f);
            info.Text = "Открой .jar, .class, .exe или .dll — или нажми «Разобрать» у находки в «Моды и файлы» / «Поиск файлов».";
            info.TextAlign = ContentAlignment.MiddleLeft;
            Controls.Add(info, 0, 2);

            SplitContainer sp = new SplitContainer(); sp.Dock = DockStyle.Fill; sp.BackColor = Theme.Border; sp.SplitterWidth = Theme.Px(6); sp.Margin = new Padding(0, Theme.Px(4), 0, 0);
            sp.Panel1.BackColor = Theme.Card; sp.Panel2.BackColor = Theme.Card;
            tree = new TreeView(); tree.Dock = DockStyle.Fill; tree.BackColor = Theme.Card; tree.ForeColor = Theme.Text; tree.BorderStyle = BorderStyle.None;
            tree.Font = Theme.Font(9f); tree.HideSelection = false; tree.ShowNodeToolTips = true; tree.ItemHeight = Theme.Px(22);
            tree.HandleCreated += delegate { Native.SetWindowTheme(tree.Handle, "DarkMode_Explorer", null); };
            tree.AfterSelect += (s, e) => ShowItem(e.Node);
            tree.BeforeExpand += (s, e) => ExpandNested(e.Node);
            sp.Panel1.Controls.Add(tree);
            code = new TextBox(); code.Multiline = true; code.ReadOnly = true; code.ScrollBars = ScrollBars.Both; code.WordWrap = false; code.MaxLength = int.MaxValue;
            code.BorderStyle = BorderStyle.None; code.BackColor = Theme.Card; code.ForeColor = Theme.Text; code.Font = Theme.Mono(9.5f); code.Dock = DockStyle.Fill;
            code.HandleCreated += delegate { Native.SetWindowTheme(code.Handle, "DarkMode_Explorer", null); };
            sp.Panel2.Padding = new Padding(Theme.Px(8), Theme.Px(6), 0, 0);
            sp.Panel2.Controls.Add(code);
            Controls.Add(sp, 0, 3);
            sp.FixedPanel = FixedPanel.Panel1;
            bool splitSet = false;
            sp.SizeChanged += delegate { if (!splitSet && sp.Width > Theme.Px(700)) { splitSet = true; try { sp.SplitterDistance = Theme.Px(380); } catch { } } };

            bOpen.Click += delegate
            {
                OpenFileDialog d = new OpenFileDialog(); d.Title = "Что разобрать";
                d.Filter = "Моды и программы (*.jar;*.class;*.exe;*.dll;*.zip)|*.jar;*.class;*.exe;*.dll;*.zip;*.disabled;*.sys|Все файлы (*.*)|*.*";
                if (d.ShowDialog(FindForm()) == DialogResult.OK) Open(d.FileName);
            };
            bSave.Click += delegate
            {
                if (code.TextLength == 0) return;
                SaveFileDialog d = new SaveFileDialog(); d.Filter = "Текст (*.txt;*.java)|*.txt;*.java"; d.FileName = (tree.SelectedNode != null ? Path.GetFileNameWithoutExtension(tree.SelectedNode.Text) : "code") + ".txt";
                if (d.ShowDialog(FindForm()) == DialogResult.OK) try { File.WriteAllText(d.FileName, code.Text, Encoding.UTF8); } catch { }
            };
            find.Box.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; Rebuild(); } };
            tSusp.Click += delegate { Rebuild(); };
            tCfr.Click += delegate { if (tree.SelectedNode != null) ShowItem(tree.SelectedNode); };
        }

        // ---------- открытие ----------
        public void Open(string path)
        {
            if (cts != null) cts.Cancel();
            info.Text = "Читаю " + path + "…";
            tree.Nodes.Clear(); code.Text = "";
            Task.Factory.StartNew(() =>
            {
                Archive a = null; string err = null;
                try { a = Load(path, File.ReadAllBytes(path), Path.GetFileName(path)); }
                catch (Exception ex) { err = ex.Message; }
                try
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (a == null) { info.Text = "Не удалось открыть: " + err; return; }
                        root = a;
                        Rebuild();
                        int susp = a.Items.Count(x => x.Weight > 0);
                        int cls = a.Items.Count(x => x.Name.EndsWith(".class", StringComparison.OrdinalIgnoreCase));
                        info.Text = path + "   ·   файлов: " + a.Items.Count + ", классов: " + cls + (susp > 0 ? ", С ПРИЗНАКАМИ ЧИТА: " + susp + " (красные)" : ", признаков чита в классах нет") +
                                    "   ·   " + (Cfr.Java != null ? "Java: " + Cfr.Java : "Java не найдена — показываю байткод");
                        Item best = a.Items.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).FirstOrDefault()
                            ?? a.Items.FirstOrDefault(x => x.Name == "fabric.mod.json" || x.Name.EndsWith("mods.toml") || x.Name == "mcmod.info")
                            ?? a.Items.FirstOrDefault(x => x.Name.EndsWith(".class")) ?? a.Items.FirstOrDefault();
                        TreeNode bn = best == null ? null : FindNode(tree.Nodes, best);
                        if (bn != null) { tree.SelectedNode = bn; bn.EnsureVisible(); }
                    }));
                }
                catch { }
            });
        }

        static TreeNode FindNode(TreeNodeCollection nodes, Item it)
        {
            foreach (TreeNode n in nodes)
            {
                if (n.Tag == it) return n;
                TreeNode r = FindNode(n.Nodes, it);
                if (r != null) return r;
            }
            return null;
        }

        Archive Load(string file, byte[] bytes, string label)
        {
            Archive a = new Archive(); a.File = file; a.Bytes = bytes; a.Label = label;
            bool zip = bytes.Length > 4 && bytes[0] == 'P' && bytes[1] == 'K';
            if (!zip)
            {
                Item it = new Item(); it.Name = label; it.Data = bytes; it.Owner = a; Mark(it);
                a.Items.Add(it);
                return a;
            }
            using (MemoryStream ms = new MemoryStream(bytes))
            using (ZipArchive za = new ZipArchive(ms, ZipArchiveMode.Read))
            {
                long total = 0;
                foreach (ZipArchiveEntry e in za.Entries)
                {
                    if (string.IsNullOrEmpty(e.Name)) continue;
                    Item it = new Item(); it.Name = e.FullName; it.Owner = a;
                    if (e.Length < 64L * 1024 * 1024 && total < 800L * 1024 * 1024)
                    {
                        try
                        {
                            using (Stream s = e.Open()) using (MemoryStream m = new MemoryStream()) { s.CopyTo(m); it.Data = m.ToArray(); }
                            total += it.Data.Length;
                        }
                        catch { }
                    }
                    Mark(it);
                    a.Items.Add(it);
                }
            }
            return a;
        }

        static void Mark(Item it)
        {
            if (it.Data == null || it.Data.Length == 0) return;
            string n = it.Name.ToLowerInvariant();
            if (!(n.EndsWith(".class") || n.EndsWith(".json") || n.EndsWith(".dll") || n.EndsWith(".exe") || n.EndsWith(".so") || n.EndsWith(".mf") || n.EndsWith(".txt") || n.EndsWith(".properties"))) return;
            try
            {
                byte[] low = new byte[it.Data.Length];
                for (int i = 0; i < low.Length; i++) { byte c = it.Data[i]; low[i] = c >= 'A' && c <= 'Z' ? (byte)(c + 32) : c; }
                int[] counts = new int[Signatures.All.Count]; int st = 0;
                Signatures.Matcher.Search(low, 0, low.Length, ref st, counts);
                List<string> hits = new List<string>(); int w = 0;
                for (int i = 0; i < counts.Length; i++)
                {
                    if (counts[i] == 0) continue;
                    Sig s = Signatures.All[i];
                    if (s.Weight <= 0 || s.Kind == SigKind.Context || s.Kind == SigKind.Jni || s.Kind == SigKind.Injector) continue;
                    w += s.Weight; hits.Add(s.Label ?? s.Token);
                }
                byte[] nb = Encoding.ASCII.GetBytes(n); st = 0; int[] c2 = new int[Signatures.All.Count];
                Signatures.Matcher.Search(nb, 0, nb.Length, ref st, c2);
                for (int i = 0; i < c2.Length; i++) if (c2[i] > 0 && counts[i] == 0 && Signatures.All[i].Weight > 0 && (Signatures.All[i].Kind == SigKind.ClientPackage || Signatures.All[i].Kind == SigKind.ClientName || Signatures.All[i].Kind == SigKind.CheatModule)) { w += Signatures.All[i].Weight; hits.Add(Signatures.All[i].Label ?? Signatures.All[i].Token); }
                if (w >= 25) { it.Weight = w; it.Hits = string.Join(", ", hits.Distinct().Take(8)); }
            }
            catch { }
        }

        void Rebuild()
        {
            if (root == null) return;
            string q = find.Box.Text.Trim();
            byte[] qb = q.Length > 0 ? Encoding.UTF8.GetBytes(q.ToLowerInvariant()) : null;
            tree.BeginUpdate();
            tree.Nodes.Clear();
            TreeNode top = new TreeNode(root.Label); top.ForeColor = Theme.Text;
            tree.Nodes.Add(top);
            Fill(top, root, q, qb);
            top.Expand();
            if (q.Length > 0 || tSusp.Checked) top.ExpandAll();
            tree.EndUpdate();
        }

        void Fill(TreeNode top, Archive a, string q, byte[] qb)
        {
            Dictionary<string, TreeNode> dirs = new Dictionary<string, TreeNode>();
            foreach (Item it in a.Items.OrderBy(x => x.Name.Contains("/") ? 0 : 1).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
            {
                if (tSusp.Checked && it.Weight == 0) continue;
                if (q.Length > 0 && it.Name.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0 && !Contains(it.Data, qb)) continue;
                string[] parts = it.Name.Split('/');
                TreeNode parent = top; string key = "";
                for (int i = 0; i < parts.Length - 1; i++)
                {
                    key += parts[i] + "/";
                    TreeNode dn;
                    if (!dirs.TryGetValue(key, out dn)) { dn = new TreeNode(parts[i]); dn.ForeColor = Theme.Muted; parent.Nodes.Add(dn); dirs[key] = dn; }
                    parent = dn;
                }
                TreeNode n = new TreeNode(parts[parts.Length - 1]); n.Tag = it;
                n.ForeColor = it.Weight >= 50 ? Theme.Red : it.Weight > 0 ? Theme.Orange : Theme.Text;
                if (it.Hits != null) n.ToolTipText = "Признаки чита: " + it.Hits;
                string ln = it.Name.ToLowerInvariant();
                if ((ln.EndsWith(".jar") || ln.EndsWith(".zip")) && it.Data != null) n.Nodes.Add(new TreeNode("…"));
                parent.Nodes.Add(n);
                for (TreeNode p = parent; p != null && p != top && it.Weight > 0; p = p.Parent) if (p.ForeColor != Theme.Red) p.ForeColor = it.Weight >= 50 ? Theme.Red : Theme.Orange;
            }
        }

        static bool Contains(byte[] d, byte[] q)
        {
            if (d == null || q == null || q.Length == 0 || d.Length < q.Length) return false;
            byte f = q[0];
            for (int i = 0; i <= d.Length - q.Length; i++)
            {
                byte c = d[i]; if (c >= 'A' && c <= 'Z') c += 32;
                if (c != f) continue;
                int k = 1;
                for (; k < q.Length; k++) { byte x = d[i + k]; if (x >= 'A' && x <= 'Z') x += 32; if (x != q[k]) break; }
                if (k == q.Length) return true;
            }
            return false;
        }

        void ExpandNested(TreeNode n)
        {
            Item it = n.Tag as Item;
            if (it == null || n.Nodes.Count != 1 || n.Nodes[0].Tag != null || n.Nodes[0].Text != "…") return;
            n.Nodes.Clear();
            try
            {
                Archive a = Load(null, it.Data, it.Name);
                a.TempPath = null;
                Fill(n, a, "", null);
            }
            catch (Exception ex) { n.Nodes.Add(new TreeNode("не открывается: " + ex.Message)); }
        }

        // ---------- показ ----------
        void ShowItem(TreeNode node)
        {
            Item it = node == null ? null : node.Tag as Item;
            if (it == null) return;
            if (cts != null) cts.Cancel();
            cts = new CancellationTokenSource();
            CancellationToken ct = cts.Token;
            string ln = it.Name.ToLowerInvariant();
            if (it.Data == null) { code.Text = "// файл слишком большой или не читается"; return; }
            bool isClass = it.Data.Length > 4 && it.Data[0] == 0xCA && it.Data[1] == 0xFE && it.Data[2] == 0xBA && it.Data[3] == 0xBE;
            if (isClass)
            {
                string head = it.Hits != null ? "// ПРИЗНАКИ ЧИТА В КЛАССЕ: " + it.Hits + "\r\n\r\n" : "";
                string dis;
                try { dis = ClassFile.Parse(it.Data).ToText(); } catch (Exception ex) { dis = "// не разобрать: " + ex.Message; }
                code.Text = head + Crlf(dis);
                if (tCfr.Checked && Cfr.Java != null && Cfr.Embedded)
                {
                    code.Text = head + "// CFR декомпилирует…\r\n\r\n" + Crlf(dis);
                    Item cur = it;
                    Task.Factory.StartNew(() =>
                    {
                        string res;
                        try { res = DecompileItem(cur, ct); } catch (Exception ex) { res = null; dis = "// CFR: " + ex.Message + "\n\n" + dis; }
                        if (ct.IsCancellationRequested) return;
                        try
                        {
                            BeginInvoke(new Action(() =>
                            {
                                if (ct.IsCancellationRequested) return;
                                code.Text = head + (res != null ? Crlf(res) + "\r\n\r\n// ===================== БАЙТКОД =====================\r\n" : "") + Crlf(dis);
                            }));
                        }
                        catch { }
                    });
                }
                return;
            }
            if (it.Data.Length > 2 && it.Data[0] == 'M' && it.Data[1] == 'Z') { code.Text = Crlf(PeText(it)); return; }
            if (it.Data.Length > 2 && it.Data[0] == 'P' && it.Data[1] == 'K') { code.Text = "Вложенный архив — раскрой его в дереве слева (" + DetailsView.FormatSize(it.Data.Length) + ")"; return; }
            if (IsText(it.Data)) { code.Text = Crlf(Encoding.UTF8.GetString(it.Data, 0, Math.Min(it.Data.Length, 4 * 1024 * 1024))); return; }
            code.Text = Crlf(Hex(it.Data, 8192) + "\n\nСТРОКИ:\n" + string.Join("\n", Strs(it.Data, 5, 1500)));
        }

        string DecompileItem(Item it, CancellationToken ct)
        {
            Archive a = it.Owner;
            string file;
            string cls = null;
            if (a.File != null && a.Items.Count > 1) { file = a.File; cls = it.Name.Substring(0, it.Name.Length - 6); }
            else if (a.File != null && a.Items.Count == 1) file = a.File;
            else
            {
                if (a.TempPath == null)
                {
                    string dir = Path.Combine(Path.GetTempPath(), "RamixyCheaker", "dec");
                    Directory.CreateDirectory(dir);
                    a.TempPath = Path.Combine(dir, "nested_" + Math.Abs(a.Label.GetHashCode()) + "_" + a.Bytes.Length + ".jar");
                    File.WriteAllBytes(a.TempPath, a.Bytes);
                }
                file = a.TempPath; cls = it.Name.Substring(0, it.Name.Length - 6);
            }
            if (file.EndsWith(".class", StringComparison.OrdinalIgnoreCase)) cls = null;
            else if (!file.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && !file.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                // мод с другим расширением (.disabled, .dll-маскировка) — CFR нужен .jar
                string dir = Path.Combine(Path.GetTempPath(), "RamixyCheaker", "dec");
                Directory.CreateDirectory(dir);
                string tmp = Path.Combine(dir, Path.GetFileNameWithoutExtension(file) + (a.Items.Count == 1 ? ".class" : ".jar"));
                File.Copy(file, tmp, true);
                file = tmp;
                if (a.Items.Count == 1) cls = null;
            }
            return Cfr.Decompile(file, cls, ct);
        }

        static string Crlf(string s) { return s.Replace("\r\n", "\n").Replace("\n", "\r\n"); }

        static bool IsText(byte[] d)
        {
            int n = Math.Min(d.Length, 4096), bad = 0;
            for (int i = 0; i < n; i++) { byte c = d[i]; if (c == 0) return false; if (c < 9 || (c > 13 && c < 32)) bad++; }
            return bad < n / 50 + 1;
        }

        static string Hex(byte[] d, int max)
        {
            StringBuilder sb = new StringBuilder();
            int n = Math.Min(d.Length, max);
            for (int i = 0; i < n; i += 16)
            {
                sb.Append(i.ToString("X8")).Append("  ");
                for (int k = 0; k < 16; k++) sb.Append(i + k < n ? d[i + k].ToString("X2") + " " : "   ");
                sb.Append(' ');
                for (int k = 0; k < 16 && i + k < n; k++) { byte c = d[i + k]; sb.Append(c >= 32 && c < 127 ? (char)c : '.'); }
                sb.Append('\n');
            }
            if (d.Length > max) sb.Append("… ещё " + (d.Length - max).ToString("N0") + " байт");
            return sb.ToString();
        }

        public static List<string> Strs(byte[] d, int min, int max)
        {
            List<string> res = new List<string>();
            HashSet<string> seen = new HashSet<string>();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i <= d.Length && res.Count < max; i++)
            {
                byte c = i < d.Length ? d[i] : (byte)0;
                if (c >= 32 && c < 127) { sb.Append((char)c); continue; }
                if (sb.Length >= min) { string s = sb.ToString(); if (seen.Add(s)) res.Add(s); }
                sb.Length = 0;
            }
            // UTF-16
            for (int i = 0; i + 1 < d.Length && res.Count < max; i += 2)
            {
                byte c = d[i];
                if (d[i + 1] == 0 && c >= 32 && c < 127) { sb.Append((char)c); continue; }
                if (sb.Length >= min) { string s = sb.ToString(); if (seen.Add(s)) res.Add("[UTF-16] " + s); }
                sb.Length = 0;
            }
            return res;
        }

        static string PeText(Item it)
        {
            StringBuilder sb = new StringBuilder();
            PeInfo pe;
            using (MemoryStream ms = new MemoryStream(it.Data)) pe = PeInfo.Parse(ms);
            sb.AppendLine("// " + it.Name + " — " + pe.Describe() + ", " + DetailsView.FormatSize(it.Data.Length));
            string real = it.Owner.File != null && it.Owner.Items.Count == 1 ? it.Owner.File : null;
            if (real != null)
            {
                try
                {
                    SigInfo sig = Native.CheckSignature(real);
                    sb.AppendLine("// Подпись: " + sig + "  →  " + PeClass.Label(real, sig));
                    FileVersionInfo vi = FileVersionInfo.GetVersionInfo(real);
                    sb.AppendLine("// Компания: " + vi.CompanyName + " · Продукт: " + vi.ProductName + " · Описание: " + vi.FileDescription + " · Версия: " + vi.FileVersion + " · Исходное имя: " + vi.OriginalFilename);
                    sb.AppendLine("// Откуда: " + Origin.Explain(real).Text.Replace("\n", "\n//         "));
                }
                catch { }
            }
            if (pe.TimeStamp > 0) sb.AppendLine("// Дата сборки: " + new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(pe.TimeStamp).ToLocalTime().ToString("dd.MM.yyyy HH:mm"));
            Finding tf = new Finding();
            PeClass.Traits(tf, pe, it.Name, false);
            foreach (string r in tf.Reasons) sb.AppendLine("// ПРИЗНАК: " + r);
            sb.AppendLine();
            sb.AppendLine("СЕКЦИИ: " + string.Join(", ", pe.SectionNames));
            sb.AppendLine();
            sb.AppendLine("ИМПОРТ (" + pe.ImportDlls.Count + " библиотек, " + pe.ImportFuncs.Count + " функций):");
            sb.AppendLine("  " + string.Join(", ", pe.ImportDlls));
            List<string> fl = pe.ImportFuncs.OrderBy(x => x).Take(3000).ToList();
            for (int i = 0; i < fl.Count; i += 6) sb.AppendLine("  " + string.Join(", ", fl.Skip(i).Take(6)));
            if (pe.Exports.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("ЭКСПОРТ (" + pe.Exports.Count + ")" + (pe.ExportDllName != null ? ", внутреннее имя " + pe.ExportDllName : "") + ":");
                sb.AppendLine("  " + string.Join(", ", pe.Exports.Take(3000)));
            }
            sb.AppendLine();
            List<string> st = Strs(it.Data, 6, 4000);
            sb.AppendLine("СТРОКИ (" + st.Count + (st.Count >= 4000 ? "+" : "") + "):");
            foreach (string s in st) sb.AppendLine("  " + (s.Length > 300 ? s.Substring(0, 300) + "…" : s));
            return sb.ToString();
        }
    }
}
