using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace InjectHunter
{
    /// <summary>Список находок раздела: фильтры, таблица, детали.</summary>
    class ResultsView : TableLayoutPanel
    {
        public List<Finding> All = new List<Finding>();
        ConcurrentQueue<Finding> pending = new ConcurrentQueue<Finding>();
        int sevFilter;
        SearchBox search;
        Chip cAll, cCrit, cSusp, cWarn, cOk;
        public int Clean;
        DataGridView grid;
        DetailsView details;
        int hoverRow = -1;
        public bool Running, Scanned;
        public string IdleTitle = "Здесь появятся находки", IdleSub = "";
        public int Crit, Susp, Warn;

        public ResultsView() : this(false, false) { }
        public ResultsView(bool showClean) : this(showClean, false) { }

        public ResultsView(bool showClean, bool compact)
        {
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 3; Margin = Padding.Empty; Padding = Padding.Empty; BackColor = Theme.Bg;
            RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(44)));
            RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(210)));

            FlowLayoutPanel fl = new FlowLayoutPanel(); fl.Dock = DockStyle.Fill; fl.BackColor = Theme.Bg; fl.Margin = Padding.Empty; fl.WrapContents = false;
            search = new SearchBox("Поиск по пути, типу или причине");
            search.Size = new Size(Theme.Px(300), Theme.Px(30)); search.Margin = new Padding(0, Theme.Px(4), Theme.Px(12), 0);
            search.Box.TextChanged += delegate { Refilter(); };
            fl.Controls.Add(search);
            cAll = AddChip(fl, "Все", Color.Empty, 0);
            cCrit = AddChip(fl, "Критично", Theme.Red, 3);
            cSusp = AddChip(fl, "Подозрительно", Theme.Orange, 2);
            cWarn = AddChip(fl, "Внимание", Theme.Yellow, 1);
            cOk = AddChip(fl, "ОК", Theme.Dim, -1);
            cOk.Visible = showClean;
            cAll.Active = true;
            Controls.Add(fl, 0, 0);

            CardPanel gp = new CardPanel(); gp.Dock = DockStyle.Fill; gp.Margin = new Padding(0, Theme.Px(6), 0, 0);
            gp.Padding = new Padding(1, Theme.Px(4), 1, Theme.Px(4));
            grid = BuildGrid();
            gp.Controls.Add(grid);
            Controls.Add(gp, 0, 1);

            CardPanel dp = new CardPanel(); dp.Dock = DockStyle.Fill; dp.Margin = new Padding(0, Theme.Px(10), 0, 0);
            dp.Padding = new Padding(1, Theme.Px(2), Theme.Px(2), Theme.Px(2));
            details = new DetailsView(); details.Dock = DockStyle.Fill;
            details.bFolder.Click += delegate { Reveal(details.Current); };
            details.bCopy.Click += delegate { Finding f = details.Current; if (f != null) Clipboard.SetText(f.Path); };
            details.bHash.Click += delegate { Finding f = details.Current; if (f != null && f.Sha256 != null && f.Sha256.Length == 64) Clipboard.SetText(f.Sha256); };
            details.bVt.Click += delegate { OpenVt(details.Current); };
            dp.Controls.Add(details);
            Controls.Add(dp, 0, 2);
            if (compact) { RowStyles[2].Height = 0; dp.Visible = false; }
        }

        Chip AddChip(FlowLayoutPanel fl, string text, Color dot, int sev)
        {
            Chip c = new Chip(text, dot);
            c.Count = 0; c.Fit();
            c.Margin = new Padding(0, Theme.Px(4), Theme.Px(6), 0);
            c.Click += delegate
            {
                sevFilter = sev;
                foreach (Chip x in new Chip[] { cAll, cCrit, cSusp, cWarn, cOk }) { x.Active = x == c; x.Invalidate(); }
                Refilter();
            };
            fl.Controls.Add(c);
            return c;
        }

        DataGridView BuildGrid()
        {
            DataGridView g = new DataGridView();
            g.Dock = DockStyle.Fill;
            g.BackgroundColor = Theme.Card; g.BorderStyle = BorderStyle.None; g.GridColor = Theme.Border;
            g.CellBorderStyle = DataGridViewCellBorderStyle.None;
            g.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            g.EnableHeadersVisualStyles = false;
            g.RowHeadersVisible = false; g.AllowUserToAddRows = false; g.AllowUserToDeleteRows = false; g.AllowUserToResizeRows = false;
            g.ReadOnly = true; g.SelectionMode = DataGridViewSelectionMode.FullRowSelect; g.MultiSelect = false;
            g.RowTemplate.Height = Theme.Px(50);
            g.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            g.ColumnHeadersHeight = Theme.Px(32);
            g.ColumnHeadersDefaultCellStyle.BackColor = Theme.Card;
            g.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Dim;
            g.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Card;
            g.ColumnHeadersDefaultCellStyle.Font = Theme.Font(8f);
            g.ColumnHeadersDefaultCellStyle.Padding = new Padding(Theme.Px(12), 0, 0, 0);
            g.DefaultCellStyle.BackColor = Theme.Card;
            g.DefaultCellStyle.ForeColor = Theme.Text;
            g.DefaultCellStyle.SelectionBackColor = Theme.CardHi;
            g.DefaultCellStyle.SelectionForeColor = Theme.Text;
            g.DefaultCellStyle.Font = Theme.Font(9f);
            g.DefaultCellStyle.Padding = new Padding(Theme.Px(12), 0, Theme.Px(8), 0);
            typeof(DataGridView).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).SetValue(g, true, null);
            g.HandleCreated += delegate { Native.SetWindowTheme(g.Handle, "DarkMode_Explorer", null); };

            AddCol(g, "sev", "Уровень", typeof(int), 150, DataGridViewAutoSizeColumnMode.None);
            AddCol(g, "name", "Объект", typeof(string), 300, DataGridViewAutoSizeColumnMode.None);
            AddCol(g, "why", "Причина", typeof(string), 300, DataGridViewAutoSizeColumnMode.Fill);
            AddCol(g, "size", "Размер", typeof(long), 80, DataGridViewAutoSizeColumnMode.None);
            AddCol(g, "date", "Время", typeof(DateTime), 110, DataGridViewAutoSizeColumnMode.None);
            g.Columns["why"].MinimumWidth = Theme.Px(200);
            g.Columns["why"].DefaultCellStyle.WrapMode = DataGridViewTriState.True;
            g.Columns["size"].DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
            g.Columns["size"].HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleRight;

            g.CellPainting += CellPainting;
            g.CellFormatting += CellFormatting;
            g.Paint += PaintEmpty;
            g.CellMouseEnter += (s, e) => { if (e.RowIndex != hoverRow) { int old = hoverRow; hoverRow = e.RowIndex; InvRow(old); InvRow(hoverRow); } };
            g.MouseLeave += delegate { int old = hoverRow; hoverRow = -1; InvRow(old); };
            g.SelectionChanged += delegate { ShowDetails(Selected()); };
            g.CellDoubleClick += (s, e) => { if (e.RowIndex >= 0) Reveal(Selected()); };
            g.Resize += delegate { if (g.Rows.Count == 0) g.Invalidate(); };

            ContextMenuStrip cm = new ContextMenuStrip();
            cm.Renderer = new ToolStripProfessionalRenderer(new DarkColors());
            cm.BackColor = Theme.Card; cm.ForeColor = Theme.Text; cm.Font = Theme.Font(9.5f);
            cm.Items.Add("Показать в папке", null, delegate { Reveal(Selected()); });
            cm.Items.Add("Копировать путь", null, delegate { Finding f = Selected(); if (f != null) Clipboard.SetText(f.Path); });
            cm.Items.Add("Копировать SHA-256", null, delegate { Finding f = Selected(); if (f != null && f.Sha256 != null && f.Sha256.Length == 64) Clipboard.SetText(f.Sha256); });
            cm.Items.Add("Копировать отчёт по строке", null, delegate { Finding f = Selected(); if (f != null) Clipboard.SetText(FindingText(f)); });
            cm.Items.Add(new ToolStripSeparator());
            cm.Items.Add("Открыть хэш в VirusTotal", null, delegate { OpenVt(Selected()); });
            foreach (ToolStripItem it in cm.Items) it.ForeColor = Theme.Text;
            g.ContextMenuStrip = cm;
            g.CellMouseDown += (s, e) =>
            {
                if (e.Button == MouseButtons.Right && e.RowIndex >= 0) { g.ClearSelection(); g.Rows[e.RowIndex].Selected = true; g.CurrentCell = g.Rows[e.RowIndex].Cells[1]; }
            };
            return g;
        }

        static void AddCol(DataGridView g, string name, string header, Type t, int width, DataGridViewAutoSizeColumnMode mode)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name; c.HeaderText = header; c.ValueType = t; c.AutoSizeMode = mode;
            c.Width = Theme.Px(width); c.SortMode = DataGridViewColumnSortMode.Automatic;
            g.Columns.Add(c);
        }

        void InvRow(int i) { if (i >= 0 && i < grid.Rows.Count) grid.InvalidateRow(i); }

        void CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.Value == null) return;
            string col = grid.Columns[e.ColumnIndex].Name;
            if (col == "size") { e.Value = DetailsView.FormatSize((long)e.Value); e.FormattingApplied = true; e.CellStyle.ForeColor = Theme.Dim; }
            else if (col == "date")
            {
                DateTime d = (DateTime)e.Value;
                e.Value = d.Year < 1990 ? "" : d.ToString("dd.MM.yyyy\nHH:mm");
                e.CellStyle.WrapMode = DataGridViewTriState.True;
                e.FormattingApplied = true; e.CellStyle.ForeColor = Theme.Dim;
            }
            else if (col == "why") { e.CellStyle.ForeColor = Theme.Muted; e.CellStyle.SelectionForeColor = Theme.Text; }
        }

        void CellPainting(object sender, DataGridViewCellPaintingEventArgs e)
        {
            Graphics g = e.Graphics;
            if (e.RowIndex < 0)
            {
                e.PaintBackground(e.CellBounds, false);
                using (Pen p = new Pen(Theme.Border)) g.DrawLine(p, e.CellBounds.Left, e.CellBounds.Bottom - 1, e.CellBounds.Right, e.CellBounds.Bottom - 1);
                e.PaintContent(e.CellBounds);
                e.Handled = true;
                return;
            }
            Finding f = grid.Rows[e.RowIndex].Tag as Finding;
            if (f == null) return;
            Theme.Prep(g);
            bool sel = (e.State & DataGridViewElementStates.Selected) != 0;
            Rectangle cb = e.CellBounds;
            using (SolidBrush b = new SolidBrush(sel ? Theme.CardHi : e.RowIndex == hoverRow ? Theme.Mix(Theme.Card, Theme.CardHi, 0.6f) : Theme.Card)) g.FillRectangle(b, cb);
            using (Pen p = new Pen(Theme.Mix(Theme.Border, Theme.Card, 0.35f))) g.DrawLine(p, cb.Left, cb.Bottom - 1, cb.Right, cb.Bottom - 1);
            string col = grid.Columns[e.ColumnIndex].Name;
            if (col == "sev")
            {
                Color c = f.Severity == 0 ? Theme.Dim : Theme.Sev(f.Severity);
                if (sel) using (SolidBrush b = new SolidBrush(Theme.Text)) g.FillRectangle(b, cb.X, cb.Y, Theme.Px(2), cb.Height);
                using (SolidBrush b = new SolidBrush(c)) g.FillEllipse(b, cb.X + Theme.Px(16), cb.Y + Theme.Px(15), Theme.Px(7), Theme.Px(7));
                using (Font fn = Theme.Semi(8f))
                    TextRenderer.DrawText(g, Finding.SevName(f.Severity), fn, new Point(cb.X + Theme.Px(30), cb.Y + Theme.Px(11)), c, TextFormatFlags.NoPadding);
                RectangleF track = new RectangleF(cb.X + Theme.Px(30), cb.Y + Theme.Px(32), Theme.Px(80), Theme.Px(2));
                using (SolidBrush b = new SolidBrush(Theme.Border)) g.FillRectangle(b, track);
                using (SolidBrush b = new SolidBrush(Theme.Mix(c, Theme.Card, 0.25f))) g.FillRectangle(b, track.X, track.Y, track.Width * Math.Min(1f, f.Score / 120f), track.Height);
                e.Handled = true;
            }
            else if (col == "name")
            {
                string badge = Theme.TypeBadge(f.RealType);
                RectangleF ib = new RectangleF(cb.X + Theme.Px(12), cb.Y + (cb.Height - Theme.Px(28)) / 2f, Theme.Px(36), Theme.Px(28));
                Theme.FillRound(g, ib, Theme.Px(6), Color.Empty, Theme.Border);
                using (Font bf = Theme.Semi(7f))
                    TextRenderer.DrawText(g, badge, bf, Rectangle.Round(ib), Theme.Muted, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
                int x = (int)ib.Right + Theme.Px(12);
                int w = cb.Right - x - Theme.Px(8);
                using (Font nf = Theme.Semi(9.5f))
                    TextRenderer.DrawText(g, f.FileName, nf, new Rectangle(x, cb.Y + Theme.Px(8), w, Theme.Px(18)), Theme.Text, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
                using (Font pf = Theme.Font(8f))
                {
                    string sub = f.RealType.Contains(" · ") ? f.RealType.Substring(f.RealType.IndexOf(" · ") + 3) : f.RealType;
                    string dir = f.Source == "Диск" ? (Path.GetDirectoryName(f.Path) ?? "") : f.Path;
                    TextRenderer.DrawText(g, sub + "   " + dir, pf, new Rectangle(x, cb.Y + Theme.Px(27), w, Theme.Px(16)), Theme.Dim, TextFormatFlags.Left | TextFormatFlags.PathEllipsis | TextFormatFlags.NoPadding);
                }
                e.Handled = true;
            }
            else { e.PaintContent(cb); e.Handled = true; }
        }

        void PaintEmpty(object sender, PaintEventArgs e)
        {
            if (grid.Rows.Count > 0) return;
            Graphics g = e.Graphics; Theme.Prep(g);
            string title, sub;
            if (Running) { title = "Идёт проверка…"; sub = "Находки появятся здесь сразу"; }
            else if (All.Count > 0) { title = "Нет строк под этот фильтр"; sub = "Сбрось фильтр или поиск"; }
            else if (Scanned) { title = "Ничего не найдено"; sub = "Совпадений и подозрительных объектов нет"; }
            else { title = IdleTitle; sub = IdleSub; }
            int cy = grid.Height / 2;
            using (Font tf = Theme.Semi(11f))
                TextRenderer.DrawText(g, title, tf, new Rectangle(0, cy - Theme.Px(22), grid.Width, Theme.Px(24)), Theme.Text, TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPadding);
            using (Font sf = Theme.Font(9f))
                TextRenderer.DrawText(g, sub, sf, new Rectangle(0, cy + Theme.Px(6), grid.Width, Theme.Px(20)), Theme.Dim, TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPadding);
        }

        // ---------- данные ----------
        public void Enqueue(Finding f) { pending.Enqueue(f); }
        public event Action<Finding> Added;

        public void Clear()
        {
            All.Clear(); grid.Rows.Clear();
            Finding d; while (pending.TryDequeue(out d)) { }
            Crit = Susp = Warn = Clean = 0;
            details.Display(null);
            UpdateChips();
            grid.Invalidate();
        }

        public int Pump()
        {
            Finding f; int added = 0;
            while (added < 400 && pending.TryDequeue(out f))
            {
                All.Add(f);
                if (Added != null) Added(f);
                if (f.Severity >= 3) Crit++; else if (f.Severity == 2) Susp++; else if (f.Severity == 1) Warn++; else Clean++;
                if (Pass(f)) AddRow(f);
                added++;
            }
            if (added > 0) UpdateChips();
            return added;
        }

        void UpdateChips()
        {
            cAll.Count = All.Count; cCrit.Count = Crit; cSusp.Count = Susp; cWarn.Count = Warn; cOk.Count = Clean;
            foreach (Chip c in new Chip[] { cAll, cCrit, cSusp, cWarn, cOk }) { c.Fit(); c.Invalidate(); }
        }

        public void Finish()
        {
            Pump();
            if (grid.Rows.Count > 0)
            {
                grid.Sort(grid.Columns["sev"], System.ComponentModel.ListSortDirection.Descending);
                grid.ClearSelection();
                grid.Rows[0].Selected = true;
                grid.CurrentCell = grid.Rows[0].Cells[1];
            }
            grid.Invalidate();
        }

        public void RepaintEmpty() { grid.Invalidate(); }

        bool Pass(Finding f)
        {
            if (sevFilter > 0 && f.Severity != sevFilter) return false;
            if (sevFilter < 0 && f.Severity != 0) return false;
            string q = search.Box.Text.Trim();
            if (q.Length == 0) return true;
            return f.Path.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0 || f.RealType.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0 ||
                   f.Reasons.Any(r => r.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        void AddRow(Finding f)
        {
            int i = grid.Rows.Add(f.Severity, f.FileName, f.Summary, f.Size, f.Modified);
            grid.Rows[i].Tag = f;
            grid.Rows[i].Cells[1].ToolTipText = f.Path;
            grid.Rows[i].Cells[2].ToolTipText = string.Join("\n", f.Reasons);
        }

        void Refilter()
        {
            grid.SuspendLayout();
            grid.Rows.Clear();
            foreach (Finding f in All.OrderByDescending(x => x.Severity).ThenByDescending(x => x.Score)) if (Pass(f)) AddRow(f);
            grid.ResumeLayout();
            grid.Invalidate();
        }

        Finding Selected() { return grid.SelectedRows.Count == 0 ? null : grid.SelectedRows[0].Tag as Finding; }

        void ShowDetails(Finding f)
        {
            details.Display(f);
            if (f != null && f.Sha256 == null && f.Path.Length > 3 && f.Path[1] == ':' && File.Exists(f.Path))
            {
                Task.Factory.StartNew(() =>
                {
                    try { f.Sha256 = Analyzer.Sha256(f.Path); } catch { f.Sha256 = "нет доступа"; }
                    try { BeginInvoke(new Action(() => { if (details.Current == f) details.Invalidate(); })); } catch { }
                });
            }
            else if (f != null && f.Sha256 == null) f.Sha256 = "—";
        }

        static void Reveal(Finding f)
        {
            if (f == null) return;
            try
            {
                if (File.Exists(f.Path)) Process.Start("explorer.exe", "/select,\"" + f.Path + "\"");
                else if (Directory.Exists(f.Path)) Process.Start("explorer.exe", "\"" + f.Path + "\"");
                else
                {
                    string d = Path.GetDirectoryName(f.Path);
                    if (d != null && Directory.Exists(d)) Process.Start("explorer.exe", "\"" + d + "\"");
                }
            }
            catch { }
        }

        static void OpenVt(Finding f)
        {
            if (f != null && f.Sha256 != null && f.Sha256.Length == 64)
                try { Process.Start("https://www.virustotal.com/gui/file/" + f.Sha256); } catch { }
        }

        public static string FindingText(Finding f)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("[" + Finding.SevName(f.Severity) + "] (" + f.Score + ") " + f.Path);
            sb.AppendLine("    Тип: " + f.RealType + (f.Size > 0 ? "   Размер: " + f.Size.ToString("N0") : "") + "   Источник: " + f.Source);
            if (f.Created.Year > 1990) sb.AppendLine("    Создан: " + f.Created.ToString("dd.MM.yyyy HH:mm:ss") + "   Изменён: " + f.Modified.ToString("dd.MM.yyyy HH:mm:ss"));
            else if (f.Modified.Year > 1990) sb.AppendLine("    Время: " + f.Modified.ToString("dd.MM.yyyy HH:mm:ss"));
            if (f.Sig != null) sb.AppendLine("    Подпись: " + f.Sig);
            if (f.Sha256 != null) sb.AppendLine("    SHA-256: " + f.Sha256);
            foreach (string r in f.Reasons) sb.AppendLine("      " + r);
            return sb.ToString();
        }
    }
}
