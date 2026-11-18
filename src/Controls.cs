using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace InjectHunter
{
    /// <summary>Минималистичная тема: графит + белый, цвет только у уровней опасности.</summary>
    static class Theme
    {
        public static float S = 1f;
        public static int Px(float v) { return (int)Math.Round(v * S); }

        static Color C(int r, int g, int b) { return Color.FromArgb(r, g, b); }
        public static Color Bg = C(0x0C, 0x0C, 0x0D);
        public static Color Side = C(0x10, 0x10, 0x12);
        public static Color Card = C(0x15, 0x15, 0x17);
        public static Color CardHi = C(0x1D, 0x1D, 0x20);
        public static Color Border = C(0x25, 0x25, 0x29);
        public static Color Text = C(0xF4, 0xF4, 0xF5);
        public static Color Muted = C(0xA1, 0xA1, 0xAA);
        public static Color Dim = C(0x63, 0x63, 0x6B);
        public static Color Accent = C(0xF4, 0xF4, 0xF5);
        public static Color Accent2 = C(0xA1, 0xA1, 0xAA);
        public static Color Red = C(0xEF, 0x44, 0x44);
        public static Color Orange = C(0xF5, 0x9E, 0x0B);
        public static Color Yellow = C(0xE5, 0xC0, 0x2A);
        public static Color Green = C(0x22, 0xC5, 0x5E);

        public static Color Sev(int s) { return s >= 3 ? Red : s == 2 ? Orange : s == 1 ? Yellow : Green; }
        public static Color Mix(Color a, Color b, float t)
        {
            return Color.FromArgb((int)(a.R + (b.R - a.R) * t), (int)(a.G + (b.G - a.G) * t), (int)(a.B + (b.B - a.B) * t));
        }

        public static Font Font(float size, FontStyle st = FontStyle.Regular) { return new Font("Segoe UI", size, st, GraphicsUnit.Point); }
        public static Font Semi(float size) { return new Font("Segoe UI Semibold", size, FontStyle.Regular, GraphicsUnit.Point); }
        public static Font Bold(float size) { return new Font("Segoe UI", size, FontStyle.Bold, GraphicsUnit.Point); }
        public static Font Mono(float size) { return new Font("Consolas", size, FontStyle.Regular, GraphicsUnit.Point); }

        static string iconFamily;
        static bool iconChecked;
        public static Font Icon(float size)
        {
            if (!iconChecked)
            {
                iconChecked = true;
                try
                {
                    string[] names = new InstalledFontCollection().Families.Select(f => f.Name).ToArray();
                    if (names.Contains("Segoe Fluent Icons")) iconFamily = "Segoe Fluent Icons";
                    else if (names.Contains("Segoe MDL2 Assets")) iconFamily = "Segoe MDL2 Assets";
                }
                catch { }
            }
            return iconFamily == null ? null : new Font(iconFamily, size, FontStyle.Regular, GraphicsUnit.Point);
        }
        public const string IcPlay = "", IcStop = "", IcSave = "", IcSearch = "", IcFolder = "",
            IcCopy = "", IcGlobe = "", IcShield = "", IcWarn = "", IcOk = "", IcError = "",
            IcClock = "", IcDoc = "", IcDrive = "", IcCpu = "", IcBug = "", IcHash = "",
            IcCheck = "", IcInfo = "", IcFilter = "", IcLock = "", IcHistory = "", IcTools = "",
            IcList = "", IcOpen = "", IcMemory = "", IcTag = "";

        public static void DrawIcon(Graphics g, string glyph, float size, Rectangle r, Color c)
        {
            using (Font f = Icon(size))
            {
                if (f == null) return;
                TextRenderer.DrawText(g, glyph, f, r, c, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            }
        }

        public static GraphicsPath Round(RectangleF r, float rad)
        {
            GraphicsPath p = new GraphicsPath();
            float d = rad * 2;
            if (d > r.Height) d = r.Height;
            if (d > r.Width) d = r.Width;
            if (d < 1) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static void FillRound(Graphics g, RectangleF r, float rad, Color fill, Color border)
        {
            using (GraphicsPath p = Round(r, rad))
            {
                if (fill != Color.Empty) using (SolidBrush b = new SolidBrush(fill)) g.FillPath(b, p);
                if (border != Color.Empty) using (Pen pen = new Pen(border)) g.DrawPath(pen, p);
            }
        }

        public static void Prep(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        }

        public static string TypeBadge(string realType)
        {
            string t = realType ?? "";
            int dot = t.IndexOf(" · ");
            if (dot > 0 && dot <= 4) return t.Substring(0, dot);
            if (t.StartsWith("JAR") || t.StartsWith("ZIP")) return "JAR";
            if (t.Contains("class")) return "CLS";
            if (t.Contains("RAM") || t.Contains("память") || t.Contains("manual") || t.Contains("скрытый") || t.Contains("процесс")) return "RAM";
            if (t.Contains(".NET")) return "NET";
            if (t.Contains("DLL")) return "DLL";
            if (t.Contains("EXE")) return "EXE";
            if (t.Contains("драйвер")) return "SYS";
            if (t.StartsWith("архив")) return "ZIP";
            return "—";
        }
    }

    class Smooth : Control
    {
        public Smooth()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            ForeColor = Theme.Text;
        }
        protected bool hover, down;
        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { down = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
        protected void ClearBg(Graphics g) { g.Clear(Parent != null ? Parent.BackColor : Theme.Bg); }
    }

    /// <summary>Кнопка: Primary — белая с тёмным текстом; иначе — контурная.</summary>
    class FlatButton : Smooth
    {
        public bool Primary, Danger;
        public string Glyph;
        public FlatButton(string text, bool primary, string glyph = null, bool danger = false)
        {
            Text = text; Primary = primary; Glyph = glyph; Danger = danger;
            Font = Theme.Semi(9.5f);
            Cursor = Cursors.Hand;
            Height = Theme.Px(36);
            Width = TextRenderer.MeasureText(text, Font).Width + Theme.Px(glyph != null ? 54 : 32);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Color tc;
            if (Primary)
            {
                Color fill = !Enabled ? Theme.CardHi : down ? Theme.Mix(Theme.Text, Theme.Bg, 0.15f) : hover ? Color.White : Theme.Text;
                Theme.FillRound(g, r, Theme.Px(8), fill, Color.Empty);
                tc = Enabled ? Theme.Bg : Theme.Dim;
            }
            else
            {
                Color fill = !Enabled ? Color.Empty : down ? Theme.Border : hover ? Theme.CardHi : Color.Empty;
                Theme.FillRound(g, r, Theme.Px(8), fill, hover && Enabled ? Theme.Mix(Theme.Border, Theme.Text, 0.2f) : Theme.Border);
                tc = !Enabled ? Theme.Dim : Danger ? Theme.Red : Theme.Text;
            }
            Size ts = TextRenderer.MeasureText(Text, Font);
            int iconW = Glyph != null ? Theme.Px(22) : 0;
            int x = (Width - ts.Width - iconW) / 2;
            if (Glyph != null) Theme.DrawIcon(g, Glyph, 9.5f, new Rectangle(x, 0, Theme.Px(16), Height), tc);
            TextRenderer.DrawText(g, Text, Font, new Rectangle(x + iconW, 0, ts.Width + 4, Height), tc,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }

    class IconButton : Smooth
    {
        public string Glyph;
        public IconButton(string glyph, string text)
        {
            Glyph = glyph; Text = text; Font = Theme.Font(8.5f); Cursor = Cursors.Hand;
            Height = Theme.Px(28);
            Width = TextRenderer.MeasureText(text, Font).Width + Theme.Px(38);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Theme.FillRound(g, r, Theme.Px(7), down ? Theme.Border : hover ? Theme.CardHi : Color.Empty, Theme.Border);
            Theme.DrawIcon(g, Glyph, 8.5f, new Rectangle(Theme.Px(8), 0, Theme.Px(16), Height), hover ? Theme.Text : Theme.Muted);
            TextRenderer.DrawText(g, Text, Font, new Rectangle(Theme.Px(28), 0, Width - Theme.Px(30), Height), hover ? Theme.Text : Theme.Muted,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }

    /// <summary>Пункт навигации слева.</summary>
    class NavItem : Smooth
    {
        public string Glyph;
        public bool Active;
        public int Badge = -1;
        public Color BadgeColor = Theme.Muted;
        public NavItem(string glyph, string text)
        {
            Glyph = glyph; Text = text; Font = Theme.Font(9.5f); Cursor = Cursors.Hand; Height = Theme.Px(38);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            if (Active || hover) Theme.FillRound(g, r, Theme.Px(7), Active ? Theme.CardHi : Theme.Card, Color.Empty);
            Color c = Active ? Theme.Text : hover ? Theme.Text : Theme.Muted;
            Theme.DrawIcon(g, Glyph, 10f, new Rectangle(Theme.Px(10), 0, Theme.Px(20), Height), c);
            using (Font f = Active ? Theme.Semi(9.5f) : Theme.Font(9.5f))
                TextRenderer.DrawText(g, Text, f, new Rectangle(Theme.Px(40), 0, Width - Theme.Px(80), Height), c,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
            if (Badge > 0)
                using (Font bf = Theme.Semi(7.5f))
                {
                    string t = Badge > 999 ? "999+" : Badge.ToString();
                    Size ts = TextRenderer.MeasureText(t, bf);
                    RectangleF br = new RectangleF(Width - ts.Width - Theme.Px(22), (Height - Theme.Px(18)) / 2f, ts.Width + Theme.Px(12), Theme.Px(18));
                    Theme.FillRound(g, br, br.Height / 2, Color.FromArgb(40, BadgeColor), Color.Empty);
                    TextRenderer.DrawText(g, t, bf, Rectangle.Round(br), BadgeColor, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
                }
        }
    }

    /// <summary>Переключатель-«пилюля» с галочкой (компактная опция).</summary>
    class PillToggle : Smooth
    {
        bool _checked;
        public string Tip;
        public bool Checked { get { return _checked; } set { _checked = value; Invalidate(); } }
        public PillToggle(string text, bool on, string tip = null)
        {
            Text = text; _checked = on; Tip = tip; Font = Theme.Font(9f); Cursor = Cursors.Hand;
            Height = Theme.Px(30);
            Width = TextRenderer.MeasureText(text, Font).Width + Theme.Px(44);
        }
        protected override void OnClick(EventArgs e) { Checked = !Checked; base.OnClick(e); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Theme.FillRound(g, r, r.Height / 2, hover ? Theme.CardHi : Theme.Card, _checked ? Theme.Mix(Theme.Border, Theme.Text, 0.35f) : Theme.Border);
            RectangleF cb = new RectangleF(Theme.Px(10), (Height - Theme.Px(14)) / 2f, Theme.Px(14), Theme.Px(14));
            if (_checked)
            {
                Theme.FillRound(g, cb, Theme.Px(4), Theme.Text, Color.Empty);
                using (Pen pen = new Pen(Theme.Bg, Theme.Px(1.8f)))
                {
                    pen.StartCap = pen.EndCap = LineCap.Round;
                    g.DrawLines(pen, new PointF[] { new PointF(cb.X + cb.Width * 0.24f, cb.Y + cb.Height * 0.52f),
                        new PointF(cb.X + cb.Width * 0.43f, cb.Y + cb.Height * 0.72f), new PointF(cb.X + cb.Width * 0.78f, cb.Y + cb.Height * 0.3f) });
                }
            }
            else Theme.FillRound(g, cb, Theme.Px(4), Color.Empty, Theme.Dim);
            TextRenderer.DrawText(g, Text, Font, new Rectangle(Theme.Px(32), 0, Width - Theme.Px(36), Height), _checked ? Theme.Text : Theme.Muted,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }

    class DriveCard : Smooth
    {
        public string Root;
        string label, fs;
        long total, free;
        bool _checked;
        public bool Checked { get { return _checked; } set { _checked = value; Invalidate(); } }
        public DriveCard(DriveInfo d)
        {
            Root = d.Name;
            try { label = d.VolumeLabel; } catch { label = ""; }
            try { fs = d.DriveFormat; } catch { fs = ""; }
            try { total = d.TotalSize; free = d.TotalFreeSpace; } catch { }
            string kind = d.DriveType == DriveType.Fixed ? "Локальный диск" : d.DriveType == DriveType.Removable ? "Съёмный диск" :
                   d.DriveType == DriveType.Network ? "Сетевой диск" : d.DriveType.ToString();
            if (string.IsNullOrEmpty(label)) label = kind;
            Height = Theme.Px(58); Width = Theme.Px(230);
            Cursor = Cursors.Hand;
            Font = Theme.Font(9f);
        }
        protected override void OnClick(EventArgs e) { Checked = !Checked; base.OnClick(e); }
        static string Gb(long b) { return (b / 1073741824.0).ToString(b >= 100L * 1073741824 ? "0" : "0.0") + " ГБ"; }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Theme.FillRound(g, r, Theme.Px(10), hover ? Theme.CardHi : Theme.Card, _checked ? Theme.Mix(Theme.Border, Theme.Text, 0.45f) : Theme.Border);
            using (Font bf = Theme.Semi(13f))
                TextRenderer.DrawText(g, Root.Substring(0, 2), bf, new Rectangle(Theme.Px(14), 0, Theme.Px(36), Height), _checked ? Theme.Text : Theme.Dim,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            int x = Theme.Px(54);
            using (Font tf = Theme.Font(9f))
                TextRenderer.DrawText(g, label, tf, new Rectangle(x, Theme.Px(11), Width - x - Theme.Px(36), Theme.Px(18)), _checked ? Theme.Text : Theme.Muted,
                    TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
            using (Font sf = Theme.Font(7.5f))
                TextRenderer.DrawText(g, (total > 0 ? Gb(total - free) + " / " + Gb(total) : "нет доступа") + (fs.Length > 0 ? " · " + fs : ""), sf,
                    new Rectangle(x, Theme.Px(29), Width - x - Theme.Px(12), Theme.Px(14)), Theme.Dim, TextFormatFlags.Left | TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
            RectangleF bar = new RectangleF(x, Theme.Px(45), Width - x - Theme.Px(14), Theme.Px(2));
            using (SolidBrush b = new SolidBrush(Theme.Border)) g.FillRectangle(b, bar);
            if (total > 0)
                using (SolidBrush b = new SolidBrush(_checked ? Theme.Muted : Theme.Dim))
                    g.FillRectangle(b, bar.X, bar.Y, bar.Width * Math.Max(0.02f, (float)(total - free) / total), bar.Height);
            RectangleF cb = new RectangleF(Width - Theme.Px(28), Theme.Px(10), Theme.Px(16), Theme.Px(16));
            if (_checked)
            {
                Theme.FillRound(g, cb, Theme.Px(4), Theme.Text, Color.Empty);
                using (Pen pen = new Pen(Theme.Bg, Theme.Px(1.8f)))
                {
                    pen.StartCap = pen.EndCap = LineCap.Round;
                    g.DrawLines(pen, new PointF[] { new PointF(cb.X + cb.Width * 0.24f, cb.Y + cb.Height * 0.52f),
                        new PointF(cb.X + cb.Width * 0.43f, cb.Y + cb.Height * 0.72f), new PointF(cb.X + cb.Width * 0.78f, cb.Y + cb.Height * 0.3f) });
                }
            }
            else Theme.FillRound(g, cb, Theme.Px(4), Color.Empty, Theme.Dim);
        }
    }

    /// <summary>Строка статуса раздела: индикатор, заголовок, подпись, проценты, тонкий прогресс.</summary>
    class VerdictBar : Smooth
    {
        public enum State { Idle, Running, Clean, Warn, Crit, Info }
        public State Mode = State.Idle;
        public string Title = "", Sub = "";
        public double Progress;
        public bool ShowPercent;
        float spin;
        Timer t = new Timer();
        public VerdictBar()
        {
            t.Interval = 16;
            t.Tick += delegate { if (Mode == State.Running) { spin = (spin + 8) % 360; Invalidate(); } };
            t.Start();
            Height = Theme.Px(64);
        }
        protected override void Dispose(bool disposing) { if (disposing) t.Dispose(); base.Dispose(disposing); }
        public void Set(State m, string title, string sub)
        {
            if (m != Mode || title != Title || sub != Sub) { Mode = m; Title = title; Sub = sub; Invalidate(); }
        }
        Color ModeColor()
        {
            switch (Mode)
            {
                case State.Clean: return Theme.Green;
                case State.Warn: return Theme.Orange;
                case State.Crit: return Theme.Red;
                case State.Info: return Theme.Yellow;
                default: return Theme.Text;
            }
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            Color c = ModeColor();
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Theme.FillRound(g, r, Theme.Px(10), Theme.Card, Theme.Border);
            int cs = Theme.Px(18);
            RectangleF ic = new RectangleF(Theme.Px(18), (Height - cs) / 2f - Theme.Px(1), cs, cs);
            if (Mode == State.Running)
            {
                using (Pen pen = new Pen(Theme.Border, Theme.Px(2))) g.DrawEllipse(pen, ic);
                using (Pen pen = new Pen(Theme.Text, Theme.Px(2))) { pen.StartCap = pen.EndCap = LineCap.Round; g.DrawArc(pen, ic, spin, 90); }
            }
            else if (Mode == State.Idle)
                using (Pen pen = new Pen(Theme.Dim, Theme.Px(2))) g.DrawEllipse(pen, RectangleF.Inflate(ic, -Theme.Px(3), -Theme.Px(3)));
            else
            {
                using (SolidBrush b = new SolidBrush(Color.FromArgb(40, c))) g.FillEllipse(b, ic);
                using (SolidBrush b = new SolidBrush(c)) g.FillEllipse(b, RectangleF.Inflate(ic, -Theme.Px(5), -Theme.Px(5)));
            }
            int x = (int)ic.Right + Theme.Px(16);
            int right = Width - Theme.Px(ShowPercent ? 80 : 18);
            using (Font tf = Theme.Semi(10.5f))
                TextRenderer.DrawText(g, Title, tf, new Rectangle(x, Theme.Px(12), right - x, Theme.Px(22)),
                    Mode == State.Idle || Mode == State.Running ? Theme.Text : Theme.Mix(c, Theme.Text, 0.35f),
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
            using (Font sf = Theme.Font(8.5f))
                TextRenderer.DrawText(g, Sub, sf, new Rectangle(x, Theme.Px(34), right - x, Theme.Px(18)), Theme.Dim,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.PathEllipsis | TextFormatFlags.NoPadding);
            if (ShowPercent)
                using (Font pf = Theme.Font(13f))
                    TextRenderer.DrawText(g, ((int)(Progress * 100)) + "%", pf, new Rectangle(right, 0, Width - right - Theme.Px(18), Height),
                        Theme.Text, TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            if (Mode == State.Running)
            {
                float w = (float)((Width - Theme.Px(2)) * Math.Max(0, Math.Min(1, Progress)));
                using (SolidBrush b = new SolidBrush(Theme.Text)) g.FillRectangle(b, Theme.Px(1), Height - Theme.Px(3), w, Theme.Px(2));
            }
        }
    }

    class Chip : Smooth
    {
        public bool Active;
        public Color Dot;
        public int Count = -1;
        public Chip(string text, Color dot)
        {
            Text = text; Dot = dot; Font = Theme.Font(9f); Cursor = Cursors.Hand; Height = Theme.Px(30);
        }
        string CountText() { return Count >= 0 ? Count.ToString() : ""; }
        public void Fit()
        {
            int w = TextRenderer.MeasureText(Text, Font).Width + Theme.Px(Dot == Color.Empty ? 24 : 36);
            if (Count >= 0) w += TextRenderer.MeasureText(CountText(), Font).Width + Theme.Px(6);
            if (w != Width) { Width = w; Invalidate(); }
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Theme.FillRound(g, r, Theme.Px(7), Active ? Theme.CardHi : hover ? Theme.Card : Color.Empty, Active ? Theme.Mix(Theme.Border, Theme.Text, 0.3f) : Theme.Border);
            int x = Theme.Px(12);
            if (Dot != Color.Empty)
            {
                using (SolidBrush b = new SolidBrush(Dot)) g.FillEllipse(b, x, Height / 2f - Theme.Px(3), Theme.Px(6), Theme.Px(6));
                x += Theme.Px(13);
            }
            Size ts = TextRenderer.MeasureText(Text, Font);
            TextRenderer.DrawText(g, Text, Font, new Rectangle(x, 0, ts.Width + 2, Height), Active ? Theme.Text : Theme.Muted,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            if (Count >= 0)
                TextRenderer.DrawText(g, CountText(), Font, new Rectangle(x + ts.Width + Theme.Px(4), 0, Width, Height), Theme.Dim,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }

    class CardPanel : Panel
    {
        public CardPanel()
        {
            DoubleBuffered = true; BackColor = Theme.Card;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; Theme.Prep(g);
            g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            Theme.FillRound(g, new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), Theme.Px(10), Theme.Card, Theme.Border);
        }
    }

    /// <summary>Заголовок раздела: крупное название + подпись.</summary>
    class PageTitle : Control
    {
        public string Sub;
        public PageTitle(string title, string sub)
        {
            Text = title; Sub = sub; Height = Theme.Px(56);
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            using (Font tf = Theme.Semi(16f))
                TextRenderer.DrawText(g, Text, tf, new Point(0, Theme.Px(2)), Theme.Text, TextFormatFlags.NoPadding);
            using (Font sf = Theme.Font(9f))
                TextRenderer.DrawText(g, Sub, sf, new Rectangle(0, Theme.Px(34), Width, Theme.Px(18)), Theme.Dim, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
        }
    }

    /// <summary>Карточка встроенной программы.</summary>
    class ToolCard : Smooth
    {
        public ToolInfo Tool;
        public ToolCard(ToolInfo t)
        {
            Tool = t; Cursor = Cursors.Hand; Width = Theme.Px(300); Height = Theme.Px(104); Font = Theme.Font(9f);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Theme.FillRound(g, r, Theme.Px(10), down ? Theme.Border : hover ? Theme.CardHi : Theme.Card, hover ? Theme.Mix(Theme.Border, Theme.Text, 0.25f) : Theme.Border);
            int p = Theme.Px(16);
            using (Font tf = Theme.Semi(10f))
                TextRenderer.DrawText(g, Tool.Title, tf, new Rectangle(p, Theme.Px(13), Width - p * 2 - Theme.Px(24), Theme.Px(20)), Theme.Text,
                    TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
            Theme.DrawIcon(g, Tool.Installer ? Theme.IcSave : Theme.IcOpen, 9f, new Rectangle(Width - Theme.Px(36), Theme.Px(10), Theme.Px(24), Theme.Px(24)), hover ? Theme.Text : Theme.Dim);
            using (Font df = Theme.Font(8.5f))
                TextRenderer.DrawText(g, Tool.Desc, df, new Rectangle(p, Theme.Px(36), Width - p * 2, Theme.Px(34)), Theme.Muted,
                    TextFormatFlags.Left | TextFormatFlags.WordBreak | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
            string sig = Tool.Sig == null ? "" : Tool.Sig.Trusted ? "подпись: " + (Tool.Sig.Signer ?? "есть") : "без подписи";
            string meta = (Tool.Installer ? "установщик · " : Tool.Zip ? "архив · " : "") + DetailsView.FormatSize(Tool.Size) + (sig.Length > 0 ? " · " + sig : "") + (Tool.NirArgs != null ? " · авто" : "");
            using (Font mf = Theme.Font(7.5f))
                TextRenderer.DrawText(g, meta, mf, new Rectangle(p, Height - Theme.Px(24), Width - p * 2, Theme.Px(14)), Theme.Dim,
                    TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
        }
    }

    /// <summary>Панель деталей выбранной находки.</summary>
    class DetailsView : Panel
    {
        Finding f;
        public IconButton bFolder, bCopy, bHash, bVt, bCode;
        int contentH;
        public string EmptyText = "Выбери строку, чтобы увидеть причины.";

        public DetailsView()
        {
            DoubleBuffered = true; BackColor = Theme.Card; AutoScroll = true;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
            bFolder = new IconButton(Theme.IcFolder, "В папке");
            bCopy = new IconButton(Theme.IcCopy, "Путь");
            bHash = new IconButton(Theme.IcHash, "SHA-256");
            bVt = new IconButton(Theme.IcGlobe, "VirusTotal");
            bCode = new IconButton("", "Разобрать");
            foreach (IconButton b in new IconButton[] { bFolder, bCopy, bHash, bVt, bCode }) { b.Visible = false; b.BackColor = Theme.Card; Controls.Add(b); }
            HandleCreated += delegate { Native.SetWindowTheme(Handle, "DarkMode_Explorer", null); };
        }

        public void Display(Finding x)
        {
            f = x;
            foreach (Control c in Controls) c.Visible = f != null;
            AutoScrollPosition = Point.Empty;
            PerformLayout();
            Invalidate();
        }
        public Finding Current { get { return f; } }

        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            if (bFolder == null) return;
            int pad = Theme.Px(16);
            int x = Width - pad - (AutoScrollMinSize.Height > Height ? SystemInformation.VerticalScrollBarWidth : 0);
            Point off = AutoScrollPosition;
            foreach (IconButton b in new IconButton[] { bVt, bHash, bCopy, bFolder, bCode })
            {
                x -= b.Width;
                b.Location = new Point(x, pad + off.Y);
                x -= Theme.Px(6);
            }
        }

        protected override void OnScroll(ScrollEventArgs se) { base.OnScroll(se); Invalidate(); }
        protected override void OnMouseWheel(MouseEventArgs e) { base.OnMouseWheel(e); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; Theme.Prep(g);
            g.Clear(Theme.Card);
            int pad = Theme.Px(16);
            if (f == null)
            {
                using (Font ef = Theme.Font(9f))
                    TextRenderer.DrawText(g, EmptyText, ef, new Rectangle(0, 0, Width, Height), Theme.Dim, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                if (contentH != 0) { contentH = 0; AutoScrollMinSize = Size.Empty; }
                return;
            }
            g.TranslateTransform(0, AutoScrollPosition.Y);
            int y = PaintFinding(g, pad, ClientSize.Width - pad * 2);
            g.ResetTransform();
            if (y + pad != contentH) { contentH = y + pad; AutoScrollMinSize = new Size(0, contentH); }
        }

        int PaintFinding(Graphics g, int pad, int w)
        {
            Color sc = Theme.Sev(f.Severity);
            int y = pad;
            int buttonsW = bFolder.Width + bCopy.Width + bHash.Width + bVt.Width + bCode.Width + Theme.Px(36);
            using (SolidBrush b = new SolidBrush(sc)) g.FillEllipse(b, pad, y + Theme.Px(9), Theme.Px(8), Theme.Px(8));
            using (Font sf = Theme.Semi(8f))
                TextRenderer.DrawText(g, Finding.SevName(f.Severity), sf, new Point(pad + Theme.Px(14), y + Theme.Px(6)), sc, TextFormatFlags.NoPadding);
            using (Font nf = Theme.Semi(12f))
                TextRenderer.DrawText(g, f.FileName, nf, new Rectangle(pad + Theme.Px(120), y, Math.Max(10, w - Theme.Px(120) - buttonsW), Theme.Px(26)), Theme.Text,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
            y += Theme.Px(30);
            using (Font mf = Theme.Mono(8.5f))
                TextRenderer.DrawText(g, f.Path, mf, new Rectangle(pad, y, w, Theme.Px(16)), Theme.Muted,
                    TextFormatFlags.Left | TextFormatFlags.PathEllipsis | TextFormatFlags.NoPadding);
            y += Theme.Px(26);

            List<string[]> meta = new List<string[]>();
            meta.Add(new string[] { "Тип", f.RealType });
            meta.Add(new string[] { "Баллы", f.Score.ToString() });
            if (f.Size > 0) meta.Add(new string[] { "Размер", FormatSize(f.Size) });
            if (f.Created.Year > 1990) meta.Add(new string[] { "Создан", f.Created.ToString("dd.MM.yyyy HH:mm") });
            if (f.Modified.Year > 1990) meta.Add(new string[] { f.Source == "Диск" ? "Изменён" : "Время", f.Modified.ToString("dd.MM.yyyy HH:mm") });
            if (f.Sig != null) meta.Add(new string[] { "Подпись", f.Sig.Trusted ? (f.Sig.State == SigState.Catalog ? "каталог Windows" : f.Sig.Signer ?? "есть") : f.Sig.State == SigState.Invalid ? "недействительна" : "нет" });
            meta.Add(new string[] { "Источник", f.Source });
            int mx = pad;
            using (Font lf = Theme.Font(7.5f))
            using (Font vf = Theme.Font(9f))
                foreach (string[] m in meta)
                {
                    int cw = Math.Min(Theme.Px(300), Math.Max(TextRenderer.MeasureText(m[0], lf).Width, TextRenderer.MeasureText(m[1], vf).Width) + Theme.Px(4));
                    if (mx + cw > pad + w && mx > pad) { mx = pad; y += Theme.Px(40); }
                    TextRenderer.DrawText(g, m[0].ToUpperInvariant(), lf, new Rectangle(mx, y, cw, Theme.Px(14)), Theme.Dim, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
                    Color vc = m[0] == "Подпись" ? (f.Sig != null && f.Sig.Trusted ? Theme.Green : Theme.Orange) : m[0] == "Баллы" ? sc : Theme.Text;
                    TextRenderer.DrawText(g, m[1], vf, new Rectangle(mx, y + Theme.Px(15), cw, Theme.Px(18)), vc, TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
                    mx += cw + Theme.Px(28);
                }
            y += Theme.Px(46);
            using (Pen p = new Pen(Theme.Border)) g.DrawLine(p, pad, y, pad + w, y);
            y += Theme.Px(14);

            using (Font bf = Theme.Semi(8f))
            using (Font rf = Theme.Font(9.5f))
                foreach (string r in f.Reasons)
                {
                    string badge = "·"; string text = r;
                    int sp = r.IndexOf("  ");
                    if (sp > 0 && sp < 6) { badge = r.Substring(0, sp).Trim(); text = r.Substring(sp + 2); }
                    bool plus = badge.StartsWith("+"), minus = badge.StartsWith("-");
                    Color bc = plus ? sc : minus ? Theme.Green : Theme.Dim;
                    TextRenderer.DrawText(g, plus || minus ? badge : "", bf, new Rectangle(pad, y + Theme.Px(2), Theme.Px(40), Theme.Px(18)), bc, TextFormatFlags.Right | TextFormatFlags.NoPadding);
                    int tx = pad + Theme.Px(52);
                    Size ts = TextRenderer.MeasureText(g, text, rf, new Size(w - Theme.Px(52), 1000), TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);
                    TextRenderer.DrawText(g, text, rf, new Rectangle(tx, y, w - Theme.Px(52), ts.Height + 2), plus ? Theme.Text : minus ? Theme.Green : Theme.Muted,
                        TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);
                    y += Math.Max(Theme.Px(24), ts.Height + Theme.Px(8));
                }
            y += Theme.Px(6);
            using (Font hf = Theme.Font(7.5f))
                TextRenderer.DrawText(g, "SHA-256", hf, new Point(pad, y + 2), Theme.Dim, TextFormatFlags.NoPadding);
            using (Font mono = Theme.Mono(8.5f))
                TextRenderer.DrawText(g, f.Sha256 ?? "считаю…", mono, new Point(pad + Theme.Px(60), y), Theme.Muted, TextFormatFlags.NoPadding);
            y += Theme.Px(24);
            using (Font hf = Theme.Font(7.5f))
                TextRenderer.DrawText(g, "ОТКУДА", hf, new Point(pad, y + 2), Theme.Dim, TextFormatFlags.NoPadding);
            using (Font of = Theme.Font(9f))
            {
                string ot = f.Origin ?? "ищу метку скачивания…";
                int ow = w - Theme.Px(60);
                Size os = TextRenderer.MeasureText(g, ot, of, new Size(ow, 2000), TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);
                TextRenderer.DrawText(g, ot, of, new Rectangle(pad + Theme.Px(60), y, ow, os.Height + 2), Theme.Muted, TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);
                y += os.Height;
            }
            return y + Theme.Px(20);
        }

        public static string FormatSize(long v)
        {
            return v <= 0 ? "" : v < 1024 ? v + " Б" : v < 1048576 ? (v / 1024.0).ToString("0.#") + " КБ" : (v / 1048576.0).ToString("0.#") + " МБ";
        }
    }

    class SearchBox : Panel
    {
        TextBox tb;
        public TextBox Box { get { return tb; } }
        public SearchBox(string cue)
        {
            BackColor = Theme.Bg; DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw, true);
            tb = new TextBox();
            tb.BorderStyle = BorderStyle.None; tb.BackColor = Theme.Card; tb.ForeColor = Theme.Text; tb.Font = Theme.Font(9.5f);
            Controls.Add(tb);
            tb.GotFocus += delegate { Invalidate(); };
            tb.LostFocus += delegate { Invalidate(); };
            tb.HandleCreated += delegate { SendMessage(tb.Handle, 0x1501, (IntPtr)1, cue); };
        }
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, string l);
        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            int x = Theme.Px(34);
            tb.SetBounds(x, (Height - tb.PreferredHeight) / 2 + 1, Width - x - Theme.Px(12), tb.PreferredHeight);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; Theme.Prep(g);
            g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            Theme.FillRound(g, new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), Theme.Px(7), Theme.Card, tb.Focused ? Theme.Mix(Theme.Border, Theme.Text, 0.4f) : Theme.Border);
            Theme.DrawIcon(g, Theme.IcSearch, 9f, new Rectangle(Theme.Px(10), 0, Theme.Px(18), Height), Theme.Dim);
        }
    }

    /// <summary>Зона «перетащи сюда файл».</summary>
    class DropZone : Smooth
    {
        public bool Dragging;
        public string Title = "Перетащи сюда файлы или папку", Sub = ".jar моды, .exe, .dll, архивы — проверю, есть ли там чит";
        public DropZone() { Height = Theme.Px(110); Cursor = Cursors.Hand; AllowDrop = true; }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(1, 1, Width - 3, Height - 3);
            using (GraphicsPath p = Theme.Round(r, Theme.Px(12)))
            {
                using (SolidBrush b = new SolidBrush(Dragging ? Theme.CardHi : hover ? Theme.Card : Theme.Bg)) g.FillPath(b, p);
                using (Pen pen = new Pen(Dragging ? Theme.Text : hover ? Theme.Muted : Theme.Border, Dragging ? 1.6f : 1.2f))
                {
                    pen.DashPattern = new float[] { 5, 4 };
                    g.DrawPath(pen, p);
                }
            }
            Theme.DrawIcon(g, Theme.IcOpen, 16f, new Rectangle(0, Theme.Px(14), Width, Theme.Px(34)), Dragging ? Theme.Text : Theme.Muted);
            using (Font tf = Theme.Semi(10.5f))
                TextRenderer.DrawText(g, Dragging ? "Отпусти, чтобы проверить" : Title, tf, new Rectangle(0, Theme.Px(52), Width, Theme.Px(22)), Theme.Text,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPadding);
            using (Font sf = Theme.Font(8.5f))
                TextRenderer.DrawText(g, Sub, sf, new Rectangle(0, Theme.Px(78), Width, Theme.Px(18)), Theme.Dim, TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPadding);
        }
    }

    /// <summary>Карточка раздела на странице «Сводка».</summary>
    class SummaryCard : Smooth
    {
        public string Glyph, Status = "не запускалось";
        public int Crit, Susp, Warn;
        public bool Done, Running;
        public SummaryCard(string glyph, string title) { Glyph = glyph; Text = title; Cursor = Cursors.Hand; Height = Theme.Px(112); Font = Theme.Font(9f); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; ClearBg(g); Theme.Prep(g);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
            Color c = !Done ? Theme.Dim : Crit > 0 ? Theme.Red : Susp > 0 ? Theme.Orange : Warn > 0 ? Theme.Yellow : Theme.Green;
            Theme.FillRound(g, r, Theme.Px(10), hover ? Theme.CardHi : Theme.Card, Theme.Border);
            int p = Theme.Px(16);
            Theme.DrawIcon(g, Glyph, 10f, new Rectangle(p - 2, Theme.Px(14), Theme.Px(20), Theme.Px(20)), Theme.Muted);
            using (Font tf = Theme.Semi(9.5f))
                TextRenderer.DrawText(g, Text, tf, new Rectangle(p + Theme.Px(26), Theme.Px(14), Width - p * 2, Theme.Px(20)), Theme.Text, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            string big = !Done ? (Running ? "…" : "—") : Crit > 0 ? Crit.ToString() : Susp > 0 ? Susp.ToString() : Warn > 0 ? Warn.ToString() : "0";
            using (Font bf = Theme.Font(22f))
                TextRenderer.DrawText(g, big, bf, new Point(p - 2, Theme.Px(42)), Done ? c : Theme.Dim, TextFormatFlags.NoPadding);
            string st = Running ? "идёт проверка…" : !Done ? "не запускалось" : Crit > 0 ? "критичных находок" : Susp > 0 ? "подозрительных" : Warn > 0 ? "слабых совпадений" : "чисто";
            using (SolidBrush b = new SolidBrush(Running ? Theme.Text : c)) g.FillEllipse(b, p, Height - Theme.Px(24), Theme.Px(6), Theme.Px(6));
            using (Font sf = Theme.Font(8.5f))
                TextRenderer.DrawText(g, st, sf, new Point(p + Theme.Px(12), Height - Theme.Px(28)), Theme.Muted, TextFormatFlags.NoPadding);
        }
    }

    class NavGroup : Control
    {
        public NavGroup(string t) { Text = t; Height = Theme.Px(28); SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true); }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Theme.Side);
            using (Font f = Theme.Semi(7.5f))
                TextRenderer.DrawText(e.Graphics, Text, f, new Rectangle(Theme.Px(12), 0, Width, Height - Theme.Px(4)), Theme.Dim, TextFormatFlags.Left | TextFormatFlags.Bottom | TextFormatFlags.NoPadding);
        }
    }

    class DarkColors : ProfessionalColorTable
    {
        public override Color MenuItemSelected { get { return Theme.CardHi; } }
        public override Color MenuItemBorder { get { return Theme.Border; } }
        public override Color MenuBorder { get { return Theme.Border; } }
        public override Color ToolStripDropDownBackground { get { return Theme.Card; } }
        public override Color ImageMarginGradientBegin { get { return Theme.Card; } }
        public override Color ImageMarginGradientMiddle { get { return Theme.Card; } }
        public override Color ImageMarginGradientEnd { get { return Theme.Card; } }
        public override Color SeparatorDark { get { return Theme.Border; } }
        public override Color SeparatorLight { get { return Theme.Border; } }
        public override Color MenuItemSelectedGradientBegin { get { return Theme.CardHi; } }
        public override Color MenuItemSelectedGradientEnd { get { return Theme.CardHi; } }
    }
}
