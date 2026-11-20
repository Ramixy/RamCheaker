using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace InjectHunter
{
    /// <summary>Раздел приложения.</summary>
    class Sec
    {
        public string Title, Glyph;
        public NavItem Nav;
        public Control Page;
        public ResultsView R;
        public VerdictBar V;
        public FlatButton Start, Stop, Report;
        public SummaryCard Card;
        public bool Done;
        public Func<double> Prog;
        public Func<string> Cur, Line;
    }

    class MainForm : Form
    {
        public const string AppName = "RamixyCheaker";
        public const string Version = "4.1";

        List<Sec> secs = new List<Sec>();
        Sec sOverview, sHidden, sOpen, sMem, sTraces, sBypass, sMods, sFind, sDec, sTools, sWords, shown;
        Panel host;
        System.Windows.Forms.Timer uiTimer;
        CancellationTokenSource cts;
        Stopwatch sw = new Stopwatch();
        Sec running;
        bool isAdmin;
        string autoArg;

        // Сводка / «Проверить всё»
        FlatButton bAll, bAllStop;
        VerdictBar vAll;
        ResultsView rTop;
        Queue<Action> chain = new Queue<Action>();
        bool fullRun;
        Stopwatch swAll = new Stopwatch();
        List<DriveCard> driveCards = new List<DriveCard>();

        // опции
        PillToggle tDisguise, tSysSig, tDeep, tExe, tJar, tSkip, tAll, tListAll, tMem, tNir, tLegit, tOrigin, tModList;
        DropZone drop;
        FlowLayoutPanel toolsFlow;
        bool toolsSigChecked;
        TextBox kwBox;
        Label kwInfo;

        public MainForm(string arg)
        {
            autoArg = arg;
            using (Graphics g = Graphics.FromHwnd(IntPtr.Zero)) Theme.S = g.DpiX / 96f;
            AutoScaleMode = AutoScaleMode.None;
            Text = AppName;
            BackColor = Theme.Bg; ForeColor = Theme.Text; Font = Theme.Font(9f);
            Size = new Size(Theme.Px(1400), Theme.Px(920));
            MinimumSize = new Size(Theme.Px(1140), Theme.Px(740));
            StartPosition = FormStartPosition.CenterScreen;
            DoubleBuffered = true;
            AllowDrop = true;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            try { isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { }
            Build();
            EnableDrop(this);
            uiTimer = new System.Windows.Forms.Timer();
            uiTimer.Interval = 120;
            uiTimer.Tick += delegate { Pump(); };
            uiTimer.Start();
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitleBar(Handle); }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (string.IsNullOrEmpty(autoArg)) return;
            if (autoArg.StartsWith("page:"))
            {
                int i; if (int.TryParse(autoArg.Substring(5), out i) && i >= 0 && i < secs.Count) Show(secs[i]);
            }
            else if (autoArg.StartsWith("find:")) { Show(sFind); qBox.Box.Text = autoArg.Substring(5); StartIndex(true); }
            else if (autoArg.StartsWith("dec:")) Inspect(autoArg.Substring(4));
            else if (autoArg == "all") StartAll();
            else if (autoArg == "open") { Show(sOpen); StartOpen(); }
            else if (autoArg == "legit" || autoArg == "hidden") { Show(sHidden); StartHidden(null); }
            else if (autoArg == "bypass") { Show(sBypass); StartBypass(); }
            else if (autoArg == "mem") { Show(sMem); StartMem(); }
            else if (autoArg == "traces") { Show(sTraces); StartTraces(); }
            else if (autoArg == "mods") { Show(sMods); StartMods(null); }
            else if (File.Exists(autoArg) || Directory.Exists(autoArg)) { Show(sMods); StartMods(new List<string> { autoArg }); }
        }

        // ======================= каркас =======================
        void Build()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill; root.ColumnCount = 2; root.RowCount = 1; root.BackColor = Theme.Bg; root.Margin = Padding.Empty;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Theme.Px(236)));
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Controls.Add(root);

            host = new Panel(); host.Dock = DockStyle.Fill; host.BackColor = Theme.Bg; host.Margin = Padding.Empty;
            host.Padding = new Padding(Theme.Px(28), Theme.Px(22), Theme.Px(28), Theme.Px(20));

            sOverview = NewSec("Сводка", Theme.IcShield);
            sHidden = NewSec("Скрытые читы", Theme.IcLock);
            sOpen = NewSec("Открытые читы", Theme.IcSearch);
            sMem = NewSec("Память javaw", Theme.IcCpu);
            sTraces = NewSec("Следы", Theme.IcHistory);
            sBypass = NewSec("Обходы проверки", Theme.IcWarn);
            sMods = NewSec("Моды и файлы", Theme.IcOpen);
            sFind = NewSec("Поиск файлов", Theme.IcFilter);
            sDec = NewSec("Декомпилятор", "\uE943");
            sTools = NewSec("Инструменты", Theme.IcTools);
            sWords = NewSec("Ключевые слова", Theme.IcTag);

            sHidden.Page = BuildHidden();
            sOpen.Page = BuildOpen();
            sMem.Page = BuildMem();
            sTraces.Page = BuildTraces();
            sBypass.Page = BuildBypass();
            sMods.Page = BuildMods();
            sFind.Page = BuildFind();
            dec = new DecompilerView(); sDec.Page = dec;
            sTools.Page = BuildTools();
            sWords.Page = BuildWords();
            sOverview.Page = BuildOverview();   // последним — нужны карточки остальных разделов

            root.Controls.Add(BuildNav(), 0, 0);
            root.Controls.Add(host, 1, 0);
            foreach (Sec s in secs) { s.Page.Dock = DockStyle.Fill; s.Page.Visible = false; host.Controls.Add(s.Page); }
            Show(sOverview);
        }

        Sec NewSec(string title, string glyph) { Sec s = new Sec(); s.Title = title; s.Glyph = glyph; secs.Add(s); return s; }

        Control BuildNav()
        {
            Panel side = new Panel(); side.Dock = DockStyle.Fill; side.BackColor = Theme.Side; side.Margin = Padding.Empty;
            side.Paint += (s, e) => { using (Pen p = new Pen(Theme.Border)) e.Graphics.DrawLine(p, side.Width - 1, 0, side.Width - 1, side.Height); };

            Label logo = new Label();
            logo.Text = AppName; logo.Font = Theme.Semi(15f); logo.ForeColor = Theme.Text; logo.BackColor = Theme.Side;
            logo.AutoSize = true; logo.Location = new Point(Theme.Px(22), Theme.Px(22));
            side.Controls.Add(logo);
            Label ver = new Label();
            ver.Text = "v" + Version + "  ·  проверка на читы"; ver.Font = Theme.Font(8f); ver.ForeColor = Theme.Dim; ver.BackColor = Theme.Side;
            ver.AutoSize = true; ver.Location = new Point(Theme.Px(23), Theme.Px(52));
            side.Controls.Add(ver);

            int y = Theme.Px(88);
            string[] groups = { null, "ПОИСК ЧИТОВ", null, null, "СЛЕДЫ И ОБХОДЫ", null, "ПРОВЕРКА ФАЙЛОВ", null, null, "ПРОЧЕЕ", null };
            for (int i = 0; i < secs.Count; i++)
            {
                if (groups[i] != null)
                {
                    NavGroup g = new NavGroup(groups[i]);
                    g.SetBounds(Theme.Px(12), y + Theme.Px(4), Theme.Px(208), Theme.Px(28));
                    side.Controls.Add(g);
                    y += Theme.Px(32);
                }
                Sec s = secs[i];
                NavItem n = new NavItem(s.Glyph, s.Title);
                n.BackColor = Theme.Side;
                n.SetBounds(Theme.Px(12), y, Theme.Px(212), Theme.Px(36));
                n.Click += delegate { Show(s); };
                s.Nav = n;
                side.Controls.Add(n);
                y += Theme.Px(38);
            }

            Label status = new Label();
            status.Text = isAdmin ? "● Администратор\nТолько чтение · без интернета" : "● Нет прав администратора\nЧасть данных будет недоступна";
            status.Font = Theme.Font(8f); status.ForeColor = isAdmin ? Theme.Dim : Theme.Orange; status.BackColor = Theme.Side;
            status.AutoSize = false; status.Size = new Size(Theme.Px(200), Theme.Px(36));
            side.Controls.Add(status);
            side.Resize += delegate { status.Location = new Point(Theme.Px(22), side.Height - Theme.Px(52)); };
            return side;
        }

        void Show(Sec s)
        {
            shown = s;
            foreach (Sec x in secs) { x.Page.Visible = x == s; x.Nav.Active = x == s; x.Nav.Invalidate(); }
            if (s == sTools && !toolsSigChecked) CheckToolSignatures();
        }

        // ---------- конструктор типовой страницы ----------
        TableLayoutPanel Page(Sec s, string sub, out FlowLayoutPanel toolbar, out FlowLayoutPanel options, bool showClean)
        {
            TableLayoutPanel p = new TableLayoutPanel();
            p.ColumnCount = 1; p.RowCount = 5; p.BackColor = Theme.Bg; p.Margin = Padding.Empty; p.Padding = Padding.Empty;
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(60)));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(80)));
            p.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            PageTitle pt = new PageTitle(s.Title, sub); pt.Dock = DockStyle.Fill; pt.Margin = Padding.Empty;
            p.Controls.Add(pt, 0, 0);
            toolbar = Flow(new Padding(0, 0, 0, Theme.Px(10)));
            p.Controls.Add(toolbar, 0, 1);
            options = Flow(new Padding(0, 0, 0, Theme.Px(2)));
            p.Controls.Add(options, 0, 2);
            s.V = new VerdictBar(); s.V.Dock = DockStyle.Fill; s.V.Margin = new Padding(0, Theme.Px(6), 0, Theme.Px(10));
            p.Controls.Add(s.V, 0, 3);
            s.R = new ResultsView(showClean); s.R.IdleTitle = "Пока пусто"; s.R.IdleSub = "Нажми «" + "Начать" + "», результаты появятся здесь";
            p.Controls.Add(s.R, 0, 4);
            Sec ss = s;
            s.R.Added += f => { if (f.Severity >= 2 && rTop != null && ss != sFind) rTop.Enqueue(TagSec(f, ss)); };
            HookInspect(s.R);
            return p;
        }

        static Finding TagSec(Finding f, Sec s)
        {
            if (!f.Source.StartsWith(s.Title)) f.Source = s.Title + " · " + f.Source;
            return f;
        }

        static FlowLayoutPanel Flow(Padding m)
        {
            FlowLayoutPanel f = new FlowLayoutPanel(); f.AutoSize = true; f.Dock = DockStyle.Fill; f.BackColor = Theme.Bg; f.Margin = m; f.WrapContents = true;
            return f;
        }

        FlatButton Btn(FlowLayoutPanel f, string text, bool primary, string glyph, bool danger = false)
        {
            FlatButton b = new FlatButton(text, primary, glyph, danger);
            b.Margin = new Padding(0, 0, Theme.Px(8), 0);
            f.Controls.Add(b);
            return b;
        }

        PillToggle Pill(FlowLayoutPanel f, string text, bool on)
        {
            PillToggle t = new PillToggle(text, on);
            t.Margin = new Padding(0, 0, Theme.Px(8), Theme.Px(8));
            f.Controls.Add(t);
            return t;
        }

        void StdButtons(Sec s, FlowLayoutPanel tb, string startText, Action start)
        {
            s.Start = Btn(tb, startText, true, Theme.IcPlay);
            s.Stop = Btn(tb, "Стоп", false, Theme.IcStop, true);
            s.Report = Btn(tb, "Отчёт", false, Theme.IcSave);
            s.Start.Click += delegate { start(); };
            s.Stop.Click += delegate { StopAll(); };
            Sec ss = s;
            s.Report.Click += delegate { Export(ss); };
            s.Stop.Enabled = false;
            s.R.IdleSub = "Нажми «" + startText + "» — результаты появятся здесь";
        }

        string DrivesLabel() { return string.Join(", ", driveCards.Where(c => c.Checked).Select(c => c.Root.TrimEnd('\\'))); }

        // ======================= Сводка =======================
        Control BuildOverview()
        {
            TableLayoutPanel p = new TableLayoutPanel();
            p.ColumnCount = 1; p.RowCount = 6; p.BackColor = Theme.Bg; p.Margin = Padding.Empty;
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(60)));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(80)));
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(250)));
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(30)));
            p.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            PageTitle pt = new PageTitle("Сводка", "Одна кнопка проверяет всё: скрытые и открытые читы, legit-читы, память javaw, следы, обходы, моды. Отдельно — поиск файлов и декомпилятор"); pt.Dock = DockStyle.Fill;
            p.Controls.Add(pt, 0, 0);

            FlowLayoutPanel tb = Flow(new Padding(0, 0, 0, Theme.Px(8)));
            FlowLayoutPanel bf = new FlowLayoutPanel(); bf.AutoSize = true; bf.WrapContents = false; bf.BackColor = Theme.Bg; bf.Margin = new Padding(0, Theme.Px(11), Theme.Px(16), 0);
            bAll = new FlatButton("Проверить всё", true, Theme.IcPlay); bAll.Height = Theme.Px(38); bAll.Width += Theme.Px(30);
            bAll.Margin = new Padding(0, 0, Theme.Px(8), 0); bf.Controls.Add(bAll);
            bAllStop = Btn(bf, "Стоп", false, Theme.IcStop, true); bAllStop.Enabled = false;
            bAll.Click += delegate { StartAll(); };
            bAllStop.Click += delegate { StopAll(); };
            tb.Controls.Add(bf);
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                bool ready = false;
                try { ready = d.IsReady; } catch { }
                if (!ready || d.DriveType == DriveType.CDRom) continue;
                DriveCard c = new DriveCard(d);
                c.Checked = d.DriveType == DriveType.Fixed;
                c.Margin = new Padding(0, 0, Theme.Px(8), 0);
                driveCards.Add(c); tb.Controls.Add(c);
            }
            p.Controls.Add(tb, 0, 1);

            vAll = new VerdictBar(); vAll.Dock = DockStyle.Fill; vAll.Margin = new Padding(0, Theme.Px(4), 0, Theme.Px(10));
            vAll.Set(VerdictBar.State.Idle, "Готов к проверке", "1) Отметь диски  ·  2) Нажми «Проверить всё»  ·  3) Смотри главные находки: красное — чит, оранжевое — проверь вручную, жёлтое — мелочь.");
            p.Controls.Add(vAll, 0, 2);

            TableLayoutPanel cards = new TableLayoutPanel(); cards.Dock = DockStyle.Fill; cards.ColumnCount = 3; cards.RowCount = 2; cards.BackColor = Theme.Bg; cards.Margin = Padding.Empty;
            for (int i = 0; i < 3; i++) cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.3f));
            cards.RowStyles.Add(new RowStyle(SizeType.Percent, 50)); cards.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            Sec[] list = { sHidden, sOpen, sMem, sTraces, sBypass, sMods };
            for (int i = 0; i < list.Length; i++)
            {
                Sec s = list[i];
                SummaryCard c = new SummaryCard(s.Glyph, s.Title);
                c.Dock = DockStyle.Fill; c.Margin = new Padding(i % 3 == 0 ? 0 : Theme.Px(5), 0, i % 3 == 2 ? 0 : Theme.Px(5), Theme.Px(10));
                c.Click += delegate { Show(s); };
                s.Card = c;
                cards.Controls.Add(c, i % 3, i / 3);
            }
            p.Controls.Add(cards, 0, 3);

            Label lt = new Label(); lt.Text = "ГЛАВНЫЕ НАХОДКИ (критичные и подозрительные из всех разделов)"; lt.Font = Theme.Semi(8f); lt.ForeColor = Theme.Dim;
            lt.Dock = DockStyle.Fill; lt.TextAlign = ContentAlignment.BottomLeft; lt.BackColor = Theme.Bg;
            p.Controls.Add(lt, 0, 4);
            rTop = new ResultsView(false, true); HookInspect(rTop); rTop.IdleTitle = "Пока нет находок"; rTop.IdleSub = "Здесь соберутся самые важные результаты всех проверок";
            p.Controls.Add(rTop, 0, 5);
            return p;
        }

        // ======================= Скрытые читы =======================
        DiskScanner disk; string diskLabel = ""; bool diskFolder;
        Control BuildHidden()
        {
            FlowLayoutPanel tb, op;
            TableLayoutPanel p = Page(sHidden, "Читы, которые прячутся: программы под видом .dll/.ini/.png, подделки системных файлов, legit-читы (кликеры, макросы, агенты javaw) и файлы, скачанные с сайтов читов. Подписанные системой файлы не трогаются.", out tb, out op, false);
            StdButtons(sHidden, tb, "Сканировать диски", () => StartHidden(null));
            FlatButton bf = Btn(tb, "Папка…", false, Theme.IcFolder);
            bf.Click += delegate
            {
                if (running != null) return;
                FolderBrowserDialog d = new FolderBrowserDialog(); d.Description = "Папка для проверки";
                if (d.ShowDialog(this) == DialogResult.OK) StartHidden(new List<string> { d.SelectedPath });
            };
            tDisguise = Pill(op, "Маскировка расширений", true);
            tSysSig = Pill(op, "Подписи и тайники Windows", true);
            tDeep = Pill(op, "Анализ содержимого", true);
            tExe = Pill(op, ".exe", true);
            tJar = Pill(op, ".jar", true);
            tSkip = Pill(op, "Пропускать служебные папки", true);
            tAll = Pill(op, "Все файлы (долго)", false);
            tLegit = Pill(op, "Legit-читы: кликеры, макросы, агенты", true);
            tOrigin = Pill(op, "Откуда скачаны файлы: сайты читов, Discord, Telegram, Google, GitHub", true);
            sHidden.V.Set(VerdictBar.State.Idle, "Готов", "Диски выбираются на странице «Сводка». Для каждой находки видно, с какого сайта скачан файл.");
            return p;
        }

        ScanOptions Options()
        {
            ScanOptions o = new ScanOptions();
            o.Roots = driveCards.Where(c => c.Checked).Select(c => c.Root).ToList();
            o.DisguiseExt = tDisguise.Checked; o.SystemSigCheck = tSysSig.Checked; o.DeepContent = tDeep.Checked;
            o.ScanExe = tExe.Checked; o.ScanJars = tJar.Checked; o.SkipServiceDirs = tSkip.Checked; o.AllFiles = tAll.Checked;
            return o;
        }

        LegitScanner legit; DownloadOriginScanner origins; HiddenExtraScanner hidx; volatile int hidPhase;
        void StartHidden(List<string> custom)
        {
            if (running != null) return;
            ScanOptions o = Options();
            diskFolder = custom != null;
            if (diskFolder) o.Roots = custom;
            if (o.Roots.Count == 0) { sHidden.V.Set(VerdictBar.State.Info, "Не выбран ни один диск", "Отметь диски на странице «Сводка» или выбери папку."); RunNext(); return; }
            diskLabel = string.Join(", ", o.Roots.Select(r => r.Length <= 3 ? r.TrimEnd('\\') : r));
            disk = new DiskScanner();
            disk.Found += f => sHidden.R.Enqueue(f);
            legit = new LegitScanner();
            legit.Found += f => sHidden.R.Enqueue(f);
            origins = new DownloadOriginScanner();
            origins.Found += f => sHidden.R.Enqueue(f);
            hidx = new HiddenExtraScanner();
            hidx.Found += f => sHidden.R.Enqueue(f);
            bool doLegit = tLegit.Checked && !diskFolder, doOrigin = tOrigin.Checked && !diskFolder;
            hidPhase = 0;
            Run(sHidden, "Ищу скрытые читы на " + diskLabel, ct =>
                {
                    hidPhase = 0; disk.Run(o, ct);
                    if (doLegit && !ct.IsCancellationRequested) { hidPhase = 1; legit.Run(ct); }
                    if (doOrigin && !ct.IsCancellationRequested) { hidPhase = 2; origins.Run(ct); }
                    if (!diskFolder && !ct.IsCancellationRequested) { hidPhase = 3; hidx.Run(ct); }
                },
                () =>
                {
                    if (hidPhase == 1) return 0.80 + 0.08 * legit.Progress;
                    if (hidPhase == 2) return 0.92;
                    if (hidPhase == 3) return 0.93 + 0.06 * hidx.Progress;
                    double k = diskFolder ? 1.0 : 0.80;
                    if (!diskFolder && disk.TotalBytes > 0)
                    {
                        double v = Math.Min(0.99, (double)disk.BytesSeen / disk.TotalBytes);
                        if (disk.FilesQueued > 0) v = Math.Min(v, 0.99 * (0.15 + 0.85 * disk.FilesDone / (double)Math.Max(1, disk.FilesQueued)));
                        return v * k;
                    }
                    return disk.FilesQueued > 0 ? 0.95 * k * disk.FilesDone / (double)disk.FilesQueued : 0;
                },
                () => hidPhase == 3 ? hidx.Current : hidPhase == 1 ? "Legit-читы · " + legit.Current
                    : hidPhase == 2 ? "Откуда скачаны файлы · проверено " + origins.Checked.ToString("N0") + " · " + origins.Current
                    : disk.FilesDone.ToString("N0") + " из " + disk.FilesSeen.ToString("N0") + " · " + disk.Current,
                () => diskLabel + " · файлов " + disk.FilesSeen.ToString("N0") + ", проанализировано " + disk.FilesDone.ToString("N0") +
                      (doLegit ? " · legit-читы проверены" : "") + (doOrigin ? " · скачанных файлов с меткой: " + origins.WithMark.ToString("N0") : "") +
                      (!diskFolder ? " · скрытых потоков NTFS: " + hidx.Streams.ToString("N0") + " · DLL во всех процессах: " + hidx.Modules.ToString("N0") : ""));
        }

        // ======================= Открытые читы =======================
        NameScanner names;
        Control BuildOpen()
        {
            FlowLayoutPanel tb, op;
            TableLayoutPanel p = Page(sOpen, "Читы, которые лежат открыто: поиск по названиям и размерам из сайз-листа — все файлы и папки на дисках, процессы, программы, автозапуск", out tb, out op, true);
            StdButtons(sOpen, tb, "Искать по названиям", StartOpen);
            tListAll = Pill(op, "Показать все программы списком (для ручного поиска)", false);
            sOpen.V.Set(VerdictBar.State.Idle, "Готов", "Слова — в разделе «Ключевые слова», размеры — из сайз-листа. Используй поиск над таблицей.");
            return p;
        }

        void StartOpen()
        {
            if (running != null) return;
            List<string> roots = driveCards.Where(c => c.Checked).Select(c => c.Root).ToList();
            names = new NameScanner();
            names.Found += f => sOpen.R.Enqueue(f);
            bool listAll = tListAll.Checked, skip = tSkip.Checked;
            Run(sOpen, "Ищу открытые читы по названиям и размерам", ct => names.Run(roots, skip, listAll, ct),
                () => names.Progress,
                () => "файлов " + names.FilesSeen.ToString("N0") + " · " + names.Current,
                () => "Программ: " + names.Programs + ", файлов на " + string.Join(", ", roots.Select(r => r.TrimEnd('\\'))) + ": " + names.FilesSeen.ToString("N0"));
        }

        // ======================= Память =======================
        ProcessScanner proc;
        Control BuildMem()
        {
            FlowLayoutPanel tb, op;
            TableLayoutPanel p = Page(sMem, "Запущенный Minecraft: какие модули и DLL в него загружены, с какими аргументами он запущен, скрытые и удалённые DLL, строки читов в памяти", out tb, out op, true);
            StdButtons(sMem, tb, "Проверить javaw", StartMem);
            tMem = Pill(op, "Сканировать оперативную память", true);
            tModList = Pill(op, "Показать все загруженные модули", true);
            sMem.V.Set(VerdictBar.State.Idle, "Запусти Minecraft и нажми «Проверить javaw»", "Чит должен быть загружен — проверка идёт по живому процессу.");
            return p;
        }

        void StartMem()
        {
            if (running != null) return;
            ScanOptions o = Options(); o.DeepContent = true;
            proc = new ProcessScanner();
            proc.Found += f => sMem.R.Enqueue(f);
            bool mem = tMem.Checked;
            proc.ListAll = tModList.Checked;
            Run(sMem, "Проверяю javaw", ct => proc.Run(o, mem, ct), () => proc.Progress, () => "модулей " + proc.ModulesChecked + " · " + proc.Current,
                () => proc.ProcCount == 0 ? "Minecraft не был запущен — процессов java/javaw нет" : "Процессов: " + proc.ProcCount + ", модулей: " + proc.ModulesChecked + " · фильтр «ОК» — чистые модули");
        }

        // ======================= Следы =======================
        TraceScanner traces;
        Control BuildTraces()
        {
            FlowLayoutPanel tb, op;
            TableLayoutPanel p = Page(sTraces, "Всё, что смотрят программы из «Инструментов»: Prefetch (с файлами, которые открывала программа), BAM, PCA, ShimCache, ShellBags, USN-журнал, корзина, окна «Открыть/Сохранить», реестр, автозапуск, Защитник, загрузки, история, cookies и логины браузеров, DNS-кэш", out tb, out op, false);
            StdButtons(sTraces, tb, "Собрать следы", StartTraces);
            tNir = Pill(op, "Также через NirSoft (WinPrefetchView, ExecutedProgramsList, LastActivityView, RecentFiles, USBDeview)", true);
            sTraces.V.Set(VerdictBar.State.Idle, "Готов", "Находит запуски, файлы и сайты читов, даже если их уже удалили. Prefetch, USN-журнал и чужие корзины читаются только с правами администратора.");
            return p;
        }

        void StartTraces()
        {
            if (running != null) return;
            traces = new TraceScanner();
            traces.Found += f => sTraces.R.Enqueue(f);
            bool nir = tNir.Checked;
            Run(sTraces, "Собираю следы", ct => traces.Run(nir, ct), () => traces.Progress, () => "записей " + traces.Entries.ToString("N0") + " · " + traces.Current,
                () => "Источников: " + traces.Sources + ", записей проверено: " + traces.Entries.ToString("N0"));
        }

        // ======================= Обходы проверки =======================
        BypassScanner bypass;
        Control BuildBypass()
        {
            FlowLayoutPanel tb, op;
            TableLayoutPanel p = Page(sBypass, "Пытались ли сломать проверку: блокировка сайтов и утилит, очистка журналов, выключенный Prefetch, удалённый USN-журнал. Ничего не меняет.", out tb, out op, false);
            StdButtons(sBypass, tb, "Искать обходы", StartBypass);
            sBypass.V.Set(VerdictBar.State.Idle, "Готов", "Без прав администратора часть журналов (Security) не читается.");
            return p;
        }

        void StartBypass()
        {
            if (running != null) return;
            bypass = new BypassScanner();
            bypass.Found += f => sBypass.R.Enqueue(f);
            Run(sBypass, "Ищу обходы проверки", ct => bypass.Run(ct), () => bypass.Progress, () => bypass.Current, () => "Проверок выполнено: " + bypass.Checks);
        }

        // ======================= Моды и файлы =======================
        ModScanner mods;
        Control BuildMods()
        {
            FlowLayoutPanel tb, op;
            TableLayoutPanel p = Page(sMods, "Брось сюда моды или любые файлы — проверю на читы. Или найду все папки модов всех лаунчеров автоматически.", out tb, out op, true);
            StdButtons(sMods, tb, "Найти все моды", () => StartMods(null));
            FlatButton bFiles = Btn(tb, "Выбрать файлы…", false, Theme.IcDoc);
            FlatButton bDir = Btn(tb, "Выбрать папку…", false, Theme.IcFolder);
            Action pickFiles = () =>
            {
                OpenFileDialog d = new OpenFileDialog(); d.Multiselect = true; d.Title = "Файлы для проверки";
                d.Filter = "Моды и программы (*.jar;*.exe;*.dll;*.zip;*.rar)|*.jar;*.exe;*.dll;*.zip;*.rar;*.disabled|Все файлы (*.*)|*.*";
                if (d.ShowDialog(this) == DialogResult.OK) StartMods(d.FileNames.ToList());
            };
            bFiles.Click += delegate { pickFiles(); };
            bDir.Click += delegate
            {
                FolderBrowserDialog d = new FolderBrowserDialog(); d.Description = "Папка с модами или файлами";
                if (d.ShowDialog(this) == DialogResult.OK) StartMods(new List<string> { d.SelectedPath });
            };
            drop = new DropZone(); drop.Width = Theme.Px(900); drop.Margin = new Padding(0, Theme.Px(2), 0, Theme.Px(4));
            drop.Click += delegate { pickFiles(); };
            op.Controls.Add(drop);
            op.Resize += delegate { drop.Width = Math.Max(Theme.Px(400), op.ClientSize.Width - Theme.Px(2)); };
            p.RowStyles[3].Height = Theme.Px(80);
            sMods.V.Set(VerdictBar.State.Idle, "Готов", "Для каждого мода — название, загрузчик, версия и вердикт. Известные безопасные моды помечаются «ОК».");
            return p;
        }

        void StartMods(List<string> manual)
        {
            if (running != null) { if (manual != null) MessageBox.Show(this, "Дождись окончания текущей проверки.", AppName); return; }
            mods = new ModScanner();
            mods.Found += f => sMods.R.Enqueue(f);
            string what = manual == null ? "Ищу и проверяю моды всех лаунчеров" : "Проверяю загруженные файлы (" + manual.Count + ")";
            Run(sMods, what, ct => mods.Run(manual, ct), () => mods.Progress, () => mods.Current,
                () => (manual == null ? "Папок модов: " + mods.Folders + ", " : "") + "проверено файлов: " + mods.Count);
        }

        void EnableDrop(Control c)
        {
            c.AllowDrop = true;
            c.DragEnter += OnDragEnter;
            c.DragLeave += delegate { if (drop != null) { drop.Dragging = false; drop.Invalidate(); } };
            c.DragDrop += OnDragDrop;
            foreach (Control ch in c.Controls) EnableDrop(ch);
        }

        void OnDragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) { e.Effect = DragDropEffects.Copy; if (drop != null) { drop.Dragging = true; drop.Invalidate(); } }
        }

        void OnDragDrop(object sender, DragEventArgs e)
        {
            if (drop != null) { drop.Dragging = false; drop.Invalidate(); }
            string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (files == null || files.Length == 0) return;
            if (shown == sDec) { dec.Open(files[0]); return; }
            Show(sMods);
            StartMods(files.ToList());
        }

        // ======================= Поиск файлов (как Everything) =======================
        FileIndex index, building;
        SearchBox qBox;
        PillToggle tProg, tDl;
        CancellationTokenSource findCts;
        System.Windows.Forms.Timer findTimer;
        bool findAfterIndex;
        DecompilerView dec;
        static readonly HashSet<string> progExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".exe", ".dll", ".jar", ".zip", ".rar", ".7z", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".ahk", ".lua", ".disabled", ".sys", ".class"
        };

        Control BuildFind()
        {
            FlowLayoutPanel tb, op;
            TableLayoutPanel p = Page(sFind, "Мгновенный поиск любого файла по имени на всех дисках — и для каждого видно, откуда он взялся: сайт, ссылка, браузер, Telegram, архив, флешка", out tb, out op, true);
            sFind.R.HideSearch();
            qBox = new SearchBox("Имя файла: doomsday  ·  *.jar  ·  ext:exe,dll  ·  \\downloads\\ *.exe  ·  !исключить");
            qBox.Size = new Size(Theme.Px(560), Theme.Px(38)); qBox.Margin = new Padding(0, 0, Theme.Px(10), 0);
            tb.Controls.Add(qBox);
            FlatButton bIdx = Btn(tb, "Обновить индекс", false, Theme.IcDrive);
            sFind.Stop = Btn(tb, "Стоп", false, Theme.IcStop, true); sFind.Stop.Enabled = false;
            sFind.Stop.Click += delegate { StopAll(); if (findCts != null) findCts.Cancel(); };
            sFind.Report = Btn(tb, "Отчёт", false, Theme.IcSave);
            sFind.Report.Click += delegate { Export(sFind); };
            bIdx.Click += delegate { StartIndex(false); };
            tProg = Pill(op, "Только программы, моды и архивы", false);
            tDl = Pill(op, "Только скачанные из интернета", false);
            tProg.Click += delegate { DoFind(); };
            tDl.Click += delegate { DoFind(); };
            findTimer = new System.Windows.Forms.Timer(); findTimer.Interval = 350;
            findTimer.Tick += delegate { findTimer.Stop(); DoFind(); };
            qBox.Box.TextChanged += delegate { if (index != null) { findTimer.Stop(); findTimer.Start(); } };
            qBox.Box.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; findTimer.Stop(); DoFind(); } };
            sFind.V.Set(VerdictBar.State.Idle, "Напиши имя файла и нажми Enter",
                "Первый раз диски индексируются: " + (isAdmin ? "с правами администратора — через MFT, секунды." : "без прав администратора — обходом папок, до минуты.") + " Правый клик по файлу — разобрать или проверить.");
            sFind.R.IdleSub = "Например: doomsday · autoclicker · *.jar · ext:exe,dll · \\Downloads\\";
            return p;
        }

        void StartIndex(bool thenFind)
        {
            if (running != null) return;
            List<string> roots = driveCards.Where(c => c.Checked).Select(c => c.Root).ToList();
            if (roots.Count == 0) roots = driveCards.Select(c => c.Root).ToList();
            building = new FileIndex();
            FileIndex ix = building;
            findAfterIndex = thenFind;
            Run(sFind, "Индексирую " + string.Join(", ", roots.Select(r => r.TrimEnd('\\'))),
                ct => { ix.Build(roots, ct); DownloadHistory.Reset(); try { int n = DownloadHistory.All.Count; } catch { } },
                () => 1 - Math.Exp(-ix.Progress / 700000.0),
                () => "в индексе " + ix.Progress.ToString("N0") + " · " + ix.Current,
                () => "");
        }

        void EndIndex()
        {
            sw.Stop();
            bool stopped = cts != null && cts.IsCancellationRequested;
            running = null;
            sFind.R.Running = false;
            sFind.V.Progress = 1; sFind.V.ShowPercent = false;
            if (!stopped && building != null && building.Count > 0) index = building;
            building = null;
            SetButtons();
            if (index == null) { sFind.V.Set(VerdictBar.State.Info, "Индекс не построен", stopped ? "Остановлено." : "Не удалось прочитать диски."); return; }
            sFind.V.Set(VerdictBar.State.Info, "Индекс готов: " + index.Files.ToString("N0") + " файлов, " + index.Dirs.ToString("N0") + " папок",
                index.Method + " · " + FormatTime(sw.Elapsed) + " · загрузок в истории браузеров: " + DownloadHistory.All.Count);
            if (fullRun) { BeginInvoke(new Action(RunNext)); return; }
            if (findAfterIndex || qBox.Box.Text.Trim().Length > 0) DoFind();
        }

        void DoFind()
        {
            string text = qBox.Box.Text.Trim();
            if (index == null) { if (text.Length > 0) StartIndex(true); return; }
            if (running != null) return;
            FileIndex.Query q = FileIndex.Parse(text);
            if (q.Empty && !tDl.Checked) { sFind.R.Clear(); sFind.V.Set(VerdictBar.State.Info, "Индекс готов: " + index.Files.ToString("N0") + " файлов", "Напиши имя или маску файла."); return; }
            if (q.Empty) q.Words.Add("");
            if (tProg.Checked && q.Exts == null) q.Exts = progExts;
            q.FilesOnly = tDl.Checked;
            if (findCts != null) findCts.Cancel();
            findCts = new CancellationTokenSource();
            CancellationToken ct = findCts.Token;
            bool onlyDl = tDl.Checked;
            FileIndex ix = index;
            sFind.R.Clear(); sFind.R.Running = true; sFind.R.RepaintEmpty();
            sFind.V.Set(VerdictBar.State.Running, "Ищу «" + text + "»", "");
            Stopwatch t = Stopwatch.StartNew();
            Task.Factory.StartNew(() =>
            {
                int total, shownN = 0, crit = 0;
                List<int> ids = ix.Search(q, onlyDl ? 60000 : 3000, null, out total, ct);
                int dlCount = 0;
                foreach (int id in ids)
                {
                    if (ct.IsCancellationRequested) return;
                    string path = ix.PathOf(id);
                    if (path == null) continue;
                    Finding f = SearchFinding(ix, id, path, onlyDl);
                    if (f == null) continue;
                    dlCount++;
                    if (f.Severity >= 2) crit++;
                    sFind.R.Enqueue(f);
                    if (++shownN >= 3000) break;
                }
                if (ct.IsCancellationRequested) return;
                try
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (ct.IsCancellationRequested) return;
                        sFind.R.Running = false; sFind.R.Scanned = true; sFind.R.Finish();
                        string head = onlyDl ? "Скачанных файлов: " + dlCount + (ids.Count < total ? " (проверены первые " + ids.Count.ToString("N0") + " из " + total.ToString("N0") + ")" : "")
                                             : "Найдено: " + total.ToString("N0") + (shownN < total ? " · показаны первые " + shownN.ToString("N0") : "");
                        sFind.V.Set(crit > 0 ? VerdictBar.State.Warn : VerdictBar.State.Info, head + (crit > 0 ? " · с признаками чита: " + crit : ""),
                            t.ElapsedMilliseconds + " мс · в индексе " + ix.Files.ToString("N0") + " файлов (" + ix.Built.ToString("HH:mm") + ") · колонка «Причина» — откуда взялся файл");
                    }));
                }
                catch { }
            });
        }

        static Finding SearchFinding(FileIndex ix, int id, string path, bool onlyDl)
        {
            Finding f = new Finding();
            f.Path = path; f.FileName = Path.GetFileName(path.TrimEnd('\\')); f.Source = "Поиск файлов";
            if (f.FileName.Length == 0) f.FileName = path;
            if (ix.IsDir[id])
            {
                f.RealType = "Папка";
                try { DirectoryInfo di = new DirectoryInfo(path); f.Modified = di.LastWriteTime; f.Created = di.CreationTime; } catch { }
                f.Origin = Origin.Guess(path + "\\") ?? "Папка";
                f.Note("Папка");
                foreach (Keywords.Kw k in Keywords.Match(f.FileName).Where(k => k.Strong)) f.Add(40, "В названии папки слово из списка «" + k.Word + "»");
                f.Finish();
                return f;
            }
            string ext = Path.GetExtension(path).ToLowerInvariant(); f.Ext = ext;
            try { FileInfo fi = new FileInfo(path); f.Size = fi.Length; f.Modified = fi.LastWriteTime; f.Created = fi.CreationTime; } catch { }
            Origin.Explained e;
            try { e = Origin.Explain(path); } catch { return onlyDl ? null : f; }
            if (onlyDl && e.Mark == null && e.Dl == null) return null;
            f.RealType = TypeName(ext) + " · " + (e.Domain ?? (e.Mark != null && e.Mark.App != null ? "из мессенджера" : e.Mark != null || e.Dl != null ? "скачан" : "локальный"));
            f.Origin = e.Text;
            f.Note(e.Short);
            if (e.Site != null) f.Add(55, "Скачан с сайта читов: " + (e.Domain ?? e.Site) + " (в адресе «" + e.Site + "»)");
            foreach (Keywords.Kw k in Keywords.Match(f.FileName))
            {
                if (k.Strong) f.Add(40, "Имя содержит слово из списка «" + k.Word + "»");
                else f.Note("Имя содержит частое слово из списка «" + k.Word + "»");
            }
            f.Finish();
            return f;
        }

        static string TypeName(string ext)
        {
            switch (ext)
            {
                case ".exe": return "EXE";
                case ".dll": return "DLL";
                case ".jar": return "JAR";
                case ".sys": return "SYS";
                case ".zip": case ".rar": case ".7z": return "ZIP";
                case ".class": return "CLS";
                default: return ext.Length > 1 && ext.Length <= 5 ? ext.Substring(1).ToUpperInvariant() : "—";
            }
        }

        // ======================= Разбор файла =======================
        void HookInspect(ResultsView r)
        {
            r.InspectRequested += f => Inspect(f.Path);
            r.AnalyzeRequested += f =>
            {
                if (!File.Exists(f.Path) && !Directory.Exists(f.Path)) { MessageBox.Show(this, "Файла уже нет на диске.", AppName); return; }
                Show(sMods); StartMods(new List<string> { f.Path });
            };
        }

        void Inspect(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) { MessageBox.Show(this, "Разобрать можно только существующий файл:\n" + path, AppName); return; }
            Show(sDec);
            dec.Open(path);
        }

        // ======================= Инструменты =======================
        Control BuildTools()
        {
            TableLayoutPanel p = new TableLayoutPanel();
            p.ColumnCount = 1; p.RowCount = 3; p.BackColor = Theme.Bg; p.Margin = Padding.Empty;
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(60)));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            PageTitle pt = new PageTitle("Инструменты", "Программы для проверки, встроенные в " + AppName + ". Открываются из временной папки, с теми же правами."); pt.Dock = DockStyle.Fill;
            p.Controls.Add(pt, 0, 0);
            FlowLayoutPanel tb = Flow(new Padding(0, 0, 0, Theme.Px(12)));
            FlatButton bOpen = Btn(tb, "Открыть папку инструментов", false, Theme.IcFolder);
            bOpen.Click += delegate { try { Directory.CreateDirectory(Tools.Root); Process.Start("explorer.exe", "\"" + Tools.Root + "\""); } catch { } };
            p.Controls.Add(tb, 0, 1);

            toolsFlow = new FlowLayoutPanel(); toolsFlow.Dock = DockStyle.Fill; toolsFlow.AutoScroll = true; toolsFlow.BackColor = Theme.Bg; toolsFlow.Margin = Padding.Empty;
            toolsFlow.HandleCreated += delegate { Native.SetWindowTheme(toolsFlow.Handle, "DarkMode_Explorer", null); };
            string group = null;
            foreach (ToolInfo t in Tools.All)
            {
                if (t.Group != group)
                {
                    group = t.Group;
                    Label gl = new Label(); gl.Text = group.ToUpperInvariant(); gl.Font = Theme.Semi(8f); gl.ForeColor = Theme.Dim; gl.BackColor = Theme.Bg;
                    gl.AutoSize = false; gl.Size = new Size(Theme.Px(940), Theme.Px(30)); gl.TextAlign = ContentAlignment.BottomLeft;
                    gl.Margin = new Padding(0, toolsFlow.Controls.Count == 0 ? 0 : Theme.Px(12), 0, Theme.Px(6));
                    toolsFlow.Controls.Add(gl);
                    toolsFlow.SetFlowBreak(gl, true);
                }
                ToolCard c = new ToolCard(t);
                c.Margin = new Padding(0, 0, Theme.Px(10), Theme.Px(10));
                ToolInfo tt = t;
                c.Click += delegate
                {
                    try { Tools.Launch(tt); }
                    catch (Exception ex) { MessageBox.Show(this, "Не удалось открыть " + tt.Title + ":\n" + ex.Message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                };
                toolsFlow.Controls.Add(c);
            }
            p.Controls.Add(toolsFlow, 0, 2);
            sTools.R = null;
            return p;
        }

        void CheckToolSignatures()
        {
            toolsSigChecked = true;
            Task.Factory.StartNew(() =>
            {
                Tools.CheckSignatures();
                try { BeginInvoke(new Action(() => { foreach (Control c in toolsFlow.Controls) c.Invalidate(); })); } catch { }
            });
        }

        // ======================= Ключевые слова =======================
        Control BuildWords()
        {
            TableLayoutPanel p = new TableLayoutPanel();
            p.ColumnCount = 1; p.RowCount = 4; p.BackColor = Theme.Bg; p.Margin = Padding.Empty;
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(60)));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.Px(40)));
            p.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            PageTitle pt = new PageTitle("Ключевые слова", "Названия читов, модов и лоадеров через «|» или с новой строки. Используются во всех разделах.");
            pt.Dock = DockStyle.Fill;
            p.Controls.Add(pt, 0, 0);
            FlowLayoutPanel tb = Flow(new Padding(0, 0, 0, Theme.Px(6)));
            FlatButton bSave = Btn(tb, "Сохранить", true, Theme.IcSave);
            FlatButton bReset = Btn(tb, "Вернуть стандартный список", false, null);
            p.Controls.Add(tb, 0, 1);
            kwInfo = new Label(); kwInfo.Dock = DockStyle.Fill; kwInfo.ForeColor = Theme.Muted; kwInfo.BackColor = Theme.Bg; kwInfo.Font = Theme.Font(8.5f);
            p.Controls.Add(kwInfo, 0, 2);
            CardPanel card = new CardPanel(); card.Dock = DockStyle.Fill; card.Padding = new Padding(Theme.Px(14));
            kwBox = new TextBox(); kwBox.Multiline = true; kwBox.ScrollBars = ScrollBars.Vertical; kwBox.BorderStyle = BorderStyle.None;
            kwBox.BackColor = Theme.Card; kwBox.ForeColor = Theme.Text; kwBox.Font = Theme.Mono(10f); kwBox.Dock = DockStyle.Fill;
            kwBox.Text = Keywords.CurrentText.Replace("\r\n", "\n").Replace("\n", "\r\n");
            kwBox.HandleCreated += delegate { Native.SetWindowTheme(kwBox.Handle, "DarkMode_Explorer", null); };
            card.Controls.Add(kwBox);
            p.Controls.Add(card, 0, 3);
            bSave.Click += delegate
            {
                if (running != null) { kwInfo.Text = "Дождись окончания проверки, потом сохраняй."; return; }
                Keywords.Save(kwBox.Text);
                Signatures.RebuildKeywords();
                UpdateKwInfo("Сохранено. ");
            };
            bReset.Click += delegate { kwBox.Text = Keywords.DefaultText.Replace("\n", "\r\n"); };
            UpdateKwInfo("");
            return p;
        }

        void UpdateKwInfo(string pre)
        {
            int strong = Keywords.List.Count(k => k.Strong), weak = Keywords.List.Count - strong;
            kwInfo.Text = pre + "Слов: " + Keywords.List.Count + " (точных: " + strong + ", частых — только целым словом: " + weak + ").   " +
                          "Сайз-лист: jar — " + SizeRules.JarSizes.Count + ", exe/dll — " + SizeRules.BinSizes.Count + ".   Хэшей читов: " + Analyzer.KnownBad.Count + ".";
        }

        // ======================= запуск и управление =======================
        Func<double> curProg; Func<string> curSub, curEnd; string curTitle;

        void Run(Sec s, string title, Action<CancellationToken> work, Func<double> prog, Func<string> sub, Func<string> end)
        {
            running = s;
            cts = new CancellationTokenSource();
            s.R.Clear(); s.R.Running = true; s.R.RepaintEmpty();
            s.V.Progress = 0; s.V.ShowPercent = true;
            s.V.Set(VerdictBar.State.Running, title, "Подготовка…");
            if (s.Card != null) { s.Card.Running = true; s.Card.Invalidate(); }
            curProg = prog; curSub = sub; curEnd = end; curTitle = title;
            sw.Restart();
            SetButtons();
            CancellationToken ct = cts.Token;
            Task.Factory.StartNew(() => { try { work(ct); } catch { } }, TaskCreationOptions.LongRunning)
                .ContinueWith(t => BeginInvoke(new Action(() => End(s))));
        }

        void End(Sec s)
        {
            ResultsView r = s.R;
            if (s == sFind) { EndIndex(); return; }
            r.Running = false; r.Scanned = true;
            r.Finish();
            sw.Stop();
            bool stopped = cts != null && cts.IsCancellationRequested;
            string sub = "";
            try { sub = curEnd() + " · " + FormatTime(sw.Elapsed); } catch { }
            running = null;
            s.Done = true;
            s.V.Progress = 1; s.V.ShowPercent = false;
            string pre = stopped ? "Остановлено · " : "";
            if (r.Crit > 0) s.V.Set(VerdictBar.State.Crit, pre + "Найдены читы — критичных: " + r.Crit + (r.Susp > 0 ? ", подозрительных: " + r.Susp : ""), sub);
            else if (r.Susp > 0) s.V.Set(VerdictBar.State.Warn, pre + "Критичного нет, подозрительных: " + r.Susp, sub);
            else if (r.Warn > 0) s.V.Set(VerdictBar.State.Info, pre + "Только слабые совпадения: " + r.Warn + " — проверь вручную", sub);
            else s.V.Set(VerdictBar.State.Clean, pre + "Чисто — ничего не найдено", sub);
            if (s.Card != null) { s.Card.Running = false; s.Card.Done = true; s.Card.Crit = r.Crit; s.Card.Susp = r.Susp; s.Card.Warn = r.Warn; s.Card.Invalidate(); }
            UpdateBadges();
            SetButtons();
            if (stopped) { bool wasFull = fullRun; chain.Clear(); fullRun = false; if (wasFull) FinishAll(true); }
            if (fullRun) { BeginInvoke(new Action(RunNext)); return; }
            try { if (!ContainsFocus) FlashWindow(Handle, true); } catch { }
        }

        void StopAll() { chain.Clear(); if (cts != null) cts.Cancel(); }

        void StartAll()
        {
            if (running != null) return;
            if (!driveCards.Any(c => c.Checked)) foreach (DriveCard c in driveCards) c.Checked = true;
            rTop.Clear();
            chain.Clear();
            fullRun = true;
            swAll.Restart();
            chain.Enqueue(StartTraces);
            chain.Enqueue(StartOpen);
            chain.Enqueue(StartBypass);
            chain.Enqueue(() => StartMods(null));
            chain.Enqueue(StartMem);
            chain.Enqueue(() => StartHidden(null));
            vAll.ShowPercent = true;
            RunNext();
        }

        void RunNext()
        {
            if (chain.Count > 0)
            {
                Action a = chain.Dequeue();
                a();
                return;
            }
            if (fullRun) { fullRun = false; FinishAll(false); }
        }

        void FinishAll(bool stopped)
        {
            swAll.Stop();
            vAll.ShowPercent = false; vAll.Progress = 1;
            Sec[] list = { sHidden, sOpen, sMem, sTraces, sBypass, sMods };
            int crit = list.Sum(s => s.R.Crit), susp = list.Sum(s => s.R.Susp), warn = list.Sum(s => s.R.Warn);
            string sub = "Всего: критичных " + crit + ", подозрительных " + susp + ", слабых " + warn + " · " + FormatTime(swAll.Elapsed);
            string pre = stopped ? "Остановлено · " : "";
            if (crit > 0) vAll.Set(VerdictBar.State.Crit, pre + "ЧИТЫ НАЙДЕНЫ — смотри главные находки ниже", sub);
            else if (susp > 0) vAll.Set(VerdictBar.State.Warn, pre + "Есть подозрительное — проверь вручную", sub);
            else vAll.Set(VerdictBar.State.Clean, pre + "Чисто — читов не найдено", sub);
            Show(sOverview);
            rTop.Finish();
            try { if (!ContainsFocus) FlashWindow(Handle, true); } catch { }
        }

        void SetButtons()
        {
            bool idle = running == null;
            foreach (Sec s in secs)
            {
                if (s.Start != null) s.Start.Enabled = idle;
                if (s.Stop != null) s.Stop.Enabled = running == s;
            }
            bAll.Enabled = idle;
            bAllStop.Enabled = !idle;
            foreach (DriveCard c in driveCards) c.Enabled = idle;
        }

        void UpdateBadges()
        {
            foreach (Sec s in secs)
            {
                if (s.R == null || s.Nav == null || s == sOverview) continue;
                s.Nav.Badge = s.R.Crit > 0 ? s.R.Crit : s.R.Susp;
                s.Nav.BadgeColor = s.R.Crit > 0 ? Theme.Red : Theme.Orange;
                s.Nav.Invalidate();
            }
            int crit = secs.Where(s => s.R != null && s != sOverview).Sum(s => s.R.Crit);
            sOverview.Nav.Badge = crit; sOverview.Nav.BadgeColor = Theme.Red; sOverview.Nav.Invalidate();
        }

        static string FormatTime(TimeSpan t) { return t.ToString(t.TotalHours >= 1 ? "h\\:mm\\:ss" : "mm\\:ss"); }

        void Pump()
        {
            bool any = false;
            foreach (Sec s in secs) if (s.R != null && s.R.Pump() > 0) any = true;
            if (rTop != null && rTop.Pump() > 0) any = true;
            if (any) UpdateBadges();
            if (running != null && curProg != null)
            {
                double p = 0; string sub = "";
                try { p = curProg(); sub = curSub(); } catch { }
                running.V.Progress = Math.Max(running.V.Progress, p);
                running.V.Set(VerdictBar.State.Running, curTitle + " · " + FormatTime(sw.Elapsed), sub);
                running.V.Invalidate();
                if (running.Card != null) { running.Card.Crit = running.R.Crit; running.Card.Susp = running.R.Susp; running.Card.Warn = running.R.Warn; running.Card.Invalidate(); }
                if (fullRun)
                {
                    int done = 6 - chain.Count - 1;
                    vAll.Progress = Math.Min(0.99, (done + Math.Min(1, p)) / 6.0);
                    vAll.Set(VerdictBar.State.Running, "Полная проверка · шаг " + (done + 1) + " из 6: " + running.Title + " · " + FormatTime(swAll.Elapsed), sub);
                    vAll.Invalidate();
                }
            }
        }

        void Export(Sec s)
        {
            if (s.R.All.Count == 0) { s.V.Set(s.V.Mode == VerdictBar.State.Running ? s.V.Mode : VerdictBar.State.Info, "Отчёт пуст", "Сначала запусти проверку."); return; }
            SaveFileDialog d = new SaveFileDialog();
            d.Filter = "Текстовый отчёт (*.txt)|*.txt";
            d.FileName = "RamixyCheaker_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".txt";
            if (d.ShowDialog(this) != DialogResult.OK) return;
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(AppName + " " + Version + " — отчёт");
            sb.AppendLine("Дата: " + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss") + "   Права администратора: " + (isAdmin ? "да" : "НЕТ"));
            sb.AppendLine("Раздел: " + s.Title);
            sb.AppendLine("Итог: " + s.V.Title);
            sb.AppendLine(new string('=', 90));
            foreach (Finding f in s.R.All.Where(x => x.Severity > 0).OrderByDescending(x => x.Severity).ThenByDescending(x => x.Score)) { sb.Append(ResultsView.FindingText(f)); sb.AppendLine(); }
            try { File.WriteAllText(d.FileName, sb.ToString(), Encoding.UTF8); s.V.Set(s.V.Mode, s.V.Title, "Отчёт сохранён: " + d.FileName); }
            catch (Exception ex) { s.V.Set(VerdictBar.State.Info, "Не удалось сохранить отчёт", ex.Message); }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern bool FlashWindow(IntPtr hwnd, bool invert);

        protected override void OnFormClosing(FormClosingEventArgs e) { if (cts != null) cts.Cancel(); base.OnFormClosing(e); }
    }

    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += (s, e) => MessageBox.Show(e.Exception.ToString(), "RamixyCheaker — ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Analyzer.Init();
            Tools.Load();
            string arg = null;
            for (int i = 0; i + 1 < args.Length; i++) if (args[i] == "--run") arg = args[i + 1];
            if (arg == null && args.Length == 1 && (File.Exists(args[0]) || Directory.Exists(args[0]))) arg = args[0]; // перетащили файл на exe
            Application.Run(new MainForm(arg));
        }
    }
}
