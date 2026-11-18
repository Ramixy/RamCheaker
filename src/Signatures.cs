using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace InjectHunter
{
    enum SigKind
    {
        ClientPackage,  // пакет/namespace известного чита — очень сильный признак
        ClientName,     // название/домен чита
        CheatModule,    // типичные модули читов (KillAura, AutoTotem ...)
        Evasion,        // анти-SS / самоуничтожение / чистка следов
        Jni,            // нативный код, работающий с JVM изнутри (инжект-клиенты)
        Injector,       // API инъекции в чужой процесс
        Context,        // javaw / minecraft — контекст, сам по себе не флаг
        Keyword         // слово из пользовательского списка (моды/читы)
    }

    class Sig
    {
        public string Token;
        public string Label;
        public SigKind Kind;
        public int Weight;
    }

    static class Signatures
    {
        public static readonly List<Sig> All = new List<Sig>();
        public static AhoCorasick Matcher;

        static void P(string label, params string[] pkgs)
        {
            foreach (string p in pkgs)
            {
                Add(SigKind.ClientPackage, label, 75, p);
                if (p.IndexOf('/') >= 0) Add(SigKind.ClientPackage, label, 75, p.Replace('/', '.'));
            }
        }
        static void N(string label, int w, params string[] names)
        {
            foreach (string n in names) Add(SigKind.ClientName, label, w, n);
        }
        static void M(string label, params string[] toks)
        {
            foreach (string t in toks) Add(SigKind.CheatModule, label, 10, t);
        }
        static void E(string label, int w, params string[] toks)
        {
            foreach (string t in toks) Add(SigKind.Evasion, label, w, t);
        }
        static void Add(SigKind k, string label, int w, string tok)
        {
            Sig s = new Sig();
            s.Kind = k; s.Label = label; s.Weight = w; s.Token = tok.ToLowerInvariant();
            All.Add(s);
        }

        static Signatures()
        {
            // ---- Инжект-клиенты (ghost / injectable) ----
            // Doomsday / Cortex / System / DLC: у этих клиентов нет надёжных уникальных строк (System, DLC — обычные слова),
            // поэтому они ловятся поведением: маскировка PE, тайники Windows, JNI-инжект, хэши. Здесь только однозначные формы.
            N("Doomsday", 45, "doomsdayclient", "doomsday client", "doomsday-client", "doomsday_client");
            N("Cortex", 40, "cortexcheats", "cortex cheat", "cortex ghost");
            N("Vape", 45, "vape.gg", "vapeclient", "vape client", "vape lite", "vapelite", "vape v4", "vapev4", "manthe.vape");
            N("Drip", 40, "drip.gg", "dripclient", "drip client", "drip lite", "driplite");
            N("Entropy", 40, "entropy.club", "entropyclient", "entropy client");
            N("Slinky", 40, "slinky.gg", "slinkyclient", "slinky client");
            N("Koid", 40, "koid.club", "koidclient", "koid client");
            N("Itami", 40, "itamiclient", "itami client");
            N("Whiteout", 40, "whiteoutclient", "whiteout client");
            N("Gamesense", 35, "gamesense.pub", "gamesenseclient");
            N("Prestige", 40, "prestigeclient", "prestige client");
            N("Novoware", 40, "novoware");
            N("198Macros", 40, "198macros");
            N("Argon", 40, "argonclient", "argon client");
            N("Krypton", 40, "kryptonclient", "krypton client");
            N("Grim Bypass", 30, "grimbypass", "grim bypass");
            // ---- HvH / RU клиенты ----
            N("Nursultan", 45, "nursultan");
            N("Celestial (Celka)", 40, "celestialclient", "celka.", "celkaclient");
            N("Wexside", 45, "wexside");
            N("Akrien", 45, "akrien");
            N("Expensive", 40, "expensiveclient", "expensive client", "expensive.client");
            N("Deadcode", 35, "deadcodeclient", "deadcode client", "deadcode.");
            N("Neverhook", 45, "neverhook");
            N("Fluger", 45, "flugerclient", "fluger client");
            N("Rockstar", 35, "rockstarclient", "rockstar client");
            N("Wild", 35, "wildclient", "wild client");
            N("Excellent", 35, "excellentclient", "excellent client");
            N("Haruka", 35, "harukaclient", "haruka client");
            N("Venus", 35, "venusclient", "venus client");
            N("Catlavan", 40, "catlavan");
            N("Minced", 35, "mincedclient", "minced client");
            // ---- Blatant / известные ----
            N("Rise", 35, "riseclient", "rise client");
            N("Sigma", 35, "sigmaclient", "sigma client", "jello for sigma");
            N("Astolfo", 35, "astolfoclient", "astolfo client");
            N("Exhibition", 35, "exhibitionclient", "exhibition client");
            N("Augustus", 35, "augustusclient", "augustus client");
            N("Tenacity", 35, "tenacityclient", "tenacity client");
            N("Raven", 35, "ravenb+", "raven b+", "ravenbplus", "raven b++", "ravenclient");
            N("Wurst", 35, "wurstclient", "wurst client", "wurst-client");
            N("Meteor", 35, "meteorclient", "meteor client", "meteor-client");
            N("LiquidBounce", 45, "liquidbounce");
            N("Aristois", 45, "aristois");
            N("Impact", 35, "impactclient", "impact client");
            N("Future", 35, "futureclient", "future client");
            N("RusherHack", 45, "rusherhack");
            N("ThunderHack", 45, "thunderhack");
            N("BleachHack", 45, "bleachhack");
            N("KAMI", 35, "kamiblue", "kami blue");
            N("Boze", 35, "bozeclient", "boze client");
            N("Inertia", 35, "inertiaclient", "inertia client");
            N("Coffee", 35, "coffeeclient", "coffee client");
            N("Novoline", 45, "novoline");
            N("Salhack", 45, "salhack");
            N("Konas", 35, "konasclient", "konas client");

            // ---- Пакеты (namespace) известных читов ----
            P("LiquidBounce", "net/ccbluex/liquidbounce");
            P("Meteor Client", "meteordevelopment/meteorclient");
            P("Wurst", "net/wurstclient");
            P("KAMI", "me/zeroeightsix/kami");
            P("KAMI Blue", "org/kamiblue");
            P("Lambda", "com/lambda/client");
            P("Future", "net/futureclient");
            P("RusherHack", "org/rusherhack");
            P("Aristois", "me/deftware");
            P("BleachHack", "org/bleachhack", "bleach/hack");
            P("ThunderHack", "thunder/hack");
            P("Argon", "dev/lvstrng/argon");
            P("Krypton", "skid/krypton");
            P("Raven", "keystrokesmod");
            P("OyVey", "me/alpha432/oyvey");
            P("SalHack", "com/salhack");
            P("Seppuku", "me/rigamortis/seppuku");
            P("Novoline", "cc/novoline");
            P("Sigma", "info/sigmaclient");
            P("Tenacity", "dev/tenacity");

            // ---- из MeowModAnalyzer / MeowClientFucker ----
            P("Chainlibs (чит-клиент)", "org/chainlibs/module/impl/modules");
            P("Krypton", "dev/krypton");
            P("Virel", "dev/virel");
            P("Gamble Client", "dev/gambleclient");
            P("Greaj", "xyz/greaj");
            E("Обфускатор Skidfuscator", 15, "dev/skidfuscator", "skidfuscator.dev");
            E("Обфускатор Paramorphism", 15, "dev/paramorphism", "paramorphism-");
            E("Обфускатор Radon", 15, "me/itzsomebody/radon", "radon obfuscator");
            E("Обфускатор Caesium", 15, "dev/sim0n/caesium", "caesium obfuscator");
            E("Обфускатор Bozar", 15, "vimasig/bozar", "bozar obfuscator");
            E("Обфускатор Branchlock", 15, "branchlock.dev");
            E("Обфускатор Binscure", 15, "com/binscure");
            E("Обфускатор superblaubeere", 15, "superblaubeere27");
            E("Обфускатор QProtect", 15, "mdma.dev/qprotect");
            E("Обфускатор Zelix", 10, "zelixklassmaster", "com/zelix");
            E("Глобальный перехват клавиш (кликеры)", 20, "jnativehook", "com/github/kwhat/jnativehook");
            E("Отладочный доступ ко всем модулям JVM", 25, "jdwp.virtualmachine.allmodules");
            M("AutoHitCrystal", "autohitcrystal", "auto hit crystal");
            M("DoubleAnchor", "doubleanchor", "double anchor", "safeanchor", "safe anchor", "airanchor");
            M("InventoryTotem", "inventorytotem", "inventory totem", "legittotem");
            M("AutoDoubleHand", "autodoublehand", "auto double hand");
            M("ShieldBreaker", "shieldbreaker", "shielddisabler", "shield disabler");
            M("WalksyOptimizer", "walksyoptimizer", "walskyoptimizer", "walksycrystaloptimizermod");
            M("MaceSwap", "maceswap", "mace swap", "automace", "stunslam", "stun slam");
            M("AxeSpam", "axespam", "axe spam");
            M("WebMacro", "webmacro", "web macro", "autoweb");
            M("PingSpoof", "pingspoof", "ping spoof", "fakelag", "fake lag");
            M("AutoPot", "autopot", "auto pot", "autopotrefill");
            M("FakePunch", "fakepunch", "fake punch");
            M("SelfDestruct", "selfdestruct", "self destruct");
            // ---- Модули читов (generic) ----
            M("KillAura", "killaura", "kill aura");
            M("CrystalAura", "crystalaura", "crystal aura");
            M("AnchorAura", "anchoraura", "anchor aura");
            M("AutoCrystal", "autocrystal", "auto crystal");
            M("AutoAnchor", "autoanchor", "auto anchor", "anchormacro", "anchor macro");
            M("CrystalMacro", "crystalmacro", "crystal macro");
            M("AimAssist", "aimassist", "aim assist");
            M("SilentAim", "silentaim", "silent aim");
            M("TriggerBot", "triggerbot", "trigger bot");
            M("AutoTotem", "autototem", "auto totem", "hovertotem", "hover totem");
            M("AutoClicker", "autoclicker", "auto clicker");
            M("AutoDoubleHand", "autodoublehand", "auto double hand");
            M("AntiKnockback", "antiknockback", "anti knockback");
            M("ChestStealer", "cheststealer", "chest stealer");
            M("PlayerESP", "playeresp", "player esp", "storageesp", "storage esp");
            M("ClickGUI", "clickgui", "click gui");
            M("FakeLag", "fakelag", "fake lag");
            M("PingSpoof", "pingspoof", "ping spoof");
            M("ElytraFly", "elytrafly");
            M("NoFall", "nofall");
            M("Scaffold", "scaffoldwalk", "scaffold walk");
            M("ShieldDisabler", "shielddisabler", "shield disabler");
            M("Criticals", "onlycrit", "only crit");
            M("BowAimbot", "bowaimbot", "bow aimbot");

            // ---- Анти-SS / зачистка следов ----
            E("SelfDestruct", 20, "selfdestruct", "self destruct", "self-destruct");
            E("StringCleaner", 25, "stringcleaner", "string cleaner");
            E("Чистка USN-журнала", 25, "deletejournal", "usn deletejournal", "usn journal cleaner");
            E("Очистка Prefetch", 15, "prefetch cleaner", "clear prefetch");
            E("Обход SS", 20, "ssbypass", "ss bypass", "anti ss", "antiss tool", "bypass screenshare");

            // ---- JNI / JVMTI: нативный код внутри JVM ----
            Add(SigKind.Jni, "JNI_GetCreatedJavaVMs (подключение к уже запущенной JVM)", 40, "jni_getcreatedjavavms");
            Add(SigKind.Jni, "JVMTI", 15, "jvmti");
            Add(SigKind.Jni, "Agent_OnAttach", 20, "agent_onattach");
            Add(SigKind.Jni, "сигнатура defineClass (загрузка классов из памяти)", 25, "(ljava/lang/string;[bii)ljava/lang/class;");
            Add(SigKind.Jni, "defineClass", 6, "defineclass");
            Add(SigKind.Jni, "java/lang/ClassLoader", 8, "java/lang/classloader");
            Add(SigKind.Jni, "net/minecraft/ (FindClass)", 15, "net/minecraft/");
            Add(SigKind.Jni, "Fabric intermediary (net/minecraft/class_)", 20, "net/minecraft/class_");
            Add(SigKind.Jni, "java/lang/instrument", 10, "java/lang/instrument");
            Add(SigKind.Jni, "retransformClasses", 10, "retransformclasses");
            Add(SigKind.Jni, "jvm.dll", 8, "jvm.dll");

            // ---- Инъекция в процесс ----
            Add(SigKind.Injector, "CreateRemoteThread", 8, "createremotethread");
            Add(SigKind.Injector, "NtCreateThreadEx", 10, "ntcreatethreadex");
            Add(SigKind.Injector, "RtlCreateUserThread", 10, "rtlcreateuserthread");
            Add(SigKind.Injector, "VirtualAllocEx", 6, "virtualallocex");
            Add(SigKind.Injector, "WriteProcessMemory", 6, "writeprocessmemory");
            Add(SigKind.Injector, "QueueUserAPC", 6, "queueuserapc");
            Add(SigKind.Injector, "SetWindowsHookEx", 4, "setwindowshookex");
            Add(SigKind.Injector, "Manual map", 20, "manualmap");
            Add(SigKind.Injector, "ReflectiveLoader", 25, "reflectiveloader");

            // ---- Контекст ----
            Add(SigKind.Context, "javaw.exe", 0, "javaw.exe");
            Add(SigKind.Context, "javaw", 0, "javaw");
            Add(SigKind.Context, "minecraft", 0, "minecraft");
            Add(SigKind.Context, "lwjgl", 0, "lwjgl");

            baseCount = All.Count;
            RebuildKeywords();
        }

        static int baseCount;

        /// <summary>Пересобирает автомат с учётом текущего списка ключевых слов.</summary>
        public static void RebuildKeywords()
        {
            lock (All)
            {
                if (All.Count > baseCount) All.RemoveRange(baseCount, All.Count - baseCount);
                HashSet<string> have = new HashSet<string>(All.Select(x => x.Token));
                foreach (string w in Keywords.ContentWords())
                {
                    if (have.Contains(w) || w.Any(ch => ch > 127)) continue;
                    Add(SigKind.Keyword, w, 35, w);
                    have.Add(w);
                }
                AhoCorasick m = new AhoCorasick();
                for (int i = 0; i < All.Count; i++) m.Add(Encoding.ASCII.GetBytes(All[i].Token), i);
                m.Build();
                Matcher = m;
            }
        }

        // Типичные системные DLL, которые подделывают (опечатки kerne132, user33 и т.д.)
        public static readonly string[] MimicTargets = {
            "kernel32","kernelbase","ntdll","user32","gdi32","advapi32","shell32","ole32","oleaut32","combase","rpcrt4",
            "msvcrt","msvcp140","vcruntime140","vcruntime140_1","ucrtbase","ws2_32","wininet","winhttp","crypt32","bcrypt",
            "d3d9","d3d11","d3d12","dxgi","opengl32","glu32","dinput8","xinput1_3","xinput1_4","winmm","version","dbghelp",
            "dwmapi","uxtheme","comctl32","comdlg32","shlwapi","setupapi","iphlpapi","psapi","secur32","sechost","imm32",
            "msimg32","mswsock","dnsapi","netapi32","userenv","wtsapi32","winspool","cfgmgr32","powrprof","hid",
            "jvm","java","jli","awt","jawt","jimage","net","nio","zip","verify","management","attach","instrument",
            "lwjgl","lwjgl64","lwjgl_opengl","glfw","glfw3","openal","openal32","openal64","jemalloc","jinput-raw_64","jnidispatch",
            "svchost","explorer","csrss","lsass","winlogon","conhost","dllhost","rundll32","taskhostw","runtimebroker","sihost"
        };

        public static readonly HashSet<string> KnownJavaNatives = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "lwjgl.dll","lwjgl64.dll","lwjgl32.dll","lwjgl_opengl.dll","lwjgl_stb.dll","lwjgl_tinyfd.dll","lwjgl_jemalloc.dll",
            "lwjgl_openal.dll","lwjgl_glfw.dll","glfw.dll","glfw3.dll","openal.dll","openal32.dll","openal64.dll","jemalloc.dll",
            "jinput-dx8_64.dll","jinput-raw_64.dll","jinput-dx8.dll","jinput-raw.dll","jnidispatch.dll","discord_game_sdk.dll",
            "sqlite-jdbc.dll","netty_tcnative_windows_x86_64.dll","zstd-jni.dll","lz4-java.dll","jna.dll"
        };
    }
}
