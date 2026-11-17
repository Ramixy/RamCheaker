using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace InjectHunter
{
    /// <summary>Список запрещённых слов (читы, моды, лоадеры). Сильные ищутся подстрокой, слабые — только целым словом.</summary>
    static class Keywords
    {
        public enum KwKind { Token, Ext, ExactName }
        public class Kw
        {
            public string Word;
            public bool Strong;
            public KwKind Kind;
        }

        public const string DefaultText =
            "Baritone|Nursultan | impact | wurst | bleachhack | aristois | huzuni | skillclient | inertia | ares | sigma | meteor | liquidbounce | nurik | nursultan | celestial | calestial | celka | expensive | neverhook | excellent | wexside | wildclient | minced | deadcode | akrien | jigsaw | future | jessica | dreampool | norules | konas | richclient | rusherhack | thunderhack | moonhack | doomsday | nightware | ricardo | extazyy | troxill | antileak | arbuz | .akr | .wex | dauntiblyat | rename_me_please | editme | takker | fuzeclient | wisefolder| flauncher | vec.dll | USBOblivion.exe | Feather | delta | venus | baritone | spambot | CleanCut | spam_bot | inventory_walk | player_highlighter | aimbot | freecam | bedrock_breaker_mode | viaversion | double_hotbar | elytra_swap | armor_hotswap | smart_moving | chest | savesearcher | topkautobuy | topkaautobuy | tweakeroo | mob_hitbox | librarian_trade_finder | sacurachorusfind | autoattack | entity_outliner | invmove | viabackwards | viarewind | viafabric | viaforge | viaproxy | vialoader | viamcp | hitbox | elytrahack | DiamondSim | ForgeHax | clientcommands | Control-Tweaks | SwingThroughGrass | CutThr | Haruka |  NewLauncher | Blade | Hachclient | Inertia | Fluger | Exloader\n" +
            "winston | debuda | winter | dlc";

        // Обычные английские/частые слова — ищем только целым словом и считаем слабым признаком
        static readonly HashSet<string> weakWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "impact", "ares", "sigma", "meteor", "celestial", "expensive", "excellent", "minced", "jigsaw", "future", "jessica", "ricardo",
            "feather", "delta", "venus", "chest", "hitbox", "haruka", "blade", "inertia", "winston", "winter", "dlc", "editme", "nurik",
            "arbuz", "norules", "konas", "cutthr", "freecam", "takker"
        };

        public static List<Kw> List = new List<Kw>();
        public static string UserFile;
        static Keywords() { Parse(DefaultText); }
        public static string CurrentText = DefaultText;

        public static void Load()
        {
            try
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RamCheaker");
                UserFile = Path.Combine(dir, "keywords.txt");
                if (File.Exists(UserFile)) CurrentText = File.ReadAllText(UserFile, Encoding.UTF8);
            }
            catch { }
            Parse(CurrentText);
        }

        public static void Save(string text)
        {
            CurrentText = text;
            Parse(text);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(UserFile));
                File.WriteAllText(UserFile, text, Encoding.UTF8);
            }
            catch { }
        }

        public static void Parse(string text)
        {
            List<Kw> l = new List<Kw>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in text.Split(new char[] { '|', '\n', '\r', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string w = raw.Trim().ToLowerInvariant();
                if (w.Length < 3 || w.StartsWith("#") || !seen.Add(w)) continue;
                Kw k = new Kw();
                k.Word = w;
                if (w.StartsWith(".") && w.IndexOf('.', 1) < 0) k.Kind = KwKind.Ext;
                else if (Regex.IsMatch(w, @"\.(exe|dll|jar|zip|rar|bat|cmd)$")) k.Kind = KwKind.ExactName;
                else k.Kind = KwKind.Token;
                k.Strong = !weakWords.Contains(w) && w.Length >= 5;
                l.Add(k);
            }
            List = l;
        }

        static bool IsWordChar(char c) { return char.IsLetterOrDigit(c); }

        /// <summary>Ищет слова в строке (имя файла, путь, запись реестра). Сильные — подстрокой, слабые — целым словом.</summary>
        public static List<Kw> Match(string text)
        {
            List<Kw> res = new List<Kw>();
            if (string.IsNullOrEmpty(text)) return res;
            string t = text.ToLowerInvariant();
            int sl = Math.Max(t.LastIndexOf('\\'), t.LastIndexOf('/'));
            if (IsSsTool(sl >= 0 ? t.Substring(sl + 1) : t)) return res;
            t = Regex.Replace(t, @"java-runtime-[a-z]+", "jre");
            string fileName = t;
            int slash = Math.Max(t.LastIndexOf('\\'), t.LastIndexOf('/'));
            if (slash >= 0) fileName = t.Substring(slash + 1);
            foreach (Kw k in List)
            {
                bool hit = false;
                switch (k.Kind)
                {
                    case KwKind.Ext:
                        hit = fileName.EndsWith(k.Word) || t.Contains(k.Word + "\\") || t.Contains(k.Word + " ");
                        break;
                    case KwKind.ExactName:
                        hit = fileName == k.Word || t.Contains("\\" + k.Word) || t.StartsWith(k.Word);
                        break;
                    default:
                        int i = t.IndexOf(k.Word, StringComparison.Ordinal);
                        while (i >= 0 && !hit)
                        {
                            if (k.Strong) hit = true;
                            else
                            {
                                bool before = i == 0 || !IsWordChar(t[i - 1]);
                                int e = i + k.Word.Length;
                                bool after = e >= t.Length || !IsWordChar(t[e]);
                                hit = before && after;
                            }
                            if (!hit) i = t.IndexOf(k.Word, i + 1, StringComparison.Ordinal);
                        }
                        break;
                }
                if (hit) res.Add(k);
            }
            return res;
        }

        // Сами SS-утилиты и античит-сканеры: их имена содержат названия читов, но это не читы
        static readonly string[] ssTools = { "fucker", "ramcheaker", "injecthunter", "bamparser", "journaltrace", "pathsparser", "redlotus",
            "echo-", "paladin", "avenge", "ocean ss", "sschecker", "ss-tool", "sstool", "screenshare", "anticheat", "detector" };

        public static bool IsSsTool(string text)
        {
            string t = text.ToLowerInvariant();
            foreach (string s in ssTools) if (t.Contains(s)) return true;
            return false;
        }

        public static bool HasStrong(string text) { return Match(text).Any(k => k.Strong); }

        /// <summary>Сильные слова для поиска внутри содержимого (jar, память javaw).</summary>
        public static IEnumerable<string> ContentWords()
        {
            return List.Where(k => k.Strong && k.Kind == KwKind.Token && k.Word.Length >= 6).Select(k => k.Word);
        }
    }

    /// <summary>Правила из «сайз.txt»: точные размеры известных читов и шаблоны содержимого.</summary>
    static class SizeRules
    {
        public static HashSet<long> JarSizes = new HashSet<long>();
        public static HashSet<long> BinSizes = new HashSet<long>();

        public static void Load()
        {
            string text = null;
            try
            {
                using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("rules.sizes"))
                    if (s != null) using (StreamReader r = new StreamReader(s, Encoding.UTF8)) text = r.ReadToEnd();
            }
            catch { }
            try
            {
                string user = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RamCheaker", "sizes.txt");
                if (File.Exists(user)) text = (text ?? "") + "\n" + File.ReadAllText(user);
            }
            catch { }
            if (text == null) return;
            foreach (string line in text.Split('\n'))
            {
                if (line.IndexOf("size:", StringComparison.OrdinalIgnoreCase) < 0 || line.IndexOf("content:", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                bool jar = line.IndexOf("*.jar", StringComparison.OrdinalIgnoreCase) >= 0;
                foreach (Match m in Regex.Matches(line, @"size:\s*(\d+)"))
                {
                    long v;
                    if (long.TryParse(m.Groups[1].Value, out v) && v > 0) (jar ? JarSizes : BinSizes).Add(v);
                }
            }
        }
    }
}
