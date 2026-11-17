using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace InjectHunter
{
    class ModMeta
    {
        public string Id, Name, Version, Loader, Authors;
        public bool HasMeta;
    }

    /// <summary>Раздел «Моды»: поиск папок модов всех лаунчеров + ручная загрузка файлов.</summary>
    class ModScanner
    {
        public event Action<Finding> Found;
        public volatile string Current = "";
        public double Progress;
        public int Count, Folders;

        // Популярные безопасные моды (id) — помечаются как известные
        static readonly HashSet<string> safeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "fabric", "fabric-api", "fabricloader", "minecraft", "java", "quilt_loader", "quilted_fabric_api", "forge", "neoforge",
            "sodium", "lithium", "iris", "indium", "phosphor", "starlight", "ferritecore", "lazydfu", "modmenu", "cloth-config", "cloth_config",
            "cloth-config2", "architectury", "entityculling", "dynamic_fps", "dynamicfps", "immediatelyfast", "moreculling", "krypton", "c2me",
            "modernfix", "memoryleakfix", "smoothboot", "fastload", "lambdynlights", "continuity", "zoomify", "okzoomer", "ok_zoomer", "betterf3",
            "appleskin", "jei", "roughlyenoughitems", "rei", "emi", "jade", "wthit", "journeymap", "xaerominimap", "xaeroworldmap", "voicechat",
            "replaymod", "worldedit", "optifine", "optifabric", "sodium-extra", "reeses-sodium-options", "reeses_sodium_options", "cullleaves",
            "yet_another_config_lib_v3", "yacl", "puzzle", "notenoughcrashes", "ears", "skinlayers3d", "3dskinlayers", "capes", "essential",
            "fabric-language-kotlin", "fabriclanguagekotlin", "kotlinforforge", "geckolib", "playeranimator", "bobby", "nvidium", "distanthorizons",
            "betterpingdisplay", "chat_heads", "chatheads", "mousetweaks", "inventoryprofilesnext", "controlling", "searchables", "badpackets",
            "forgeconfigapiport", "collective", "balm", "owo", "owo-lib", "midnightlib", "resourcefulconfig", "konkrete", "fancymenu", "satin",
            "entity_texture_features", "entity_model_features", "cit-resewn", "citresewn", "animatica", "visuality", "falling_leaves", "particular"
        };

        // Моды, запрещённые на большинстве серверов (по id или имени)
        static readonly string[][] banned = {
            new string[] { "xray", "X-Ray (видеть руды сквозь блоки)", "60" }, new string[] { "x-ray", "X-Ray", "60" }, new string[] { "advancedxray", "Advanced X-Ray", "60" },
            new string[] { "baritone", "Baritone (бот-автопилот)", "60" }, new string[] { "freecam", "Freecam (камера сквозь стены)", "45" },
            new string[] { "tweakeroo", "Tweakeroo (многие функции запрещены)", "45" }, new string[] { "itemscroller", "Item Scroller (массовые перекладывания)", "25" },
            new string[] { "autototem", "AutoTotem", "60" }, new string[] { "clickcrystals", "ClickCrystals (макросы кристаллов)", "60" },
            new string[] { "autoclicker", "AutoClicker", "60" }, new string[] { "killaura", "KillAura", "70" }, new string[] { "meteor-client", "Meteor Client", "80" },
            new string[] { "meteor_client", "Meteor Client", "80" }, new string[] { "wurst", "Wurst", "80" }, new string[] { "aristois", "Aristois", "80" },
            new string[] { "inertia", "Inertia", "70" }, new string[] { "boze", "Boze", "70" }, new string[] { "bleachhack", "BleachHack", "80" },
            new string[] { "liquidbounce", "LiquidBounce", "80" }, new string[] { "thunderhack", "ThunderHack", "80" }, new string[] { "rusherhack", "RusherHack", "80" },
            new string[] { "invmove", "InvMove (ходьба в инвентаре)", "35" }, new string[] { "elytrahack", "Elytra hack", "60" },
            new string[] { "entity_outliner", "Entity Outliner (подсветка игроков)", "40" }, new string[] { "player_highlighter", "Player Highlighter", "40" },
            new string[] { "mob_hitbox", "Mob Hitbox", "30" }, new string[] { "hitbox", "Hitbox-мод", "25" }, new string[] { "autoattack", "AutoAttack", "60" },
            new string[] { "trouser-streak", "Trouser-Streak (аддон Meteor)", "80" }, new string[] { "chestesp", "Chest ESP", "50" }, new string[] { "storageesp", "Storage ESP", "50" },
            new string[] { "nofall", "NoFall", "50" }, new string[] { "fullbright", "Fullbright", "15" }, new string[] { "autofish", "AutoFish", "20" },
        };

        public static List<string> FindModFolders()
        {
            List<string> res = new List<string>();
            string ad = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] roots = {
                Path.Combine(ad, ".minecraft"), Path.Combine(ad, ".tlauncher"), Path.Combine(ad, ".feather"), Path.Combine(ad, "PrismLauncher"),
                Path.Combine(ad, "PolyMC"), Path.Combine(ad, "MultiMC"), Path.Combine(ad, "ATLauncher"), Path.Combine(ad, "ModrinthApp"),
                Path.Combine(ad, "com.modrinth.theseus"), Path.Combine(ad, "GDLauncher"), Path.Combine(ad, "gdlauncher_next"), Path.Combine(home, "curseforge"),
                Path.Combine(home, ".lunarclient"), Path.Combine(ad, ".minecraft_tlauncher"), Path.Combine(ad, "Badlion Client"), Path.Combine(la, "Programs", "PrismLauncher"),
                Path.Combine(home, "Documents", "Curse"), Path.Combine(ad, ".hmcl"), Path.Combine(ad, "HMCL")
            };
            foreach (string r in roots) Find(r, 0, 7, res);
            return res.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        static void Find(string dir, int depth, int max, List<string> res)
        {
            if (depth > max || !Directory.Exists(dir) || res.Count > 300) return;
            string[] subs;
            try { subs = Directory.GetDirectories(dir); } catch { return; }
            foreach (string s in subs)
            {
                string n = Path.GetFileName(s).ToLowerInvariant();
                if (n == "mods" || n == "user-mods" || n == "coremods") { res.Add(s); Find(s, depth + 1, Math.Min(max, depth + 2), res); continue; }
                if (n == "assets" || n == "libraries" || n == "saves" || n == "logs" || n == "resourcepacks" || n == "shaderpacks" || n == "screenshots" ||
                    n == "crash-reports" || n == "natives" || n == "runtime" || n == "jre" || n == "java" || n == "cache" || n == "meta" || n == "config") continue;
                Find(s, depth + 1, max, res);
            }
        }

        public void Run(List<string> manual, CancellationToken ct)
        {
            List<string> files = new List<string>();
            if (manual == null)
            {
                Current = "Ищу папки модов…";
                List<string> dirs = FindModFolders();
                Folders = dirs.Count;
                foreach (string d in dirs)
                    try { files.AddRange(Directory.GetFiles(d, "*", SearchOption.TopDirectoryOnly).Where(IsModFile)); } catch { }
            }
            else
            {
                foreach (string p in manual)
                {
                    if (Directory.Exists(p)) { Folders++; try { files.AddRange(Directory.GetFiles(p, "*", SearchOption.AllDirectories).Where(f => IsModFile(f) || IsCheckable(f))); } catch { } }
                    else if (File.Exists(p)) files.Add(p);
                }
            }
            files = files.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            for (int i = 0; i < files.Count && !ct.IsCancellationRequested; i++)
            {
                Current = files[i];
                try
                {
                    Finding f = IsModFile(files[i]) ? CheckMod(files[i]) : CheckOther(files[i]);
                    if (f != null) { Count++; if (Found != null) Found(f); }
                }
                catch { }
                Progress = (i + 1.0) / files.Count;
            }
            Progress = 1;
        }

        static bool IsModFile(string f)
        {
            string l = f.ToLowerInvariant();
            return l.EndsWith(".jar") || l.EndsWith(".jar.disabled") || l.EndsWith(".litemod") || (l.EndsWith(".zip") && l.Contains("\\mods\\"));
        }
        static bool IsCheckable(string f)
        {
            string l = Path.GetExtension(f).ToLowerInvariant();
            return l == ".exe" || l == ".dll" || l == ".zip" || l == ".rar" || l == ".7z";
        }

        static Finding CheckOther(string path)
        {
            Finding f = Analyzer.AnalyzeFile(new FileInfo(path), new ScanOptions(), true);
            if (f != null) { f.Source = "Загружено вручную"; if (!f.RealType.Contains(" · ")) f.RealType = Theme.TypeBadge(f.RealType) + " · " + f.RealType; }
            return f;
        }

        public static ModMeta ReadMeta(string path)
        {
            ModMeta m = new ModMeta();
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (ZipArchive za = new ZipArchive(fs, ZipArchiveMode.Read))
                {
                    ZipArchiveEntry e;
                    if ((e = za.GetEntry("fabric.mod.json")) != null)
                    {
                        string j = Read(e);
                        m.Loader = "Fabric"; m.Id = Json(j, "id"); m.Name = Json(j, "name"); m.Version = Json(j, "version"); m.HasMeta = true;
                    }
                    else if ((e = za.GetEntry("quilt.mod.json")) != null)
                    {
                        string j = Read(e);
                        m.Loader = "Quilt"; m.Id = Json(j, "id"); m.Name = Json(j, "name"); m.Version = Json(j, "version"); m.HasMeta = true;
                    }
                    else if ((e = za.GetEntry("META-INF/neoforge.mods.toml")) != null || (e = za.GetEntry("META-INF/mods.toml")) != null)
                    {
                        string t = Read(e);
                        m.Loader = e.FullName.Contains("neoforge") ? "NeoForge" : "Forge";
                        m.Id = Toml(t, "modId"); m.Name = Toml(t, "displayName"); m.Version = Toml(t, "version"); m.HasMeta = true;
                    }
                    else if ((e = za.GetEntry("mcmod.info")) != null)
                    {
                        string j = Read(e);
                        m.Loader = "Forge (старый)"; m.Id = Json(j, "modid"); m.Name = Json(j, "name"); m.Version = Json(j, "version"); m.HasMeta = true;
                    }
                    else if ((e = za.GetEntry("litemod.json")) != null)
                    {
                        string j = Read(e);
                        m.Loader = "LiteLoader"; m.Name = Json(j, "name"); m.Version = Json(j, "version"); m.Id = m.Name; m.HasMeta = true;
                    }
                }
            }
            catch { }
            if (m.Version != null && m.Version.Contains("${")) m.Version = null;
            return m;
        }

        static string Read(ZipArchiveEntry e)
        {
            if (e.Length > 1024 * 1024) return "";
            using (StreamReader r = new StreamReader(e.Open(), Encoding.UTF8)) return r.ReadToEnd();
        }
        static string Json(string j, string key)
        {
            Match m = Regex.Match(j, "\"" + key + "\"\\s*:\\s*\"([^\"]{1,120})\"");
            return m.Success ? m.Groups[1].Value : null;
        }
        static string Toml(string t, string key)
        {
            Match m = Regex.Match(t, "^\\s*" + key + "\\s*=\\s*\"([^\"]{1,120})\"", RegexOptions.Multiline);
            return m.Success ? m.Groups[1].Value : null;
        }

        public static Finding CheckMod(string path)
        {
            FileInfo fi = new FileInfo(path);
            ModMeta meta = ReadMeta(path);
            Finding f = null;
            try { f = Analyzer.AnalyzeFile(fi, new ScanOptions(), true); } catch { }
            if (f == null) { f = new Finding(); f.Path = path; f.FileName = fi.Name; f.Size = fi.Length; f.Modified = fi.LastWriteTime; f.Created = fi.CreationTime; }
            f.Reasons.RemoveAll(r => r.StartsWith("·  Признаков чита не найдено"));
            f.Source = "Моды";
            string title = meta.Name ?? Path.GetFileNameWithoutExtension(fi.Name.Replace(".disabled", ""));
            f.FileName = title + (meta.Version != null ? "  " + meta.Version : "");
            f.RealType = "MOD · " + (meta.Loader ?? "без загрузчика") + (meta.Id != null ? " · " + meta.Id : "");
            if (fi.Name.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase)) f.Note("Мод отключён (.disabled) — но файл лежит в папке");
            f.Note("Файл: " + fi.Name);

            string idn = (meta.Id ?? "").ToLowerInvariant();
            string all = (meta.Id + " " + meta.Name + " " + fi.Name).ToLowerInvariant();
            bool isSafe = meta.Id != null && safeIds.Contains(meta.Id);

            // запрещённые моды
            HashSet<string> labels = new HashSet<string>();
            foreach (string[] b in banned)
            {
                string tok = b[0];
                bool hit = idn == tok || Regex.IsMatch(all, "(^|[^a-z0-9])" + Regex.Escape(tok) + "([^a-z0-9]|$)") || (tok.Length >= 7 && all.Contains(tok));
                if (hit && labels.Add(b[1])) f.Add(int.Parse(b[2]), "Запрещённый на серверах мод: " + b[1]);
            }
            // слова из списка (в модах даже частые слова — значимы, но только целым словом)
            if (!isSafe)
                foreach (Keywords.Kw k in Keywords.Match(meta.Id + " " + meta.Name))
                    if (!labels.Any(l => l.ToLowerInvariant().Contains(k.Word)) && !f.Reasons.Any(r => r.Contains("«" + k.Word + "»")))
                        f.Add(k.Strong ? 50 : 25, "Название/ID мода содержит слово из списка «" + k.Word + "»");

            if (!meta.HasMeta && fi.Length > 0 && !f.RealType.Contains("ZIP"))
                f.Add(20, "Нет описания мода (fabric.mod.json / mods.toml / mcmod.info) — нестандартный jar");
            bool cheatSigs = f.Reasons.Any(r => r.Contains("Сигнатура чита") || r.Contains("Модули чита") || r.Contains("ИЗВЕСТНЫЙ ЧИТ") || r.Contains("Запрещённый"));
            if (isSafe && !cheatSigs) { f.Score = 0; f.Reasons.RemoveAll(r => r.StartsWith("+")); f.Note("Известный безопасный мод (" + meta.Id + ")"); }
            f.Finish();
            return f;
        }
    }
}
