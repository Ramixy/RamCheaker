using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace InjectHunter
{
    /// <summary>Разбор .class и вывод в виде Java-подобного текста с байткодом (как javap -c). Java не нужна.</summary>
    class ClassFile
    {
        public int Major, Minor, Access;
        public string Name, Super, SourceFile;
        public List<string> Interfaces = new List<string>();
        public List<string> Strings = new List<string>();
        public List<Member> Fields = new List<Member>(), Methods = new List<Member>();
        object[] cp; byte[] tags;
        byte[] b; int p;

        public class Member { public int Access; public string Name, Desc; public byte[] Code; public int MaxStack, MaxLocals; public object Const; }

        public static ClassFile Parse(byte[] data)
        {
            ClassFile c = new ClassFile();
            c.b = data; c.p = 0;
            if (data.Length < 10 || c.U4() != 0xCAFEBABE) throw new InvalidDataException("не Java-класс");
            c.Minor = c.U2(); c.Major = c.U2();
            int n = c.U2();
            c.cp = new object[n]; c.tags = new byte[n];
            for (int i = 1; i < n; i++)
            {
                byte t = data[c.p++];
                c.tags[i] = t;
                switch (t)
                {
                    case 1: { int len = c.U2(); c.cp[i] = MUtf8(data, c.p, len); c.p += len; break; }
                    case 3: c.cp[i] = (int)c.U4(); break;
                    case 4: c.cp[i] = BitConverter.ToSingle(BitConverter.GetBytes(c.U4()), 0); break;
                    case 5: { long v = ((long)c.U4() << 32) | c.U4(); c.cp[i] = v; i++; break; }
                    case 6: { long v = ((long)c.U4() << 32) | c.U4(); c.cp[i] = BitConverter.Int64BitsToDouble(v); i++; break; }
                    case 7: case 8: case 16: case 19: case 20: c.cp[i] = c.U2(); break;
                    case 9: case 10: case 11: case 12: case 17: case 18: c.cp[i] = new int[] { c.U2(), c.U2() }; break;
                    case 15: c.cp[i] = new int[] { data[c.p++], c.U2() }; break;
                    default: throw new InvalidDataException("неизвестная константа " + t + " в #" + i);
                }
            }
            c.Access = c.U2();
            c.Name = c.ClassName(c.U2());
            int sup = c.U2(); c.Super = sup == 0 ? null : c.ClassName(sup);
            int ni = c.U2();
            for (int i = 0; i < ni; i++) c.Interfaces.Add(c.ClassName(c.U2()));
            for (int k = 0; k < 2; k++)
            {
                int cnt = c.U2();
                for (int i = 0; i < cnt; i++)
                {
                    Member m = new Member(); m.Access = c.U2(); m.Name = c.Utf(c.U2()); m.Desc = c.Utf(c.U2());
                    int na = c.U2();
                    for (int a = 0; a < na; a++)
                    {
                        string an = c.Utf(c.U2()); int alen = (int)c.U4(); int start = c.p;
                        if (an == "Code" && k == 1)
                        {
                            m.MaxStack = c.U2(); m.MaxLocals = c.U2();
                            int clen = (int)c.U4();
                            m.Code = new byte[Math.Max(0, Math.Min(clen, data.Length - c.p))];
                            Buffer.BlockCopy(data, c.p, m.Code, 0, m.Code.Length);
                        }
                        else if (an == "ConstantValue" && k == 0) m.Const = c.cp[c.U2()];
                        c.p = start + alen;
                    }
                    (k == 0 ? c.Fields : c.Methods).Add(m);
                }
            }
            int nca = c.U2();
            for (int a = 0; a < nca && c.p + 6 <= data.Length; a++)
            {
                string an = c.Utf(c.U2()); int alen = (int)c.U4(); int start = c.p;
                if (an == "SourceFile") c.SourceFile = c.Utf(c.U2());
                c.p = start + alen;
            }
            for (int i = 1; i < n; i++) if (c.tags[i] == 8) c.Strings.Add(c.Utf((int)c.cp[i]));
            return c;
        }

        int U2() { int v = (b[p] << 8) | b[p + 1]; p += 2; return v; }
        uint U4() { uint v = (uint)((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]); p += 4; return v; }

        static string MUtf8(byte[] d, int o, int len)
        {
            StringBuilder sb = new StringBuilder(len);
            int e = Math.Min(d.Length, o + len);
            while (o < e)
            {
                int x = d[o++];
                if (x < 0x80) sb.Append((char)x);
                else if ((x & 0xE0) == 0xC0 && o < e) sb.Append((char)(((x & 0x1F) << 6) | (d[o++] & 0x3F)));
                else if ((x & 0xF0) == 0xE0 && o + 1 < e) { sb.Append((char)(((x & 0x0F) << 12) | ((d[o] & 0x3F) << 6) | (d[o + 1] & 0x3F))); o += 2; }
                else sb.Append('?');
            }
            return sb.ToString();
        }

        string Utf(int i) { return i > 0 && i < cp.Length ? cp[i] as string ?? "?" : "?"; }
        string ClassName(int i) { return i > 0 && i < cp.Length && tags[i] == 7 ? Utf((int)cp[i]) : "?"; }

        string Nat(int i, out string desc)
        {
            desc = "";
            if (i <= 0 || i >= cp.Length || tags[i] != 12) return "?";
            int[] a = (int[])cp[i];
            desc = Utf(a[1]);
            return Utf(a[0]);
        }

        string Const(int i)
        {
            if (i <= 0 || i >= cp.Length) return "#" + i;
            switch (tags[i])
            {
                case 1: return Utf(i);
                case 3: return cp[i].ToString();
                case 4: return ((float)cp[i]).ToString(System.Globalization.CultureInfo.InvariantCulture) + "f";
                case 5: return cp[i] + "L";
                case 6: return ((double)cp[i]).ToString(System.Globalization.CultureInfo.InvariantCulture) + "d";
                case 7: return Dots(ClassName(i)) + ".class";
                case 8: return Quote(Utf((int)cp[i]));
                case 9: case 10: case 11:
                    {
                        int[] a = (int[])cp[i]; string d; string n = Nat(a[1], out d);
                        return Dots(ClassName(a[0])) + "." + n + (tags[i] == 9 ? " : " + Type(d) : Sig(d, n));
                    }
                case 15: { int[] a = (int[])cp[i]; return "MethodHandle " + Const(a[1]); }
                case 16: return "MethodType " + Utf((int)cp[i]);
                case 17: case 18: { int[] a = (int[])cp[i]; string d; string n = Nat(a[1], out d); return (tags[i] == 18 ? "invokedynamic " : "dynamic ") + n + Sig(d, n) + " [bootstrap #" + a[0] + "]"; }
                default: return "#" + i;
            }
        }

        public static string Quote(string s)
        {
            StringBuilder sb = new StringBuilder("\"");
            foreach (char ch in s)
            {
                if (ch == '"') sb.Append("\\\""); else if (ch == '\\') sb.Append("\\\\"); else if (ch == '\n') sb.Append("\\n"); else if (ch == '\r') sb.Append("\\r"); else if (ch == '\t') sb.Append("\\t");
                else if (ch < 0x20) sb.Append("\\u" + ((int)ch).ToString("x4")); else sb.Append(ch);
            }
            return sb.Append('"').ToString();
        }

        static string Dots(string s) { return s.Replace('/', '.'); }

        /// <summary>Тип из дескриптора: I → int, Ljava/lang/String; → String.</summary>
        public static string Type(string d)
        {
            int i = 0; return TypeAt(d, ref i);
        }
        static string TypeAt(string d, ref int i)
        {
            if (i >= d.Length) return "?";
            char c = d[i++];
            switch (c)
            {
                case 'B': return "byte"; case 'C': return "char"; case 'D': return "double"; case 'F': return "float";
                case 'I': return "int"; case 'J': return "long"; case 'S': return "short"; case 'Z': return "boolean"; case 'V': return "void";
                case '[': return TypeAt(d, ref i) + "[]";
                case 'L':
                    {
                        int e = d.IndexOf(';', i); if (e < 0) e = d.Length;
                        string n = d.Substring(i, e - i); i = e + 1;
                        if (n.StartsWith("java/lang/") && n.IndexOf('/', 10) < 0) n = n.Substring(10);
                        return Dots(n);
                    }
                default: return c.ToString();
            }
        }

        static string Sig(string d, string name)
        {
            if (!d.StartsWith("(")) return " " + d;
            int i = 1; List<string> args = new List<string>();
            while (i < d.Length && d[i] != ')') args.Add(TypeAt(d, ref i));
            i++;
            string ret = i < d.Length ? TypeAt(d, ref i) : "void";
            return "(" + string.Join(", ", args) + ") : " + ret;
        }

        static string Mods(int a, bool method)
        {
            List<string> r = new List<string>();
            if ((a & 1) != 0) r.Add("public"); if ((a & 2) != 0) r.Add("private"); if ((a & 4) != 0) r.Add("protected");
            if ((a & 8) != 0) r.Add("static"); if ((a & 0x10) != 0) r.Add("final");
            if (method) { if ((a & 0x20) != 0) r.Add("synchronized"); if ((a & 0x100) != 0) r.Add("native"); if ((a & 0x400) != 0) r.Add("abstract"); }
            else { if ((a & 0x40) != 0) r.Add("volatile"); if ((a & 0x80) != 0) r.Add("transient"); }
            if ((a & 0x1000) != 0) r.Add("/*synthetic*/");
            return r.Count == 0 ? "" : string.Join(" ", r) + " ";
        }

        static readonly string[] op = BuildOps();
        static string[] BuildOps()
        {
            string s = "nop aconst_null iconst_m1 iconst_0 iconst_1 iconst_2 iconst_3 iconst_4 iconst_5 lconst_0 lconst_1 fconst_0 fconst_1 fconst_2 dconst_0 dconst_1 " +
                "bipush sipush ldc ldc_w ldc2_w iload lload fload dload aload iload_0 iload_1 iload_2 iload_3 lload_0 lload_1 lload_2 lload_3 fload_0 fload_1 fload_2 fload_3 " +
                "dload_0 dload_1 dload_2 dload_3 aload_0 aload_1 aload_2 aload_3 iaload laload faload daload aaload baload caload saload istore lstore fstore dstore astore " +
                "istore_0 istore_1 istore_2 istore_3 lstore_0 lstore_1 lstore_2 lstore_3 fstore_0 fstore_1 fstore_2 fstore_3 dstore_0 dstore_1 dstore_2 dstore_3 " +
                "astore_0 astore_1 astore_2 astore_3 iastore lastore fastore dastore aastore bastore castore sastore pop pop2 dup dup_x1 dup_x2 dup2 dup2_x1 dup2_x2 swap " +
                "iadd ladd fadd dadd isub lsub fsub dsub imul lmul fmul dmul idiv ldiv fdiv ddiv irem lrem frem drem ineg lneg fneg dneg ishl lshl ishr lshr iushr lushr " +
                "iand land ior lor ixor lxor iinc i2l i2f i2d l2i l2f l2d f2i f2l f2d d2i d2l d2f i2b i2c i2s lcmp fcmpl fcmpg dcmpl dcmpg ifeq ifne iflt ifge ifgt ifle " +
                "if_icmpeq if_icmpne if_icmplt if_icmpge if_icmpgt if_icmple if_acmpeq if_acmpne goto jsr ret tableswitch lookupswitch ireturn lreturn freturn dreturn areturn return " +
                "getstatic putstatic getfield putfield invokevirtual invokespecial invokestatic invokeinterface invokedynamic new newarray anewarray arraylength athrow " +
                "checkcast instanceof monitorenter monitorexit wide multianewarray ifnull ifnonnull goto_w jsr_w";
            return s.Split(' ');
        }

        static int S2(byte[] c, int i) { return (short)((c[i] << 8) | c[i + 1]); }
        static int U2(byte[] c, int i) { return (c[i] << 8) | c[i + 1]; }
        static int S4(byte[] c, int i) { return (c[i] << 24) | (c[i + 1] << 16) | (c[i + 2] << 8) | c[i + 3]; }

        void Disasm(Member m, StringBuilder sb, string ind)
        {
            byte[] c = m.Code; int i = 0; int lines = 0;
            while (i < c.Length && lines++ < 20000)
            {
                int at = i; int o = c[i++];
                string name = o < op.Length ? op[o] : "op_" + o.ToString("x2");
                string arg = "";
                try
                {
                    if (o == 0x10) arg = ((sbyte)c[i++]).ToString();
                    else if (o == 0x11) { arg = S2(c, i).ToString(); i += 2; }
                    else if (o == 0x12) { arg = Const(c[i++]); }
                    else if (o == 0x13 || o == 0x14 || (o >= 0xb2 && o <= 0xb8) || o == 0xbb || o == 0xbd || o == 0xc0 || o == 0xc1) { arg = Const(U2(c, i)); i += 2; }
                    else if ((o >= 0x15 && o <= 0x19) || (o >= 0x36 && o <= 0x3a) || o == 0xa9) arg = c[i++].ToString();
                    else if (o == 0x84) { arg = c[i] + " " + (sbyte)c[i + 1]; i += 2; }
                    else if ((o >= 0x99 && o <= 0xa8) || o == 0xc6 || o == 0xc7) { arg = "→ " + (at + S2(c, i)); i += 2; }
                    else if (o == 0xc8 || o == 0xc9) { arg = "→ " + (at + S4(c, i)); i += 4; }
                    else if (o == 0xb9) { arg = Const(U2(c, i)); i += 4; }
                    else if (o == 0xba) { arg = Const(U2(c, i)); i += 4; }
                    else if (o == 0xbc) { string[] t = { "", "", "", "", "boolean", "char", "float", "double", "byte", "short", "int", "long" }; int ty = c[i++]; arg = ty < t.Length ? t[ty] : ty.ToString(); }
                    else if (o == 0xc5) { arg = Const(U2(c, i)) + " dim " + c[i + 2]; i += 3; }
                    else if (o == 0xc4) { int w = c[i++]; name = "wide " + (w < op.Length ? op[w] : "?"); arg = U2(c, i).ToString(); i += 2; if (w == 0x84) { arg += " " + S2(c, i); i += 2; } }
                    else if (o == 0xaa)
                    {
                        i = (i + 3) & ~3; int def = S4(c, i), lo = S4(c, i + 4), hi = S4(c, i + 8); i += 12;
                        StringBuilder a = new StringBuilder("{ default → " + (at + def));
                        for (long k = lo; k <= hi && k - lo < 1000; k++) { a.Append(", " + k + " → " + (at + S4(c, i))); i += 4; }
                        arg = a.Append(" }").ToString();
                    }
                    else if (o == 0xab)
                    {
                        i = (i + 3) & ~3; int def = S4(c, i), np = S4(c, i + 4); i += 8;
                        StringBuilder a = new StringBuilder("{ default → " + (at + def));
                        for (int k = 0; k < np && k < 1000; k++) { a.Append(", " + S4(c, i) + " → " + (at + S4(c, i + 4))); i += 8; }
                        arg = a.Append(" }").ToString();
                    }
                }
                catch { sb.AppendLine(ind + at.ToString().PadLeft(5) + ": (обрезано)"); return; }
                sb.Append(ind).Append(at.ToString().PadLeft(5)).Append(": ").Append(name);
                if (arg.Length > 0) sb.Append(' ', Math.Max(1, 16 - name.Length)).Append(arg);
                sb.AppendLine();
            }
        }

        /// <summary>Java-подобный текст: объявления + байткод методов.</summary>
        public string ToText()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("// " + Dots(Name) + "   (class " + Major + "." + Minor + JavaVer() + (SourceFile != null ? ", исходник " + SourceFile : "") + ")");
            if (Strings.Count > 0)
            {
                sb.AppendLine("// СТРОКИ В КЛАССЕ (" + Strings.Count + "):");
                foreach (string s in Strings.Take(400)) sb.AppendLine("//   " + Quote(s.Length > 300 ? s.Substring(0, 300) + "…" : s));
            }
            sb.AppendLine();
            string pkg = Name.Contains("/") ? Dots(Name.Substring(0, Name.LastIndexOf('/'))) : null;
            if (pkg != null) sb.AppendLine("package " + pkg + ";").AppendLine();
            string kind = (Access & 0x2000) != 0 ? "@interface" : (Access & 0x200) != 0 ? "interface" : (Access & 0x4000) != 0 ? "enum" : "class";
            sb.Append(Mods(Access & ~0x20 & ~(kind == "class" ? 0 : 0x400), false)).Append(kind).Append(' ').Append(Dots(Name.Substring(Name.LastIndexOf('/') + 1)));
            if (Super != null && Super != "java/lang/Object" && kind == "class") sb.Append(" extends ").Append(Dots(Super));
            if (Interfaces.Count > 0) sb.Append(kind == "interface" ? " extends " : " implements ").Append(string.Join(", ", Interfaces.Select(Dots)));
            sb.AppendLine(" {");
            foreach (Member f in Fields)
            {
                sb.Append("    ").Append(Mods(f.Access, false)).Append(Type(f.Desc)).Append(' ').Append(f.Name);
                if (f.Const != null) sb.Append(" = ").Append(f.Const is string ? Quote((string)f.Const) : f.Const is int && tags.Length > 0 ? f.Const.ToString() : f.Const.ToString());
                sb.AppendLine(";");
            }
            if (Fields.Count > 0) sb.AppendLine();
            foreach (Member m in Methods)
            {
                string sig = Sig(m.Desc, m.Name);
                int colon = sig.LastIndexOf(" : ");
                string args = colon > 0 ? sig.Substring(0, colon) : sig, ret = colon > 0 ? sig.Substring(colon + 3) : "";
                string nm = m.Name == "<init>" ? Dots(Name.Substring(Name.LastIndexOf('/') + 1)) : m.Name == "<clinit>" ? "static" : m.Name;
                sb.Append("    ").Append(Mods(m.Access, true));
                if (m.Name == "<clinit>") sb.Append("{ // статический блок");
                else sb.Append(m.Name == "<init>" ? "" : ret + " ").Append(nm).Append(args).Append(m.Code == null ? ";" : " {");
                sb.AppendLine();
                if (m.Code != null)
                {
                    Disasm(m, sb, "        ");
                    sb.AppendLine("    }");
                }
                sb.AppendLine();
            }
            sb.AppendLine("}");
            return sb.ToString();
        }

        string JavaVer() { return Major >= 45 ? ", Java " + (Major >= 49 ? (Major - 44).ToString() : "1." + (Major - 44)) : ""; }
    }
}
