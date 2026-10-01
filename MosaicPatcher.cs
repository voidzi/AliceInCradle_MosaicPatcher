// MosaicPatcher —— C# / .NET Framework 4.8 单文件版
// 功能与 Python 版完全一致：
//   自动搜索 Assembly-CSharp.dll -> 定位 nel.MosaicShower::FnDrawMosaic
//   -> 把方法末尾的 return true (ldc.i4.1) 改成 return false (ldc.i4.0)
//   自动备份 / 手动还原 / 配置文件 / MD5 校验
// 特点：真·单文件，不自解压，不依赖 Python，只依赖系统自带 .NET Framework 4.8
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace MosaicPatcher
{
    public class PatchException : Exception
    {
        public PatchException(string msg) : base(msg) { }
    }

    // =====================================================================
    // 自动搜索
    // =====================================================================
    internal class Candidate
    {
        public string Path;
        public string Rel;
        public string Source;
    }

    internal static class Finder
    {
        public const string GameSubPath = @"AliceInCradle_Data\Managed\Assembly-CSharp.dll";

        private static readonly string[] SkipDirs = new string[] {
            "$recycle.bin", "system volume information", "__pycache__", ".git",
            "node_modules", "$windows.~bt", "$windows.~ws"
        };

        public static string ProgramDir()
        {
            return Path.GetDirectoryName(Application.ExecutablePath);
        }

        public static bool IsGameDllPath(string path)
        {
            string[] parts = Path.GetFullPath(path).TrimEnd('\\').Split('\\');
            if (parts.Length < 3) return false;
            return parts[parts.Length - 1].ToLowerInvariant() == "assembly-csharp.dll"
                && parts[parts.Length - 2].ToLowerInvariant() == "managed"
                && parts[parts.Length - 3].ToLowerInvariant() == "aliceincradle_data";
        }

        public static List<Candidate> Find(string baseDir)
        {
            List<Candidate> found = new List<Candidate>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            baseDir = Path.GetFullPath(baseDir);

            AddCandidate(found, seen, baseDir, baseDir, "程序目录");
            DirectoryInfo parent = Directory.GetParent(baseDir);
            if (parent != null && !string.Equals(parent.FullName, baseDir, StringComparison.OrdinalIgnoreCase))
                AddCandidate(found, seen, parent.FullName, baseDir, "上一级目录");
            Walk(baseDir, baseDir, found, seen);
            return found;
        }

        private static void Walk(string dir, string baseDir, List<Candidate> found, HashSet<string> seen)
        {
            string[] subs;
            try { subs = Directory.GetDirectories(dir); }
            catch { return; }
            foreach (string sub in subs)
            {
                string name = Path.GetFileName(sub);
                if (IsSkipName(name)) continue;
                try
                {
                    FileAttributes at = File.GetAttributes(sub);
                    if ((at & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { continue; }

                if (name.ToLowerInvariant() == "aliceincradle_data")
                {
                    AddCandidate(found, seen, dir, baseDir, "子目录");
                    continue;
                }
                Walk(sub, baseDir, found, seen);
            }
        }

        private static bool IsSkipName(string name)
        {
            string n = name.ToLowerInvariant();
            foreach (string s in SkipDirs) if (s == n) return true;
            return false;
        }

        private static void AddCandidate(List<Candidate> found, HashSet<string> seen,
                                         string gameRoot, string baseDir, string source)
        {
            string cand = Path.Combine(gameRoot, GameSubPath);
            if (!File.Exists(cand)) return;
            if (!IsGameDllPath(cand)) return;
            string full = Path.GetFullPath(cand);
            if (!seen.Add(full)) return;
            Candidate c = new Candidate();
            c.Path = full;
            c.Rel = MakeRelative(baseDir, full);
            c.Source = source;
            found.Add(c);
        }

        public static string MakeRelative(string fromDir, string toPath)
        {
            try
            {
                Uri u1 = new Uri(AppendSlash(Path.GetFullPath(fromDir)));
                Uri u2 = new Uri(Path.GetFullPath(toPath));
                string rel = Uri.UnescapeDataString(u1.MakeRelativeUri(u2).ToString());
                return rel.Replace('/', '\\');
            }
            catch
            {
                return Path.GetFullPath(toPath);
            }
        }

        private static string AppendSlash(string p)
        {
            if (p.EndsWith("\\")) return p;
            return p + "\\";
        }
    }

    // =====================================================================
    // PE / .NET 元数据解析
    // =====================================================================
    internal class PESection
    {
        public string Name;
        public uint VA, VSize, RawPtr, RawSize;
    }

    internal class PEFile
    {
        public byte[] D;
        public List<PESection> Sections = new List<PESection>();
        public uint MdRva, MdSize;

        public ushort U16(int o) { return (ushort)(D[o] | (D[o + 1] << 8)); }
        public uint U32(int o)
        {
            return (uint)(D[o] | (D[o + 1] << 8) | (D[o + 2] << 16) | (D[o + 3] << 24));
        }

        public PEFile(byte[] data)
        {
            D = data;
            if (data.Length < 0x40 || data[0] != (byte)'M' || data[1] != (byte)'Z')
                throw new PatchException("不是有效的 PE 文件（缺少 MZ 头）");
            int pe = (int)U32(0x3C);
            if (pe + 24 > data.Length || D[pe] != (byte)'P' || D[pe + 1] != (byte)'E'
                || D[pe + 2] != 0 || D[pe + 3] != 0)
                throw new PatchException("不是有效的 PE 文件（缺少 PE 签名）");

            int coff = pe + 4;
            int numSec = U16(coff + 2);
            int sizeOpt = U16(coff + 16);
            int opt = coff + 20;
            if (opt + 2 > data.Length) throw new PatchException("PE 头不完整");
            int magic = U16(opt);
            if (magic != 0x10B && magic != 0x20B) throw new PatchException("未知的 PE 可选头");

            int dd = opt + (magic == 0x20B ? 112 : 96);
            if (dd + 15 * 8 > data.Length) throw new PatchException("PE 数据目录不完整");

            for (int i = 0; i < numSec; i++)
            {
                int o = opt + sizeOpt + 40 * i;
                if (o + 40 > data.Length) throw new PatchException("节区表不完整");
                PESection s = new PESection();
                s.Name = Encoding.ASCII.GetString(D, o, 8).TrimEnd('\0');
                s.VSize = U32(o + 8);
                s.VA = U32(o + 12);
                s.RawSize = U32(o + 16);
                s.RawPtr = U32(o + 20);
                Sections.Add(s);
            }

            uint cliRva = U32(dd + 14 * 8);
            if (cliRva == 0) throw new PatchException("不是托管程序集（没有 CLI 头），可能不是 .NET DLL");
            int cli = RvaToOff(cliRva);
            MdRva = U32(cli + 8);
            MdSize = U32(cli + 12);
            if (MdRva == 0) throw new PatchException("程序集没有元数据");
        }

        public int RvaToOff(uint rva)
        {
            foreach (PESection s in Sections)
            {
                uint size = Math.Max(s.VSize, s.RawSize);
                if (rva >= s.VA && rva < s.VA + size)
                    return (int)(rva - s.VA + s.RawPtr);
            }
            throw new PatchException("RVA 0x" + rva.ToString("X") + " 不在任何节区内");
        }
    }

    internal class Metadata
    {
        private byte[] D;
        private PEFile PE;

        public Dictionary<string, int[]> Streams = new Dictionary<string, int[]>();
        public Dictionary<int, int> RowCount = new Dictionary<int, int>();
        public Dictionary<int, int[]> Tables = new Dictionary<int, int[]>();

        private int StrSize, GuidSize, BlobSize;

        private class CodedDef
        {
            public int[] Tables;
            public int Bits;
            public CodedDef(int[] t, int b) { Tables = t; Bits = b; }
        }

        private static readonly Dictionary<string, CodedDef> Coded = BuildCoded();

        private static Dictionary<string, CodedDef> BuildCoded()
        {
            Dictionary<string, CodedDef> d = new Dictionary<string, CodedDef>();
            d["TypeDefOrRef"] = new CodedDef(new int[] { 0x02, 0x01, 0x1B }, 2);
            d["HasConstant"] = new CodedDef(new int[] { 0x04, 0x08, 0x17 }, 2);
            d["HasCustomAttribute"] = new CodedDef(new int[] { 0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00,
                0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B }, 5);
            d["HasFieldMarshal"] = new CodedDef(new int[] { 0x04, 0x08 }, 1);
            d["HasDeclSecurity"] = new CodedDef(new int[] { 0x02, 0x06, 0x20 }, 2);
            d["MemberRefParent"] = new CodedDef(new int[] { 0x02, 0x01, 0x1A, 0x06, 0x1B }, 3);
            d["HasSemantics"] = new CodedDef(new int[] { 0x14, 0x17 }, 1);
            d["MethodDefOrRef"] = new CodedDef(new int[] { 0x06, 0x0A }, 1);
            d["MemberForwarded"] = new CodedDef(new int[] { 0x04, 0x06 }, 1);
            d["Implementation"] = new CodedDef(new int[] { 0x26, 0x23, 0x27 }, 2);
            d["CustomAttributeType"] = new CodedDef(new int[] { 0xFF, 0xFF, 0x06, 0x0A, 0xFF }, 3);
            d["ResolutionScope"] = new CodedDef(new int[] { 0x00, 0x1A, 0x23, 0x01 }, 2);
            d["TypeOrMethodDef"] = new CodedDef(new int[] { 0x02, 0x06 }, 1);
            return d;
        }

        private uint U32(int o) { return PE.U32(o); }
        private ushort U16(int o) { return PE.U16(o); }

        public Metadata(PEFile pe)
        {
            PE = pe;
            D = pe.D;
            int off = pe.RvaToOff(pe.MdRva);
            if (U32(off) != 0x424A5342) throw new PatchException("元数据签名错误（不是合法的 .NET 元数据）");
            int verLen = (int)U32(off + 12);
            int p = off + 16 + verLen;
            if (p + 4 > D.Length) throw new PatchException("元数据头不完整");
            int nstreams = U16(p + 2);
            p += 4;
            for (int i = 0; i < nstreams; i++)
            {
                if (p + 8 > D.Length) throw new PatchException("流头不完整");
                int sOff = (int)U32(p);
                int sSize = (int)U32(p + 4);
                int end = p + 8;
                while (end < D.Length && D[end] != 0) end++;
                string name = Encoding.ASCII.GetString(D, p + 8, end - (p + 8));
                Streams[name] = new int[] { off + sOff, sSize };
                p = end + 1;
                p = (p + 3) & ~3;
            }

            int[] tabs = null;
            if (Streams.ContainsKey("#~")) tabs = Streams["#~"];
            else if (Streams.ContainsKey("#-")) tabs = Streams["#-"];
            if (tabs == null) throw new PatchException("找不到 #~ 表流");

            int o2 = tabs[0];
            int heap = D[o2 + 6];
            ulong valid = 0;
            for (int i = 0; i < 8; i++) valid |= ((ulong)D[o2 + 8 + i]) << (8 * i);
            p = o2 + 24;
            for (int t = 0; t < 64; t++)
            {
                if (((valid >> t) & 1) == 0) continue;
                RowCount[t] = (int)U32(p);
                p += 4;
            }

            StrSize = (heap & 1) != 0 ? 4 : 2;
            GuidSize = (heap & 2) != 0 ? 4 : 2;
            BlobSize = (heap & 4) != 0 ? 4 : 2;

            for (int t = 0; t < 64; t++)
            {
                if (!RowCount.ContainsKey(t)) continue;
                if (t > 6) break;
                int rs = RowSize(t);
                Tables[t] = new int[] { p, RowCount[t], rs };
                p += rs * RowCount[t];
            }
        }

        private int IdxSize(int tableId)
        {
            int n = RowCount.ContainsKey(tableId) ? RowCount[tableId] : 0;
            return n >= 0x10000 ? 4 : 2;
        }

        private int CodedSize(string name)
        {
            CodedDef cd = Coded[name];
            int mx = 0;
            foreach (int t in cd.Tables)
            {
                if (t == 0xFF) continue;
                int n = RowCount.ContainsKey(t) ? RowCount[t] : 0;
                if (n > mx) mx = n;
            }
            return mx >= (1 << (16 - cd.Bits)) ? 4 : 2;
        }

        private int RowSize(int tableId)
        {
            switch (tableId)
            {
                case 0x00: return 2 + StrSize + GuidSize * 3;                        // Module
                case 0x01: return CodedSize("ResolutionScope") + StrSize * 2;        // TypeRef
                case 0x02: return 4 + StrSize * 2 + CodedSize("TypeDefOrRef")
                                  + IdxSize(0x04) + IdxSize(0x06);                   // TypeDef
                case 0x03: return IdxSize(0x04);                                     // FieldPtr
                case 0x04: return 2 + StrSize + BlobSize;                            // Field
                case 0x05: return IdxSize(0x06);                                     // MethodPtr
                case 0x06: return 4 + 2 + 2 + StrSize + BlobSize + IdxSize(0x08);    // MethodDef
                default: throw new PatchException("不支持的表 0x" + tableId.ToString("X"));
            }
        }

        private int ReadIdx(int o, int size)
        {
            return size == 4 ? (int)U32(o) : (int)U16(o);
        }

        public string GetString(int index)
        {
            int b = Streams["#Strings"][0];
            int end = b + index;
            while (end < D.Length && D[end] != 0) end++;
            return Encoding.UTF8.GetString(D, b + index, end - (b + index));
        }

        // TypeDef -> {nameIdx, nsIdx, fieldList, methodList}
        public List<int[]> ReadTypeDefs()
        {
            List<int[]> list = new List<int[]>();
            if (!Tables.ContainsKey(0x02)) return list;
            int[] tb = Tables[0x02];
            int rs = tb[2];
            int extSize = CodedSize("TypeDefOrRef");
            int fieldSize = IdxSize(0x04);
            int methodSize = IdxSize(0x06);
            for (int i = 0; i < tb[1]; i++)
            {
                int q = tb[0] + i * rs;
                q += 4;                                        // Flags
                int name = ReadIdx(q, StrSize); q += StrSize;
                int ns = ReadIdx(q, StrSize); q += StrSize;
                q += extSize;                                  // Extends
                int fl = ReadIdx(q, fieldSize); q += fieldSize;
                int ml = ReadIdx(q, methodSize);
                list.Add(new int[] { name, ns, fl, ml });
            }
            return list;
        }

        // MethodDef -> {rva, nameIdx}
        public List<int[]> ReadMethodDefs()
        {
            List<int[]> list = new List<int[]>();
            if (!Tables.ContainsKey(0x06)) return list;
            int[] tb = Tables[0x06];
            int rs = tb[2];
            int paramSize = IdxSize(0x08);
            for (int i = 0; i < tb[1]; i++)
            {
                int q = tb[0] + i * rs;
                uint rva = U32(q); q += 4 + 2 + 2;              // RVA + ImplFlags + Flags
                int name = ReadIdx(q, StrSize); q += StrSize;
                q += BlobSize;                                  // Signature
                q += paramSize;                                 // ParamList
                list.Add(new int[] { (int)rva, name });
            }
            return list;
        }

        // MethodPtr -> methodDefIndex（编辑并继续的元数据才会有）
        public List<int> ReadMethodPtrs()
        {
            List<int> list = new List<int>();
            if (!Tables.ContainsKey(0x05)) return list;
            int[] tb = Tables[0x05];
            int size = IdxSize(0x06);
            for (int i = 0; i < tb[1]; i++)
                list.Add(ReadIdx(tb[0] + i * tb[2], size));
            return list;
        }
    }

    // =====================================================================
    // IL 指令长度表 + 定位/打补丁
    // =====================================================================
    internal class LocateInfo
    {
        public uint MethodRva;
        public int CodeFileOffset;
        public int IlOffset;
        public int FileOffset;
        public int CodeSize;
        public int InstrCount;
        public string State;      // original / patched
    }

    internal static class Patcher
    {
        public const string TargetNamespace = "nel";
        public const string TargetType = "MosaicShower";
        public const string TargetMethod = "FnDrawMosaic";

        private const int Ldc_I4_1 = 0x17;
        private const int Ldc_I4_0 = 0x16;
        private const int Ret = 0x2A;

        private static readonly int[] Op1 = BuildOp1();
        private static readonly Dictionary<int, int> Op2 = BuildOp2();

        private static int[] BuildOp1()
        {
            int[] t = new int[256];
            for (int i = 0; i < 256; i++) t[i] = -1;                 // -1 = 未知
            for (int op = 0x00; op < 0x10; op++) t[op] = 0;
            t[0x0E] = 1; t[0x0F] = 1; t[0x10] = 1; t[0x11] = 1; t[0x12] = 1; t[0x13] = 1;
            t[0x14] = 0; t[0x15] = 0;
            for (int op = 0x16; op < 0x1F; op++) t[op] = 0;
            t[0x1F] = 1; t[0x20] = 4; t[0x21] = 8; t[0x22] = 4; t[0x23] = 8;
            t[0x25] = 0; t[0x26] = 0; t[0x27] = 4; t[0x28] = 4; t[0x29] = 4; t[0x2A] = 0;
            for (int op = 0x2B; op <= 0x37; op++) t[op] = 1;
            for (int op = 0x38; op <= 0x44; op++) t[op] = 4;
            t[0x45] = -2;                                            // switch 特殊处理
            for (int op = 0x46; op <= 0x6E; op++) t[op] = 0;
            t[0x6F] = 4;
            t[0x70] = 4; t[0x71] = 4; t[0x72] = 4; t[0x73] = 4; t[0x74] = 4; t[0x75] = 4;
            t[0x76] = 0; t[0x79] = 4; t[0x7A] = 0;
            t[0x7B] = 4; t[0x7C] = 4; t[0x7D] = 4; t[0x7E] = 4; t[0x7F] = 4; t[0x80] = 4; t[0x81] = 4;
            for (int op = 0x82; op <= 0x8B; op++) t[op] = 0;
            t[0x8C] = 4; t[0x8D] = 4; t[0x8E] = 0; t[0x8F] = 4;
            for (int op = 0x90; op <= 0xA2; op++) t[op] = 0;
            t[0xA3] = 4; t[0xA4] = 4; t[0xA5] = 4;
            for (int op = 0xB3; op <= 0xBA; op++) t[op] = 0;
            t[0xC2] = 4; t[0xC3] = 0; t[0xC6] = 4; t[0xD0] = 4;
            for (int op = 0xD1; op <= 0xDC; op++) t[op] = 0;
            t[0xDD] = 4; t[0xDE] = 1; t[0xDF] = 0; t[0xE0] = 0;
            return t;
        }

        private static Dictionary<int, int> BuildOp2()
        {
            Dictionary<int, int> d = new Dictionary<int, int>();
            d[0x00] = 0; d[0x01] = 0; d[0x02] = 0; d[0x03] = 0; d[0x04] = 0; d[0x05] = 0;
            d[0x06] = 4; d[0x07] = 4; d[0x09] = 2; d[0x0A] = 2; d[0x0B] = 2; d[0x0C] = 2;
            d[0x0D] = 2; d[0x0E] = 2; d[0x0F] = 0; d[0x11] = 0; d[0x12] = 1; d[0x13] = 0;
            d[0x14] = 0; d[0x15] = 4; d[0x16] = 4; d[0x17] = 0; d[0x18] = 0; d[0x19] = 1;
            d[0x1A] = 0; d[0x1C] = 4; d[0x1D] = 0; d[0x1E] = 0;
            return d;
        }

        private static List<int[]> DecodeIl(byte[] code)
        {
            List<int[]> outList = new List<int[]>();
            int i = 0, n = code.Length;
            while (i < n)
            {
                int start = i;
                int op = code[i];
                int len;
                if (op == 0xFE)
                {
                    if (i + 1 >= n) throw new PatchException("IL 解析失败：截断的 0xFE 前缀");
                    int op2 = code[i + 1];
                    if (!Op2.ContainsKey(op2)) throw new PatchException("IL 解析失败：未知指令 0xFE" + op2.ToString("X2"));
                    i += 2;
                    len = Op2[op2];
                    outList.Add(new int[] { start, 0xFE00 | op2 });
                }
                else
                {
                    if (Op1[op] == -1) throw new PatchException("IL 解析失败：未知指令 0x" + op.ToString("X2") + " @ IL_" + start.ToString("X4"));
                    i += 1;
                    len = Op1[op];
                    outList.Add(new int[] { start, op });
                }
                if (len == -2)
                {
                    if (i + 4 > n) throw new PatchException("IL 解析失败：switch 越界");
                    int cnt = (int)(code[i] | (code[i + 1] << 8) | (code[i + 2] << 16) | (code[i + 3] << 24));
                    i += 4 + 4 * cnt;
                }
                else
                {
                    i += len;
                }
                if (i > n) throw new PatchException("IL 解析失败：指令越过方法体末尾");
            }
            return outList;
        }

        public static LocateInfo Locate(byte[] data)
        {
            PEFile pe = new PEFile(data);
            Metadata md = new Metadata(pe);

            List<int[]> typedefs = md.ReadTypeDefs();
            List<int[]> methoddefs = md.ReadMethodDefs();
            if (typedefs.Count == 0 || methoddefs.Count == 0)
                throw new PatchException("元数据里没有 TypeDef / MethodDef 表");
            List<int> methodPtrs = md.ReadMethodPtrs();

            int ti = -1, methodListStart = 0;
            for (int i = 0; i < typedefs.Count; i++)
            {
                string ns = md.GetString(typedefs[i][1]);
                string nm = md.GetString(typedefs[i][0]);
                if (ns == TargetNamespace && nm == TargetType)
                {
                    ti = i;
                    methodListStart = typedefs[i][3];
                    break;
                }
            }
            if (ti < 0)
                throw new PatchException("没有找到类型 " + TargetNamespace + "." + TargetType + "（可能不是这个游戏版本的 DLL）");

            int end = (ti + 1 < typedefs.Count) ? typedefs[ti + 1][3] : methoddefs.Count + 1;
            if (methodListStart < 1 || end > methoddefs.Count + 1)
                throw new PatchException("MethodList 范围异常，元数据可能已损坏");

            int foundRva = 0;
            bool found = false;
            for (int row = methodListStart; row < end; row++)
            {
                int midx = row;
                if (methodPtrs.Count > 0)
                {
                    if (row - 1 >= methodPtrs.Count) break;
                    midx = methodPtrs[row - 1];
                }
                if (midx - 1 < 0 || midx - 1 >= methoddefs.Count) continue;
                if (md.GetString(methoddefs[midx - 1][1]) == TargetMethod)
                {
                    foundRva = methoddefs[midx - 1][0];
                    found = true;
                    break;
                }
            }
            if (!found) throw new PatchException("类型找到了，但里面没有方法 " + TargetMethod);
            if (foundRva == 0) throw new PatchException("方法 " + TargetMethod + " 没有方法体（RVA=0）");

            int bodyOff = pe.RvaToOff((uint)foundRva);
            int hdr = data[bodyOff];
            int codeSize, codeOff;
            if ((hdr & 3) == 2)
            {
                codeSize = hdr >> 2;
                codeOff = bodyOff + 1;
            }
            else if ((hdr & 3) == 3)
            {
                int flags = pe.U16(bodyOff);
                int headerSize = (flags >> 12) * 4;
                if (headerSize < 12) throw new PatchException("方法体 fat 头长度异常");
                codeSize = (int)pe.U32(bodyOff + 4);
                codeOff = bodyOff + headerSize;
            }
            else
            {
                throw new PatchException("方法体头格式无效（0x" + hdr.ToString("X2") + "）");
            }
            if (codeOff + codeSize > data.Length) throw new PatchException("方法体超出文件范围");

            byte[] code = new byte[codeSize];
            Buffer.BlockCopy(data, codeOff, code, 0, codeSize);
            List<int[]> instrs = DecodeIl(code);
            if (instrs.Count < 2) throw new PatchException("方法体太短，无法识别末尾的 return");

            int[] last = instrs[instrs.Count - 1];
            int[] prev = instrs[instrs.Count - 2];
            if (last[1] != Ret)
                throw new PatchException("方法末尾不是 ret（0x" + last[1].ToString("X2") + "），未做任何修改");

            LocateInfo info = new LocateInfo();
            info.MethodRva = (uint)foundRva;
            info.CodeFileOffset = codeOff;
            info.CodeSize = codeSize;
            info.InstrCount = instrs.Count;
            info.IlOffset = prev[0];
            info.FileOffset = codeOff + prev[0];
            if (prev[1] == Ldc_I4_1) info.State = "original";
            else if (prev[1] == Ldc_I4_0) info.State = "patched";
            else throw new PatchException("方法末尾的 return 前不是 ldc.i4.1 / ldc.i4.0，而是 0x"
                                          + prev[1].ToString("X2") + "，为安全起见未做修改");
            return info;
        }

        public static LocateInfo Analyze(string path)
        {
            byte[] data = File.ReadAllBytes(path);
            return Locate(data);
        }
    }

    // =====================================================================
    // MD5 / 配置 / 备份
    // =====================================================================
    internal static class Util
    {
        public static string Md5File(string path)
        {
            using (MD5 md5 = MD5.Create())
            using (FileStream fs = File.OpenRead(path))
            {
                return ToHex(md5.ComputeHash(fs));
            }
        }

        public static string Md5Bytes(byte[] data)
        {
            using (MD5 md5 = MD5.Create())
            {
                return ToHex(md5.ComputeHash(data));
            }
        }

        private static string ToHex(byte[] h)
        {
            StringBuilder sb = new StringBuilder(h.Length * 2);
            foreach (byte b in h) sb.Append(b.ToString("X2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        public static string Now()
        {
            return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        }
    }

    internal class Config
    {
        public string backup_file = "";
        public bool backup_created;
        public string backup_md5 = "";
        public string original_md5 = "";
        public string patched_md5 = "";
        public string target_file = "";
        public string target_dir = "";
        public string state = "";
        public string updated_at = "";

        public const string Name = "mosaic_patcher.json";

        public static string PathFor(string target)
        {
            return Path.Combine(Path.GetDirectoryName(Path.GetFullPath(target)), Name);
        }

        public static Config Load(string path)
        {
            if (!File.Exists(path)) return null;
            string text;
            try { text = File.ReadAllText(path, Encoding.UTF8); }
            catch { return new Config(); }
            Config c = new Config();
            MatchCollection ms = Regex.Matches(text, "\"([A-Za-z0-9_]+)\"\\s*:\\s*(?:\"([^\"]*)\"|(true|false))");
            foreach (Match m in ms)
            {
                string k = m.Groups[1].Value;
                string v = m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
                switch (k)
                {
                    case "backup_file": c.backup_file = v; break;
                    case "backup_created": c.backup_created = (v == "true"); break;
                    case "backup_md5": c.backup_md5 = v; break;
                    case "original_md5": c.original_md5 = v; break;
                    case "patched_md5": c.patched_md5 = v; break;
                    case "target_file": c.target_file = v; break;
                    case "target_dir": c.target_dir = v; break;
                    case "state": c.state = v; break;
                    case "updated_at": c.updated_at = v; break;
                }
            }
            return c;
        }

        public void Save(string path)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \"app\": \"MosaicPatcher\",");
            sb.AppendLine("  \"version\": \"1.1\",");
            sb.AppendLine("  \"target_file\": \"" + Esc(target_file) + "\",");
            sb.AppendLine("  \"target_dir\": \"" + Esc(target_dir) + "\",");
            sb.AppendLine("  \"backup_file\": \"" + Esc(backup_file) + "\",");
            sb.AppendLine("  \"backup_created\": " + (backup_created ? "true" : "false") + ",");
            sb.AppendLine("  \"backup_md5\": \"" + Esc(backup_md5) + "\",");
            sb.AppendLine("  \"original_md5\": \"" + Esc(original_md5) + "\",");
            sb.AppendLine("  \"patched_md5\": \"" + Esc(patched_md5) + "\",");
            sb.AppendLine("  \"state\": \"" + Esc(state) + "\",");
            sb.AppendLine("  \"updated_at\": \"" + Esc(updated_at) + "\"");
            sb.AppendLine("}");
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, sb.ToString(), new UTF8Encoding(false));
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }

        private static string Esc(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }

    internal class Status
    {
        public string Target, Dir, Name, ConfigPath, BackupPath, RelPath, Md5;
        public bool Exists, PathOk, BackupExists, TargetOk, Patched;
        public bool CfgExists;
        public long FileSize, BackupSize;
        public string BackupMd5, BackupRecordedMd5, TargetError;
        public bool BackupIntact, BackupIntactKnown;
        public uint MethodRva;
        public int IlOffset, FileOffset;
        public string StateText, IntegrityText;
        public Config Cfg;
    }

    internal static class Workspace
    {
        public const string BackupSuffix = ".mosaicpatch.bak";

        public static string BackupPathFor(string target) { return target + BackupSuffix; }

        // 只读属性自动清除
        public static void ClearReadOnly(string target)
        {
            try
            {
                FileAttributes at = File.GetAttributes(target);
                if ((at & FileAttributes.ReadOnly) != 0)
                    File.SetAttributes(target, at & ~FileAttributes.ReadOnly);
            }
            catch { }
        }

        /// <summary>
        /// 把 content 写进 target。
        /// 先用常规方式覆盖；若目标被其它进程持有（写被拒绝/共享冲突），
        /// 退化为"把旧文件改名移开 + 把新文件挪到位"（资源管理器的"替换"就是这个原理，
        /// 因为删除/重命名通常仍然被允许），失败会自动回滚。
        /// 返回给用户看的说明（正常为空字符串）。
        /// </summary>
        public static string WriteFileSmart(string target, byte[] content)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(target));
            string name = Path.GetFileName(target);
            string tmp = Path.Combine(dir, name + ".mosaicpatch.new");
            File.WriteAllBytes(tmp, content);

            // 方式1：常规覆盖
            Exception first = null;
            try
            {
                File.Copy(tmp, target, true);
                try { File.Delete(tmp); } catch { }
                return "";
            }
            catch (UnauthorizedAccessException ex) { first = ex; }
            catch (IOException ex) { first = ex; }

            // 方式2：改名换位（旧文件被占用也能成功）
            string old = Path.Combine(dir, name + ".mosaicpatch.old");
            try { if (File.Exists(old)) File.Delete(old); } catch { }
            bool moved = false;
            try
            {
                File.Move(target, old);          // 删除/改名通常允许
                moved = true;
                File.Move(tmp, target);          // 新文件就位
                try { File.Delete(old); } catch { }
                return "（目标文件正被其它程序占用，已改用「替换」方式写入成功）";
            }
            catch (Exception ex2)
            {
                if (moved) { try { File.Move(old, target); } catch { } }   // 回滚
                try { File.Delete(tmp); } catch { }
                throw new PatchException("无法写入该文件。\r\n"
                    + "常规覆盖失败：" + first.Message + "\r\n"
                    + "替换方式也失败：" + ex2.Message + "\r\n"
                    + "（若游戏正在运行，请先完全退出；必要时结束残留的 UnityCrashHandler64 进程）");
            }
        }

        public static Status BuildStatus(string target)
        {
            Status st = new Status();
            st.Target = Path.GetFullPath(target);
            st.Dir = Path.GetDirectoryName(st.Target);
            st.Name = Path.GetFileName(st.Target);
            st.ConfigPath = Config.PathFor(st.Target);
            st.BackupPath = BackupPathFor(st.Target);
            st.Exists = File.Exists(st.Target);
            if (!st.Exists) throw new PatchException("文件不存在：" + target);

            st.RelPath = Finder.MakeRelative(Finder.ProgramDir(), st.Target);
            st.PathOk = Finder.IsGameDllPath(st.Target);
            FileInfo fi = new FileInfo(st.Target);
            st.FileSize = fi.Length;
            st.Md5 = Util.Md5File(st.Target);

            st.CfgExists = File.Exists(st.ConfigPath);
            st.Cfg = st.CfgExists ? Config.Load(st.ConfigPath) : null;
            st.BackupExists = File.Exists(st.BackupPath);
            if (st.BackupExists)
            {
                st.BackupSize = new FileInfo(st.BackupPath).Length;
                st.BackupMd5 = Util.Md5File(st.BackupPath);
            }

            try
            {
                byte[] data = File.ReadAllBytes(st.Target);
                LocateInfo info = Patcher.Locate(data);
                st.TargetOk = true;
                st.MethodRva = info.MethodRva;
                st.IlOffset = info.IlOffset;
                st.FileOffset = info.FileOffset;
                st.Patched = (info.State == "patched");
            }
            catch (PatchException e)
            {
                st.TargetOk = false;
                st.TargetError = e.Message;
            }

            string recorded = (st.Cfg != null) ? st.Cfg.backup_md5 : null;
            st.BackupRecordedMd5 = recorded;
            st.BackupIntactKnown = st.BackupExists && !string.IsNullOrEmpty(recorded);
            if (st.BackupIntactKnown)
                st.BackupIntact = string.Equals(st.BackupMd5, recorded.ToUpperInvariant(), StringComparison.Ordinal);

            if (st.TargetOk)
            {
                st.StateText = st.Patched ? "无马赛克（已去马赛克）" : "有马赛克（未修改）";
                string p = (st.Cfg != null) ? st.Cfg.patched_md5 : null;
                string o = (st.Cfg != null) ? st.Cfg.original_md5 : null;
                if (st.Patched)
                {
                    if (!string.IsNullOrEmpty(p) && st.Md5 == p.ToUpperInvariant()) st.IntegrityText = "与配置记录的补丁 MD5 一致";
                    else if (!string.IsNullOrEmpty(p)) st.IntegrityText = "已修改，但 MD5 与配置记录不符（文件被其它改动过？）";
                    else st.IntegrityText = "（配置里没有补丁 MD5 记录）";
                }
                else
                {
                    if (!string.IsNullOrEmpty(o) && st.Md5 == o.ToUpperInvariant()) st.IntegrityText = "与配置记录的原始 MD5 一致";
                    else if (st.BackupExists && st.Md5 == st.BackupMd5) st.IntegrityText = "与备份文件 MD5 一致";
                    else if (!string.IsNullOrEmpty(o)) st.IntegrityText = "未修改，但 MD5 与配置记录的原始值不符（文件被其它改动过？）";
                    else st.IntegrityText = "（配置里没有原始 MD5 记录）";
                }
            }
            else
            {
                st.StateText = "无法识别";
                st.IntegrityText = "-";
            }
            return st;
        }

        public static List<string> DoPatch(string target, bool makeBackup)
        {
            List<string> logs = new List<string>();
            if (!File.Exists(target)) throw new PatchException("文件不存在：" + target);

            string bpath = BackupPathFor(target);
            Config cfg = Config.Load(Config.PathFor(target));
            if (cfg == null) cfg = new Config();

            ClearReadOnly(target);

            byte[] data = File.ReadAllBytes(target);
            LocateInfo before = Patcher.Locate(data);
            if (before.State == "patched")
            {
                logs.Add("无需修改：目标方法已经处于「无马赛克」状态（return false）。");
                return logs;
            }
            string beforeMd5 = Util.Md5Bytes(data);

            if (makeBackup)
            {
                if (File.Exists(bpath))
                {
                    logs.Add("备份已存在，未覆盖：" + Path.GetFileName(bpath));
                    if (string.IsNullOrEmpty(cfg.backup_md5))
                    {
                        cfg.backup_md5 = Util.Md5File(bpath);
                        cfg.original_md5 = cfg.backup_md5;
                    }
                }
                else
                {
                    File.Copy(target, bpath, false);
                    logs.Add("已创建备份：" + Path.GetFileName(bpath));
                    cfg.backup_md5 = Util.Md5File(bpath);
                    cfg.original_md5 = cfg.backup_md5;
                    logs.Add("备份 MD5：" + cfg.backup_md5);
                }
                cfg.backup_created = true;
                cfg.backup_file = Path.GetFileName(bpath);
            }
            else
            {
                logs.Add("按设置跳过备份。");
            }

            if (data[before.FileOffset] != 0x17)
                throw new PatchException("目标字节不是 0x17，实际为 0x" + data[before.FileOffset].ToString("X2") + "，已中止");
            data[before.FileOffset] = 0x16;
            string note = WriteFileSmart(target, data);
            if (note.Length > 0) logs.Add(note);

            byte[] after = File.ReadAllBytes(target);
            LocateInfo afterInfo = Patcher.Locate(after);
            string afterMd5 = Util.Md5Bytes(after);

            logs.Add("已去马赛克：IL_" + before.IlOffset.ToString("X4") + " 的 ldc.i4.1(0x17) → ldc.i4.0(0x16)");
            logs.Add("文件偏移：0x" + before.FileOffset.ToString("X"));

            cfg.target_file = Path.GetFileName(target);
            cfg.target_dir = Path.GetDirectoryName(Path.GetFullPath(target));
            cfg.patched_md5 = afterMd5;
            cfg.state = "patched";
            cfg.updated_at = Util.Now();
            if (string.IsNullOrEmpty(cfg.original_md5)) cfg.original_md5 = beforeMd5;
            cfg.backup_created = File.Exists(bpath);
            if (File.Exists(bpath) && string.IsNullOrEmpty(cfg.backup_md5))
            {
                cfg.backup_md5 = Util.Md5File(bpath);
                cfg.backup_file = Path.GetFileName(bpath);
            }
            cfg.Save(Config.PathFor(target));
            logs.Add("补丁后 MD5：" + afterMd5);
            logs.Add("配置已写入：" + Config.Name);
            if (afterInfo.State != "patched")
                throw new PatchException("内部校验失败：修改后状态不是 patched");
            return logs;
        }

        public static List<string> DoRestore(string target, bool force)
        {
            List<string> logs = new List<string>();
            if (!File.Exists(target)) throw new PatchException("文件不存在：" + target);
            string bpath = BackupPathFor(target);
            if (!File.Exists(bpath)) throw new PatchException("没有找到备份文件：" + bpath);

            ClearReadOnly(target);

            Config cfg = Config.Load(Config.PathFor(target));
            string backupMd5 = Util.Md5File(bpath);
            if (cfg != null && !string.IsNullOrEmpty(cfg.backup_md5)
                && !string.Equals(cfg.backup_md5.ToUpperInvariant(), backupMd5, StringComparison.Ordinal))
            {
                if (!force)
                    throw new PatchException("备份文件已被改动！\n  配置记录: " + cfg.backup_md5.ToUpperInvariant()
                                             + "\n  当前实际: " + backupMd5
                                             + "\n（确认无误可强制还原）");
                logs.Add("警告：备份 MD5 与配置记录不一致，按用户要求强制还原。");
            }

            string note = WriteFileSmart(target, File.ReadAllBytes(bpath));
            logs.Add("已用备份还原：" + Path.GetFileName(bpath));
            if (note.Length > 0) logs.Add(note);
            string restored = Util.Md5File(target);
            logs.Add("还原后 MD5：" + restored);

            if (cfg == null) cfg = new Config();
            cfg.target_file = Path.GetFileName(target);
            cfg.target_dir = Path.GetDirectoryName(Path.GetFullPath(target));
            cfg.backup_file = Path.GetFileName(bpath);
            cfg.backup_created = true;
            cfg.backup_md5 = backupMd5;
            cfg.state = "restored";
            cfg.updated_at = Util.Now();
            cfg.Save(Config.PathFor(target));
            logs.Add("配置已更新：" + Config.Name);
            return logs;
        }
    }

    // =====================================================================
    // GUI
    // =====================================================================
    internal class MainForm : Form
    {
        private string target;
        private TextBox txtPath;
        private TextBox txtStatus;
        private TextBox txtLog;
        private Button btnPatch;
        private Button btnRestore;
        private CheckBox chkBackup;
        private Timer autoTimer;

        public MainForm()
        {
            AutoScaleMode = AutoScaleMode.None;      // 手动布局，避免 DPI/字体缩放把控件挤出可视区
            Text = "MosaicPatcher —— 一键去马赛克";
            ClientSize = new Size(900, 680);
            MinimumSize = new Size(800, 620);
            Font = new Font("Microsoft YaHei UI", 9F);
            StartPosition = FormStartPosition.CenterScreen;

            // ---------- 状态区（Fill，必须最先加）----------
            txtStatus = new TextBox();
            txtStatus.Multiline = true;
            txtStatus.ReadOnly = true;
            txtStatus.ScrollBars = ScrollBars.Both;
            txtStatus.WordWrap = false;
            txtStatus.Dock = DockStyle.Fill;
            txtStatus.Font = new Font("Consolas", 10F);

            GroupBox grpStatus = new GroupBox();
            grpStatus.Text = "状态";
            grpStatus.Dock = DockStyle.Fill;
            grpStatus.Padding = new Padding(6);
            grpStatus.Controls.Add(txtStatus);

            Panel statusPanel = new Panel();
            statusPanel.Dock = DockStyle.Fill;
            statusPanel.Padding = new Padding(10, 4, 10, 4);
            statusPanel.Controls.Add(grpStatus);
            Controls.Add(statusPanel);

            // ---------- 日志（贴底）----------
            txtLog = new TextBox();
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.Dock = DockStyle.Fill;
            txtLog.Font = new Font("Consolas", 9F);

            GroupBox grpLog = new GroupBox();
            grpLog.Text = "日志";
            grpLog.Dock = DockStyle.Fill;
            grpLog.Padding = new Padding(6);
            grpLog.Controls.Add(txtLog);

            Panel logPanel = new Panel();
            logPanel.Dock = DockStyle.Bottom;
            logPanel.Height = 170;
            logPanel.Padding = new Padding(10, 2, 10, 8);
            logPanel.Controls.Add(grpLog);
            Controls.Add(logPanel);

            // ---------- 按钮行（FlowLayoutPanel 自动排列，绝不会跑丢）----------
            btnPatch = MakeButton("执行去马赛克", 130, new EventHandler(OnPatch));
            btnPatch.Enabled = false;
            btnRestore = MakeButton("还原备份", 100, new EventHandler(OnRestore));
            btnRestore.Enabled = false;
            Button btnRefresh = MakeButton("刷新状态", 100, new EventHandler(OnRefresh));
            Button btnOpen = MakeButton("打开所在目录", 120, new EventHandler(OnOpenDir));

            FlowLayoutPanel flow = new FlowLayoutPanel();
            flow.Dock = DockStyle.Fill;
            flow.FlowDirection = FlowDirection.LeftToRight;
            flow.WrapContents = false;
            flow.Controls.Add(btnPatch);
            flow.Controls.Add(btnRestore);
            flow.Controls.Add(btnRefresh);
            flow.Controls.Add(btnOpen);
            foreach (Control c in flow.Controls) c.Margin = new Padding(0, 0, 8, 0);

            Panel btnPanel = new Panel();
            btnPanel.Dock = DockStyle.Bottom;
            btnPanel.Height = 52;
            btnPanel.Padding = new Padding(10, 6, 10, 6);
            btnPanel.Controls.Add(flow);
            Controls.Add(btnPanel);

            // ---------- 选项行 ----------
            chkBackup = new CheckBox();
            chkBackup.Text = "修改前自动备份（备份文件放在 DLL 同目录）";
            chkBackup.Checked = true;
            chkBackup.AutoSize = true;
            chkBackup.Location = new Point(12, 5);

            Panel optPanel = new Panel();
            optPanel.Dock = DockStyle.Top;
            optPanel.Height = 30;
            optPanel.Controls.Add(chkBackup);
            Controls.Add(optPanel);

            // ---------- 顶部路径行（Dock 布局，不靠坐标）----------
            txtPath = new TextBox();
            txtPath.ReadOnly = true;
            txtPath.Text = "（尚未选择文件）";
            txtPath.Dock = DockStyle.Fill;

            Label lbl = new Label();
            lbl.Text = "目标 DLL：";
            lbl.Dock = DockStyle.Left;
            lbl.Width = 78;
            lbl.TextAlign = ContentAlignment.MiddleLeft;

            Button btnFind = MakeButton("自动搜索", 90, new EventHandler(OnAutoSearch));
            btnFind.Dock = DockStyle.Right;
            Button btnChoose = MakeButton("选择文件…", 100, new EventHandler(OnChoose));
            btnChoose.Dock = DockStyle.Right;

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = 46;
            top.Padding = new Padding(10, 8, 10, 6);
            top.Controls.Add(txtPath);
            top.Controls.Add(lbl);
            top.Controls.Add(btnFind);
            top.Controls.Add(btnChoose);
            Controls.Add(top);

            SetStatus("正在自动搜索 Assembly-CSharp.dll……\r\n（只认 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll 这种路径）");
            WriteLog("运行环境：权限=" + (IsElevated() ? "管理员" : "普通用户")
                     + " / 完整性=" + GetIntegrityLevelText()
                     + " / 会话=" + System.Diagnostics.Process.GetCurrentProcess().SessionId);
            WriteLog("就绪。");

            autoTimer = new Timer();
            autoTimer.Interval = 80;
            autoTimer.Tick += new EventHandler(OnAutoTimer);
        }

        private static Button MakeButton(string text, int width, EventHandler onClick)
        {
            Button b = new Button();
            b.Text = text;
            b.Width = width;
            b.Height = 30;
            b.Click += onClick;
            return b;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            autoTimer.Start();
        }

        private void OnAutoTimer(object sender, EventArgs e)
        {
            autoTimer.Stop();
            AutoSearch(true);
        }

        private void SetStatus(string s)
        {
            txtStatus.Text = s;
        }

        private void WriteLog(string s)
        {
            txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + s + "\r\n");
        }

        public void SelectTarget(string path)
        {
            target = path;
            txtPath.Text = path;
            RefreshStatus();
        }

        private void OnAutoSearch(object sender, EventArgs e) { AutoSearch(false); }
        private void OnRefresh(object sender, EventArgs e) { RefreshStatus(); }
        // 打开所在目录：优先让资源管理器定位该文件；受限权限下自动退化为"复制路径"
        private void OnOpenDir(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(target)) return;
            string dir = Path.GetDirectoryName(target);
            string il = GetIntegrityLevelText();

            // 低完整性进程调不起 explorer.exe（会报 0xc0000142），直接走复制路径
            if (il.IndexOf("低") >= 0 || il.IndexOf("不可信") >= 0)
            {
                WriteLog("当前进程完整性为「" + il + "」，无法调用资源管理器，改用路径复制方式。");
                ShowPathDialog(dir, "当前权限受限，无法打开资源管理器，已把路径复制到剪贴板：");
                return;
            }

            string err = null;
            // 方式1：explorer.exe /select（打开文件夹并选中文件）
            try
            {
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
                psi.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                psi.Arguments = "/select,\"" + target + "\"";
                psi.UseShellExecute = true;
                System.Diagnostics.Process.Start(psi);
                WriteLog("已在资源管理器中定位：" + target);
                return;
            }
            catch (Exception ex) { err = ex.Message; }

            // 方式2：Shell.Application COM（交给已在运行的资源管理器）
            try
            {
                ExploreViaShellCom(dir);
                WriteLog("已打开目录：" + dir);
                return;
            }
            catch (Exception ex) { err = err + " / " + ex.Message; }

            // 方式3：ShellExecute 直接打开文件夹
            try
            {
                System.Diagnostics.ProcessStartInfo psi2 = new System.Diagnostics.ProcessStartInfo();
                psi2.FileName = dir;
                psi2.UseShellExecute = true;
                System.Diagnostics.Process.Start(psi2);
                WriteLog("已打开目录：" + dir);
                return;
            }
            catch (Exception ex) { err = err + " / " + ex.Message; }

            // 方式4：兜底 —— 复制路径 + 弹窗显示
            WriteLog("打开目录失败：" + err);
            ShowPathDialog(dir, "打开文件夹失败，已把路径复制到剪贴板：");
        }

        private void ShowPathDialog(string dir, string header)
        {
            string info;
            try
            {
                Clipboard.SetText(dir);
                info = header;
            }
            catch (Exception ex)
            {
                info = header + "（写入剪贴板失败：" + ex.Message + "）";
            }
            WriteLog("目录路径：" + dir + "（" + info + "）");

            Form win = new Form();
            win.Text = "所在目录";
            win.ClientSize = new Size(680, 190);
            win.StartPosition = FormStartPosition.CenterParent;
            win.FormBorderStyle = FormBorderStyle.FixedDialog;
            win.MaximizeBox = false;
            win.MinimizeBox = false;
            win.Font = Font;

            Label lbl = new Label();
            lbl.Text = info + "\r\n可以复制下面的路径，粘贴到「文件资源管理器」的地址栏：";
            lbl.AutoSize = true;
            lbl.MaximumSize = new Size(656, 0);
            lbl.Location = new Point(12, 12);
            win.Controls.Add(lbl);

            TextBox tb = new TextBox();
            tb.Text = dir;
            tb.ReadOnly = true;
            tb.Location = new Point(12, 62);
            tb.Width = 656;
            tb.SelectAll();
            win.Controls.Add(tb);

            Button btnCopy = new Button();
            btnCopy.Text = "再次复制";
            btnCopy.Location = new Point(492, 100);
            btnCopy.Width = 82;
            btnCopy.Click += delegate(object s2, EventArgs e2)
            {
                try { Clipboard.SetText(dir); lbl.Text = "已复制到剪贴板。"; }
                catch (Exception ex) { lbl.Text = "复制失败：" + ex.Message; }
            };
            win.Controls.Add(btnCopy);

            Button btnOk = new Button();
            btnOk.Text = "关闭";
            btnOk.DialogResult = DialogResult.OK;
            btnOk.Location = new Point(582, 100);
            btnOk.Width = 82;
            win.Controls.Add(btnOk);
            win.AcceptButton = btnOk;
            win.CancelButton = btnOk;

            win.ShowDialog(this);
        }

        private static bool IsElevated()
        {
            try
            {
                using (System.Security.Principal.WindowsIdentity id =
                       System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    return new System.Security.Principal.WindowsPrincipal(id)
                        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        // 交给"已经在运行的资源管理器"去打开目录（不新起 explorer.exe）
        private static void ExploreViaShellCom(string dir)
        {
            Type t = Type.GetTypeFromProgID("Shell.Application");
            if (t == null) throw new PatchException("系统未注册 Shell.Application");
            object shell = Activator.CreateInstance(t);
            try
            {
                t.InvokeMember("Explore", System.Reflection.BindingFlags.InvokeMethod,
                               null, shell, new object[] { dir });
            }
            finally
            {
                try { System.Runtime.InteropServices.Marshal.ReleaseComObject(shell); }
                catch { }
            }
        }

        // ---- 诊断用：读当前进程完整性级别 ----
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr h, int access, out IntPtr token);
        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int retLen);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr h);

        private static string GetIntegrityLevelText()
        {
            IntPtr token = IntPtr.Zero, buf = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out token)) return "未知";
                int len;
                GetTokenInformation(token, 25, IntPtr.Zero, 0, out len);
                if (len <= 0) return "未知";
                buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(len);
                if (!GetTokenInformation(token, 25, buf, len, out len)) return "未知";
                IntPtr sid = System.Runtime.InteropServices.Marshal.ReadIntPtr(buf);
                byte subCount = System.Runtime.InteropServices.Marshal.ReadByte(sid, 1);
                IntPtr last = IntPtr.Add(sid, 8 + (subCount - 1) * 4);
                int rid = System.Runtime.InteropServices.Marshal.ReadInt32(last);
                if (rid >= 0x4000) return "System";
                if (rid >= 0x3000) return "高 High（管理员）";
                if (rid >= 0x2000) return "中 Medium（普通）";
                if (rid >= 0x1000) return "低 Low";
                return "不可信 Untrusted";
            }
            catch { return "未知"; }
            finally
            {
                if (buf != IntPtr.Zero) System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        private void AutoSearch(bool silent)
        {
            List<Candidate> cands;
            try { cands = Finder.Find(Finder.ProgramDir()); }
            catch (Exception ex) { WriteLog("自动搜索出错：" + ex.Message); return; }

            if (cands.Count == 0)
            {
                WriteLog("自动搜索：未找到 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll");
                if (silent)
                    SetStatus("未自动找到 Assembly-CSharp.dll。\r\n请点「自动搜索」重试，或点「选择文件…」手动选择。");
                else
                    MessageBox.Show(this,
                        "没有自动找到 Assembly-CSharp.dll。\r\n\r\n只搜索了：\r\n"
                        + "  1) 程序所在目录\r\n  2) 上一级目录（1 层）\r\n  3) 程序目录下的所有子目录\r\n\r\n"
                        + "而且只认路径形如 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll 的文件。\r\n"
                        + "请手动点「选择文件…」。", "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            foreach (Candidate c in cands) WriteLog("自动搜索命中 [" + c.Source + "] " + c.Path);

            string pick = cands[0].Path;
            if (cands.Count > 1 && !silent)
            {
                string chosen = AskCandidate(cands);
                if (chosen == null) return;
                pick = chosen;
            }
            else if (cands.Count > 1)
            {
                WriteLog("共找到 " + cands.Count + " 个候选，已默认选用优先级最高的一个；可点「自动搜索」重新挑选。");
            }
            WriteLog("自动搜索选用：" + pick);
            SelectTarget(pick);
        }

        private string AskCandidate(List<Candidate> cands)
        {
            Form win = new Form();
            win.Text = "找到多个 Assembly-CSharp.dll";
            win.ClientSize = new Size(760, 300);
            win.StartPosition = FormStartPosition.CenterParent;
            win.FormBorderStyle = FormBorderStyle.FixedDialog;
            win.MaximizeBox = false;
            win.MinimizeBox = false;

            Label lbl = new Label();
            lbl.Text = "找到 " + cands.Count + " 个符合路径形态的候选，请选择要操作的文件：";
            lbl.AutoSize = true;
            lbl.Location = new Point(12, 12);
            win.Controls.Add(lbl);

            ListBox lb = new ListBox();
            lb.Location = new Point(12, 38);
            lb.Size = new Size(736, 200);
            lb.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            foreach (Candidate c in cands) lb.Items.Add("[" + c.Source + "] " + c.Path);
            lb.SelectedIndex = 0;
            win.Controls.Add(lb);

            Button ok = new Button();
            ok.Text = "确定";
            ok.DialogResult = DialogResult.OK;
            ok.Location = new Point(672, 250);
            win.Controls.Add(ok);
            Button cancel = new Button();
            cancel.Text = "取消";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.Location = new Point(590, 250);
            win.Controls.Add(cancel);
            win.AcceptButton = ok;
            win.CancelButton = cancel;

            if (win.ShowDialog(this) != DialogResult.OK) return null;
            if (lb.SelectedIndex < 0) return null;
            return cands[lb.SelectedIndex].Path;
        }

        private void OnChoose(object sender, EventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Title = "选择 Assembly-CSharp.dll";
            dlg.Filter = "托管程序集 (*.dll)|*.dll|所有文件 (*.*)|*.*";
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            string p = Path.GetFullPath(dlg.FileName);
            if (!Finder.IsGameDllPath(p))
            {
                DialogResult r = MessageBox.Show(this,
                    "这个路径不是标准的游戏路径：\r\n" + p + "\r\n\r\n"
                    + "标准形态应该是：\r\n…\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll\r\n\r\n"
                    + "可能不是你想要的 DLL。仍要使用它吗？",
                    "MosaicPatcher", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r != DialogResult.Yes) return;
            }
            WriteLog("手动选择：" + p);
            SelectTarget(p);
        }

        private void RefreshStatus()
        {
            if (string.IsNullOrEmpty(target)) return;
            Status st;
            try { st = Workspace.BuildStatus(target); }
            catch (Exception ex)
            {
                SetStatus("读取失败：" + ex.Message);
                btnPatch.Enabled = false;
                btnRestore.Enabled = false;
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("【目标文件】");
            sb.AppendLine("  路径      : " + st.Target);
            sb.AppendLine("  相对路径  : " + st.RelPath);
            sb.AppendLine("  路径校验  : " + (st.PathOk
                ? "符合 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll"
                : "不是标准游戏路径，请确认选对文件"));
            sb.AppendLine("  大小      : " + st.FileSize + " 字节");
            sb.AppendLine("  MD5       : " + st.Md5);
            sb.AppendLine();
            sb.AppendLine("【方法定位】");
            if (st.TargetOk)
            {
                sb.AppendLine("  目标      : " + Patcher.TargetNamespace + "." + Patcher.TargetType + "::" + Patcher.TargetMethod);
                sb.AppendLine("  Method RVA: 0x" + st.MethodRva.ToString("X"));
                sb.AppendLine("  IL 位置   : IL_" + st.IlOffset.ToString("X4") + "   （文件偏移 0x" + st.FileOffset.ToString("X") + "）");
                sb.AppendLine("  当前状态  : " + st.StateText);
                sb.AppendLine("  完整性    : " + st.IntegrityText);
            }
            else
            {
                sb.AppendLine("  失败      : " + st.TargetError);
            }
            sb.AppendLine();
            sb.AppendLine("【备份 / 配置文件】（都在 DLL 同目录）");
            sb.AppendLine("  配置文件  : " + st.ConfigPath);
            if (!st.CfgExists) sb.AppendLine("              （不存在，本次将新建）");
            else if (st.Cfg != null)
            {
                sb.AppendLine("              记录状态 : " + st.Cfg.state);
                sb.AppendLine("              是否备份 : " + (st.Cfg.backup_created ? "是" : "否"));
                sb.AppendLine("              更新时间 : " + st.Cfg.updated_at);
            }
            sb.AppendLine("  备份文件  : " + st.BackupPath);
            if (!st.BackupExists) sb.AppendLine("              不存在（执行修改时会自动创建）");
            else
            {
                sb.AppendLine("              存在，" + st.BackupSize + " 字节");
                sb.AppendLine("              备份 MD5 : " + st.BackupMd5);
                if (!st.BackupIntactKnown) sb.AppendLine("              校验结果 : 配置里没有记录，无法比对");
                else if (st.BackupIntact) sb.AppendLine("              校验结果 : 与配置记录一致（备份未被改动）");
                else
                {
                    sb.AppendLine("              校验结果 : 与配置记录不一致（备份已被改动！）");
                    sb.AppendLine("                         配置记录 : " + st.BackupRecordedMd5);
                }
            }
            sb.AppendLine();
            sb.AppendLine("【运行环境】（排查问题时可把这几行发给我）");
            sb.AppendLine("  权限/完整性/会话 : " + (IsElevated() ? "管理员" : "普通用户")
                          + " / " + GetIntegrityLevelText()
                          + " / " + System.Diagnostics.Process.GetCurrentProcess().SessionId);
            sb.AppendLine("  程序目录         : " + Finder.ProgramDir());
            SetStatus(sb.ToString());

            btnPatch.Enabled = st.TargetOk && !st.Patched;
            btnRestore.Enabled = st.BackupExists;
        }

        private void OnPatch(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(target)) return;
            Status st;
            try { st = Workspace.BuildStatus(target); }
            catch (Exception ex) { MessageBox.Show(this, "读取失败：" + ex.Message, "MosaicPatcher"); return; }

            if (!st.TargetOk)
            {
                MessageBox.Show(this, "无法定位目标方法：\r\n" + st.TargetError, "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (st.Patched)
            {
                MessageBox.Show(this, "当前已经是「无马赛克」状态，无需再处理。", "MosaicPatcher");
                return;
            }
            string note = chkBackup.Checked ? "会先自动备份。" : "注意：你取消了自动备份！";
            DialogResult r = MessageBox.Show(this,
                "即将去马赛克：\r\n" + st.Target + "\r\n\r\n当前状态：有马赛克\r\n处理之后：无马赛克\r\n\r\n"
                + "（原理：把 " + Patcher.TargetNamespace + "." + Patcher.TargetType + "::" + Patcher.TargetMethod
                + " 末尾的 return true 改成 return false）\r\n\r\n" + note,
                "MosaicPatcher", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (r != DialogResult.Yes) return;

            try
            {
                List<string> logs = Workspace.DoPatch(target, chkBackup.Checked);
                foreach (string line in logs) WriteLog(line);
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show(this, "写入失败（拒绝访问）：\r\n" + ex.Message
                    + "\r\n\r\n请先完全关闭游戏再试；若文件是只读属性，取消只读即可。",
                    "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                WriteLog("写入失败：" + ex.Message);
            }
            catch (IOException ex)
            {
                MessageBox.Show(this, "写入失败（文件被占用）：\r\n" + ex.Message
                    + "\r\n\r\n请先完全关闭游戏再试。",
                    "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                WriteLog("写入失败：" + ex.Message);
            }
            catch (PatchException ex)
            {
                MessageBox.Show(this, ex.Message, "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                WriteLog("去马赛克失败：" + ex.Message);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "去马赛克失败：" + ex.Message, "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                WriteLog("去马赛克失败：" + ex.Message);
            }
            RefreshStatus();
        }

        private void OnRestore(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(target)) return;
            Status st;
            try { st = Workspace.BuildStatus(target); }
            catch (Exception ex) { MessageBox.Show(this, "读取失败：" + ex.Message, "MosaicPatcher"); return; }

            if (!st.BackupExists)
            {
                MessageBox.Show(this, "没有找到备份文件：\r\n" + st.BackupPath, "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            string warn = "";
            if (st.BackupIntactKnown && !st.BackupIntact)
                warn = "\r\n\r\n警告：备份文件 MD5 与配置记录不一致，备份可能已被改动！\r\n  配置记录: "
                     + st.BackupRecordedMd5 + "\r\n  当前实际: " + st.BackupMd5;

            DialogResult r = MessageBox.Show(this,
                "将用备份覆盖：\r\n" + st.Target + "\r\n\r\n备份文件：\r\n" + st.BackupPath + warn,
                "MosaicPatcher", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (r != DialogResult.Yes) return;

            try
            {
                List<string> logs = Workspace.DoRestore(target, st.BackupIntactKnown && !st.BackupIntact);
                foreach (string line in logs) WriteLog(line);
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show(this, "文件被占用，无法写入。\r\n请先完全关闭游戏再试。", "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (PatchException ex)
            {
                MessageBox.Show(this, ex.Message, "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
                WriteLog("还原失败：" + ex.Message);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "还原失败：" + ex.Message, "MosaicPatcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            RefreshStatus();
        }
    }

    // =====================================================================
    // 入口
    // =====================================================================
    internal static class Program
    {
        private static TextWriter Out = Console.Out;

        [STAThread]
        public static int Main(string[] args)
        {
            if (args.Length == 0) return RunGui();

            // --out <文件>：把命令行输出写进文件（窗口版没有控制台）
            string outFile = null;
            List<string> a = new List<string>(args);
            int oi = a.IndexOf("--out");
            if (oi >= 0 && oi + 1 < a.Count)
            {
                outFile = a[oi + 1];
                a.RemoveRange(oi, 2);
            }
            if (outFile != null)
            {
                try { Out = new StreamWriter(outFile, false, new UTF8Encoding(false)); }
                catch { Out = TextWriter.Null; }
            }
            else
            {
                Out = TextWriter.Null;      // winexe 没有控制台
            }

            try
            {
                return Cli(a);
            }
            finally
            {
                try { Out.Flush(); Out.Close(); }
                catch { }
            }
        }

        private static int RunGui()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }

        private static int GuiSelfTest()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            MainForm f = new MainForm();
            Timer t = new Timer();
            t.Interval = 1200;
            t.Tick += delegate(object s, EventArgs e) { t.Stop(); f.Close(); };
            f.Shown += delegate(object s, EventArgs e) { t.Start(); };
            Application.Run(f);
            Out.WriteLine("GUI selftest OK");
            return 0;
        }

        // 截取界面图，给 README 用
        private static int GuiShot(string dst, string initialTarget)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            MainForm f = new MainForm();
            string shotTarget = initialTarget;
            Timer t = new Timer();
            t.Interval = 1800;                       // 等自动搜索完成后再切到指定文件
            t.Tick += delegate(object s, EventArgs e)
            {
                t.Stop();
                try
                {
                    if (!string.IsNullOrEmpty(shotTarget))
                    {
                        f.SelectTarget(Path.GetFullPath(shotTarget));
                        Application.DoEvents();
                    }
                    using (Bitmap bmp = new Bitmap(f.Width, f.Height))
                    {
                        f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                        bmp.Save(dst, System.Drawing.Imaging.ImageFormat.Png);
                    }
                    Out.WriteLine("GUI shot saved: " + dst);
                }
                catch (Exception ex) { Out.WriteLine("shot failed: " + ex.Message); }
                f.Close();
            };
            f.Shown += delegate(object s, EventArgs e) { t.Start(); };
            Application.Run(f);
            return 0;
        }

        // 把界面控件的实际位置打印出来，便于自动化验证"按钮有没有跑到可视区外"
        private static int GuiDump(string dst)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            MainForm f = new MainForm();
            f.Show();
            Application.DoEvents();
            f.PerformLayout();
            Application.DoEvents();

            using (StreamWriter w = new StreamWriter(dst, false, new UTF8Encoding(false)))
            {
                w.WriteLine("ClientSize=" + f.ClientSize.Width + "x" + f.ClientSize.Height);
                w.WriteLine("AutoScaleMode=" + f.AutoScaleMode);
                DumpControls(f, f, f.ClientSize, w, 0);
            }
            f.Close();
            return 0;
        }

        private static void DumpControls(Control parent, Form form, Size client, TextWriter w, int depth)
        {
            foreach (Control c in parent.Controls)
            {
                Point abs = c.Location;
                Control p = c.Parent;
                while (p != null && p != form) { abs.Offset(p.Location); p = p.Parent; }
                Rectangle r = new Rectangle(abs, c.Size);
                bool inside = r.Left >= 0 && r.Top >= 0
                              && r.Right <= client.Width && r.Bottom <= client.Height;
                string label = (c.Text == null || c.Text.Length == 0) ? c.GetType().Name : c.Text;
                if (label.Length > 24) label = label.Substring(0, 24);
                w.WriteLine(new string(' ', depth * 2)
                    + c.GetType().Name + " [" + label.Replace("\r", " ").Replace("\n", " ") + "]"
                    + " bounds=" + r.Left + "," + r.Top + "," + r.Width + "x" + r.Height
                    + " visible=" + c.Visible
                    + " inside=" + inside);
                if (c.Controls.Count > 0) DumpControls(c, form, client, w, depth + 1);
            }
        }

        private static int Cli(List<string> a)
        {
            if (a.Contains("--dumpargs"))
            {
                string dst = a[a.IndexOf("--dumpargs") + 1];
                using (StreamWriter w = new StreamWriter(dst, false, new UTF8Encoding(false)))
                {
                    w.WriteLine("argc=" + a.Count);
                    for (int i = 0; i < a.Count; i++) w.WriteLine(i + ": [" + a[i] + "]");
                }
                return 0;
            }
            if (a.Contains("--gui-selftest")) return GuiSelfTest();
            if (a.Contains("--gui-shot"))
            {
                int si = a.IndexOf("--gui-shot");
                string dst = a[si + 1];
                string shotTarget = (si + 2 < a.Count && !a[si + 2].StartsWith("--")) ? a[si + 2] : null;
                return GuiShot(dst, shotTarget);
            }
            if (a.Contains("--gui-dump"))
            {
                string dst = a[a.IndexOf("--gui-dump") + 1];
                return GuiDump(dst);
            }

            if (a.Contains("--find"))
            {
                string baseDir = null;
                int bi = a.IndexOf("--base");
                if (bi >= 0 && bi + 1 < a.Count) baseDir = a[bi + 1];
                if (baseDir == null) baseDir = Finder.ProgramDir();
                List<Candidate> cands = Finder.Find(baseDir);
                if (cands.Count == 0)
                {
                    Out.WriteLine("未找到候选（只认 ...\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll）");
                    return 1;
                }
                foreach (Candidate c in cands)
                {
                    Out.WriteLine("[" + c.Source + "] " + c.Path);
                    Out.WriteLine("          相对路径: " + c.Rel);
                }
                return 0;
            }

            if (a.Contains("--status"))
            {
                string target = a[a.IndexOf("--status") + 1];
                Status st;
                try { st = Workspace.BuildStatus(target); }
                catch (PatchException ex) { Out.WriteLine("错误：" + ex.Message); return 1; }
                Out.WriteLine("文件        : " + st.Target);
                Out.WriteLine("相对路径    : " + st.RelPath + "   " + (st.PathOk ? "OK 路径形态正确" : "警告 不是标准游戏路径"));
                Out.WriteLine("大小        : " + st.FileSize + " 字节");
                Out.WriteLine("MD5         : " + st.Md5);
                if (st.TargetOk)
                {
                    Out.WriteLine("方法        : " + Patcher.TargetNamespace + "." + Patcher.TargetType + "::" + Patcher.TargetMethod
                                  + "  (RVA 0x" + st.MethodRva.ToString("X") + ")");
                    Out.WriteLine("IL 位置     : IL_" + st.IlOffset.ToString("X4") + "  文件偏移 0x" + st.FileOffset.ToString("X"));
                }
                else Out.WriteLine("方法        : 未找到 -> " + st.TargetError);
                Out.WriteLine("当前状态    : " + st.StateText);
                Out.WriteLine("完整性      : " + st.IntegrityText);
                Out.WriteLine("配置文件    : " + st.ConfigPath + (st.CfgExists ? "" : "（不存在）"));
                Out.WriteLine("备份文件    : " + st.BackupPath);
                Out.WriteLine("备份存在    : " + (st.BackupExists ? "是" : "否"));
                if (st.BackupExists)
                {
                    Out.WriteLine("备份 MD5    : " + st.BackupMd5);
                    if (!st.BackupIntactKnown) Out.WriteLine("备份校验    : 配置里没有记录");
                    else Out.WriteLine("备份校验    : " + (st.BackupIntact ? "一致（未被改动）" : "不一致（备份已被改动！）"));
                }
                return 0;
            }

            if (a.Contains("--patch"))
            {
                string target = a[a.IndexOf("--patch") + 1];
                try
                {
                    foreach (string line in Workspace.DoPatch(target, !a.Contains("--no-backup"))) Out.WriteLine(line);
                }
                catch (PatchException ex) { Out.WriteLine("错误：" + ex.Message); return 1; }
                return 0;
            }

            if (a.Contains("--restore"))
            {
                string target = a[a.IndexOf("--restore") + 1];
                try
                {
                    foreach (string line in Workspace.DoRestore(target, a.Contains("--force"))) Out.WriteLine(line);
                }
                catch (PatchException ex) { Out.WriteLine("错误：" + ex.Message); return 1; }
                return 0;
            }

            Out.WriteLine("MosaicPatcher —— 把 nel.MosaicShower::FnDrawMosaic 末尾的 return true 改成 return false");
            Out.WriteLine("  --find [--base <目录>]      自动搜索候选");
            Out.WriteLine("  --status <dll>              查看状态");
            Out.WriteLine("  --patch <dll> [--no-backup] 执行去马赛克");
            Out.WriteLine("  --restore <dll> [--force]   还原备份");
            Out.WriteLine("  --gui-selftest              界面自检");
            Out.WriteLine("  --out <文件>                把输出写进文件");
            return 0;
        }
    }
}
