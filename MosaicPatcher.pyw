# -*- coding: utf-8 -*-
"""
MosaicPatcher —— 把 Alice in Cradle 里 nel.MosaicShower::FnDrawMosaic 末尾的
                   return true; 改成 return false;（只翻 1 个字节：IL 0x17 -> 0x16）

特点
  * 单文件、只依赖 Python 标准库（tkinter + hashlib + struct）
  * 自己解析 PE / .NET 元数据定位方法，不需要 dnlib / dnSpy
  * 自动备份（备份文件放在目标 DLL 同目录）
  * 手动还原
  * 目标目录下生成配置文件 mosaic_patcher.json，记录是否备份 + 各种 MD5
  * 用 MD5 判断备份文件是否被改动过，并在界面上显示
  * 未选择文件时不会去读任何配置文件

命令行模式（便于脚本 / 自动验证）
  python MosaicPatcher.pyw --status  <dll>
  python MosaicPatcher.pyw --patch   <dll> [--no-backup]
  python MosaicPatcher.pyw --restore <dll> [--force]
  python MosaicPatcher.pyw --gui-selftest
"""

import os
import sys
import json
import time
import struct
import hashlib
import datetime

APP_NAME = "MosaicPatcher"
APP_VERSION = "1.0"

TARGET_NAMESPACE = "nel"          # 目标类型命名空间
TARGET_TYPE = "MosaicShower"      # 目标类型名
TARGET_METHOD = "FnDrawMosaic"    # 目标方法名

CONFIG_NAME = "mosaic_patcher.json"
BACKUP_SUFFIX = ".mosaicpatch.bak"

LDC_I4_1 = 0x17   # return true 之前压入的常量 1
LDC_I4_0 = 0x16   # 改成 0
RET = 0x2A


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def md5_file(path, chunk_size=1 << 20):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest().upper()


class PatchError(Exception):
    """所有可预期的错误（给界面直接看的中文提示）"""


# --------------------------------------------------------------------------
# 自动搜索：找 ...\AliceInCradle_Data\Managed\Assembly-CSharp.dll
# --------------------------------------------------------------------------
GAME_SUBPATH = os.path.join("AliceInCradle_Data", "Managed", "Assembly-CSharp.dll")

_SKIP_DIR_NAMES = {"$recycle.bin", "system volume information", "__pycache__",
                   ".git", "node_modules", "$windows.~bt", "$windows.~ws"}


def program_dir():
    """本程序所在目录"""
    if getattr(sys, "frozen", False):            # PyInstaller 打包后
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def is_game_dll_path(path):
    """
    只认这种形态的路径：
        ...\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll
    其它地方的 Assembly-CSharp.dll 一律不认（可能是别的游戏的，或不是目标文件）。
    """
    p = os.path.normpath(os.path.abspath(path)).split(os.sep)
    return (len(p) >= 3
            and p[-1].lower() == "assembly-csharp.dll"
            and p[-2].lower() == "managed"
            and p[-3].lower() == "aliceincradle_data")


def _skip_dir(path, name):
    if name.lower() in _SKIP_DIR_NAMES:
        return True
    try:
        if os.path.islink(path):                 # 跳过符号链接/联接点，避免绕圈
            return True
    except OSError:
        pass
    return False


def auto_find_targets(base=None):
    """
    自动搜索 Assembly-CSharp.dll：
      1) 程序目录本身            -> .\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll
      2) 上一级目录（只找 1 层） -> ..\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll
      3) 程序目录下所有子目录（递归遍历）
    只有路径形如 AliceInCradle_Data\\Managed\\Assembly-CSharp.dll 的才算数。
    返回 [(绝对路径, 相对程序目录的路径, 来源说明), ...]，按优先级排序。
    """
    if base is None:
        base = program_dir()
    base = os.path.abspath(base)
    found = []
    seen = set()

    def add(root_dir, source):
        cand = os.path.join(root_dir, GAME_SUBPATH)
        if not os.path.isfile(cand) or not is_game_dll_path(cand):
            return
        key = os.path.normcase(os.path.abspath(cand))
        if key in seen:
            return
        seen.add(key)
        try:
            rel = os.path.relpath(cand, base)
        except ValueError:
            rel = os.path.abspath(cand)
        found.append((os.path.abspath(cand), rel, source))

    add(base, "程序目录")
    parent = os.path.dirname(base)
    if parent and os.path.abspath(parent) != base:
        add(parent, "上一级目录")
    for root, dirs, _files in os.walk(base):
        dirs[:] = [d for d in dirs if not _skip_dir(os.path.join(root, d), d)]
        if os.path.basename(root).lower() == "aliceincradle_data":
            add(os.path.dirname(root), "子目录")
            dirs[:] = []                         # 这个游戏目录不用再往里挖
    return found


def _u8(b, o):
    return b[o]


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


# --------------------------------------------------------------------------
# PE 解析
# --------------------------------------------------------------------------
class PEFile(object):
    def __init__(self, data):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PatchError("不是有效的 PE 文件（缺少 MZ 头）")
        pe = _u32(data, 0x3C)
        if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
            raise PatchError("不是有效的 PE 文件（缺少 PE 签名）")
        coff = pe + 4
        self.num_sections = _u16(data, coff + 2)
        size_opt = _u16(data, coff + 16)
        opt = coff + 20
        if opt + 2 > len(data):
            raise PatchError("PE 头不完整")
        magic = _u16(data, opt)
        self.is_pe32plus = (magic == 0x20B)
        if magic not in (0x10B, 0x20B):
            raise PatchError("未知的 PE 可选头 Magic: 0x%X" % magic)

        self.sections = []
        sec = opt + size_opt
        for i in range(self.num_sections):
            o = sec + 40 * i
            if o + 40 > len(data):
                raise PatchError("节区表不完整")
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize = _u32(data, o + 8)
            va = _u32(data, o + 12)
            rawsize = _u32(data, o + 16)
            rawptr = _u32(data, o + 20)
            self.sections.append((name, va, vsize, rawptr, rawsize))

        dd = opt + (112 if self.is_pe32plus else 96)
        if dd + 15 * 8 > len(data):
            raise PatchError("PE 数据目录不完整")
        cli_rva = _u32(data, dd + 14 * 8)
        if cli_rva == 0:
            raise PatchError("不是托管程序集（没有 CLI 头），可能不是 .NET DLL")
        cli = self.rva_to_off(cli_rva)
        self.md_rva = _u32(data, cli + 8)
        self.md_size = _u32(data, cli + 12)
        if self.md_rva == 0:
            raise PatchError("程序集没有元数据")

    def rva_to_off(self, rva):
        for _name, va, vsize, rawptr, rawsize in self.sections:
            if va <= rva < va + max(vsize, rawsize):
                return rva - va + rawptr
        raise PatchError("RVA 0x%X 不在任何节区内" % rva)


# --------------------------------------------------------------------------
# .NET 元数据解析（只解析到 MethodDef 为止需要的那几张表）
# --------------------------------------------------------------------------
# 表编号
T_MODULE, T_TYPEREF, T_TYPEDEF = 0x00, 0x01, 0x02
T_FIELDPTR, T_FIELD, T_METHODPTR, T_METHODDEF = 0x03, 0x04, 0x05, 0x06
T_PARAM = 0x08

# 编码索引定义：名字 -> (涉及的表编号列表, tag 位数)
CODED_INDEX = {
    "TypeDefOrRef": ([0x02, 0x01, 0x1B], 2),
    "HasConstant": ([0x04, 0x08, 0x17], 2),
    "HasCustomAttribute": ([0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00,
                            0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23,
                            0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B], 5),
    "HasFieldMarshal": ([0x04, 0x08], 1),
    "HasDeclSecurity": ([0x02, 0x06, 0x20], 2),
    "MemberRefParent": ([0x02, 0x01, 0x1A, 0x06, 0x1B], 3),
    "HasSemantics": ([0x14, 0x17], 1),
    "MethodDefOrRef": ([0x06, 0x0A], 1),
    "MemberForwarded": ([0x04, 0x06], 1),
    "Implementation": ([0x26, 0x23, 0x27], 2),
    "CustomAttributeType": ([0xFF, 0xFF, 0x06, 0x0A, 0xFF], 3),
    "ResolutionScope": ([0x00, 0x1A, 0x23, 0x01], 2),
    "TypeOrMethodDef": ([0x02, 0x06], 1),
}

# 需要的表的列布局（只到 0x06，之后的表不影响前面的偏移）
TABLE_LAYOUT = {
    T_MODULE:    [("Generation", ("const", 2)), ("Name", ("str",)),
                  ("Mvid", ("guid",)), ("EncId", ("guid",)), ("EncBaseId", ("guid",))],
    T_TYPEREF:   [("ResolutionScope", ("coded", "ResolutionScope")),
                  ("Name", ("str",)), ("Namespace", ("str",))],
    T_TYPEDEF:   [("Flags", ("const", 4)), ("Name", ("str",)), ("Namespace", ("str",)),
                  ("Extends", ("coded", "TypeDefOrRef")),
                  ("FieldList", ("table", T_FIELD)), ("MethodList", ("table", T_METHODDEF))],
    T_FIELDPTR:  [("Field", ("table", T_FIELD))],
    T_FIELD:     [("Flags", ("const", 2)), ("Name", ("str",)), ("Signature", ("blob",))],
    T_METHODPTR: [("Method", ("table", T_METHODDEF))],
    T_METHODDEF: [("RVA", ("const", 4)), ("ImplFlags", ("const", 2)), ("Flags", ("const", 2)),
                  ("Name", ("str",)), ("Signature", ("blob",)), ("ParamList", ("table", T_PARAM))],
}


class Metadata(object):
    def __init__(self, pe):
        self.data = pe.data
        data = self.data
        off = pe.rva_to_off(pe.md_rva)
        if _u32(data, off) != 0x424A5342:
            raise PatchError("元数据签名错误（不是合法的 .NET 元数据）")
        ver_len = _u32(data, off + 12)
        p = off + 16 + ver_len
        nstreams = _u16(data, p + 2)
        p += 4
        self.streams = {}
        for _ in range(nstreams):
            s_off = _u32(data, p)
            s_size = _u32(data, p + 4)
            end = data.index(b"\0", p + 8)
            name = data[p + 8:end].decode("ascii", "replace")
            self.streams[name] = (off + s_off, s_size)
            p = end + 1
            p = (p + 3) & ~3

        tabs = self.streams.get("#~") or self.streams.get("#-")
        if tabs is None:
            raise PatchError("找不到 #~ 表流")
        o = tabs[0]
        heap = _u8(data, o + 6)
        valid = struct.unpack_from("<Q", data, o + 8)[0]
        p = o + 24
        self.rowcount = {}
        for t in range(64):
            if (valid >> t) & 1:
                self.rowcount[t] = _u32(data, p)
                p += 4

        self.str_size = 4 if (heap & 0x01) else 2
        self.guid_size = 4 if (heap & 0x02) else 2
        self.blob_size = 4 if (heap & 0x04) else 2

        # 计算需要的表的数据起始偏移
        self.tables = {}
        for t in range(64):
            if t not in self.rowcount:
                continue
            if t <= T_METHODDEF:
                row_size = self._row_size(t)
                self.tables[t] = [p, self.rowcount[t], row_size]
                p += row_size * self.rowcount[t]
            else:
                break

    # ---- 行大小 ----
    def _idx_size(self, table_id):
        return 4 if self.rowcount.get(table_id, 0) >= 0x10000 else 2

    def _coded_size(self, name):
        tables, bits = CODED_INDEX[name]
        mx = 0
        for t in tables:
            if t == 0xFF:
                continue
            mx = max(mx, self.rowcount.get(t, 0))
        return 4 if mx >= (1 << (16 - bits)) else 2

    def _row_size(self, table_id):
        total = 0
        for _name, kind in TABLE_LAYOUT[table_id]:
            if kind[0] == "const":
                total += kind[1]
            elif kind[0] == "str":
                total += self.str_size
            elif kind[0] == "guid":
                total += self.guid_size
            elif kind[0] == "blob":
                total += self.blob_size
            elif kind[0] == "table":
                total += self._idx_size(kind[1])
            elif kind[0] == "coded":
                total += self._coded_size(kind[1])
            else:
                raise PatchError("未知列类型 %r" % (kind,))
        return total

    # ---- 读取某张表的全部行 ----
    def read_table(self, table_id):
        if table_id not in self.tables:
            return []
        base, count, row_size = self.tables[table_id]
        layout = TABLE_LAYOUT[table_id]
        rows = []
        for i in range(count):
            o = base + i * row_size
            row = {}
            for name, kind in layout:
                k = kind[0]
                if k == "const":
                    n = kind[1]
                    if n == 2:
                        row[name] = _u16(self.data, o)
                    elif n == 4:
                        row[name] = _u32(self.data, o)
                    o += n
                elif k == "str":
                    row[name] = self._read_index(o, self.str_size)
                    o += self.str_size
                elif k == "guid":
                    row[name] = self._read_index(o, self.guid_size)
                    o += self.guid_size
                elif k == "blob":
                    row[name] = self._read_index(o, self.blob_size)
                    o += self.blob_size
                elif k == "table":
                    row[name] = self._read_index(o, self._idx_size(kind[1]))
                    o += self._idx_size(kind[1])
                elif k == "coded":
                    row[name] = self._read_index(o, self._coded_size(kind[1]))
                    o += self._coded_size(kind[1])
            rows.append(row)
        return rows

    def _read_index(self, o, size):
        return _u32(self.data, o) if size == 4 else _u16(self.data, o)

    # ---- 字符串堆 ----
    def get_string(self, index):
        base = self.streams["#Strings"][0]
        end = self.data.index(b"\0", base + index)
        return self.data[base + index:end].decode("utf-8", "replace")


# --------------------------------------------------------------------------
# IL 指令长度表
# --------------------------------------------------------------------------
_OPERAND_LEN = {}


def _fill():
    for op in range(0x00, 0x10):
        _OPERAND_LEN[op] = 0                     # nop/break/ldarg.0-3/ldloc.0-3/stloc.0-3
    for op in (0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F):
        _OPERAND_LEN[op] = 1                     # ldarg.s ... ldc.i4.s
    for op in (0x14, 0x15):
        _OPERAND_LEN[op] = 0
    for op in range(0x16, 0x1F):
        _OPERAND_LEN[op] = 0                     # ldc.i4.0 .. ldc.i4.8
    _OPERAND_LEN[0x20] = 4
    _OPERAND_LEN[0x21] = 8
    _OPERAND_LEN[0x22] = 4
    _OPERAND_LEN[0x23] = 8
    _OPERAND_LEN[0x25] = 0
    _OPERAND_LEN[0x26] = 0
    for op in (0x27, 0x28, 0x29):
        _OPERAND_LEN[op] = 4                     # jmp / call / calli
    _OPERAND_LEN[0x2A] = 0
    for op in range(0x2B, 0x38):
        _OPERAND_LEN[op] = 1                     # 短跳转
    for op in range(0x38, 0x45):
        _OPERAND_LEN[op] = 4                     # 长跳转
    _OPERAND_LEN[0x45] = -1                      # switch 特殊处理
    for op in range(0x46, 0x6F):
        _OPERAND_LEN[op] = 0                     # 各种运算/转换
    _OPERAND_LEN[0x6F] = 4                       # callvirt
    for op in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79,
               0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F,
               0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0):
        _OPERAND_LEN[op] = 4
    for op in range(0x76, 0x79):
        _OPERAND_LEN[op] = 0
    _OPERAND_LEN[0x7A] = 0
    for op in range(0x82, 0x8C):
        _OPERAND_LEN[op] = 0
    _OPERAND_LEN[0x8E] = 0
    for op in range(0x90, 0xA3):
        _OPERAND_LEN[op] = 0
    _OPERAND_LEN[0xA3] = 4
    _OPERAND_LEN[0xA4] = 4
    _OPERAND_LEN[0xA5] = 4
    for op in range(0xB3, 0xBB):
        _OPERAND_LEN[op] = 0
    _OPERAND_LEN[0xC3] = 0
    for op in range(0xD1, 0xDD):
        _OPERAND_LEN[op] = 0                     # conv.u2..endfinally
    _OPERAND_LEN[0xDC] = 0
    _OPERAND_LEN[0xDD] = 4                       # leave
    _OPERAND_LEN[0xDE] = 1                       # leave.s
    _OPERAND_LEN[0xDF] = 0                       # stind.i
    _OPERAND_LEN[0xE0] = 0                       # conv.u


_fill()

_OPERAND_LEN_FE = {
    0x00: 0, 0x01: 0, 0x02: 0, 0x03: 0, 0x04: 0, 0x05: 0,
    0x06: 4, 0x07: 4, 0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2, 0x0E: 2,
    0x0F: 0, 0x11: 0, 0x12: 1, 0x13: 0, 0x14: 0, 0x15: 4, 0x16: 4,
    0x17: 0, 0x18: 0, 0x19: 1, 0x1A: 0, 0x1C: 4, 0x1D: 0, 0x1E: 0,
}


def decode_il(code):
    """返回 [(offset, opcode_int, operand_len)]，遇到不认识的指令抛错"""
    out = []
    i = 0
    n = len(code)
    while i < n:
        start = i
        op = code[i]
        if op == 0xFE:
            if i + 1 >= n:
                raise PatchError("IL 解析失败：截断的 0xFE 前缀")
            op2 = code[i + 1]
            if op2 not in _OPERAND_LEN_FE:
                raise PatchError("IL 解析失败：未知的 0xFE%02X 指令" % op2)
            i += 2
            ln = _OPERAND_LEN_FE[op2]
            out.append((start, 0xFE00 | op2, ln))
        else:
            if op not in _OPERAND_LEN:
                raise PatchError("IL 解析失败：未知的指令 0x%02X @ IL_%04X" % (op, start))
            i += 1
            ln = _OPERAND_LEN[op]
            out.append((start, op, ln))
        if ln == -1:                              # switch
            cnt = _u32(code, i)
            i += 4 + 4 * cnt
        else:
            i += ln
        if i > n:
            raise PatchError("IL 解析失败：指令越过方法体末尾")
    return out


# --------------------------------------------------------------------------
# 定位并修改
# --------------------------------------------------------------------------
def locate_method(data):
    """
    解析 DLL，定位 nel.MosaicShower::FnDrawMosaic 的 return true/false。
    返回 dict：{'code_file_offset','il_offset','file_offset','state','method_rva'}
      state: 'original' / 'patched'
    """
    pe = PEFile(data)
    md = Metadata(pe)

    typedefs = md.read_table(T_TYPEDEF)
    methoddefs = md.read_table(T_METHODDEF)
    if not typedefs or not methoddefs:
        raise PatchError("元数据里没有 TypeDef / MethodDef 表")

    # 若存在 MethodPtr 表（编辑并继续的元数据），MethodList 指向它
    methodptrs = md.read_table(T_METHODPTR)

    target_type = None
    for i, td in enumerate(typedefs):
        ns = md.get_string(td["Namespace"])
        nm = md.get_string(td["Name"])
        if ns == TARGET_NAMESPACE and nm == TARGET_TYPE:
            target_type = (i, td)
            break
    if target_type is None:
        raise PatchError("没有找到类型 %s.%s（可能不是这个游戏版本的 DLL）" % (TARGET_NAMESPACE, TARGET_TYPE))

    ti, td = target_type
    start = td["MethodList"]
    if ti + 1 < len(typedefs):
        end = typedefs[ti + 1]["MethodList"]
    else:
        end = len(methoddefs) + 1
    if start < 1 or end > len(methoddefs) + 1:
        raise PatchError("MethodList 范围异常，元数据可能已损坏")

    found = None
    for row in range(start, end):
        midx = row
        if methodptrs:
            if row - 1 >= len(methodptrs):
                break
            midx = methodptrs[row - 1]["Method"]
        if midx - 1 < 0 or midx - 1 >= len(methoddefs):
            continue
        mdef = methoddefs[midx - 1]
        if md.get_string(mdef["Name"]) == TARGET_METHOD:
            found = mdef
            break
    if found is None:
        raise PatchError("类型找到了，但里面没有方法 %s" % TARGET_METHOD)

    rva = found["RVA"]
    if rva == 0:
        raise PatchError("方法 %s 没有方法体（RVA=0）" % TARGET_METHOD)

    body_off = pe.rva_to_off(rva)
    hdr = _u8(data, body_off)
    if (hdr & 3) == 2:                            # tiny 头
        code_size = hdr >> 2
        code_off = body_off + 1
    elif (hdr & 3) == 3:                          # fat 头
        flags = _u16(data, body_off)
        header_size = (flags >> 12) * 4
        if header_size < 12:
            raise PatchError("方法体 fat 头长度异常")
        code_size = _u32(data, body_off + 4)
        code_off = body_off + header_size
    else:
        raise PatchError("方法体头格式无效（0x%02X）" % hdr)

    code = data[code_off:code_off + code_size]
    instrs = decode_il(code)
    if len(instrs) < 2:
        raise PatchError("方法体太短，无法识别末尾的 return")

    last_off, last_op, _ = instrs[-1]
    prev_off, prev_op, _ = instrs[-2]
    if last_op != RET:
        raise PatchError("方法末尾不是 ret（0x%02X），未做任何修改" % last_op)
    if prev_op == LDC_I4_1:
        state = "original"
    elif prev_op == LDC_I4_0:
        state = "patched"
    else:
        raise PatchError("方法末尾的 return 前不是 ldc.i4.1 / ldc.i4.0，"
                         "而是 0x%02X，为安全起见未做修改" % prev_op)

    return {
        "method_rva": rva,
        "code_file_offset": code_off,
        "il_offset": prev_off,
        "file_offset": code_off + prev_off,
        "state": state,
        "code_size": code_size,
        "instr_count": len(instrs),
    }


def analyze(path):
    """读取文件并返回状态信息（不修改）"""
    with open(path, "rb") as f:
        data = f.read()
    info = locate_method(data)
    info["file_size"] = len(data)
    info["md5"] = hashlib.md5(data).hexdigest().upper()
    return info


def apply_patch(path):
    """把末尾的 ldc.i4.1 改成 ldc.i4.0；返回 (旧状态, 新信息)"""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    info = locate_method(bytes(data))
    if info["state"] == "patched":
        return info, info, False
    off = info["file_offset"]
    if data[off] != LDC_I4_1:
        raise PatchError("目标字节不是 0x17，实际为 0x%02X，已中止" % data[off])
    data[off] = LDC_I4_0
    with open(path, "wb") as f:
        f.write(bytes(data))
    return info, analyze(path), True


# --------------------------------------------------------------------------
# 备份 / 配置文件
# --------------------------------------------------------------------------
def backup_path_for(target):
    return target + BACKUP_SUFFIX


def config_path_for(target):
    return os.path.join(os.path.dirname(os.path.abspath(target)), CONFIG_NAME)


def read_config(target):
    """只读目标所在目录的配置文件；不存在返回 None"""
    cfg_path = config_path_for(target)
    if not os.path.isfile(cfg_path):
        return None
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"__broken__": True}


def write_config(target, cfg):
    cfg_path = config_path_for(target)
    tmp = cfg_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, cfg_path)
    return cfg_path


def build_status(target):
    """汇总目标的完整状态，供界面/命令行展示"""
    st = {
        "target": os.path.abspath(target),
        "dir": os.path.dirname(os.path.abspath(target)),
        "name": os.path.basename(target),
        "exists": os.path.isfile(target),
        "config_path": config_path_for(target),
        "backup_path": backup_path_for(target),
    }
    if not st["exists"]:
        raise PatchError("文件不存在：%s" % target)

    try:
        st["rel_path"] = os.path.relpath(st["target"], program_dir())
    except ValueError:
        st["rel_path"] = st["target"] + "（与程序不在同一盘符，无法给出相对路径）"
    st["path_ok"] = is_game_dll_path(st["target"])
    st["file_size"] = os.path.getsize(target)
    st["md5"] = md5_file(target)
    st["config"] = read_config(target)

    st["backup_exists"] = os.path.isfile(st["backup_path"])
    st["backup_size"] = os.path.getsize(st["backup_path"]) if st["backup_exists"] else None
    st["backup_md5"] = md5_file(st["backup_path"]) if st["backup_exists"] else None

    try:
        info = locate_method(open(target, "rb").read())
        st["target_ok"] = True
        st["method_rva"] = info["method_rva"]
        st["file_offset"] = info["file_offset"]
        st["il_offset"] = info["il_offset"]
        st["patched"] = (info["state"] == "patched")
        st["target_error"] = None
    except PatchError as e:
        st["target_ok"] = False
        st["patched"] = None
        st["target_error"] = str(e)

    cfg = st["config"] or {}
    recorded = cfg.get("backup_md5")
    if st["backup_exists"] and recorded:
        st["backup_intact"] = (st["backup_md5"] == str(recorded).upper())
    else:
        st["backup_intact"] = None
    st["backup_recorded_md5"] = recorded

    # 当前文件处于什么状态（以 IL 为准），再单独给一行完整性比对
    cfg = st["config"] or {}
    if st["target_ok"]:
        # return false = 不画马赛克；return true = 画马赛克
        st["state_text"] = "无马赛克（已去马赛克）" if st["patched"] else "有马赛克（未修改）"
        patched_md5 = cfg.get("patched_md5")
        original_md5 = cfg.get("original_md5")
        if st["patched"]:
            if patched_md5 and st["md5"] == str(patched_md5).upper():
                st["integrity_text"] = "与配置记录的补丁 MD5 一致 ✔"
            elif patched_md5:
                st["integrity_text"] = "⚠ 已修改，但 MD5 与配置记录不符（文件被其它改动过？）"
            else:
                st["integrity_text"] = "（配置里没有补丁 MD5 记录）"
        else:
            if original_md5 and st["md5"] == str(original_md5).upper():
                st["integrity_text"] = "与配置记录的原始 MD5 一致 ✔"
            elif st["backup_exists"] and st["md5"] == st["backup_md5"]:
                st["integrity_text"] = "与备份文件 MD5 一致 ✔"
            elif original_md5:
                st["integrity_text"] = "⚠ 未修改，但 MD5 与配置记录的原始值不符（文件被其它改动过？）"
            else:
                st["integrity_text"] = "（配置里没有原始 MD5 记录）"
    else:
        st["state_text"] = "无法识别"
        st["integrity_text"] = "—"
    return st


def do_patch(target, make_backup=True):
    """执行修改；返回人类可读的操作日志"""
    logs = []
    if not os.path.isfile(target):
        raise PatchError("文件不存在：%s" % target)

    bpath = backup_path_for(target)
    cfg = read_config(target) or {}

    before = analyze(target)
    if before["state"] == "patched":
        logs.append("无需修改：目标方法已经处于「无马赛克」状态（return false）。")
        return logs

    before_md5 = before["md5"]

    if make_backup:
        if os.path.isfile(bpath):
            logs.append("备份已存在，未覆盖：%s" % os.path.basename(bpath))
            if not cfg.get("backup_md5"):
                cfg["backup_md5"] = md5_file(bpath)
            if not cfg.get("original_md5"):
                cfg["original_md5"] = cfg["backup_md5"]
        else:
            with open(target, "rb") as src, open(bpath, "wb") as dst:
                dst.write(src.read())
            logs.append("已创建备份：%s" % os.path.basename(bpath))
            cfg["backup_md5"] = md5_file(bpath)
            cfg["original_md5"] = cfg["backup_md5"]
            logs.append("备份 MD5：%s" % cfg["backup_md5"])
        cfg["backup_created"] = True
        cfg["backup_file"] = os.path.basename(bpath)
    else:
        logs.append("按设置跳过备份。")

    old_info, new_info, changed = apply_patch(target)
    if not changed:
        logs.append("无需修改：目标方法已经处于「无马赛克」状态（return false）。")
        return logs

    logs.append("已去马赛克：IL_%04X 的 ldc.i4.1(0x17) → ldc.i4.0(0x16)" % old_info["il_offset"])
    logs.append("文件偏移：0x%X" % old_info["file_offset"])

    cfg["app"] = APP_NAME
    cfg["version"] = APP_VERSION
    cfg["target_file"] = os.path.basename(target)
    cfg["target_dir"] = os.path.dirname(os.path.abspath(target))
    cfg["patched_md5"] = new_info["md5"]
    cfg["state"] = "patched"
    cfg["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if "original_md5" not in cfg:
        cfg["original_md5"] = before_md5
    cfg["backup_created"] = os.path.isfile(bpath)
    if os.path.isfile(bpath) and "backup_md5" not in cfg:
        cfg["backup_md5"] = md5_file(bpath)
        cfg["backup_file"] = os.path.basename(bpath)
    cpath = write_config(target, cfg)
    logs.append("补丁后 MD5：%s" % new_info["md5"])
    logs.append("配置已写入：%s" % os.path.basename(cpath))
    return logs


def do_restore(target, force=False):
    """用备份还原；返回操作日志"""
    logs = []
    if not os.path.isfile(target):
        raise PatchError("文件不存在：%s" % target)
    bpath = backup_path_for(target)
    if not os.path.isfile(bpath):
        raise PatchError("没有找到备份文件：%s" % bpath)

    cfg = read_config(target) or {}
    backup_md5 = md5_file(bpath)
    recorded = cfg.get("backup_md5")
    if recorded and str(recorded).upper() != backup_md5:
        if not force:
            raise PatchError(
                "备份文件已被改动！\n  配置记录: %s\n  当前实际: %s\n"
                "（确认无误可用 --force / 界面上的确认框强制还原）"
                % (str(recorded).upper(), backup_md5))
        logs.append("警告：备份 MD5 与配置记录不一致，按用户要求强制还原。")

    with open(bpath, "rb") as src, open(target, "wb") as dst:
        dst.write(src.read())
    logs.append("已用备份还原：%s" % os.path.basename(bpath))
    logs.append("还原后 MD5：%s" % md5_file(target))

    cfg["app"] = APP_NAME
    cfg["version"] = APP_VERSION
    cfg["target_file"] = os.path.basename(target)
    cfg["target_dir"] = os.path.dirname(os.path.abspath(target))
    cfg["backup_file"] = os.path.basename(bpath)
    cfg["backup_created"] = True
    cfg["backup_md5"] = backup_md5
    cfg["restored_md5"] = md5_file(target)
    cfg["state"] = "restored"
    cfg["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cpath = write_config(target, cfg)
    logs.append("配置已更新：%s" % os.path.basename(cpath))
    return logs


# --------------------------------------------------------------------------
# 命令行模式
# --------------------------------------------------------------------------
def cli_main(argv):
    if "--gui-selftest" in argv:
        return gui_selftest()
    if "--find" in argv:
        base = None
        if "--base" in argv:
            base = argv[argv.index("--base") + 1]
        cands = auto_find_targets(base)
        if not cands:
            print("未找到候选（只认 ...\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll）")
            return 1
        for p, rel, src in cands:
            print("[%s] %s" % (src, p))
            print("          相对路径: %s" % rel)
        return 0
    if "--status" in argv:
        target = argv[argv.index("--status") + 1]
        try:
            st = build_status(target)
        except PatchError as e:
            print("错误：%s" % e)
            return 1
        print("文件        : %s" % st["target"])
        print("相对路径    : %s   %s" % (
            st["rel_path"],
            "✔ 路径形态正确" if st["path_ok"]
            else "⚠ 不是 ...\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll"))
        print("大小        : %d 字节" % st["file_size"])
        print("MD5         : %s" % st["md5"])
        if st["target_ok"]:
            print("方法        : %s.%s::%s  (RVA 0x%X)"
                  % (TARGET_NAMESPACE, TARGET_TYPE, TARGET_METHOD, st["method_rva"]))
            print("IL 位置     : IL_%04X  文件偏移 0x%X" % (st["il_offset"], st["file_offset"]))
        else:
            print("方法        : 未找到 -> %s" % st["target_error"])
        print("当前状态    : %s" % st["state_text"])
        print("完整性      : %s" % st["integrity_text"])
        print("配置文件    : %s%s" % (st["config_path"], "" if st["config"] else "（不存在）"))
        print("备份文件    : %s" % st["backup_path"])
        print("备份存在    : %s" % ("是" if st["backup_exists"] else "否"))
        if st["backup_exists"]:
            print("备份 MD5    : %s" % st["backup_md5"])
            if st["backup_intact"] is None:
                print("备份校验    : 配置里没有记录")
            else:
                print("备份校验    : %s" % ("一致（未被改动）" if st["backup_intact"] else "不一致（备份已被改动！）"))
        return 0
    if "--patch" in argv:
        target = argv[argv.index("--patch") + 1]
        try:
            for line in do_patch(target, make_backup=("--no-backup" not in argv)):
                print(line)
        except PatchError as e:
            print("错误：%s" % e)
            return 1
        return 0
    if "--restore" in argv:
        target = argv[argv.index("--restore") + 1]
        try:
            for line in do_restore(target, force=("--force" in argv)):
                print(line)
        except PatchError as e:
            print("错误：%s" % e)
            return 1
        return 0
    print(__doc__)
    return 0


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
def run_gui(selftest=False):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    class App(object):
        def __init__(self, root):
            self.root = root
            self.target = None
            root.title("%s v%s —— 一键去马赛克" % (APP_NAME, APP_VERSION))
            root.geometry("860x640")
            root.minsize(740, 560)

            top = ttk.Frame(root, padding=(10, 10, 10, 4))
            top.pack(fill="x")
            ttk.Label(top, text="目标 DLL：").pack(side="left")
            self.var_path = tk.StringVar(value="（尚未选择文件）")
            ttk.Entry(top, textvariable=self.var_path, state="readonly").pack(
                side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Button(top, text="自动搜索", command=self.auto_search).pack(side="left")
            ttk.Button(top, text="选择文件…", command=self.choose).pack(side="left", padx=(6, 0))

            opt = ttk.Frame(root, padding=(10, 0, 10, 4))
            opt.pack(fill="x")
            self.var_backup = tk.BooleanVar(value=True)
            ttk.Checkbutton(opt, text="修改前自动备份（备份文件放在 DLL 同目录）",
                            variable=self.var_backup).pack(side="left")

            mid = ttk.LabelFrame(root, text="状态", padding=8)
            mid.pack(fill="both", expand=True, padx=10, pady=4)
            self.txt = tk.Text(mid, height=18, wrap="none", font=("Consolas", 10))
            self.txt.pack(fill="both", expand=True)
            self.txt.configure(state="disabled")

            btns = ttk.Frame(root, padding=(10, 4, 10, 4))
            btns.pack(fill="x")
            self.btn_patch = ttk.Button(btns, text="执行去马赛克",
                                        command=self.on_patch, state="disabled")
            self.btn_patch.pack(side="left")
            self.btn_restore = ttk.Button(btns, text="还原备份",
                                          command=self.on_restore, state="disabled")
            self.btn_restore.pack(side="left", padx=6)
            ttk.Button(btns, text="刷新状态", command=self.refresh).pack(side="left")
            ttk.Button(btns, text="打开所在目录", command=self.open_dir).pack(side="left", padx=6)

            logf = ttk.LabelFrame(root, text="日志", padding=6)
            logf.pack(fill="both", padx=10, pady=(0, 10))
            self.log = tk.Text(logf, height=7, wrap="word", font=("Consolas", 9))
            self.log.pack(fill="both", expand=True)

            self.set_text("正在自动搜索 Assembly-CSharp.dll……\n"
                          "（只认 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll 这种路径）")
            self.write_log("就绪。")
            # 启动即自动搜索一次
            self.root.after(60, lambda: self.auto_search(silent=True))

        # ---------- 辅助 ----------
        def set_text(self, s):
            self.txt.configure(state="normal")
            self.txt.delete("1.0", "end")
            self.txt.insert("1.0", s)
            self.txt.configure(state="disabled")

        def write_log(self, s):
            ts = time.strftime("%H:%M:%S")
            self.log.insert("end", "[%s] %s\n" % (ts, s))
            self.log.see("end")

        # ---------- 动作 ----------
        def _select(self, path):
            self.target = path
            self.var_path.set(path)
            self.refresh()

        def choose(self):
            p = filedialog.askopenfilename(
                title="选择 Assembly-CSharp.dll",
                filetypes=[("托管程序集", "*.dll"), ("所有文件", "*.*")])
            if not p:
                return
            p = os.path.abspath(p)
            if not is_game_dll_path(p):
                if not messagebox.askyesno(
                        APP_NAME,
                        "这个路径不是标准的游戏路径：\n%s\n\n"
                        "标准形态应该是：\n…\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll\n\n"
                        "可能不是你想要的 DLL。仍要使用它吗？" % p):
                    return
            self.write_log("手动选择：%s" % p)
            self._select(p)

        def auto_search(self, silent=False):
            cands = auto_find_targets()
            if not cands:
                self.write_log("自动搜索：未找到 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll")
                if not silent:
                    messagebox.showwarning(
                        APP_NAME,
                        "没有自动找到 Assembly-CSharp.dll。\n\n"
                        "只搜索了：\n"
                        "  1) 程序所在目录\n"
                        "  2) 上一级目录（1 层）\n"
                        "  3) 程序目录下的所有子目录\n\n"
                        "而且只认路径形如 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll 的文件。\n"
                        "请手动点「选择文件…」。")
                else:
                    self.set_text("未自动找到 Assembly-CSharp.dll。\n"
                                  "请点「自动搜索」重试，或点「选择文件…」手动选择。")
                return
            for p, rel, src in cands:
                self.write_log("自动搜索命中 [%s] %s" % (src, p))
            pick = cands[0][0]
            if len(cands) > 1:
                if silent:
                    self.write_log("共找到 %d 个候选，已默认选用优先级最高的一个；"
                                   "可点「自动搜索」重新挑选。" % len(cands))
                else:
                    chosen = self._ask_candidate(cands)
                    if chosen is None:
                        return
                    pick = chosen
            self.write_log("自动搜索选用：%s" % pick)
            self._select(pick)

        def _ask_candidate(self, cands):
            """多个候选时弹一个小窗让用户挑"""
            win = tk.Toplevel(self.root)
            win.title("找到多个 Assembly-CSharp.dll")
            win.transient(self.root)
            win.grab_set()
            ttk.Label(win, text="找到 %d 个符合路径形态的候选，请选择要操作的文件："
                      % len(cands)).pack(anchor="w", padx=10, pady=(10, 4))
            lb = tk.Listbox(win, width=110, height=min(10, len(cands)))
            lb.pack(fill="both", expand=True, padx=10, pady=(0, 6))
            for p, rel, src in cands:
                lb.insert("end", "[%s] %s" % (src, p))
            lb.selection_set(0)
            result = {"v": None}

            def ok():
                sel = lb.curselection()
                if sel:
                    result["v"] = cands[sel[0]][0]
                win.destroy()

            bar = ttk.Frame(win, padding=(10, 0, 10, 10))
            bar.pack(fill="x")
            ttk.Button(bar, text="取消", command=win.destroy).pack(side="right")
            ttk.Button(bar, text="确定", command=ok).pack(side="right", padx=6)
            lb.bind("<Double-Button-1>", lambda e: ok())
            self.root.wait_window(win)
            return result["v"]

        def refresh(self):
            if not self.target:
                return
            try:
                st = build_status(self.target)
            except PatchError as e:
                self.set_text("读取失败：%s" % e)
                self.write_log("读取失败：%s" % e)
                self.btn_patch.configure(state="disabled")
                self.btn_restore.configure(state="disabled")
                return
            except Exception as e:
                self.set_text("读取失败：%r" % e)
                self.write_log("读取失败：%r" % e)
                return

            L = []
            L.append("【目标文件】")
            L.append("  路径      : %s" % st["target"])
            L.append("  相对路径  : %s" % st["rel_path"])
            L.append("  路径校验  : %s" % (
                "✔ 形如 …\\AliceInCradle_Data\\Managed\\Assembly-CSharp.dll"
                if st["path_ok"] else
                "⚠ 不是标准游戏路径，请确认选对文件"))
            L.append("  大小      : %d 字节" % st["file_size"])
            L.append("  MD5       : %s" % st["md5"])
            L.append("")
            L.append("【方法定位】")
            if st["target_ok"]:
                L.append("  目标      : %s.%s::%s"
                         % (TARGET_NAMESPACE, TARGET_TYPE, TARGET_METHOD))
                L.append("  Method RVA: 0x%X" % st["method_rva"])
                L.append("  IL 位置   : IL_%04X   （文件偏移 0x%X）"
                         % (st["il_offset"], st["file_offset"]))
                L.append("  当前状态  : %s" % st["state_text"])
                L.append("  完整性    : %s" % st["integrity_text"])
            else:
                L.append("  失败      : %s" % st["target_error"])
            L.append("")
            L.append("【备份 / 配置文件】（都在 DLL 同目录）")
            L.append("  配置文件  : %s" % st["config_path"])
            if st["config"] is None:
                L.append("              （不存在，本次将新建）")
            elif st["config"].get("__broken__"):
                L.append("              （存在但无法解析，将覆盖重建）")
            else:
                cfg = st["config"]
                L.append("              记录状态 : %s" % cfg.get("state", "?"))
                L.append("              是否备份 : %s"
                         % ("是" if cfg.get("backup_created") else "否"))
                L.append("              更新时间 : %s" % cfg.get("updated_at", "?"))
            L.append("  备份文件  : %s" % st["backup_path"])
            if not st["backup_exists"]:
                L.append("              不存在（执行修改时会自动创建）")
            else:
                L.append("              存在，%d 字节" % st["backup_size"])
                L.append("              备份 MD5 : %s" % st["backup_md5"])
                if st["backup_intact"] is None:
                    L.append("              校验结果 : 配置里没有记录，无法比对")
                elif st["backup_intact"]:
                    L.append("              校验结果 : 与配置记录一致 ✔（备份未被改动）")
                else:
                    L.append("              校验结果 : 与配置记录不一致 ✘（备份已被改动！）")
                    L.append("                         配置记录 : %s" % st["backup_recorded_md5"])
            self.set_text("\n".join(L))

            can_patch = st["target_ok"] and not st["patched"]
            self.btn_patch.configure(state=("normal" if can_patch else "disabled"))
            self.btn_restore.configure(state=("normal" if st["backup_exists"] else "disabled"))

        def on_patch(self):
            if not self.target:
                return
            try:
                st = build_status(self.target)
            except Exception as e:
                messagebox.showerror(APP_NAME, "读取失败：%r" % e)
                return
            if not st["target_ok"]:
                messagebox.showerror(APP_NAME, "无法定位目标方法：\n%s" % st["target_error"])
                return
            if st["patched"]:
                messagebox.showinfo(APP_NAME, "当前已经是「无马赛克」状态，无需再处理。")
                return
            if not messagebox.askyesno(
                    APP_NAME,
                    "即将去马赛克：\n%s\n\n当前状态：有马赛克\n处理之后：无马赛克\n\n"
                    "（原理：把 %s.%s::%s 末尾的 return true 改成 return false）\n\n%s"
                    % (st["target"], TARGET_NAMESPACE, TARGET_TYPE, TARGET_METHOD,
                       "会先自动备份。" if self.var_backup.get() else "注意：你取消了自动备份！")):
                return
            try:
                for line in do_patch(self.target, make_backup=self.var_backup.get()):
                    self.write_log(line)
            except PatchError as e:
                messagebox.showerror(APP_NAME, str(e))
                self.write_log("去马赛克失败：%s" % e)
            except PermissionError:
                messagebox.showerror(APP_NAME, "文件被占用，无法写入。\n请先完全关闭游戏再试。")
                self.write_log("写入失败：文件被占用")
            except Exception as e:
                messagebox.showerror(APP_NAME, "去马赛克失败：%r" % e)
                self.write_log("去马赛克失败：%r" % e)
            self.refresh()

        def on_restore(self):
            if not self.target:
                return
            try:
                st = build_status(self.target)
            except Exception as e:
                messagebox.showerror(APP_NAME, "读取失败：%r" % e)
                return
            if not st["backup_exists"]:
                messagebox.showerror(APP_NAME, "没有找到备份文件：\n%s" % st["backup_path"])
                return
            warn = ""
            if st["backup_intact"] is False:
                warn = ("\n\n⚠ 警告：备份文件 MD5 与配置记录不一致，备份可能已被改动！\n"
                        "  配置记录: %s\n  当前实际: %s\n"
                        % (st["backup_recorded_md5"], st["backup_md5"]))
            if not messagebox.askyesno(
                    APP_NAME,
                    "将用备份覆盖：\n%s\n\n备份文件：\n%s%s" % (st["target"], st["backup_path"], warn)):
                return
            try:
                for line in do_restore(self.target, force=(st["backup_intact"] is False)):
                    self.write_log(line)
            except PatchError as e:
                messagebox.showerror(APP_NAME, str(e))
                self.write_log("还原失败：%s" % e)
            except PermissionError:
                messagebox.showerror(APP_NAME, "文件被占用，无法写入。\n请先完全关闭游戏再试。")
                self.write_log("还原失败：文件被占用")
            except Exception as e:
                messagebox.showerror(APP_NAME, "还原失败：%r" % e)
                self.write_log("还原失败：%r" % e)
            self.refresh()

        def open_dir(self):
            if not self.target:
                return
            try:
                os.startfile(os.path.dirname(os.path.abspath(self.target)))
            except Exception as e:
                self.write_log("打开目录失败：%r" % e)

    root = tk.Tk()
    try:
        style = ttk.Style()
        style.theme_use("vista")
    except Exception:
        pass
    App(root)
    if selftest:
        root.after(500, root.destroy)
        root.mainloop()
        print("GUI selftest OK")
        return 0
    root.mainloop()
    return 0


def gui_selftest():
    """构建一次完整界面后立刻销毁，用于自动化验证界面代码没有错误"""
    return run_gui(selftest=True)


def main():
    argv = sys.argv[1:]
    if not argv:
        return run_gui()

    # --out <文件>：把命令行输出写进文件（窗口版 exe 没有控制台时特别有用）
    out_file = None
    if "--out" in argv:
        i = argv.index("--out")
        if i + 1 < len(argv):
            out_file = argv[i + 1]
            argv = argv[:i] + argv[i + 2:]

    stream = None
    if out_file:
        try:
            stream = open(out_file, "w", encoding="utf-8")
        except OSError:
            stream = None
    if stream is None:
        stream = sys.stdout
    if stream is None:                            # 窗口化打包后没有控制台
        try:
            stream = open(os.devnull, "w", encoding="utf-8")
        except OSError:
            stream = None
    if stream is not None:
        sys.stdout = stream
        if out_file or sys.stderr is None:
            sys.stderr = stream
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    try:
        return cli_main(argv)
    finally:
        if out_file and stream is not None:
            try:
                stream.flush()
                stream.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
