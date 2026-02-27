using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace EasyInject;

public static class MiniAssembler
{

    private static readonly Dictionary<string, byte> Reg64 = new(StringComparer.OrdinalIgnoreCase)
    {
        ["rax"] = 0,
        ["rcx"] = 1,
        ["rdx"] = 2,
        ["rbx"] = 3,
        ["rsp"] = 4,
        ["rbp"] = 5,
        ["rsi"] = 6,
        ["rdi"] = 7,
        ["r8"] = 8,
        ["r9"] = 9,
        ["r10"] = 10,
        ["r11"] = 11,
        ["r12"] = 12,
        ["r13"] = 13,
        ["r14"] = 14,
        ["r15"] = 15,
    };
    private static readonly Dictionary<string, byte> Reg32 = new(StringComparer.OrdinalIgnoreCase)
    {
        ["eax"] = 0,
        ["ecx"] = 1,
        ["edx"] = 2,
        ["ebx"] = 3,
        ["esp"] = 4,
        ["ebp"] = 5,
        ["esi"] = 6,
        ["edi"] = 7,
    };

    private static readonly Dictionary<string, byte> SegPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cs"] = 0x2E,
        ["ds"] = 0x3E,
        ["es"] = 0x26,
        ["fs"] = 0x64,
        ["gs"] = 0x65,
        ["ss"] = 0x36,
    };

    public static AssemblerResult Assemble(string source, bool is64bit)
    {
        var output = new List<byte>();
        var labels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        string[] lines = source.Split('\n');

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            string raw = lines[lineNum];
            string line = StripComment(raw).Trim();
            if (string.IsNullOrWhiteSpace(line)) continue;

            if (line.EndsWith(":"))
            {
                labels[line[..^1].Trim()] = output.Count;
                continue;
            }

            try
            {
                byte[] encoded = EncodeLine(line, is64bit, output.Count, labels);
                output.AddRange(encoded);
            }
            catch (Exception ex)
            {
                return new AssemblerResult
                {
                    Success = false,
                    ErrorMessage = $"Line {lineNum + 1}: {ex.Message}  →  \"{raw.Trim()}\""
                };
            }
        }

        return new AssemblerResult { Success = true, Bytes = output.ToArray() };
    }

    private enum OperandKind { Reg64, Reg32, Imm, Mem }
    private enum OpSize { Default, Byte, Word, Dword, Qword }

    private sealed class Operand
    {
        public OperandKind Kind;
        public byte RegNum;
        public bool IsReg64;
        public long Imm;
        public MemAddr? Mem;
        public OpSize SizeHint = OpSize.Default;
    }

    private sealed class MemAddr
    {
        public byte? SegPrefix;
        public int Base = -1;
        public int Index = -1;
        public int Scale = 1;
        public long Disp = 0;
    }


    private static (string mnem, string[] ops) SplitInstruction(string line)
    {
        int sp = line.IndexOfAny(new[] { ' ', '\t' });
        if (sp < 0) return (line.ToUpperInvariant(), Array.Empty<string>());

        string mnem = line[..sp].ToUpperInvariant();
        string rest = line[sp..].Trim();
        var opStrs = new List<string>();

        int depth = 0;
        int start = 0;
        for (int i = 0; i < rest.Length; i++)
        {
            if (rest[i] == '[') depth++;
            else if (rest[i] == ']') depth--;
            else if (rest[i] == ',' && depth == 0)
            {
                opStrs.Add(rest[start..i].Trim());
                start = i + 1;
            }
        }
        if (start < rest.Length)
            opStrs.Add(rest[start..].Trim());

        return (mnem, opStrs.ToArray());
    }

    private static Operand ParseOperand(string raw)
    {
        raw = raw.Trim();

        var sizeHint = OpSize.Default;
        string lo = raw.ToLowerInvariant();
        if (lo.StartsWith("qword ptr ")) { sizeHint = OpSize.Qword; raw = raw[10..].Trim(); }
        else if (lo.StartsWith("dword ptr ")) { sizeHint = OpSize.Dword; raw = raw[10..].Trim(); }
        else if (lo.StartsWith("word ptr ")) { sizeHint = OpSize.Word; raw = raw[9..].Trim(); }
        else if (lo.StartsWith("byte ptr ")) { sizeHint = OpSize.Byte; raw = raw[9..].Trim(); }

        if (Reg64.TryGetValue(raw, out byte r64))
            return new Operand { Kind = OperandKind.Reg64, RegNum = r64, IsReg64 = true, SizeHint = sizeHint };
        if (Reg32.TryGetValue(raw, out byte r32))
            return new Operand { Kind = OperandKind.Reg32, RegNum = r32, IsReg64 = false, SizeHint = sizeHint };

        int lbracket = raw.IndexOf('[');
        if (lbracket >= 0)
        {
            int rbracket = raw.IndexOf(']', lbracket);
            if (rbracket < 0) throw new Exception($"Unmatched '[' in '{raw}'");

            var mem = new MemAddr();

            if (lbracket > 0)
            {
                string seg = raw[..lbracket].TrimEnd(':').Trim();
                if (SegPrefixes.TryGetValue(seg, out byte sp))
                    mem.SegPrefix = sp;
                else
                    throw new Exception($"Unknown segment register '{seg}'");
            }

            string inner = raw[(lbracket + 1)..rbracket].Trim();
            ParseMemExpr(inner, mem);

            return new Operand { Kind = OperandKind.Mem, Mem = mem, SizeHint = sizeHint };
        }

        return new Operand { Kind = OperandKind.Imm, Imm = ParseImmL(raw), SizeHint = sizeHint };
    }


    private static void ParseMemExpr(string expr, MemAddr mem)
    {
        var tokens = TokeniseMemExpr(expr);

        foreach (var (sign, tok) in tokens)
        {
            if (tok.Contains('*'))
            {
                string[] parts = tok.Split('*');
                string regPart = parts[0].Trim();
                string scalePart = parts[1].Trim();

                if (!Reg64.TryGetValue(regPart, out byte ireg))
                    throw new Exception($"Expected 64-bit register for SIB index, got '{regPart}'");
                int scale = (int)ParseImmL(scalePart);
                if (scale != 1 && scale != 2 && scale != 4 && scale != 8)
                    throw new Exception($"Scale must be 1, 2, 4 or 8; got {scale}");

                mem.Index = ireg;
                mem.Scale = scale;
            }
            else if (Reg64.TryGetValue(tok, out byte breg))
            {
                if (mem.Base == -1)
                    mem.Base = breg;
                else if (mem.Index == -1)
                    mem.Index = breg;
                else
                    throw new Exception($"Too many registers in memory expression");
            }
            else
            {
                long disp = ParseImmL(tok);
                mem.Disp += sign < 0 ? -disp : disp;
            }
        }
    }

    private static List<(int sign, string token)> TokeniseMemExpr(string expr)
    {
        var result = new List<(int, string)>();

        int i = 0, sign = 1;
        int start = 0;
        while (i <= expr.Length)
        {
            bool end = i == expr.Length;
            bool sep = !end && (expr[i] == '+' || expr[i] == '-');

            if (end || sep)
            {
                string tok = expr[start..i].Trim();
                if (tok.Length > 0)
                    result.Add((sign, tok));
                if (sep) sign = expr[i] == '+' ? 1 : -1;
                start = i + 1;
            }
            i++;
        }
        return result;
    }

    private static byte[] EncodeModRm(MemAddr mem, byte regField,
        out bool rexR_mem, out bool rexX, out bool rexB)
    {
        rexR_mem = false;
        rexX = false;
        rexB = false;

        int baseReg = mem.Base;
        int indexReg = mem.Index;
        int scale = mem.Scale;
        long disp = mem.Disp;

        if (baseReg >= 8) { rexB = true; }
        if (indexReg >= 8) { rexX = true; }

        byte baseRM = baseReg >= 0 ? (byte)(baseReg & 7) : (byte)5;
        byte indexRM = indexReg >= 0 ? (byte)(indexReg & 7) : (byte)4;

        byte scaleBits = scale switch { 1 => 0, 2 => 1, 4 => 2, 8 => 3, _ => 0 };

        var bytes = new List<byte>();
        bool needSib;


        needSib = baseReg == -1 || (baseRM == 4) || indexReg >= 0;

        byte mod;
        if (baseReg == -1)
        {
            mod = 0;
        }
        else if (disp == 0 && (baseRM != 5))
        {
            mod = 0;
        }
        else if (disp >= -128 && disp <= 127)
        {
            mod = 1;
        }
        else
        {
            mod = 2;
        }


        if (mod == 0 && baseReg >= 0 && (baseRM == 5))
            mod = 1;

        byte rm = needSib ? (byte)4 : baseRM;
        byte modrm = (byte)((mod << 6) | (regField << 3) | rm);
        bytes.Add(modrm);

        if (needSib)
        {

            byte sib = (byte)((scaleBits << 6) | (indexRM << 3) | baseRM);
            bytes.Add(sib);
        }

        if (mod == 1)
            bytes.Add((byte)(sbyte)disp);
        else if (mod == 2)
            bytes.AddRange(BitConverter.GetBytes((int)disp));
        else if (baseReg == -1)
            bytes.AddRange(BitConverter.GetBytes((int)disp));

        return bytes.ToArray();
    }

    private static byte[] EncodeLine(string line, bool is64, int currentOffset,
        Dictionary<string, int> labels)
    {
        var (mnem, opStrs) = SplitInstruction(line);

        Operand? op1 = opStrs.Length > 0 ? ParseOperand(opStrs[0]) : null;
        Operand? op2 = opStrs.Length > 1 ? ParseOperand(opStrs[1]) : null;

        return mnem switch
        {
            "NOP" => [0x90],
            "RET" => [0xC3],
            "RETN" => [0xC3],
            "INT3" => [0xCC],
            "INT" => op1!.Imm == 3 ? new byte[] { 0xCC } : [0xCD, (byte)op1.Imm],
            "SYSCALL" => [0x0F, 0x05],
            "LEAVE" => [0xC9],
            "PUSHAD" => [0x60],
            "POPAD" => [0x61],
            "PUSHFD" => [0x9C],
            "POPFD" => [0x9D],
            "DB" => ParseDbOperands(opStrs),

            "PUSH" => EncodePush(op1!),
            "POP" => EncodePop(op1!),

            "MOV" => EncodeMov(op1!, op2!),
            "XOR" => EncodeAlu(0x31, 0x33, 0x81, 0x83, 6, op1!, op2!),
            "ADD" => EncodeAlu(0x01, 0x03, 0x81, 0x83, 0, op1!, op2!),
            "SUB" => EncodeAlu(0x29, 0x2B, 0x81, 0x83, 5, op1!, op2!),
            "AND" => EncodeAlu(0x21, 0x23, 0x81, 0x83, 4, op1!, op2!),
            "OR" => EncodeAlu(0x09, 0x0B, 0x81, 0x83, 1, op1!, op2!),
            "CMP" => EncodeAlu(0x39, 0x3B, 0x81, 0x83, 7, op1!, op2!),

            "INC" => EncodeIncDec(op1!, false),
            "DEC" => EncodeIncDec(op1!, true),

            "JMP" => EncodeJump(0xEB, 0xE9, op1!, currentOffset, labels),
            "JE" or "JZ" => EncodeJump(0x74, null, op1!, currentOffset, labels),
            "JNE" or "JNZ" => EncodeJump(0x75, null, op1!, currentOffset, labels),
            "JL" or "JB" => EncodeJump(0x7C, null, op1!, currentOffset, labels),
            "JG" or "JA" => EncodeJump(0x7F, null, op1!, currentOffset, labels),
            "CALL" => EncodeCall(op1!, currentOffset, labels),

            _ => throw new NotSupportedException($"Unknown mnemonic '{mnem}'")
        };
    }

    private static byte[] EncodeMov(Operand dst, Operand src)
    {
        var result = new List<byte>();

        byte? seg = dst.Kind == OperandKind.Mem ? dst.Mem!.SegPrefix
                  : src.Kind == OperandKind.Mem ? src.Mem!.SegPrefix
                  : null;
        if (seg.HasValue) result.Add(seg.Value);

        bool rexW = false;
        bool rexR = false;
        bool rexX = false;
        bool rexB = false;

        byte[] tail;

        switch (dst.Kind, src.Kind)
        {

            case (OperandKind.Reg64, OperandKind.Reg64):
                {
                    rexW = true;
                    rexR = src.RegNum >= 8;
                    rexB = dst.RegNum >= 8;
                    byte modrm = (byte)(0xC0 | ((src.RegNum & 7) << 3) | (dst.RegNum & 7));
                    tail = [0x89, modrm];
                    break;
                }

            case (OperandKind.Reg32, OperandKind.Reg32):
                {
                    byte modrm = (byte)(0xC0 | (src.RegNum << 3) | dst.RegNum);
                    result.Add(0x89);
                    result.Add(modrm);
                    return result.ToArray();
                }

            case (OperandKind.Reg64, OperandKind.Imm):
                {
                    rexW = true;
                    rexB = dst.RegNum >= 8;
                    byte op = (byte)(0xB8 + (dst.RegNum & 7));
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    result.Add(op);
                    result.AddRange(BitConverter.GetBytes(src.Imm));
                    return result.ToArray();
                }

            case (OperandKind.Reg32, OperandKind.Imm):
                {
                    result.Add((byte)(0xB8 + dst.RegNum));
                    result.AddRange(BitConverter.GetBytes((int)src.Imm));
                    return result.ToArray();
                }

            case (OperandKind.Reg64, OperandKind.Mem):
                {
                    rexW = true;
                    rexR = dst.RegNum >= 8;
                    byte regF = (byte)(dst.RegNum & 7);
                    byte[] mrm = EncodeModRm(src.Mem!, regF, out _, out rexX, out rexB);
                    if (dst.RegNum >= 8) rexR = true;
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    result.Add(0x8B);
                    result.AddRange(mrm);
                    return result.ToArray();
                }

            case (OperandKind.Reg32, OperandKind.Mem):
                {
                    byte regF = dst.RegNum;
                    byte[] mrm = EncodeModRm(src.Mem!, regF, out _, out rexX, out rexB);
                    if (rexX || rexB) EmitRex(result, false, false, rexX, rexB);
                    result.Add(0x8B);
                    result.AddRange(mrm);
                    return result.ToArray();
                }

            case (OperandKind.Mem, OperandKind.Reg64):
                {
                    rexW = true;
                    rexR = src.RegNum >= 8;
                    byte regF = (byte)(src.RegNum & 7);
                    byte[] mrm = EncodeModRm(dst.Mem!, regF, out _, out rexX, out rexB);
                    if (src.RegNum >= 8) rexR = true;
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    result.Add(0x89);
                    result.AddRange(mrm);
                    return result.ToArray();
                }

            case (OperandKind.Mem, OperandKind.Reg32):
                {
                    byte regF = src.RegNum;
                    byte[] mrm = EncodeModRm(dst.Mem!, regF, out _, out rexX, out rexB);
                    if (rexX || rexB) EmitRex(result, false, false, rexX, rexB);
                    result.Add(0x89);
                    result.AddRange(mrm);
                    return result.ToArray();
                }

            case (OperandKind.Mem, OperandKind.Imm):
                {
                    bool forceQword = dst.SizeHint == OpSize.Qword;
                    bool forceDword = dst.SizeHint == OpSize.Dword;
                    rexW = forceQword;
                    byte[] mrm = EncodeModRm(dst.Mem!, 0, out _, out rexX, out rexB);
                    EmitRex(result, rexW, false, rexX, rexB);
                    result.Add(0xC7);
                    result.AddRange(mrm);
                    result.AddRange(BitConverter.GetBytes((int)src.Imm));
                    return result.ToArray();
                }
            default:
                throw new Exception($"MOV: unsupported operand combination");
        }

        EmitRex(result, rexW, rexR, rexX, rexB);
        result.AddRange(tail);
        return result.ToArray();
    }

    private static byte[] EncodeAlu(byte opMR, byte opRM, byte opImm, byte opImm8,
                                    byte regF, Operand dst, Operand src)
    {
        var result = new List<byte>();
        bool rexW, rexR, rexX, rexB;

        byte? seg = dst.Kind == OperandKind.Mem ? dst.Mem!.SegPrefix
                  : src.Kind == OperandKind.Mem ? src.Mem!.SegPrefix
                  : null;
        if (seg.HasValue) result.Add(seg.Value);

        switch (dst.Kind, src.Kind)
        {

            case (OperandKind.Reg64, OperandKind.Reg64):
                {
                    rexW = true; rexR = src.RegNum >= 8; rexB = dst.RegNum >= 8; rexX = false;
                    byte modrm = (byte)(0xC0 | ((src.RegNum & 7) << 3) | (dst.RegNum & 7));
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    result.Add(opMR); result.Add(modrm);
                    break;
                }

            case (OperandKind.Reg32, OperandKind.Reg32):
                {
                    byte modrm = (byte)(0xC0 | (src.RegNum << 3) | dst.RegNum);
                    result.Add(opMR); result.Add(modrm);
                    break;
                }

            case (OperandKind.Reg64, OperandKind.Mem):
                {
                    rexW = true; rexR = dst.RegNum >= 8;
                    byte[] mrm = EncodeModRm(src.Mem!, (byte)(dst.RegNum & 7), out _, out rexX, out rexB);
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    result.Add(opRM); result.AddRange(mrm);
                    break;
                }

            case (OperandKind.Reg32, OperandKind.Mem):
                {
                    byte[] mrm = EncodeModRm(src.Mem!, dst.RegNum, out _, out rexX, out rexB);
                    if (rexX || rexB) EmitRex(result, false, false, rexX, rexB);
                    result.Add(opRM); result.AddRange(mrm);
                    break;
                }

            case (OperandKind.Mem, OperandKind.Reg64):
                {
                    rexW = true; rexR = src.RegNum >= 8;
                    byte[] mrm = EncodeModRm(dst.Mem!, (byte)(src.RegNum & 7), out _, out rexX, out rexB);
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    result.Add(opMR); result.AddRange(mrm);
                    break;
                }

            case (OperandKind.Mem, OperandKind.Reg32):
                {
                    byte[] mrm = EncodeModRm(dst.Mem!, src.RegNum, out _, out rexX, out rexB);
                    if (rexX || rexB) EmitRex(result, false, false, rexX, rexB);
                    result.Add(opMR); result.AddRange(mrm);
                    break;
                }

            case (OperandKind.Reg64, OperandKind.Imm):
                {
                    long imm = src.Imm;
                    rexW = true; rexR = false; rexX = false; rexB = dst.RegNum >= 8;
                    byte rm = (byte)(dst.RegNum & 7);
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    if (imm >= -128 && imm <= 127)
                    {
                        result.Add(opImm8);
                        result.Add((byte)(0xC0 | (regF << 3) | rm));
                        result.Add((byte)(sbyte)imm);
                    }
                    else
                    {
                        result.Add(opImm);
                        result.Add((byte)(0xC0 | (regF << 3) | rm));
                        result.AddRange(BitConverter.GetBytes((int)imm));
                    }
                    break;
                }

            case (OperandKind.Reg32, OperandKind.Imm):
                {
                    int imm = (int)src.Imm;
                    if (imm >= -128 && imm <= 127)
                    {
                        result.Add(opImm8);
                        result.Add((byte)(0xC0 | (regF << 3) | dst.RegNum));
                        result.Add((byte)(sbyte)imm);
                    }
                    else
                    {
                        result.Add(opImm);
                        result.Add((byte)(0xC0 | (regF << 3) | dst.RegNum));
                        result.AddRange(BitConverter.GetBytes(imm));
                    }
                    break;
                }

            case (OperandKind.Mem, OperandKind.Imm):
                {
                    bool isQword = dst.SizeHint == OpSize.Qword;
                    rexW = isQword; rexR = false;
                    byte[] mrm = EncodeModRm(dst.Mem!, regF, out _, out rexX, out rexB);
                    long imm = src.Imm;
                    EmitRex(result, rexW, rexR, rexX, rexB);
                    if (imm >= -128 && imm <= 127)
                    {
                        result.Add(opImm8);
                        result.AddRange(mrm);
                        result.Add((byte)(sbyte)imm);
                    }
                    else
                    {
                        result.Add(opImm);
                        result.AddRange(mrm);
                        result.AddRange(BitConverter.GetBytes((int)imm));
                    }
                    break;
                }
            default:
                throw new Exception($"ALU: unsupported operand combination");
        }

        return result.ToArray();
    }

    private static byte[] EncodePush(Operand op)
    {
        if (op.Kind == OperandKind.Reg64)
        {
            if (op.RegNum >= 8) return [0x41, (byte)(0x50 + (op.RegNum & 7))];
            return [(byte)(0x50 + op.RegNum)];
        }
        if (op.Kind == OperandKind.Reg32)
            return [(byte)(0x50 + op.RegNum)];
        if (op.Kind == OperandKind.Imm)
        {
            long imm = op.Imm;
            if (imm >= -128 && imm <= 127) return [0x6A, (byte)(sbyte)imm];
            return [0x68, .. BitConverter.GetBytes((int)imm)];
        }
        if (op.Kind == OperandKind.Mem)
        {

            var result = new List<byte>();
            if (op.Mem!.SegPrefix.HasValue) result.Add(op.Mem.SegPrefix.Value);
            byte[] mrm = EncodeModRm(op.Mem, 6, out _, out bool rexX, out bool rexB);
            if (rexX || rexB) EmitRex(result, false, false, rexX, rexB);
            result.Add(0xFF);
            result.AddRange(mrm);
            return result.ToArray();
        }
        throw new Exception("PUSH: unsupported operand");
    }

    private static byte[] EncodePop(Operand op)
    {
        if (op.Kind == OperandKind.Reg64)
        {
            if (op.RegNum >= 8) return [0x41, (byte)(0x58 + (op.RegNum & 7))];
            return [(byte)(0x58 + op.RegNum)];
        }
        if (op.Kind == OperandKind.Reg32)
            return [(byte)(0x58 + op.RegNum)];
        if (op.Kind == OperandKind.Mem)
        {
            var result = new List<byte>();
            if (op.Mem!.SegPrefix.HasValue) result.Add(op.Mem.SegPrefix.Value);
            byte[] mrm = EncodeModRm(op.Mem, 0, out _, out bool rexX, out bool rexB);
            if (rexX || rexB) EmitRex(result, false, false, rexX, rexB);
            result.Add(0x8F);
            result.AddRange(mrm);
            return result.ToArray();
        }
        throw new Exception($"POP: unsupported operand");
    }

    private static byte[] EncodeIncDec(Operand op, bool isDec)
    {
        byte regField = isDec ? (byte)1 : (byte)0;

        if (op.Kind == OperandKind.Reg64)
        {
            bool rex = op.RegNum >= 8;
            var r = new List<byte>();
            EmitRex(r, true, false, false, rex);
            r.Add(0xFF);
            r.Add((byte)(0xC0 | (regField << 3) | (op.RegNum & 7)));
            return r.ToArray();
        }
        if (op.Kind == OperandKind.Reg32)
            return [0xFF, (byte)(0xC0 | (regField << 3) | op.RegNum)];

        if (op.Kind == OperandKind.Mem)
        {
            bool isQword = op.SizeHint == OpSize.Qword;
            var result = new List<byte>();
            if (op.Mem!.SegPrefix.HasValue) result.Add(op.Mem.SegPrefix.Value);
            byte[] mrm = EncodeModRm(op.Mem, regField, out _, out bool rexX, out bool rexB);
            EmitRex(result, isQword, false, rexX, rexB);
            result.Add(0xFF);
            result.AddRange(mrm);
            return result.ToArray();
        }
        throw new Exception($"INC/DEC: unsupported operand");
    }

    private static byte[] EncodeJump(byte shortOp, byte? nearOp,
        Operand op, int currentOffset, Dictionary<string, int> labels)
    {
        string target = op.Kind == OperandKind.Imm ? op.Imm.ToString()
                      : throw new Exception("JMP operand must be label or immediate");

        return EncodeJumpRaw(shortOp, nearOp, target, currentOffset, labels);
    }

    private static byte[] EncodeJumpRaw(byte shortOp, byte? nearOp,
        string target, int currentOffset, Dictionary<string, int> labels)
    {
        if (!labels.TryGetValue(target, out int targetOffset))
        {
            long abs = ParseImmL(target);
            int rel8 = (int)(abs - (currentOffset + 2));
            if (rel8 >= -128 && rel8 <= 127) return [shortOp, (byte)(sbyte)rel8];
            if (nearOp is null) throw new Exception($"Short jump out of range for '{target}'");
            int rel32 = (int)(abs - (currentOffset + 5));
            return [nearOp.Value, .. BitConverter.GetBytes(rel32)];
        }
        {
            int rel8 = targetOffset - (currentOffset + 2);
            if (rel8 >= -128 && rel8 <= 127) return [shortOp, (byte)(sbyte)rel8];
            if (nearOp is null) throw new Exception($"Short jump to '{target}' out of range");
            int rel32 = targetOffset - (currentOffset + 5);
            return [nearOp.Value, .. BitConverter.GetBytes(rel32)];
        }
    }

    private static byte[] EncodeCall(Operand op, int currentOffset,
        Dictionary<string, int> labels)
    {

        if (op.Kind == OperandKind.Reg64)
        {
            var r = new List<byte>();
            if (op.RegNum >= 8) EmitRex(r, false, false, false, true);
            r.Add(0xFF);
            r.Add((byte)(0xD0 | (op.RegNum & 7)));
            return r.ToArray();
        }

        if (op.Kind == OperandKind.Mem)
        {
            var result = new List<byte>();
            if (op.Mem!.SegPrefix.HasValue) result.Add(op.Mem.SegPrefix.Value);
            byte[] mrm = EncodeModRm(op.Mem, 2, out _, out bool rexX, out bool rexB);
            if (rexX || rexB) EmitRex(result, false, false, rexX, rexB);
            result.Add(0xFF);
            result.AddRange(mrm);
            return result.ToArray();
        }

        string target = op.Imm.ToString();
        int destOffset = labels.TryGetValue(target, out int lo) ? lo : (int)op.Imm;
        int rel32 = destOffset - (currentOffset + 5);
        return [0xE8, .. BitConverter.GetBytes(rel32)];
    }

    private static byte[] ParseDbOperands(string[] opStrs)
    {
        var bytes = new List<byte>();
        foreach (string s in opStrs)
            bytes.Add(ParseImm8(s.Trim()));
        return bytes.ToArray();
    }

    private static void EmitRex(List<byte> buf, bool W, bool R, bool X, bool B)
    {
        if (!W && !R && !X && !B) return;
        buf.Add((byte)(0x40 | (W ? 8 : 0) | (R ? 4 : 0) | (X ? 2 : 0) | (B ? 1 : 0)));
    }

    private static string StripComment(string line)
    {
        int semi = line.IndexOf(';');
        return semi >= 0 ? line[..semi] : line;
    }

    private static bool TryReg64(string s, out byte r) => Reg64.TryGetValue(s, out r);
    private static bool TryReg32(string s, out byte r) => Reg32.TryGetValue(s, out r);

    private static byte ParseImm8(string s) => (byte)(ParseImmL(s) & 0xFF);

    private static long ParseImmL(string s)
    {
        s = s.Trim();
        bool neg = s.StartsWith('-');
        if (neg) s = s[1..].Trim();

        long val;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            val = long.Parse(s[2..], NumberStyles.HexNumber);
        else if (s.StartsWith("$") || s.StartsWith("0h"))
            val = long.Parse(s[1..], NumberStyles.HexNumber);
        else if (s.EndsWith("h", StringComparison.OrdinalIgnoreCase) && s.Length > 1)
            val = long.Parse(s[..^1], NumberStyles.HexNumber);
        else
            val = long.Parse(s);

        return neg ? -val : val;
    }
}

public class AssemblerResult
{
    public bool Success { get; set; }
    public byte[] Bytes { get; set; } = [];
    public string ErrorMessage { get; set; } = string.Empty;
}