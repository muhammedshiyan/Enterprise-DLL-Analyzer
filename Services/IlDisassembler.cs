using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

namespace EnterpriseDllAnalyzer.Services;

internal static class IlDisassembler
{
    private static readonly Dictionary<ushort, OpCode> Codes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!).GroupBy(c => unchecked((ushort)c.Value)).ToDictionary(g => g.Key, g => g.First());

    public static IReadOnlyList<object> Disassemble(byte[] il, MetadataReader md)
    {
        var rows = new List<object>(); int p = 0;
        while (p < il.Length)
        {
            int offset = p; ushort key = il[p++];
            if (key == 0xFE && p < il.Length) key = (ushort)(0xFE00 | il[p++]);
            if (!Codes.TryGetValue(key, out var op)) { rows.Add(new { offset, opcode = $"<unknown 0x{key:X4}>", operand = "" }); break; }
            string operand = "";
            try
            {
                switch (op.OperandType)
                {
                    case OperandType.InlineNone: break;
                    case OperandType.ShortInlineI: operand = unchecked((sbyte)il[p++]).ToString(); break;
                    case OperandType.InlineI: operand = BitConverter.ToInt32(il, p).ToString(); p += 4; break;
                    case OperandType.InlineI8: operand = BitConverter.ToInt64(il, p).ToString(); p += 8; break;
                    case OperandType.ShortInlineR: operand = BitConverter.ToSingle(il, p).ToString("R"); p += 4; break;
                    case OperandType.InlineR: operand = BitConverter.ToDouble(il, p).ToString("R"); p += 8; break;
                    case OperandType.ShortInlineVar: operand = il[p++].ToString(); break;
                    case OperandType.InlineVar: operand = BitConverter.ToUInt16(il, p).ToString(); p += 2; break;
                    case OperandType.ShortInlineBrTarget: { int d = unchecked((sbyte)il[p++]); operand = $"IL_{p + d:X4}"; break; }
                    case OperandType.InlineBrTarget: { int d = BitConverter.ToInt32(il, p); p += 4; operand = $"IL_{p + d:X4}"; break; }
                    case OperandType.InlineSwitch:
                    {
                        int n = BitConverter.ToInt32(il, p); p += 4; int baseOffset = p + n * 4;
                        var targets = new List<string>(); for (int i = 0; i < n; i++) { int d = BitConverter.ToInt32(il, p); p += 4; targets.Add($"IL_{baseOffset + d:X4}"); }
                        operand = "(" + string.Join(", ", targets) + ")"; break;
                    }
                    case OperandType.InlineString:
                    { int token = BitConverter.ToInt32(il, p); p += 4; try { operand = "\"" + md.GetString(MetadataTokens.UserStringHandle(token & 0x00FFFFFF)).Replace("\"", "\\\"") + "\""; } catch { operand = $"0x{token:X8}"; } break; }
                    case OperandType.InlineField: case OperandType.InlineMethod: case OperandType.InlineType:
                    case OperandType.InlineTok: case OperandType.InlineSig:
                    { int token = BitConverter.ToInt32(il, p); p += 4; operand = ResolveToken(md, token); break; }
                    default: operand = "<unsupported operand>"; break;
                }
                if (p > il.Length) throw new BadImageFormatException("IL operand extends beyond method body.");
            }
            catch (Exception ex) when (ex is ArgumentException or BadImageFormatException or IndexOutOfRangeException)
            { operand = "<invalid/truncated operand>"; p = il.Length; }
            rows.Add(new { offset, opcode = op.Name ?? "?", operand });
        }
        return rows;
    }

    public static string ResolveToken(MetadataReader md, int token)
    {
        try
        {
            var h = MetadataTokens.EntityHandle(token);
            return h.Kind switch
            {
                HandleKind.MethodDefinition => MethodName(md, (MethodDefinitionHandle)h),
                HandleKind.MemberReference => MemberName(md, (MemberReferenceHandle)h),
                HandleKind.FieldDefinition => md.GetString(md.GetFieldDefinition((FieldDefinitionHandle)h).Name),
                HandleKind.TypeDefinition => TypeName(md, md.GetTypeDefinition((TypeDefinitionHandle)h).Namespace, md.GetTypeDefinition((TypeDefinitionHandle)h).Name),
                HandleKind.TypeReference => TypeName(md, md.GetTypeReference((TypeReferenceHandle)h).Namespace, md.GetTypeReference((TypeReferenceHandle)h).Name),
                _ => $"0x{token:X8}"
            };
        }
        catch { return $"0x{token:X8}"; }
    }
    private static string MethodName(MetadataReader md, MethodDefinitionHandle h)
    {
        var m = md.GetMethodDefinition(h);
        foreach (var th in md.TypeDefinitions)
        {
            var t = md.GetTypeDefinition(th);
            if (t.GetMethods().Contains(h))
            {
                string type = TypeName(md, t.Namespace, t.Name);
                return type + "::" + md.GetString(m.Name);
            }
        }
        return md.GetString(m.Name);
    }
    private static string MemberName(MetadataReader md, MemberReferenceHandle h)
    { var m = md.GetMemberReference(h); string parent = m.Parent.Kind switch
      { HandleKind.TypeDefinition => TypeName(md, md.GetTypeDefinition((TypeDefinitionHandle)m.Parent).Namespace, md.GetTypeDefinition((TypeDefinitionHandle)m.Parent).Name),
        HandleKind.TypeReference => TypeName(md, md.GetTypeReference((TypeReferenceHandle)m.Parent).Namespace, md.GetTypeReference((TypeReferenceHandle)m.Parent).Name), _ => "" };
      return (parent.Length == 0 ? "" : parent + "::") + md.GetString(m.Name); }
    private static string TypeName(MetadataReader md, StringHandle ns, StringHandle name)
    { string n = md.GetString(name), s = ns.IsNil ? "" : md.GetString(ns); return s.Length == 0 ? n : s + "." + n; }
}
