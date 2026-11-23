
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

namespace EnterpriseDllAnalyzer.Services;

internal static class IlDisassembler
{
    private static readonly Dictionary<ushort, OpCode> Codes =
        typeof(OpCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(OpCode))
            .Select(f => (OpCode)f.GetValue(null)!)
            .GroupBy(c => unchecked((ushort)c.Value))
            .ToDictionary(g => g.Key, g => g.First());

    public static IReadOnlyList<object> Disassemble(byte[] il, MetadataReader md)
    {
        var rows = new List<object>();
        int p = 0;

        while (p < il.Length)
        {
            int offset = p;
            ushort key = il[p++];

            if (key == 0xFE)
            {
                if (p >= il.Length)
                {
                    rows.Add(new
                    {
                        offset,
                        opcode = "<truncated opcode>",
                        operand = ""
                    });
                    break;
                }

                key = (ushort)(0xFE00 | il[p++]);
            }

            if (!Codes.TryGetValue(key, out var op))
            {
                rows.Add(new
                {
                    offset,
                    opcode = $"<unknown 0x{key:X4}>",
                    operand = ""
                });

                break;
            }

            string operand = "";

            try
            {
                switch (op.OperandType)
                {
                    case OperandType.InlineNone:
                        break;

                    case OperandType.ShortInlineI:
                        operand = unchecked((sbyte)ReadByte(il, ref p)).ToString();
                        break;

                    case OperandType.InlineI:
                        operand = ReadInt32(il, ref p).ToString();
                        break;

                    case OperandType.InlineI8:
                        operand = ReadInt64(il, ref p).ToString();
                        break;

                    case OperandType.ShortInlineR:
                        operand = ReadSingle(il, ref p).ToString("R");
                        break;

                    case OperandType.InlineR:
                        operand = ReadDouble(il, ref p).ToString("R");
                        break;

                    case OperandType.ShortInlineVar:
                        operand = ReadByte(il, ref p).ToString();
                        break;

                    case OperandType.InlineVar:
                        operand = ReadUInt16(il, ref p).ToString();
                        break;

                    case OperandType.ShortInlineBrTarget:
                        {
                            int delta = unchecked((sbyte)ReadByte(il, ref p));
                            operand = $"IL_{p + delta:X4}";
                            break;
                        }

                    case OperandType.InlineBrTarget:
                        {
                            int delta = ReadInt32(il, ref p);
                            operand = $"IL_{p + delta:X4}";
                            break;
                        }

                    case OperandType.InlineSwitch:
                        {
                            int count = ReadInt32(il, ref p);

                            if (count < 0 || count > (il.Length - p) / 4)
                                throw new BadImageFormatException(
                                    "Invalid switch instruction.");

                            int baseOffset = checked(p + count * 4);

                            var targets = new List<string>(count);

                            for (int i = 0; i < count; i++)
                            {
                                int delta = ReadInt32(il, ref p);
                                targets.Add($"IL_{baseOffset + delta:X4}");
                            }

                            operand = "(" + string.Join(", ", targets) + ")";
                            break;
                        }

                    case OperandType.InlineString:
                        {
                            int token = ReadInt32(il, ref p);

                            try
                            {
                                if ((token & unchecked((int)0xFF000000)) != 0x70000000)
                                    throw new BadImageFormatException(
                                        "Invalid user-string token.");

                                var handle = MetadataTokens.UserStringHandle(
                                    token & 0x00FFFFFF);

                                string value = md.GetUserString(handle);

                                operand = "\"" +
                                    value
                                        .Replace("\\", "\\\\")
                                        .Replace("\"", "\\\"")
                                        .Replace("\r", "\\r")
                                        .Replace("\n", "\\n")
                                        .Replace("\t", "\\t") +
                                    "\"";
                            }
                            catch (Exception ex) when (
                                ex is ArgumentException or BadImageFormatException)
                            {
                                operand = $"0x{token:X8}";
                            }

                            break;
                        }

                    case OperandType.InlineField:
                    case OperandType.InlineMethod:
                    case OperandType.InlineType:
                    case OperandType.InlineTok:
                    case OperandType.InlineSig:
                        {
                            int token = ReadInt32(il, ref p);
                            operand = ResolveToken(md, token);
                            break;
                        }

                    default:
                        operand = "<unsupported operand>";
                        break;
                }
            }
            catch (Exception ex) when (
                ex is ArgumentException
                    or BadImageFormatException
                    or IndexOutOfRangeException
                    or OverflowException)
            {
                operand = "<invalid/truncated operand>";
                p = il.Length;
            }

            rows.Add(new
            {
                offset,
                opcode = op.Name ?? "?",
                operand
            });
        }

        return rows;
    }

    private static byte ReadByte(byte[] il, ref int p)
    {
        if (p >= il.Length)
            throw new BadImageFormatException("Unexpected end of IL.");

        return il[p++];
    }

    private static ushort ReadUInt16(byte[] il, ref int p)
    {
        EnsureAvailable(il, p, 2);

        ushort value = BitConverter.ToUInt16(il, p);
        p += 2;

        return value;
    }

    private static int ReadInt32(byte[] il, ref int p)
    {
        EnsureAvailable(il, p, 4);

        int value = BitConverter.ToInt32(il, p);
        p += 4;

        return value;
    }

    private static long ReadInt64(byte[] il, ref int p)
    {
        EnsureAvailable(il, p, 8);

        long value = BitConverter.ToInt64(il, p);
        p += 8;

        return value;
    }

    private static float ReadSingle(byte[] il, ref int p)
    {
        EnsureAvailable(il, p, 4);

        float value = BitConverter.ToSingle(il, p);
        p += 4;

        return value;
    }

    private static double ReadDouble(byte[] il, ref int p)
    {
        EnsureAvailable(il, p, 8);

        double value = BitConverter.ToDouble(il, p);
        p += 8;

        return value;
    }

    private static void EnsureAvailable(byte[] il, int p, int count)
    {
        if (p < 0 || count < 0 || p > il.Length - count)
            throw new BadImageFormatException(
                "IL operand extends beyond method body.");
    }

    public static string ResolveToken(MetadataReader md, int token)
    {
        try
        {
            var handle = MetadataTokens.EntityHandle(token);

            return handle.Kind switch
            {
                HandleKind.MethodDefinition =>
                    MethodName(md, (MethodDefinitionHandle)handle),

                HandleKind.MemberReference =>
                    MemberName(md, (MemberReferenceHandle)handle),

                HandleKind.FieldDefinition =>
                    md.GetString(
                        md.GetFieldDefinition((FieldDefinitionHandle)handle).Name),

                HandleKind.TypeDefinition =>
                    TypeName(
                        md,
                        md.GetTypeDefinition((TypeDefinitionHandle)handle).Namespace,
                        md.GetTypeDefinition((TypeDefinitionHandle)handle).Name),

                HandleKind.TypeReference =>
                    TypeName(
                        md,
                        md.GetTypeReference((TypeReferenceHandle)handle).Namespace,
                        md.GetTypeReference((TypeReferenceHandle)handle).Name),

                HandleKind.MethodSpecification =>
                    ResolveMethodSpecification(md, (MethodSpecificationHandle)handle),

                HandleKind.StandaloneSignature =>
                    $"StandaloneSignature: 0x{token:X8}",

                _ => $"0x{token:X8}"
            };
        }
        catch
        {
            return $"0x{token:X8}";
        }
    }

    private static string ResolveMethodSpecification(
        MetadataReader md,
        MethodSpecificationHandle handle)
    {
        var specification = md.GetMethodSpecification(handle);

        return ResolveToken(
            md,
            MetadataTokens.GetToken(specification.Method));
    }

    private static string MethodName(
        MetadataReader md,
        MethodDefinitionHandle handle)
    {
        var method = md.GetMethodDefinition(handle);

        foreach (var typeHandle in md.TypeDefinitions)
        {
            var type = md.GetTypeDefinition(typeHandle);

            if (type.GetMethods().Contains(handle))
            {
                string typeName = TypeName(
                    md,
                    type.Namespace,
                    type.Name);

                return typeName + "::" + md.GetString(method.Name);
            }
        }

        return md.GetString(method.Name);
    }

    private static string MemberName(
        MetadataReader md,
        MemberReferenceHandle handle)
    {
        var member = md.GetMemberReference(handle);

        string parent = member.Parent.Kind switch
        {
            HandleKind.TypeDefinition =>
                TypeName(
                    md,
                    md.GetTypeDefinition(
                        (TypeDefinitionHandle)member.Parent).Namespace,
                    md.GetTypeDefinition(
                        (TypeDefinitionHandle)member.Parent).Name),

            HandleKind.TypeReference =>
                TypeName(
                    md,
                    md.GetTypeReference(
                        (TypeReferenceHandle)member.Parent).Namespace,
                    md.GetTypeReference(
                        (TypeReferenceHandle)member.Parent).Name),

            HandleKind.TypeSpecification =>
                $"TypeSpecification: {MetadataTokens.GetToken(member.Parent):X8}",

            _ => ""
        };

        return (parent.Length == 0 ? "" : parent + "::")
            + md.GetString(member.Name);
    }

    private static string TypeName(
        MetadataReader md,
        StringHandle ns,
        StringHandle name)
    {
        string typeName = md.GetString(name);
        string namespaceName = ns.IsNil ? "" : md.GetString(ns);

        return namespaceName.Length == 0
            ? typeName
            : namespaceName + "." + typeName;
    }
}
