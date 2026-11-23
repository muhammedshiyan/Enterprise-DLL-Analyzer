using System.Reflection.Metadata;

namespace EnterpriseDllAnalyzer.Services;

internal sealed class SignatureNameProvider : ISignatureTypeProvider<string, object?>
{
    public string GetArrayType(string elementType, ArrayShape shape) => $"{elementType}[{new string(',', Math.Max(0, shape.Rank - 1))}]";
    public string GetByReferenceType(string elementType) => elementType + "&";
    public string GetFunctionPointerType(MethodSignature<string> signature) => "methodptr " + signature.ReturnType;
    public string GetGenericInstantiation(string genericType, System.Collections.Immutable.ImmutableArray<string> typeArguments) => $"{genericType}<{string.Join(", ", typeArguments)} >";
    public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
    public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
    public string GetPinnedType(string elementType) => elementType + " pinned";
    public string GetPointerType(string elementType) => elementType + "*";
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
    {
        PrimitiveTypeCode.Void => "void", PrimitiveTypeCode.Boolean => "bool", PrimitiveTypeCode.Char => "char",
        PrimitiveTypeCode.SByte => "sbyte", PrimitiveTypeCode.Byte => "byte", PrimitiveTypeCode.Int16 => "short",
        PrimitiveTypeCode.UInt16 => "ushort", PrimitiveTypeCode.Int32 => "int", PrimitiveTypeCode.UInt32 => "uint",
        PrimitiveTypeCode.Int64 => "long", PrimitiveTypeCode.UInt64 => "ulong", PrimitiveTypeCode.Single => "float",
        PrimitiveTypeCode.Double => "double", PrimitiveTypeCode.String => "string", PrimitiveTypeCode.Object => "object",
        PrimitiveTypeCode.IntPtr => "nint", PrimitiveTypeCode.UIntPtr => "nuint", PrimitiveTypeCode.TypedReference => "TypedReference",
        _ => typeCode.ToString()
    };
    public string GetSZArrayType(string elementType) => elementType + "[]";
    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => TypeName(reader, reader.GetTypeDefinition(handle).Namespace, reader.GetTypeDefinition(handle).Name);
    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => TypeName(reader, reader.GetTypeReference(handle).Namespace, reader.GetTypeReference(handle).Name);
    public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
    private static string TypeName(MetadataReader r, StringHandle ns, StringHandle name)
    { var n = r.GetString(name); var space = ns.IsNil ? "" : r.GetString(ns); return string.IsNullOrEmpty(space) ? n : space + "." + n; }
}
