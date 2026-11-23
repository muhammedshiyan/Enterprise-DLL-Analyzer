using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.TypeSystem;

namespace EnterpriseDllAnalyzer.Services;

public sealed class AssemblyAnalysisService(PathPolicy paths)
{
    private readonly SignatureNameProvider signatureTypes = new();

    public object Inspect(string input)
    {
        string path = paths.ValidateAssembly(input);
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var pe = new PEReader(stream);
        if (!pe.HasMetadata) throw new InvalidOperationException("This is not a managed .NET assembly.");
        MetadataReader md = pe.GetMetadataReader();
        string assemblyName = md.IsAssembly ? md.GetString(md.GetAssemblyDefinition().Name) : Path.GetFileNameWithoutExtension(path);
        var types = md.TypeDefinitions.Select(handle =>
        {
            var t = md.GetTypeDefinition(handle); string ns = md.GetString(t.Namespace), name = md.GetString(t.Name);
            return new { token = MetadataTokens.GetToken(handle).ToString("X8"), name,
                fullName = string.IsNullOrEmpty(ns) ? name : ns + "." + name,
                methods = t.GetMethods().Select(m => md.GetString(md.GetMethodDefinition(m).Name)).ToArray() };
        }).Where(t => t.name != "<Module>").ToArray();
        var references = md.AssemblyReferences.Select(h => { var r = md.GetAssemblyReference(h); return new
            { name = md.GetString(r.Name), version = r.Version.ToString(), culture = r.Culture.IsNil ? "" : md.GetString(r.Culture) }; }).ToArray();
        return new { path, assemblyName, sizeBytes = new FileInfo(path).Length,
            sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
            mvid = md.GetGuid(md.GetModuleDefinition().Mvid).ToString(), types, references };
    }

    public object InspectType(string input, string typeName)
    {
        string path = paths.ValidateAssembly(input); using var stream = File.OpenRead(path); using var pe = new PEReader(stream);
        MetadataReader md = RequireMetadata(pe); var th = FindType(md, typeName); var t = md.GetTypeDefinition(th);
        var methods = t.GetMethods().Select(h => MethodInfo(md, h)).ToArray();
        var fields = t.GetFields().Select(h => { var f = md.GetFieldDefinition(h); return new { token = Token(h), name = md.GetString(f.Name), signature = f.DecodeSignature(signatureTypes, null), attributes = Attributes(md, f.GetCustomAttributes()) }; }).ToArray();
        var properties = t.GetProperties().Select(h => { var p = md.GetPropertyDefinition(h); var sig = p.DecodeSignature(signatureTypes, null); return new { token = Token(h), name = md.GetString(p.Name), type = sig.ReturnType, indexParameters = sig.ParameterTypes, attributes = Attributes(md, p.GetCustomAttributes()) }; }).ToArray();
        return new { typeName, token = Token(th), attributes = Attributes(md, t.GetCustomAttributes()), methods, fields, properties };
    }

    private object MethodInfo(MetadataReader md, MethodDefinitionHandle h)
    {
        var m = md.GetMethodDefinition(h); var sig = m.DecodeSignature(signatureTypes, null);
        var paramNames = m.GetParameters().Select(ph => md.GetParameter(ph)).Where(p => p.SequenceNumber > 0)
            .ToDictionary(p => (int)p.SequenceNumber, p => p.Name.IsNil ? "" : md.GetString(p.Name));
        var parameters = sig.ParameterTypes.Select((type, i) => new { position = i + 1, name = paramNames.GetValueOrDefault(i + 1, "arg" + i), type }).ToArray();
        return new { token = Token(h), name = md.GetString(m.Name), returnType = sig.ReturnType, parameters,
            genericParameterCount = sig.GenericParameterCount, isStatic = (m.Attributes & System.Reflection.MethodAttributes.Static) != 0,
            isConstructor = md.GetString(m.Name) is ".ctor" or ".cctor", attributes = Attributes(md, m.GetCustomAttributes()), hasBody = m.RelativeVirtualAddress != 0 };
    }

    public string DecompileType(string input, string typeName) { string path = paths.ValidateAssembly(input); return new CSharpDecompiler(path, new DecompilerSettings()).DecompileTypeAsString(new FullTypeName(typeName)); }
    public string DecompileAssembly(string input) { string path = paths.ValidateAssembly(input); return new CSharpDecompiler(path, new DecompilerSettings()).DecompileWholeModuleAsString(); }

    public object ReadMethodIl(string input, string typeName, string methodName)
    {
        string path = paths.ValidateAssembly(input); using var stream = File.OpenRead(path); using var pe = new PEReader(stream); MetadataReader md = RequireMetadata(pe);
        var th = FindType(md, typeName); var t = md.GetTypeDefinition(th); var results = new List<object>();
        foreach (var mh in t.GetMethods())
        {
            var m = md.GetMethodDefinition(mh); if (!string.Equals(md.GetString(m.Name), methodName, StringComparison.Ordinal)) continue;
            if (m.RelativeVirtualAddress == 0) { results.Add(new { token = Token(mh), name = methodName, hasBody = false, instructions = Array.Empty<object>() }); continue; }
            var body = pe.GetMethodBody(m.RelativeVirtualAddress); byte[] il = body.GetILBytes() ?? Array.Empty<byte>();
            results.Add(new { token = Token(mh), name = methodName, hasBody = true, maxStack = body.MaxStack,
                localSignatureToken = body.LocalSignature.IsNil ? "" : Token(body.LocalSignature), initLocals = body.LocalVariablesInitialized,
                instructions = IlDisassembler.Disassemble(il, md) });
        }
        if (results.Count == 0) throw new InvalidOperationException($"Method not found: {methodName}");
        return new { typeName, overloadCount = results.Count, methods = results };
    }

    public object FindCallers(string input, string typeName, string methodName)
    {
        string targetPath = paths.ValidateAssembly(input); var target = ReadTargetIdentity(targetPath, typeName, methodName);
        string folder = Path.GetDirectoryName(targetPath)!; var files = Directory.EnumerateFiles(folder, "*.*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint })
            .Where(IsAssemblyFile).Take(2000).ToArray();
        var callers = new List<object>();
        foreach (string file in files)
        {
            try
            {
                using var fs = File.OpenRead(file); using var pe = new PEReader(fs); if (!pe.HasMetadata) continue; var md = pe.GetMetadataReader();
                foreach (var th in md.TypeDefinitions)
                {
                    var td = md.GetTypeDefinition(th); string callerType = FullType(md, td.Namespace, td.Name);
                    foreach (var mh in td.GetMethods())
                    {
                        var method = md.GetMethodDefinition(mh); if (method.RelativeVirtualAddress == 0) continue;
                        var body = pe.GetMethodBody(method.RelativeVirtualAddress); var instructions = IlDisassembler.Disassemble(body.GetILBytes() ?? Array.Empty<byte>(), md);
                        if (instructions.Any(row => InstructionMatches(row, target)))
                            callers.Add(new { assembly = Path.GetFileName(file), type = callerType, method = md.GetString(method.Name), token = Token(mh) });
                    }
                }
            }
            catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException) { }
        }
        return new { target = target.Display, searchedAssemblies = files.Length, callerCount = callers.Count, callers };
    }

    public object AnalyzePublishFolder(string input)
    {
        string folder = paths.ValidateDirectory(input);
        var files = Directory.EnumerateFiles(folder, "*.*", SearchOption.AllDirectories).Where(IsAssemblyFile).Take(5000).ToArray();
        var records = new List<AssemblyRecord>(); var errors = new List<object>();
        foreach (string file in files)
        {
            try
            {
                string valid = paths.ValidateAssembly(file); using var fs = File.OpenRead(valid); using var pe = new PEReader(fs); if (!pe.HasMetadata) continue;
                var md = pe.GetMetadataReader(); string name = md.IsAssembly ? md.GetString(md.GetAssemblyDefinition().Name) : Path.GetFileNameWithoutExtension(file);
                var refs = md.AssemblyReferences.Select(h => md.GetString(md.GetAssemblyReference(h).Name)).ToArray();
                records.Add(new AssemblyRecord(Path.GetFileName(file), file, name, refs));
            }
            catch (Exception ex) { errors.Add(new { file, error = ex.Message }); }
        }
        var byName = records.GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);
        var edges = records.SelectMany(a => a.References.Select(r =>
        {
            bool resolved = byName.TryGetValue(r, out var matches);
            return new { from = a.Name, reference = r, resolved,
                resolvedFiles = resolved ? matches!.Select(x => x.File).ToArray() : Array.Empty<string>() };
        })).ToArray();
        return new { folder, assemblyCount = records.Count, dependencyEdgeCount = edges.Length,
            unresolvedReferences = edges.Where(e => !e.resolved).ToArray(), assemblies = records, dependencies = edges, errors };
    }

    public object SearchSource(string input, string query)
    {
        if (string.IsNullOrWhiteSpace(query)) throw new ArgumentException("Search query is required."); string source = DecompileAssembly(input);
        var matches = source.Split('\n').Select((line, index) => new { lineNumber = index + 1, text = line.TrimEnd('\r') })
            .Where(x => x.text.Contains(query, StringComparison.OrdinalIgnoreCase)).Take(500).ToArray();
        return new { query, count = matches.Length, matches };
    }
    public string ExportSource(string input, string outputDirectory)
    {
        string path = paths.ValidateAssembly(input), output = paths.ValidateOutputDirectory(outputDirectory); Directory.CreateDirectory(output);
        string source = new CSharpDecompiler(path, new DecompilerSettings()).DecompileWholeModuleAsString();
        string destination = Path.Combine(output, Path.GetFileNameWithoutExtension(path) + ".decompiled.cs"); File.WriteAllText(destination, source, new System.Text.UTF8Encoding(false)); return destination;
    }

    private static MetadataReader RequireMetadata(PEReader pe) => pe.HasMetadata ? pe.GetMetadataReader() : throw new InvalidOperationException("No .NET metadata found.");
    private static TypeDefinitionHandle FindType(MetadataReader md, string typeName)
    {
        foreach (var h in md.TypeDefinitions) { var t = md.GetTypeDefinition(h); if (FullType(md, t.Namespace, t.Name) == typeName) return h; }
        throw new InvalidOperationException("Type not found: " + typeName);
    }
    private static string FullType(MetadataReader md, StringHandle ns, StringHandle name) { string n = md.GetString(name), s = ns.IsNil ? "" : md.GetString(ns); return s.Length == 0 ? n : s + "." + n; }
    private static string Token(EntityHandle h) => "0x" + MetadataTokens.GetToken(h).ToString("X8");
    private static string[] Attributes(MetadataReader md, CustomAttributeHandleCollection handles) => handles.Select(h =>
    {
        var a = md.GetCustomAttribute(h);
        EntityHandle parent = a.Constructor.Kind == HandleKind.MethodDefinition
            ? md.GetMethodDefinition((MethodDefinitionHandle)a.Constructor).GetDeclaringType()
            : a.Constructor.Kind == HandleKind.MemberReference ? md.GetMemberReference((MemberReferenceHandle)a.Constructor).Parent : default;
        string name = parent.Kind switch
        {
            HandleKind.TypeDefinition => FullType(md, md.GetTypeDefinition((TypeDefinitionHandle)parent).Namespace, md.GetTypeDefinition((TypeDefinitionHandle)parent).Name),
            HandleKind.TypeReference => FullType(md, md.GetTypeReference((TypeReferenceHandle)parent).Namespace, md.GetTypeReference((TypeReferenceHandle)parent).Name),
            _ => "UnknownAttribute"
        };
        return name.EndsWith("Attribute", StringComparison.Ordinal) ? name[..^9] : name;
    }).ToArray();
    private static bool IsAssemblyFile(string f) => Path.GetExtension(f).Equals(".dll", StringComparison.OrdinalIgnoreCase) || Path.GetExtension(f).Equals(".exe", StringComparison.OrdinalIgnoreCase);
    private static (string Display, string Type, string Method) ReadTargetIdentity(string path, string type, string method)
    { return ($"{type}::{method}", type, method); }
    private static bool InstructionMatches(object row, (string Display, string Type, string Method) target)
    {
        string json = System.Text.Json.JsonSerializer.Serialize(row);
        return json.Contains(target.Display, StringComparison.OrdinalIgnoreCase) ||
               (json.Contains("::" + target.Method, StringComparison.Ordinal) && json.Contains(target.Type, StringComparison.Ordinal));
    }
    private sealed record AssemblyRecord(string FileName, string File, string Name, string[] References);
}
