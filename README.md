# Enterprise DLL Analyzer — Phase 2

ASP.NET Core 9 local web application for static inspection of managed .NET DLL/EXE files. The analyzer does not load or execute target assemblies.

## Phase 2 features

- Real IL instruction decoding (opcode, operand, offset, branch targets, metadata token names).
- Method overloads, return types, generic arity, parameter names/types, static/constructor flags.
- Type constructors/methods, fields, properties, indexer parameter types, and custom-attribute names.
- Static caller search across managed assemblies in the selected DLL's directory tree.
- Publish-folder inventory and assembly-reference graph, including unresolved references.
- Existing Phase 1 functions retained: assembly metadata, references, C# decompilation, source search and export.

## Requirements

- .NET SDK 9.0.x
- NuGet restore access for `ICSharpCode.Decompiler` 9.1.0.7988 (unless the package is already cached)
- Windows 10/11 recommended for the current CMD workflow

## Run from CMD

Extract the ZIP. Then run:

```bat
cd /d "%USERPROFILE%\Downloads\EnterpriseDllAnalyzer_Source\EnterpriseDllAnalyzer"
dotnet --version
dotnet restore
dotnet build -c Release
dotnet run
```

Open `http://127.0.0.1:5088`.

## Configure allowed paths

For development the supplied `appsettings.json` allows `C:\\`. Narrow this before routine use, for example:

```json
"Analysis": {
  "AllowedRoots": [ "C:\\PR\\", "C:\\Apps\\" ],
  "MaximumAssemblySizeMB": 512
}
```

Restart the application after editing configuration. The configured roots apply to target assemblies, publish folders and export destinations.

## Suggested tests

1. Analyze the existing `MyApi.Business.dll` from the Phase 1 project.
2. Select a class and click **Inspect members** to view overloads, parameters, fields, properties and attributes.
3. Switch to the **Method IL** tab, enter a method name, and click **Disassemble IL**. Overloads with the same name are returned together.
4. Enter a method name and click **Find callers**. The scan is limited to managed assemblies under the selected DLL's directory tree and is static only.
5. Enter the published application's output folder (for example `bin\Release\net9.0\publish`) and click **Analyze publish folder**.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/inspect` | Assembly metadata and references |
| POST | `/api/inspect/type` | Methods, overloads, parameters, fields, properties, attributes |
| POST | `/api/method/il` | Decoded IL instructions for all overloads matching the method name |
| POST | `/api/method/callers` | Static caller scan beneath the target assembly directory |
| POST | `/api/publish-folder/analyze` | Publish-folder inventory and dependency graph |
| POST | `/api/decompile/type` | Decompile one type |
| POST | `/api/decompile/assembly` | Decompile entire assembly |
| POST | `/api/search` | Search decompiled source |
| POST | `/api/export` | Export decompiled source file |

## Publish for offline deployment

On a build machine with NuGet access:

```bat
dotnet restore
dotnet publish -c Release -r win-x64 --self-contained true -o publish
```

Copy the `publish` directory to the offline Windows machine and run:

```bat
EnterpriseDllAnalyzer.exe
```

Then browse to `http://127.0.0.1:5088`. If you use framework-dependent deployment instead, install the matching .NET 9 ASP.NET Core Runtime on the destination machine.

## Analysis limitations and security

- Static caller discovery only finds IL references that can be resolved by this scanner. Reflection, `dynamic`, dependency injection by string, generated code, native interop and runtime-generated calls may not appear.
- Publish-folder dependency resolution is based on assembly simple names. It does not replace the .NET host's `.deps.json`/runtime resolution algorithm. Framework references may be reported unresolved if their DLLs are not copied into the publish folder.
- IL operand decoding is best-effort for malformed or unsupported metadata and reports invalid/truncated operands rather than executing the file.
- The current caller search returns methods that contain at least one matching IL reference; it is not a complete semantic call graph.
- Keep the service bound to loopback. Do not expose it to a LAN or the Internet without authentication, authorization, CSRF/Origin defenses, per-user filesystem isolation, auditing and stronger sandboxing.
- Narrow `AllowedRoots` to approved analysis folders. Analyze untrusted assemblies in a low-privilege environment. The application never calls `Assembly.Load` on target files.
- Review the ILSpy/decompiler package license and all transitive dependencies under your organization's software-compliance process before enterprise distribution.
