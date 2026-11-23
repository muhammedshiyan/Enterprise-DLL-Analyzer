using EnterpriseDllAnalyzer.Services;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:5088");
builder.Services.AddSingleton<PathPolicy>();
builder.Services.AddSingleton<AssemblyAnalysisService>();
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddFixedWindowLimiter("analysis", x => { x.PermitLimit = 15; x.Window = TimeSpan.FromMinutes(1); x.QueueLimit = 0; });
});

var app = builder.Build();
app.Use(async (context, next) =>
{
    try { await next(); }
    catch (UnauthorizedAccessException ex) { context.Response.StatusCode = 403; await context.Response.WriteAsJsonAsync(new { error = ex.Message }); }
    catch (FileNotFoundException ex) { context.Response.StatusCode = 404; await context.Response.WriteAsJsonAsync(new { error = ex.Message }); }
    catch (ArgumentException ex) { context.Response.StatusCode = 400; await context.Response.WriteAsJsonAsync(new { error = ex.Message }); }
    catch (Exception ex) { app.Logger.LogError(ex, "Analysis request failed"); context.Response.StatusCode = 500; await context.Response.WriteAsJsonAsync(new { error = ex.Message }); }
});
app.UseDefaultFiles(); app.UseStaticFiles(); app.UseRateLimiter();
app.MapGet("/api/health", () => Results.Ok(new { application = "Enterprise DLL Analyzer", status = "running", mode = "local-only", phase = 2 }));
app.MapPost("/api/inspect", (PathRequest r, AssemblyAnalysisService s) => Results.Ok(s.Inspect(r.Path))).RequireRateLimiting("analysis");
app.MapPost("/api/inspect/type", (TypeRequest r, AssemblyAnalysisService s) => Results.Ok(s.InspectType(r.Path, r.TypeName))).RequireRateLimiting("analysis");
app.MapPost("/api/decompile/type", (TypeRequest r, AssemblyAnalysisService s) => Results.Text(s.DecompileType(r.Path, r.TypeName), "text/plain; charset=utf-8")).RequireRateLimiting("analysis");
app.MapPost("/api/decompile/assembly", (PathRequest r, AssemblyAnalysisService s) => Results.Text(s.DecompileAssembly(r.Path), "text/plain; charset=utf-8")).RequireRateLimiting("analysis");
app.MapPost("/api/method/il", (MethodRequest r, AssemblyAnalysisService s) => Results.Ok(s.ReadMethodIl(r.Path, r.TypeName, r.MethodName))).RequireRateLimiting("analysis");
app.MapPost("/api/method/callers", (MethodRequest r, AssemblyAnalysisService s) => Results.Ok(s.FindCallers(r.Path, r.TypeName, r.MethodName))).RequireRateLimiting("analysis");
app.MapPost("/api/publish-folder/analyze", (FolderRequest r, AssemblyAnalysisService s) => Results.Ok(s.AnalyzePublishFolder(r.Folder))).RequireRateLimiting("analysis");
app.MapPost("/api/search", (SearchRequest r, AssemblyAnalysisService s) => Results.Ok(s.SearchSource(r.Path, r.Query))).RequireRateLimiting("analysis");
app.MapPost("/api/export", (ExportRequest r, AssemblyAnalysisService s) => Results.Ok(new { outputPath = s.ExportSource(r.Path, r.OutputDirectory) })).RequireRateLimiting("analysis");
app.Run();

record PathRequest(string Path);
record TypeRequest(string Path, string TypeName);
record MethodRequest(string Path, string TypeName, string MethodName);
record FolderRequest(string Folder);
record SearchRequest(string Path, string Query);
record ExportRequest(string Path, string OutputDirectory);
