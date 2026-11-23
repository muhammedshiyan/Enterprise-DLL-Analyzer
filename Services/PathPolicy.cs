namespace EnterpriseDllAnalyzer.Services;

public sealed class PathPolicy(IConfiguration configuration)
{
    public string ValidateAssembly(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException("DLL/EXE path is required.");

        string path = Path.GetFullPath(input.Trim().Trim('"'));
        string[] roots = configuration.GetSection("Analysis:AllowedRoots").Get<string[]>() ?? [];

        bool allowed = roots.Any(root =>
        {
            string r = Path.GetFullPath(root);
            if (!r.EndsWith(Path.DirectorySeparatorChar)) r += Path.DirectorySeparatorChar;
            return path.StartsWith(r, StringComparison.OrdinalIgnoreCase);
        });

        if (!allowed)
            throw new UnauthorizedAccessException("Path is outside configured analysis roots.");

        string ext = Path.GetExtension(path);
        if (!ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
            !ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Only .NET DLL and EXE files are accepted.");

        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Assembly not found.", path);
        long max = configuration.GetValue("Analysis:MaximumAssemblySizeMB", 512) * 1024L * 1024L;
        if (info.Length > max) throw new InvalidOperationException("Assembly exceeds configured size limit.");
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse-point files are not accepted.");

        return path;
    }

    public string ValidateDirectory(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("Folder path is required.");
        string path = Path.GetFullPath(input.Trim().Trim('"'));
        string[] roots = configuration.GetSection("Analysis:AllowedRoots").Get<string[]>() ?? [];
        bool allowed = roots.Any(root =>
        {
            string r = Path.GetFullPath(root);
            if (!r.EndsWith(Path.DirectorySeparatorChar)) r += Path.DirectorySeparatorChar;
            return path.Equals(r.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(r, StringComparison.OrdinalIgnoreCase);
        });
        if (!allowed) throw new UnauthorizedAccessException("Folder is outside configured analysis roots.");
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException(path);
        return path;
    }

    public string ValidateOutputDirectory(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("Output directory is required.");
        string path = Path.GetFullPath(input.Trim().Trim('"'));
        string[] roots = configuration.GetSection("Analysis:AllowedRoots").Get<string[]>() ?? [];
        bool allowed = roots.Any(root =>
        {
            string r = Path.GetFullPath(root);
            if (!r.EndsWith(Path.DirectorySeparatorChar)) r += Path.DirectorySeparatorChar;
            return path.StartsWith(r, StringComparison.OrdinalIgnoreCase);
        });
        if (!allowed) throw new UnauthorizedAccessException("Output path is outside configured roots.");
        return path;
    }
}
