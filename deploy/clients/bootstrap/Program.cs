using System;
using System.Diagnostics;
using System.IO;

var root = AppContext.BaseDirectory;
var installer = Path.Combine(root, "Install-Aegis.ps1");
if (!File.Exists(installer)) return 2;
var info = new ProcessStartInfo
{
    FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    UseShellExecute = false,
    CreateNoWindow = true,
};
foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installer })
    info.ArgumentList.Add(argument);
using var process = Process.Start(info);
if (process is null) return 3;
process.WaitForExit();
return process.ExitCode;
