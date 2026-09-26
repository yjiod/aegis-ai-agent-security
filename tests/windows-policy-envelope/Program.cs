using System.Text.Json;
using System.Runtime.InteropServices;
using AegisServiceHost;

if (args.Length != 1) return 64;
using var fixtures = JsonDocument.Parse(File.ReadAllBytes(args[0]));
var count = 0;
foreach (var item in fixtures.RootElement.EnumerateArray())
{
    var name = item.GetProperty("name").GetString()!;
    var expected = item.GetProperty("expected").GetString()!;
    var trusted = new Dictionary<string, byte[]>(StringComparer.Ordinal);
    foreach (var entry in item.GetProperty("trusted_keys").EnumerateObject())
        trusted.Add(entry.Name, Convert.FromBase64String(entry.Value.GetString()!));
    byte[]? accepted = null;
    string actual;
    try
    {
        accepted = PolicyEnvelope.Verify(Convert.FromBase64String(item.GetProperty("envelope").GetString()!),
            trusted, item.GetProperty("current_version").GetString()!);
        actual = "accepted";
    }
    catch (PolicyEnvelopeException ex) { actual = ex.Message; }
    if (actual != expected || (accepted is not null && !accepted.SequenceEqual(Convert.FromBase64String(item.GetProperty("expected_payload").GetString()!))))
    {
        Console.Error.WriteLine($"fixture_failed:{name}:{actual}");
        return 1;
    }
    count++;
}
// Only aggregate scope and execution architecture, never fixture contents.
Console.WriteLine($"policy_envelope_vectors_passed:{count}:os={RuntimeInformation.OSArchitecture}:process={RuntimeInformation.ProcessArchitecture}");
return count >= 30 ? 0 : 1;
