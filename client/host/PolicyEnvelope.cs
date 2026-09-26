using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AegisServiceHost;

// Pure verification boundary. Callers own trusted-key provisioning, policy
// semantics, durable version state and atomic installation of returned bytes.
internal static class PolicyEnvelope
{
    internal const string Schema = "aegis.policy-envelope/v1";
    internal const int MaxPayloadBytes = 1_048_576;
    internal const int MaxEnvelopeBytes = 1_400_000;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonDocumentOptions JsonOptions = new() { MaxDepth = 32 };

    internal static byte[] Verify(byte[] envelopeBytes, IReadOnlyDictionary<string, byte[]> trustedSpkiKeys, string currentVersion)
    {
        try
        {
            var floor = ParseVersion(currentVersion);
            if (envelopeBytes.Length == 0 || envelopeBytes.Length > MaxEnvelopeBytes) Fail("policy_envelope_size");
            using var envelope = ParseJson(envelopeBytes);
            var root = envelope.RootElement;
            if (root.ValueKind != JsonValueKind.Object) Fail("policy_envelope_format");
            var expected = new HashSet<string>(new[] { "schema", "algorithm", "key_id", "payload", "signature" }, StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!expected.Remove(property.Name)) Fail("policy_envelope_format");
            if (expected.Count != 0 || Text(root, "schema") != Schema || Text(root, "algorithm") != "ES256")
                Fail("policy_envelope_format");
            var keyId = Text(root, "key_id");
            if (keyId.Length != 64 || keyId.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
                Fail("policy_envelope_key_invalid");
            if (!trustedSpkiKeys.TryGetValue(keyId, out var spki)) Fail("policy_envelope_key_unknown");
            if (spki is null || spki.Length > 512) Fail("policy_envelope_key_invalid");
            if (Convert.ToHexStringLower(SHA256.HashData(spki!)) != keyId) Fail("policy_envelope_key_invalid");
            var payload = Decode(Text(root, "payload"), MaxPayloadBytes);
            var signature = Decode(Text(root, "signature"), 64);
            if (signature.Length != 64) Fail("policy_envelope_signature_invalid");
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spki!, out var read);
            if (read != spki!.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                Fail("policy_envelope_key_invalid");
            var prefix = StrictUtf8.GetBytes($"{Schema}\0ES256\0{keyId}\0");
            var signed = new byte[prefix.Length + payload.Length];
            prefix.CopyTo(signed, 0);
            payload.CopyTo(signed, prefix.Length);
            if (!key.VerifyData(signed, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                Fail("policy_envelope_signature_invalid");

            // Parse only after authentication. Reject ambiguous property names,
            // including case aliases that Windows PowerShell cannot distinguish.
            using var policy = ParseJson(payload);
            UniqueProperties(policy.RootElement);
            if (policy.RootElement.ValueKind != JsonValueKind.Object || Text(policy.RootElement, "schema") != "aegis.policy/v1")
                Fail("policy_envelope_policy_invalid");
            var version = ParseVersion(Text(policy.RootElement, "version"));
            if (version.CompareTo(floor) <= 0) Fail("policy_envelope_version_rejected");
            return payload;
        }
        catch (PolicyEnvelopeException) { throw; }
        catch (Exception ex) when (ex is JsonException or FormatException or DecoderFallbackException or InvalidOperationException or CryptographicException or ArgumentException)
        {
            // Never include untrusted payload, platform exception or key material.
            throw new PolicyEnvelopeException("policy_envelope_invalid");
        }
    }

    private static JsonDocument ParseJson(byte[] bytes)
    {
        // JsonDocument can defer decoding string values. Validate all UTF-8 first.
        _ = StrictUtf8.GetCharCount(bytes);
        return JsonDocument.Parse(bytes, JsonOptions);
    }

    private static string Text(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
            throw new PolicyEnvelopeException("policy_envelope_format");
        return property.GetString()!;
    }

    private static byte[] Decode(string value, int limit)
    {
        if (value.Length == 0 || value.Length > ((limit + 2) / 3) * 4) Fail("policy_envelope_encoding");
        var bytes = Convert.FromBase64String(value);
        // Reject whitespace, base64url, noncanonical padding and unused pad bits.
        if (bytes.Length > limit || Convert.ToBase64String(bytes) != value) Fail("policy_envelope_encoding");
        return bytes;
    }

    private static void UniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) Fail("policy_envelope_policy_invalid");
                UniqueProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) UniqueProperties(item);
    }

    private static Version ParseVersion(string value)
    {
        if (value.Length > 32) throw new PolicyEnvelopeException("policy_envelope_version_invalid");
        var parts = value.Split('.');
        if (parts.Length != 3) throw new PolicyEnvelopeException("policy_envelope_version_invalid");
        var numbers = new int[3];
        for (var i = 0; i < 3; i++)
        {
            if (parts[i].Length == 0 || (parts[i].Length > 1 && parts[i][0] == '0')
                || parts[i].Any(c => c is < '0' or > '9')
                || !int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
                throw new PolicyEnvelopeException("policy_envelope_version_invalid");
        }
        return new Version(numbers[0], numbers[1], numbers[2]);
    }

    private static void Fail(string code) => throw new PolicyEnvelopeException(code);
}

internal sealed class PolicyEnvelopeException(string code) : Exception(code);
