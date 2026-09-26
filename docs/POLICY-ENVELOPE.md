# Policy envelope verification contract

This contract is implemented by `lib/policy-envelope.ts` and
`client/host/PolicyEnvelope.cs`. It is a verification component awaiting transport,
installer and durable update integration. Its tests do not establish that installed
clients use the component or that an end-to-end policy update is trusted.

## Wire format

The envelope has exactly five string fields: `schema`, `algorithm`, `key_id`,
`payload`, and `signature`. The schema is `aegis.policy-envelope/v1`; the algorithm
is `ES256`. Unknown or duplicate fields are rejected. JSON field order and envelope
whitespace do not matter.

`payload` is standard, padded, canonical Base64 of the complete policy UTF-8 bytes.
Do not reserialize these bytes between signing and installation. This outer format
does not add fields to the existing HMAC/Ed25519 policy object, so it can carry that
object without changing its existing signatures.

`key_id` is the full lowercase SHA-256 hex digest of the trusted public key's DER
SubjectPublicKeyInfo encoding. The public key must use the named P-256 curve
(`1.2.840.10045.3.1.7`). The verifier receives its key map from the trusted caller;
the envelope cannot provision or replace trust anchors. SPKI trailing bytes and
non-P-256 keys are rejected.

The signed message is this concatenation, with actual zero bytes at `\0`:

```text
UTF8("aegis.policy-envelope/v1\0ES256\0" + key_id + "\0") || payload_bytes
```

ECDSA hashes the message with SHA-256. `signature` encodes the 64-byte IEEE P1363
`r || s` representation in canonical standard Base64; it is not ASN.1 DER. The
implementation uses the existing Node and .NET platform crypto libraries, with
no additional dependencies or custom crypto primitives.

## Acceptance boundary

The envelope is limited to 1,400,000 bytes; the decoded payload to 1,048,576 bytes.
JSON nesting is limited to 32. UTF-8, Base64 and JSON must be valid. Comments and
trailing commas are rejected. The payload is parsed only after signature
verification. Duplicate payload properties are rejected recursively, including
escaped names and case aliases that would be ambiguous to PowerShell.

The authenticated payload must be an object with schema `aegis.policy/v1` and a
version of exactly three decimal components, each in `0..2147483647`, with no
leading zeros, signs, suffixes or whitespace. Its version must be numerically
greater than the caller's current version. Equal versions are replay rejections.
An invalid current version also rejects the update; it does not reset the floor.

Success returns the exact authenticated payload bytes. Failure raises a fixed
`policy_envelope_*` error code without payloads, paths, public keys or platform
exception details. This function does not read files, use the network or modify
the active policy. It does not log itself: the integrating caller must audit the
safe error code and retain the current policy on failure.

The caller must still enforce the full policy schema and executable rule limits,
provision keys independently through a trusted package or authorized rotation,
bind trust to the intended environment, persist a protected monotonic version
floor, and perform serialized atomic replacement with recovery. The envelope
does not supply expiry, deployment targeting or key revocation by itself. Do not
enable an update channel until those integration requirements are met.

## Verification

`scripts/test-policy-envelope.mjs` exercises the real Node signer and generates
disposable test vectors. Test private keys remain in process memory; files contain
only public keys and synthetic signed policies. The .NET test executable links
the same verifier source as the host and checks exact returned bytes as well as
failure codes. Native Windows ARM64 and x64 CI publishes the trimmed test program
and executes the vectors on each architecture.

```sh
node --experimental-strip-types --no-warnings scripts/test-policy-envelope.mjs /tmp/aegis-policy-vectors.json
dotnet run --project tests/windows-policy-envelope/EnvelopeTests.csproj -- /tmp/aegis-policy-vectors.json
```

These checks cover tampering, wrong signers, missing domain context, replay,
rollback, malformed encodings, ambiguous JSON, wrong key curves and payload
boundaries. They do not test installation, trust provisioning, offline recovery
or policy enforcement.

Platform references: [Node crypto signing](https://nodejs.org/api/crypto.html#cryptosignalgorithm-data-key-callback)
and [Microsoft ECDsa](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa?view=net-10.0).
