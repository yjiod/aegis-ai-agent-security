// Generate disposable interoperability fixtures. Only PUBLIC keys and signed
// synthetic policy data leave this process; private test keys stay in memory.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { signPolicyEnvelope, policyEnvelopeKeyId, POLICY_PAYLOAD_MAX_BYTES } from '../lib/policy-envelope.ts';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
const keyId = policyEnvelopeKeyId(publicKey);
const spki = publicKey.export({ type: 'spki', format: 'der' });
const trusted = { [keyId]: spki.toString('base64') };
const payload = Buffer.from('{"schema":"aegis.policy/v1","version":"2.0.0","note":"中文 🛡️ \\u0061","limits":{"sample":10}}\n');
const valid = signPolicyEnvelope(payload, privateKey);
const context = Buffer.from(`aegis.policy-envelope/v1\0ES256\0${keyId}\0`);
assert.equal(verify('sha256', Buffer.concat([context, payload]), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(valid.signature, 'base64')), true);
assert.equal(verify('sha256', payload, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(valid.signature, 'base64')), false);
assert.equal(Buffer.from(valid.payload, 'base64').equals(payload), true);
assert.equal(keyId, createHash('sha256').update(spki).digest('hex'));
assert.throws(() => signPolicyEnvelope(new Uint8Array(), privateKey), /payload_size/);
assert.throws(() => signPolicyEnvelope(Buffer.alloc(POLICY_PAYLOAD_MAX_BYTES + 1), privateKey), /payload_size/);
assert.throws(() => signPolicyEnvelope(payload, publicKey), /key_invalid/);
assert.throws(() => signPolicyEnvelope(payload, p384.privateKey), /key_invalid/);
assert.throws(() => policyEnvelopeKeyId(privateKey), /key_invalid/);

const cases = [];
function add(name, envelope, expected, opts = {}) {
  const bytes = Buffer.isBuffer(envelope) ? envelope : Buffer.from(JSON.stringify(envelope));
  cases.push({ name, envelope: bytes.toString('base64'), trusted_keys: opts.trusted ?? trusted,
    current_version: opts.current ?? '1.0.0', expected, expected_payload: (opts.payload ?? payload).toString('base64') });
}
function signed(name, text, expected, opts = {}) {
  const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text);
  add(name, signPolicyEnvelope(bytes, privateKey), expected, { ...opts, payload: bytes });
}
function policy(version) { return JSON.stringify({ schema: 'aegis.policy/v1', version }); }
add('valid_exact_utf8', valid, 'accepted');
add('valid_formatted_envelope', Buffer.from(JSON.stringify(valid, null, 2)), 'accepted');
signed('minor_numeric_order', policy('1.10.0'), 'accepted', { current: '1.9.9' });
signed('max_numeric_version', policy('2147483647.0.0'), 'accepted');
add('replayed_version', valid, 'policy_envelope_version_rejected', { current: '2.0.0' });
add('rollback', valid, 'policy_envelope_version_rejected', { current: '3.0.0' });
add('unknown_key', valid, 'policy_envelope_key_unknown', { trusted: {} });
add('substituted_trust_key', valid, 'policy_envelope_key_invalid', { trusted: { [keyId]: other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') } });
add('empty_envelope', Buffer.alloc(0), 'policy_envelope_size');
add('oversize_envelope', Buffer.alloc(1_400_001, 32), 'policy_envelope_size');
add('not_json', Buffer.from('{'), 'policy_envelope_invalid');
add('array_envelope', Buffer.from('[]'), 'policy_envelope_format');
add('null_envelope', Buffer.from('null'), 'policy_envelope_format');
add('unknown_field', { ...valid, public_key: spki.toString('base64') }, 'policy_envelope_format');
add('wrong_schema', { ...valid, schema: 'aegis.policy-envelope/v2' }, 'policy_envelope_format');
add('wrong_algorithm', { ...valid, algorithm: 'none' }, 'policy_envelope_format');
add('invalid_key_id', { ...valid, key_id: keyId.toUpperCase() }, 'policy_envelope_key_invalid');
add('payload_not_string', { ...valid, payload: 42 }, 'policy_envelope_format');
const missing = { ...valid }; delete missing.signature;
add('missing_signature', missing, 'policy_envelope_format');
add('duplicate_envelope_key', Buffer.from(JSON.stringify(valid).replace('"signature":', '"schema":"aegis.policy-envelope/v1","signature":')), 'policy_envelope_format');
add('escaped_duplicate_envelope_key', Buffer.from(JSON.stringify(valid).replace('"signature":', '"\\u0073chema":"aegis.policy-envelope/v1","signature":')), 'policy_envelope_format');
add('base64_whitespace', { ...valid, payload: `${valid.payload}\n` }, 'policy_envelope_encoding');
add('base64_malformed', { ...valid, payload: '!!!!' }, 'policy_envelope_invalid');
add('empty_payload', { ...valid, payload: '' }, 'policy_envelope_encoding');
add('base64_unused_pad_bits', { ...valid, payload: 'YR==' }, 'policy_envelope_encoding');
add('short_signature', { ...valid, signature: Buffer.alloc(63).toString('base64') }, 'policy_envelope_signature_invalid');
add('long_signature', { ...valid, signature: Buffer.alloc(65).toString('base64') }, 'policy_envelope_encoding');
add('changed_payload', { ...valid, payload: Buffer.from(policy('99.0.0')).toString('base64') }, 'policy_envelope_signature_invalid');
const changed = Buffer.from(valid.signature, 'base64'); changed[0] ^= 1;
add('changed_signature', { ...valid, signature: changed.toString('base64') }, 'policy_envelope_signature_invalid');
add('different_signer', { ...valid, signature: sign('sha256', Buffer.concat([context, payload]), { key: other.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64') }, 'policy_envelope_signature_invalid');
add('missing_protocol_context', { ...valid, signature: sign('sha256', payload, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64') }, 'policy_envelope_signature_invalid');
signed('signed_invalid_utf8', Buffer.from([0xff, 0xfe]), 'policy_envelope_invalid');
signed('signed_invalid_json', '{', 'policy_envelope_invalid');
signed('signed_array_payload', '[]', 'policy_envelope_policy_invalid');
signed('signed_wrong_schema', '{"schema":"other","version":"2.0.0"}', 'policy_envelope_policy_invalid');
signed('signed_duplicate_version', '{"schema":"aegis.policy/v1","version":"1.0.0","version":"2.0.0"}', 'policy_envelope_policy_invalid');
signed('signed_nested_case_alias', '{"schema":"aegis.policy/v1","version":"2.0.0","limits":{"max":1,"MAX":2}}', 'policy_envelope_policy_invalid');
signed('signed_nested_array_duplicate', '{"schema":"aegis.policy/v1","version":"2.0.0","a":[{"a":1,"a":2}]}', 'policy_envelope_policy_invalid');
signed('signed_escaped_duplicate', '{"schema":"aegis.policy/v1","version":"2.0.0","\\u0076ersion":"3.0.0"}', 'policy_envelope_policy_invalid');
signed('signed_excessive_depth', '{"schema":"aegis.policy/v1","version":"2.0.0","a":' + '['.repeat(33) + '0' + ']'.repeat(33) + '}', 'policy_envelope_invalid');
signed('signed_comment', '{/*comment*/"schema":"aegis.policy/v1","version":"2.0.0"}', 'policy_envelope_invalid');
signed('signed_trailing_comma', '{"schema":"aegis.policy/v1","version":"2.0.0",}', 'policy_envelope_invalid');
for (const version of ['2', '2.0', '2.0.0.1', '02.0.0', '2.0.0-beta', '+2.0.0', '2.0.0 ', '2147483648.0.0', '٢.0.0'])
  signed(`bad_version_${cases.length}`, policy(version), 'policy_envelope_version_invalid');
add('invalid_current_version', valid, 'policy_envelope_version_invalid', { current: 'broken' });
signed('missing_version', '{"schema":"aegis.policy/v1"}', 'policy_envelope_format');
signed('numeric_version', '{"schema":"aegis.policy/v1","version":2}', 'policy_envelope_format');
const exactLimit = Buffer.from(policy('2.0.0') + ' '.repeat(POLICY_PAYLOAD_MAX_BYTES - Buffer.byteLength(policy('2.0.0'))));
signed('max_payload_bytes', exactLimit, 'accepted');
add('oversize_decoded_payload', { ...valid, payload: Buffer.alloc(POLICY_PAYLOAD_MAX_BYTES + 1, 32).toString('base64') }, 'policy_envelope_encoding');
const wrongCurveSpki = p384.publicKey.export({ type: 'spki', format: 'der' });
const wrongCurveId = createHash('sha256').update(wrongCurveSpki).digest('hex');
add('non_p256_anchor', { ...valid, key_id: wrongCurveId }, 'policy_envelope_key_invalid', { trusted: { [wrongCurveId]: wrongCurveSpki.toString('base64') } });
const trailingSpki = Buffer.concat([spki, Buffer.from([0])]);
const trailingId = createHash('sha256').update(trailingSpki).digest('hex');
add('trailing_spki_bytes', { ...valid, key_id: trailingId }, 'policy_envelope_key_invalid', { trusted: { [trailingId]: trailingSpki.toString('base64') } });

if (process.argv.length !== 3) throw new Error('usage: test-policy-envelope.mjs output.json');
writeFileSync(process.argv[2], JSON.stringify(cases));
console.log(`policy_envelope_signer_passed:fixtures=${cases.length}`);
