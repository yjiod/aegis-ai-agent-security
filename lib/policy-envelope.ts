import { createHash, createPublicKey, sign, type KeyObject } from 'node:crypto';

/** Separate wire format: never add these fields to a legacy signed policy. */
export const POLICY_ENVELOPE_SCHEMA = 'aegis.policy-envelope/v1';
export const POLICY_ENVELOPE_ALGORITHM = 'ES256';
export const POLICY_PAYLOAD_MAX_BYTES = 1_048_576;

export interface PolicyEnvelope {
  schema: typeof POLICY_ENVELOPE_SCHEMA;
  algorithm: typeof POLICY_ENVELOPE_ALGORITHM;
  key_id: string;
  payload: string;
  signature: string;
}

/** Public identifier for an independently provisioned P-256 trust anchor. */
export function policyEnvelopeKeyId(publicKey: KeyObject): string {
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ec'
      || publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('policy_envelope_key_invalid');
  }
  return createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
}

/** No JSON normalization: sign the exact UTF-8 bytes delivered to the client. */
export function signPolicyEnvelope(payload: Uint8Array, privateKey: KeyObject): PolicyEnvelope {
  if (payload.byteLength === 0 || payload.byteLength > POLICY_PAYLOAD_MAX_BYTES) {
    throw new Error('policy_envelope_payload_size');
  }
  if (privateKey.type !== 'private') throw new Error('policy_envelope_key_invalid');
  const keyId = policyEnvelopeKeyId(createPublicKey(privateKey));
  const bytes = Buffer.from(payload);
  const context = Buffer.from(`${POLICY_ENVELOPE_SCHEMA}\0${POLICY_ENVELOPE_ALGORITHM}\0${keyId}\0`, 'utf8');
  const signature = sign('sha256', Buffer.concat([context, bytes]), {
    key: privateKey, dsaEncoding: 'ieee-p1363',
  });
  return {
    schema: POLICY_ENVELOPE_SCHEMA,
    algorithm: POLICY_ENVELOPE_ALGORITHM,
    key_id: keyId,
    payload: bytes.toString('base64'),
    signature: Buffer.from(signature).toString('base64'),
  };
}
