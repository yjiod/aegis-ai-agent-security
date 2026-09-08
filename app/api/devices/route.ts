import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
const generations = ['current', 'previous', 'legacy'] as const;

function unavailable(error: string, status = 503) {
  return NextResponse.json({ connected: false, error }, { status, headers: { 'Cache-Control': 'no-store' } });
}

async function readBoundedJson(response: Response, limit = 262_144) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > limit || !response.body) throw new Error('collector response invalid');
  const reader=response.body.getReader(); const chunks:Uint8Array[]=[]; let size=0;
  while (true) {
    const {done,value}=await reader.read(); if (done) break; size+=value.byteLength;
    if (size>limit) { await reader.cancel(); throw new Error('collector response too large'); }
    chunks.push(value);
  }
  const bytes=new Uint8Array(size); let offset=0;
  for (const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown;
}

function sanitizeDevices(value:unknown) {
  if (!value || typeof value!=='object' || Array.isArray(value)) return null;
  const data=value as Record<string,unknown>;
  if (Object.keys(data).length!==3 || !Number.isSafeInteger(data.generated_at) || typeof data.complete!=='boolean' || !Array.isArray(data.devices) || data.devices.length>200) return null;
  const now=Math.floor(Date.now()/1000); const generated=Number(data.generated_at);
  if (generated>now+300 || now-generated>900) return null;
  const seen=new Set<string>(); const devices=[];
  for (const raw of data.devices) {
    if (!raw || typeof raw!=='object' || Array.isArray(raw)) return null;
    const item=raw as Record<string,unknown>;
    if (Object.keys(item).length!==7 || typeof item.device_id!=='string' || !/^[A-Za-z0-9._:-]{8,128}$/.test(item.device_id) || seen.has(item.device_id) || !Number.isSafeInteger(item.last_seen) || Number(item.last_seen)<0 || Number(item.last_seen)>now+300 || !Number.isSafeInteger(item.report_count) || Number(item.report_count)<1 || Number(item.report_count)>1_000_000_000 || !generations.includes(item.credential_generation as typeof generations[number]) || !['normal','high','critical'].includes(String(item.severity)) || typeof item.agent_version!=='string' || item.agent_version.length<1 || item.agent_version.length>64 || typeof item.policy_version!=='string' || item.policy_version.length<1 || item.policy_version.length>64) return null;
    seen.add(item.device_id); devices.push({device_id:item.device_id,last_seen:item.last_seen,report_count:item.report_count,credential_generation:item.credential_generation,severity:item.severity,agent_version:item.agent_version,policy_version:item.policy_version});
  }
  return {generated_at:data.generated_at,complete:data.complete,devices};
}

export async function GET() {
  const endpoint=process.env.SENTINEL_COLLECTOR_URL; const allowedHost=process.env.SENTINEL_COLLECTOR_ALLOWED_HOST; const token=process.env.SENTINEL_COLLECTOR_TOKEN;
  if (!endpoint || !allowedHost || !token) return unavailable('collector_not_configured');
  let target:URL;
  try {
    const base=new URL(endpoint);
    if (base.protocol!=='https:' || base.hostname.toLowerCase()!==allowedHost.toLowerCase() || base.username || base.password || base.search || base.hash || token.length<32 || token.length>4096) throw new Error('invalid collector configuration');
    target=new URL('/v1/devices?limit=200&view=console',base.origin);
  } catch { return unavailable('collector_configuration_invalid'); }
  try {
    const response=await fetch(target,{headers:{Authorization:`Bearer ${token}`,Accept:'application/json'},cache:'no-store',signal:AbortSignal.timeout(5000)});
    if (!response.ok) return unavailable('collector_unavailable');
    const result=sanitizeDevices(await readBoundedJson(response));
    if (!result) return unavailable('collector_contract_invalid',502);
    return NextResponse.json({connected:true,...result},{headers:{'Cache-Control':'no-store'}});
  } catch { return unavailable('collector_unavailable'); }
}
