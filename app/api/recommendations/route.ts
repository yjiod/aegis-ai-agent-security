import { NextResponse } from 'next/server';

export const dynamic='force-dynamic';
const reasons=['risk_critical','risk_high','service_health_invalid','service_health_degraded','service_health_missing','version_drift'] as const;
const actions=['containment_pending_approval','access_review_pending','verify_integrity','repair_service','upgrade_client'] as const;
const workflowStates=['pending','approved','rejected','executing','succeeded','failed'] as const;

function unavailable(error:string,status=503){return NextResponse.json({connected:false,error},{status,headers:{'Cache-Control':'no-store'}})}
async function readBoundedJson(response:Response,limit=262_144){
  const declared=Number(response.headers.get('content-length')||0); if(declared>limit||!response.body) throw new Error('invalid response');
  const reader=response.body.getReader(); const chunks:Uint8Array[]=[]; let size=0;
  while(true){const {done,value}=await reader.read(); if(done)break; size+=value.byteLength; if(size>limit){await reader.cancel();throw new Error('response too large')} chunks.push(value)}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown;
}
function sanitize(value:unknown){
  if(!value||typeof value!=='object'||Array.isArray(value))return null;const data=value as Record<string,unknown>;
  if(Object.keys(data).length!==3||!Number.isSafeInteger(data.generated_at)||typeof data.complete!=='boolean'||!Array.isArray(data.recommendations)||data.recommendations.length>200)return null;
  const now=Math.floor(Date.now()/1000),seen=new Set<string>(),items=[];if(Number(data.generated_at)>now+300||now-Number(data.generated_at)>900)return null;
  for(const raw of data.recommendations){if(!raw||typeof raw!=='object'||Array.isArray(raw))return null;const item=raw as Record<string,unknown>;
    if(Object.keys(item).length!==10||typeof item.recommendation_id!=='string'||!/^[0-9a-f]{40}$/.test(item.recommendation_id)||seen.has(item.recommendation_id)||typeof item.device_id!=='string'||!/^[A-Za-z0-9._:-]{8,128}$/.test(item.device_id)||!reasons.includes(item.reason as typeof reasons[number])||!actions.includes(item.recommended_action as typeof actions[number])||item.approval_state!=='external_approval_required'||!['high','critical'].includes(String(item.severity))||!Number.isSafeInteger(item.observed_at)||Number(item.observed_at)<0||Number(item.observed_at)>now+300||item.correlation_id!==item.recommendation_id||!workflowStates.includes(item.workflow_state as typeof workflowStates[number])||!Number.isSafeInteger(item.receipt_updated_at)||Number(item.receipt_updated_at)<0||Number(item.receipt_updated_at)>now+300||(item.workflow_state==='pending'&&item.receipt_updated_at!==0)||(item.workflow_state!=='pending'&&Number(item.receipt_updated_at)<Number(item.observed_at)-300))return null;
    seen.add(item.recommendation_id);items.push({recommendation_id:item.recommendation_id,device_id:item.device_id,reason:item.reason,recommended_action:item.recommended_action,approval_state:item.approval_state,severity:item.severity,observed_at:item.observed_at,correlation_id:item.correlation_id,workflow_state:item.workflow_state,receipt_updated_at:item.receipt_updated_at});
  }return{generated_at:data.generated_at,complete:data.complete,recommendations:items};
}
export async function GET(){
  const endpoint=process.env.SENTINEL_COLLECTOR_URL,allowedHost=process.env.SENTINEL_COLLECTOR_ALLOWED_HOST,token=process.env.SENTINEL_COLLECTOR_TOKEN;if(!endpoint||!allowedHost||!token)return unavailable('collector_not_configured');
  try{const base=new URL(endpoint);if(base.protocol!=='https:'||base.hostname.toLowerCase()!==allowedHost.toLowerCase()||base.username||base.password||base.search||base.hash||token.length<32||token.length>4096)throw new Error('invalid configuration');
    const response=await fetch(new URL('/v1/recommendations',base.origin),{headers:{Authorization:`Bearer ${token}`,Accept:'application/json'},cache:'no-store',signal:AbortSignal.timeout(5000)});if(!response.ok)return unavailable('collector_unavailable');const result=sanitize(await readBoundedJson(response));if(!result)return unavailable('collector_contract_invalid',502);return NextResponse.json({connected:true,...result},{headers:{'Cache-Control':'no-store'}});
  }catch{return unavailable('collector_unavailable')}
}
