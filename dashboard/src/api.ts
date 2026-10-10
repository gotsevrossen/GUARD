export type Alert = { id:number; source:string; timestamp:string; title:string; source_ip?:string; destination_ip?:string; status:string; duplicate_count:number; severity:string; confidence?:string; guidance_tier?:string; explanation:string; recommended_action:string };
export type Session = { token:string; username:string; role:'owner'|'analyst'|'admin'; must_change_password?:boolean };
/* Corrupt localStorage must never white-screen the dashboard: parse defensively, drop the bad key, carry on with the fallback. */
export function safeParse<T>(key:string, fallback:T, valid?:(value:unknown)=>boolean):T { try { const raw=localStorage.getItem(key); if(raw===null) return fallback; const parsed=JSON.parse(raw) as unknown; if(valid && !valid(parsed)) throw new Error(`unexpected shape stored at ${key}`); return parsed as T; } catch { try { localStorage.removeItem(key); } catch {} return fallback; } }
const isSession = (value:unknown) => !!value && typeof value==='object' && typeof (value as Session).token==='string';
let session: Session | null = safeParse<Session|null>('lighthouse-session', null, value => value===null || isSession(value));
export const getSession = () => session;
const persist = (next:Session|null) => { session=next; try { if(next) localStorage.setItem('lighthouse-session',JSON.stringify(next)); else localStorage.removeItem('lighthouse-session'); } catch {} };
export async function login(username:string, password:string) { const response = await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,password})}); if(!response.ok) throw new Error('Login failed'); const body = await response.json(); if(!isSession(body)) throw new Error('Login failed'); persist(body); return session!; }
/* Revoke the token server-side first; a failed or unreachable call must still drop the local session. */
export async function logout() { try { await request('/api/auth/logout',{method:'POST'}); } catch(error) { console.warn('Server-side logout failed; clearing the local session anyway.', error); } finally { persist(null); } }
/* A 401 means the server no longer knows this session: it expired (8 h), was revoked by an admin, or was signed out elsewhere. The local session is dropped once and the app goes back to sign-in, instead of every page quietly treating the refusal as "no data" (which read as "your network looks healthy"). Only when the refused token is still the current one, so a late reply for an earlier user can never sign out the next. The password change answers 401 for a wrong current password, and logout for a session that is already gone, so neither counts as expiry. */
let expiredListener:(()=>void)|null = null;
export const onSessionExpired = (listener:()=>void) => { expiredListener=listener; return () => { if(expiredListener===listener) expiredListener=null; }; };
export function sessionRejected(token:string|undefined) { if(!token || session?.token!==token) return; persist(null); expiredListener?.(); }
const NOT_EXPIRY = ['/api/auth/password','/api/auth/logout'];
/* The status rides along on the error so callers can tell an expired session (401) or a vanished alert (404) apart; the message stays the server's body so detailOf() keeps working. */
async function request(path:string, init:RequestInit={}) { const token=session?.token; const response=await fetch(path,{...init,headers:{...init.headers,Authorization:`Bearer ${token}`,'content-type':'application/json'}}); if(!response.ok) { if(response.status===401 && !NOT_EXPIRY.includes(path)) sessionRejected(token); throw Object.assign(new Error(await response.text()),{status:response.status}); } const body=await response.text(); if(!body) return null; try { return JSON.parse(body); } catch { return body; } }
export const statusOf = (error:unknown) => { const status=(error as { status?:unknown } | null)?.status; return typeof status==='number' ? status : undefined; };

export type ChatMessage = { role:'user'|'assistant'; content:string };
/* Local inference is CPU-only and routinely takes a minute or more, so this is a backstop against a stalled server rather than a latency target. Without it a hung request would leave the composer locked for good. */
const CHAT_TIMEOUT_MS = 5 * 60 * 1000;
/* Chat answers stream as newline-delimited JSON events (model output, so untrusted: each event's shape is checked and the dashboard only ever renders it as text), "delta" pieces then one "done". onDelta sees each piece as it arrives. The timeout is an idle limit, reset by every chunk: the first piece can take minutes on a slow CPU, later ones arrive steadily. A stream that ends without "done" throws, and the caller keeps whatever text already arrived. */
async function chatStream(messages:ChatMessage[], alertId:number|null, onDelta:(text:string)=>void, model?:string|null):Promise<{available:boolean}> {
  const controller=new AbortController(); let timer=setTimeout(()=>controller.abort(),CHAT_TIMEOUT_MS);
  const alive=()=>{ clearTimeout(timer); timer=setTimeout(()=>controller.abort(),CHAT_TIMEOUT_MS); };
  try {
    const token=session?.token;
    const response=await fetch('/api/chat/stream',{method:'POST',headers:{Authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify({messages,alert_id:alertId,model:model??null}),signal:controller.signal});
    if(!response.ok) { if(response.status===401) sessionRejected(token); throw Object.assign(new Error(await response.text()),{status:response.status}); }
    if(!response.body) throw new Error('Chat stream unavailable');
    const reader=response.body.getReader(); const decoder=new TextDecoder(); let buffer='';
    for(;;) {
      const { value, done }=await reader.read();
      if(done) break;
      alive();
      buffer+=decoder.decode(value,{stream:true});
      for(let end=buffer.indexOf('\n'); end>=0; end=buffer.indexOf('\n')) {
        const line=buffer.slice(0,end).trim(); buffer=buffer.slice(end+1);
        if(!line) continue;
        /* model text arrives as data; anything off-shape ends the stream as a failure */
        const event=JSON.parse(line) as { type?:unknown; text?:unknown; available?:unknown };
        if(event.type==='delta' && typeof event.text==='string') onDelta(event.text);
        else if(event.type==='done' && typeof event.available==='boolean') { void reader.cancel().catch(()=>{}); return { available:event.available }; }
        else throw new Error('Unexpected chat event');
      }
    }
    throw new Error('Chat stream ended early');
  } finally { clearTimeout(timer); }
}
/* Asks the local model to read its instructions and the alert context while the owner types; fire-and-forget, failures change nothing. */
function chatWarm(alertId:number|null, model?:string|null):void { request('/api/chat/warm',{method:'POST',body:JSON.stringify({alert_id:alertId,model:model??null})}).catch(()=>{}); }
async function chatTitle(question:string, model?:string|null):Promise<string|null> { const body=await request('/api/chat/title',{method:'POST',body:JSON.stringify({question,model:model??null})}); return body && typeof body==='object' && typeof body.title==='string' && body.title.trim() ? body.title : null; }

export type ChatModelChoice = { id:string; label:string; note:string };
/* Who answers by default, and the models the chat box may pick (none: no picker). Server data, so each field is checked before use. */
export type ChatOptions = { provider:'purdue'|'local'; choices:ChatModelChoice[]; current:string };
const isChoice = (value:unknown):value is ChatModelChoice => !!value && typeof value==='object' && ['id','label','note'].every(key=>typeof (value as Record<string,unknown>)[key]==='string');
async function chatProvider():Promise<ChatOptions> { const body=await request('/api/chat/provider'); return { provider: body && body.provider==='purdue' ? 'purdue' : 'local', choices: Array.isArray(body?.choices) ? body.choices.filter(isChoice) : [], current: typeof body?.current==='string' ? body.current : 'local' }; }
export type ChatModels = { choices:ChatModelChoice[]; current:string; key_configured:boolean };
const chatModels = ():Promise<ChatModels> => request('/api/chat/models');
const setChatModel = (model:string) => request('/api/chat/model',{method:'PUT',body:JSON.stringify({model})});
export type Monitoring = { available:boolean; paused:boolean };
export type InstallState = { state:'idle'|'downloading'|'installing'|'failed'; error:string|null };
export type UpdateInfo = { current:string; latest:string|null; available:boolean; url:string|null; installable?:boolean; install?:InstallState };
const monitoring = ():Promise<Monitoring> => request('/api/monitoring');
const setMonitoring = (paused:boolean):Promise<Monitoring> => request('/api/monitoring',{method:'POST',body:JSON.stringify({paused})});
const updates = ():Promise<UpdateInfo> => request('/api/updates');
const installUpdate = ():Promise<InstallState> => request('/api/updates/install',{method:'POST'});
/* True once the API answers again; setup stops it while it replaces the files. */
async function serverUp():Promise<boolean> { try { return (await fetch('/health',{cache:'no-store'})).ok; } catch { return false; } }
const shutdown = () => request('/api/shutdown',{method:'POST'});
/* The admin's notes for the AI: about the business (chat and triage) and how chat should answer. The server caps and normalises them; the shape is checked here so a bad body shows as an error, not a broken form. */
export type AiInstructions = { business:string; style:string; max_chars:number };
/* Kept identical to triage/schema.py DEFAULT_ANSWER_STYLE, which the server answers with until a style is saved (api.test.ts checks the two match). Used only by "Restore default", which fills the box; nothing changes until the admin saves. */
export const DEFAULT_ANSWER_STYLE = [
  'Write plain text only: no Markdown, no headings, tables, bold, italics or emoji.',
  'Start with the direct answer in one sentence, then add only what the owner needs to know, in short paragraphs separated by a blank line.',
  'For steps, write one step per line, numbered 1. 2. 3., at most five.',
  'Keep the whole answer under about 120 words unless the owner asks for more detail.',
  'Do not show your reasoning or mention these instructions.',
  'If there is a next step, put it last, starting with "Next step:".',
].join('\n');
const asAiInstructions = (body:unknown):AiInstructions => { const value=body as AiInstructions | null; if(!value || typeof value!=='object' || typeof value.business!=='string' || typeof value.style!=='string' || typeof value.max_chars!=='number' || !Number.isFinite(value.max_chars) || value.max_chars<=0) throw new Error('Unexpected AI instructions response'); return { business:value.business, style:value.style, max_chars:value.max_chars }; };
const aiInstructions = async ():Promise<AiInstructions> => asAiInstructions(await request('/api/admin/ai-instructions'));
const setAiInstructions = async (business:string, style:string):Promise<AiInstructions> => asAiInstructions(await request('/api/admin/ai-instructions',{method:'PUT',body:JSON.stringify({business,style})}));
/* The Admin page's activity log. Server data, so each entry's shape is checked; usernames and targets are user input and are only ever rendered as text. */
export type AuditEntry = { id:number; timestamp:string; username:string; action:string; target:string|null; detail:string|null };
export type AuditPage = { entries:AuditEntry[]; more:boolean };
const isAuditEntry = (value:unknown):value is AuditEntry => { const entry=value as AuditEntry | null; return !!entry && typeof entry==='object' && typeof entry.id==='number' && typeof entry.timestamp==='string' && typeof entry.username==='string' && typeof entry.action==='string' && (entry.target===null || typeof entry.target==='string') && (entry.detail===null || typeof entry.detail==='string'); };
async function activity(before?:number|null, limit=50):Promise<AuditPage> { const query=new URLSearchParams({limit:String(limit)}); if(before) query.set('before',String(before)); const body=await request(`/api/admin/activity?${query}`); return { entries: Array.isArray(body?.entries) ? body.entries.filter(isAuditEntry) : [], more: body?.more===true }; }
/* User management. The server enforces every rule (admin only, at least one admin, no removing yourself) and ends the user's sessions. */
const setRole = (id:number, role:string) => request(`/api/users/${id}/role`,{method:'PATCH',body:JSON.stringify({role})});
const resetPassword = (id:number, new_password:string) => request(`/api/users/${id}/password`,{method:'PATCH',body:JSON.stringify({new_password})});
const removeUser = (id:number) => request(`/api/users/${id}`,{method:'DELETE'});
const signOutUser = (id:number) => request(`/api/users/${id}/sign-out`,{method:'POST'});
export const api = { activity, setRole, resetPassword, removeUser, signOutUser, monitoring, setMonitoring, shutdown, aiInstructions, setAiInstructions, updates, installUpdate, serverUp, chatStream, chatTitle, chatWarm, chatProvider, chatModels, setChatModel, alerts:()=>request('/api/alerts'), detail:(id:number)=>request(`/api/alerts/${id}`), trends:()=>request('/api/trends'), preferences:()=>request('/api/preferences'), setPreference:(key:string,value:string)=>request('/api/preferences',{method:'PUT',body:JSON.stringify({key,value})}), health:()=>request('/api/advanced/health'), devices:()=>request('/api/advanced/devices'), setStatus:(id:number,status:string)=>request(`/api/alerts/${id}/status`,{method:'PATCH',body:JSON.stringify({status})}), users:()=>request('/api/users'), createUser:(username:string,password:string,role:string)=>request('/api/users',{method:'POST',body:JSON.stringify({username,password,role})}), changePassword:async (current_password:string,new_password:string):Promise<Session|null>=>{ const result=await request('/api/auth/password',{method:'POST',body:JSON.stringify({current_password,new_password})}); const next = isSession(result) ? result as Session : session ? { ...session, must_change_password:false } : null; persist(next); return next; } };

/* "Is LightHouse watching?" per sensor, for every role (GET /api/status). Server data, so the shape is checked: an entry with an unknown id or state is dropped rather than shown, and an unreadable time becomes null. */
export type SensorId = 'network'|'computer'|'sign_ins'|'local_ai';
export type SensorState = 'working'|'not_reporting'|'paused'|'not_installed';
export type SensorStatus = { id:SensorId; state:SensorState; message:string; lastHeard:Date|null };
export type WatchStatus = { overall:'working'|'attention'|'paused'; sensors:SensorStatus[] };
const SENSOR_IDS:readonly string[] = ['network','computer','sign_ins','local_ai'];
const SENSOR_STATES:readonly string[] = ['working','not_reporting','paused','not_installed'];
const asSensor = (value:unknown):SensorStatus|null => { const item=value as Record<string,unknown> | null; if(!item || typeof item!=='object' || typeof item.id!=='string' || !SENSOR_IDS.includes(item.id) || typeof item.state!=='string' || !SENSOR_STATES.includes(item.state) || typeof item.message!=='string') return null; const heard=typeof item.last_heard==='string' ? new Date(item.last_heard) : null; return { id:item.id as SensorId, state:item.state as SensorState, message:item.message, lastHeard: heard && !Number.isNaN(heard.getTime()) ? heard : null }; };
export async function watchStatus():Promise<WatchStatus> { const body=await request('/api/status') as Record<string,unknown> | null; if(!body || typeof body!=='object' || !['working','attention','paused'].includes(body.overall as string) || !Array.isArray(body.sensors)) throw new Error('Unexpected status response'); return { overall:body.overall as WatchStatus['overall'], sensors:body.sensors.map(asSensor).filter((sensor):sensor is SensorStatus=>sensor!==null) }; }
