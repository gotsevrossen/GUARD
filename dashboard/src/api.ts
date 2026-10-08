export type Alert = { id:number; source:string; timestamp:string; title:string; source_ip?:string; destination_ip?:string; status:string; duplicate_count:number; severity:string; confidence?:string; guidance_tier?:string; explanation:string; recommended_action:string };
export type Session = { token:string; username:string; role:'owner'|'analyst'|'admin'; must_change_password?:boolean };
/* Corrupt localStorage must never white-screen the appliance: parse defensively, drop the bad key, carry on with the fallback. */
export function safeParse<T>(key:string, fallback:T, valid?:(value:unknown)=>boolean):T { try { const raw=localStorage.getItem(key); if(raw===null) return fallback; const parsed=JSON.parse(raw) as unknown; if(valid && !valid(parsed)) throw new Error(`unexpected shape stored at ${key}`); return parsed as T; } catch { try { localStorage.removeItem(key); } catch {} return fallback; } }
const isSession = (value:unknown) => !!value && typeof value==='object' && typeof (value as Session).token==='string';
let session: Session | null = safeParse<Session|null>('lighthouse-session', null, value => value===null || isSession(value));
export const getSession = () => session;
const persist = (next:Session|null) => { session=next; try { if(next) localStorage.setItem('lighthouse-session',JSON.stringify(next)); else localStorage.removeItem('lighthouse-session'); } catch {} };
export async function login(username:string, password:string) { const response = await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,password})}); if(!response.ok) throw new Error('Login failed'); const body = await response.json(); if(!isSession(body)) throw new Error('Login failed'); persist(body); return session!; }
/* Revoke the token server-side first; a failed or unreachable call must still drop the local session. */
export async function logout() { try { await request('/api/auth/logout',{method:'POST'}); } catch(error) { console.warn('Server-side logout failed; clearing the local session anyway.', error); } finally { persist(null); } }
/* The status rides along on the error so callers can tell an expired session (401) or a vanished alert (404) apart; the message stays the server's body so detailOf() keeps working. */
async function request(path:string, init:RequestInit={}) { const response=await fetch(path,{...init,headers:{...init.headers,Authorization:`Bearer ${session?.token}`,'content-type':'application/json'}}); if(!response.ok) throw Object.assign(new Error(await response.text()),{status:response.status}); const body=await response.text(); if(!body) return null; try { return JSON.parse(body); } catch { return body; } }
export const statusOf = (error:unknown) => { const status=(error as { status?:unknown } | null)?.status; return typeof status==='number' ? status : undefined; };

export type ChatMessage = { role:'user'|'assistant'; content:string };
export type ChatReply = { reply:string; available:boolean };
/* Local inference is CPU-only and routinely takes a minute or more, so this is a backstop against a stalled server rather than a latency target. Without it a hung request would leave the composer locked for good. */
const CHAT_TIMEOUT_MS = 5 * 60 * 1000;
/* The reply is model output and therefore untrusted: check its shape here, and the dashboard only ever renders it as text. */
async function chat(messages:ChatMessage[], alertId:number|null):Promise<ChatReply> {
  const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),CHAT_TIMEOUT_MS);
  try {
    const body=await request('/api/chat',{method:'POST',body:JSON.stringify({messages,alert_id:alertId}),signal:controller.signal});
    if(!body || typeof body!=='object' || typeof body.reply!=='string' || !body.reply.trim() || typeof body.available!=='boolean') throw new Error('Unexpected chat response');
    return { reply:body.reply, available:body.available };
  } finally { clearTimeout(timer); }
}
/* The streamed form of chat(): newline-delimited JSON events, "delta" pieces then one "done". onDelta sees each piece as it arrives. The timeout is an idle limit, reset by every chunk: the first piece can take minutes on a slow CPU, later ones arrive steadily. A stream that ends without "done" throws, and the caller keeps whatever text already arrived. */
async function chatStream(messages:ChatMessage[], alertId:number|null, onDelta:(text:string)=>void):Promise<{available:boolean}> {
  const controller=new AbortController(); let timer=setTimeout(()=>controller.abort(),CHAT_TIMEOUT_MS);
  const alive=()=>{ clearTimeout(timer); timer=setTimeout(()=>controller.abort(),CHAT_TIMEOUT_MS); };
  try {
    const response=await fetch('/api/chat/stream',{method:'POST',headers:{Authorization:`Bearer ${session?.token}`,'content-type':'application/json'},body:JSON.stringify({messages,alert_id:alertId}),signal:controller.signal});
    if(!response.ok) throw Object.assign(new Error(await response.text()),{status:response.status});
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
function chatWarm(alertId:number|null):void { request('/api/chat/warm',{method:'POST',body:JSON.stringify({alert_id:alertId})}).catch(()=>{}); }
async function chatTitle(question:string):Promise<string|null> { const body=await request('/api/chat/title',{method:'POST',body:JSON.stringify({question})}); return body && typeof body==='object' && typeof body.title==='string' && body.title.trim() ? body.title : null; }

async function chatProvider():Promise<string> { const body=await request('/api/chat/provider'); return body && body.provider==='purdue' ? 'purdue' : 'local'; }
export type ChatModelChoice = { id:string; label:string; note:string };
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
export const api = { monitoring, setMonitoring, shutdown, updates, installUpdate, serverUp, chat, chatStream, chatTitle, chatWarm, chatProvider, chatModels, setChatModel, alerts:()=>request('/api/alerts'), detail:(id:number)=>request(`/api/alerts/${id}`), trends:()=>request('/api/trends'), preferences:()=>request('/api/preferences'), setPreference:(key:string,value:string)=>request('/api/preferences',{method:'PUT',body:JSON.stringify({key,value})}), health:()=>request('/api/advanced/health'), devices:()=>request('/api/advanced/devices'), setStatus:(id:number,status:string)=>request(`/api/alerts/${id}/status`,{method:'PATCH',body:JSON.stringify({status})}), users:()=>request('/api/users'), createUser:(username:string,password:string,role:string)=>request('/api/users',{method:'POST',body:JSON.stringify({username,password,role})}), changePassword:async (current_password:string,new_password:string):Promise<Session|null>=>{ const result=await request('/api/auth/password',{method:'POST',body:JSON.stringify({current_password,new_password})}); const next = isSession(result) ? result as Session : session ? { ...session, must_change_password:false } : null; persist(next); return next; } };
