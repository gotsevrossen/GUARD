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
async function chatTitle(question:string):Promise<string|null> { const body=await request('/api/chat/title',{method:'POST',body:JSON.stringify({question})}); return body && typeof body==='object' && typeof body.title==='string' && body.title.trim() ? body.title : null; }

export const api = { chat, chatTitle, alerts:()=>request('/api/alerts'), detail:(id:number)=>request(`/api/alerts/${id}`), trends:()=>request('/api/trends'), preferences:()=>request('/api/preferences'), setPreference:(key:string,value:string)=>request('/api/preferences',{method:'PUT',body:JSON.stringify({key,value})}), health:()=>request('/api/advanced/health'), devices:()=>request('/api/advanced/devices'), setStatus:(id:number,status:string)=>request(`/api/alerts/${id}/status`,{method:'PATCH',body:JSON.stringify({status})}), users:()=>request('/api/users'), createUser:(username:string,password:string,role:string)=>request('/api/users',{method:'POST',body:JSON.stringify({username,password,role})}), changePassword:async (current_password:string,new_password:string):Promise<Session|null>=>{ const result=await request('/api/auth/password',{method:'POST',body:JSON.stringify({current_password,new_password})}); const next = isSession(result) ? result as Session : session ? { ...session, must_change_password:false } : null; persist(next); return next; } };
