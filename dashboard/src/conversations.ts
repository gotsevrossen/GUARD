/* Chat history, stored as whole conversations rather than loose messages.
 *
 * The sidebar lists one row per thread — titled by how the thread opened — the way
 * the Claude apps list them. An earlier version pushed every question into the list
 * as its own entry, which turned a four-question conversation into four rows that
 * all reopened the same place.
 *
 * History is kept in this browser's localStorage only, one list per signed-in user,
 * so a different account in the same window never sees another user's chats. (What
 * a question sends to be answered is decided by the server, not stored here.) */
import { ChatMessage, safeParse } from './api';

/* local: written by the dashboard (a failure notice) or a fixed server notice (AI
 * unavailable), not by the model. It is shown in the thread but never sent back to
 * the model as its own words. */
/* at: when the turn was written (epoch ms), for the thread's "2 min ago". Threads
 * stored before it existed have none, and simply show no time. */
export type Turn = { role: 'me' | 'them'; text: string; local?: boolean; at?: number };
/* alertId ties a thread to the alert it was opened from. The server looks that alert
 * up and fences it itself, so the alert's sensor text never travels in the question. */
export type Conversation = { id: string; title: string; turns: Turn[]; updated: number; alertId?: number };

/* Per user: `lighthouse-chats:<username>`. The bare key is where every user's chats
 * used to share one list; see migrate(). */
const KEY = 'lighthouse-chats';
export const chatsKey = (username: string) => `${KEY}:${username}`;
const TITLE_LIMIT = 48;
/* Superseded by KEY: it held individual questions, so carrying it forward would
 * reintroduce exactly the per-message rows this module replaces. */
const LEGACY_KEY = 'lighthouse-recent-chats';
/* The pre-model stub stored this canned answer as a reply. The model never said it,
 * so older threads must not feed it back as context. */
const LEGACY_PLACEHOLDER = 'Chat will run on the local AI model once its evaluation is complete.';
/* The server's limits for POST /api/chat and POST /api/chat/title. */
export const MAX_MESSAGES = 12;
export const MAX_CONTENT = 2000;
export const MAX_QUESTION = 500;

const isTurn = (value: unknown): boolean => {
  const turn = value as Turn;
  return !!turn && typeof turn === 'object' && (turn.role === 'me' || turn.role === 'them') && typeof turn.text === 'string';
};

const isConversation = (value: unknown): boolean => {
  const chat = value as Conversation;
  return !!chat && typeof chat === 'object' && typeof chat.id === 'string' && typeof chat.title === 'string'
    && Array.isArray(chat.turns) && chat.turns.every(isTurn);
};

/* Optional fields are checked one by one and dropped when malformed, so a bad
 * alertId costs that one thread its alert link rather than costing every thread. */
const clean = (chat: Conversation): Conversation => {
  const turns = chat.turns.map(({ role, text, local, at }): Turn => ({
    role, text,
    ...(local === true || (role === 'them' && text.startsWith(LEGACY_PLACEHOLDER)) ? { local: true } : {}),
    ...(typeof at === 'number' && Number.isFinite(at) ? { at } : {}),
  }));
  const { alertId, updated, ...rest } = chat;
  const base = { ...rest, updated: typeof updated === 'number' && Number.isFinite(updated) ? updated : 0 };
  return typeof alertId === 'number' && Number.isSafeInteger(alertId) && alertId >= 0 ? { ...base, turns, alertId } : { ...base, turns };
};

/* Older dashboards kept one list for everyone in the browser. It moves, once, to the
 * first user who loads chats here and is then removed, so no later account inherits
 * it. Should that user already have a list (a downgrade wrote the old key again), the
 * old threads are added to theirs rather than lost. */
function migrate(key: string): void {
  try {
    const legacy = localStorage.getItem(KEY);
    if (legacy === null) return;
    const current = localStorage.getItem(key);
    if (current === null) localStorage.setItem(key, legacy);
    else {
      const mine = JSON.parse(current) as unknown;
      const theirs = JSON.parse(legacy) as unknown;
      if (Array.isArray(mine) && Array.isArray(theirs)) {
        const ids = new Set(mine.map(chat => (chat as Conversation | null)?.id));
        localStorage.setItem(key, JSON.stringify([...mine, ...theirs.filter(chat => !ids.has((chat as Conversation | null)?.id))]));
      }
    }
    localStorage.removeItem(KEY);
  } catch {
    /* unreadable old list or blocked store: drop the shared key so it cannot leak to another user */
    try { localStorage.removeItem(KEY); } catch { /* a blocked store is not a failure */ }
  }
}

/* Each thread is checked on its own, so one malformed thread costs only itself, never
 * the whole history. */
export function loadConversations(username: string): Conversation[] {
  try { localStorage.removeItem(LEGACY_KEY); } catch { /* a blocked store is not a failure */ }
  const key = chatsKey(username);
  migrate(key);
  const stored = safeParse<unknown[]>(key, [], value => Array.isArray(value));
  return stored.filter(isConversation).map(chat => clean(chat as Conversation)).sort((a, b) => b.updated - a.updated);
}

export function saveConversations(username: string, chats: Conversation[]): void {
  try { localStorage.setItem(chatsKey(username), JSON.stringify(chats)); } catch { /* a private or full store must not break chat */ }
}

export const titleFor = (question: string) => {
  const trimmed = question.trim().replace(/\s+/g, ' ');
  return trimmed.length > TITLE_LIMIT ? `${trimmed.slice(0, TITLE_LIMIT - 1)}…` : trimmed;
};

/* Cuts to at most `limit` UTF-16 units without leaving half a surrogate pair behind,
 * which would otherwise reach the server as an unpaired escape. */
export const clip = (text: string, limit: number) => {
  const cut = text.slice(0, limit);
  return /[\uD800-\uDBFF]$/.test(cut) ? cut.slice(0, -1) : cut;
};

/* The thread as the server accepts it: at most MAX_MESSAGES, each at most
 * MAX_CONTENT, opening on a user turn and ending on the newest question. The oldest
 * turns go first, and local notices never go back to the model. Returns [] if the
 * thread does not end on a question. */
export function toChatMessages(turns: Turn[]): ChatMessage[] {
  const messages = turns
    .filter(turn => !turn.local)
    .map((turn): ChatMessage => ({ role: turn.role === 'me' ? 'user' : 'assistant', content: clip(turn.text.trim(), MAX_CONTENT) }))
    .filter(message => message.content.length > 0)
    .slice(-MAX_MESSAGES);
  while (messages.length && messages[0].role !== 'user') messages.shift();
  return messages.length && messages[messages.length - 1].role === 'user' ? messages : [];
}

/* What a retry answers again: the thread up to and including its last question,
 * so every reply after it (an answer, a cut-off answer and its notice, or a failure
 * notice) is dropped and regenerated. null when there is no question to retry. */
export function retryTurns(turns: Turn[]): Turn[] | null {
  for (let index = turns.length - 1; index >= 0; index--) if (turns[index].role === 'me') return turns.slice(0, index + 1);
  return null;
}

/* "just now", "2 min ago", "3 h ago", "yesterday", then a short date, measured
 * against `now` so a timer can keep it current. A clock that has moved backwards
 * reads as "just now" rather than as a time in the future. */
export function relativeTime(at: number, now: number): string {
  const then = new Date(at);
  if (Number.isNaN(then.getTime())) return '';
  const minutes = Math.floor((now - at) / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const today = new Date(now); today.setHours(0, 0, 0, 0);
  const day = new Date(at); day.setHours(0, 0, 0, 0);
  const days = Math.round((today.getTime() - day.getTime()) / 86400000);
  if (days <= 0) return `${Math.floor(minutes / 60)} h ago`;
  if (days === 1) return 'yesterday';
  return then.toLocaleDateString([], then.getFullYear() === new Date(now).getFullYear()
    ? { month: 'short', day: 'numeric' } : { year: 'numeric', month: 'short', day: 'numeric' });
}

/* The full local date and time, for the hover title behind a relative time. */
export const fullTime = (at: number) => {
  const then = new Date(at);
  return Number.isNaN(then.getTime()) ? '' : then.toLocaleString([], { dateStyle: 'full', timeStyle: 'short' });
};

/* crypto.randomUUID needs a secure context. 127.0.0.1 normally counts as one, but an
 * unusual browser setup must not stop chat, so there is a fallback. */
export const newId = () => (globalThis.crypto?.randomUUID?.() ?? `c${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`);
