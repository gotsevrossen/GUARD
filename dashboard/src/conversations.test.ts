// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest';
import { clip, Conversation, loadConversations, MAX_CONTENT, MAX_MESSAGES, relativeTime, retryTurns, saveConversations, toChatMessages, Turn } from './conversations';

const KEY = 'lighthouse-chats';
const turn = (role: Turn['role'], text: string, local?: boolean): Turn => (local ? { role, text, local } : { role, text });

describe('toChatMessages', () => {
  it('maps roles and ends on the newest question', () => {
    expect(toChatMessages([turn('me', 'hi'), turn('them', 'hello'), turn('me', ' what now? ')])).toEqual([
      { role: 'user', content: 'hi' },
      { role: 'assistant', content: 'hello' },
      { role: 'user', content: 'what now?' },
    ]);
  });

  it('keeps only the newest turns and opens on a user message', () => {
    const turns: Turn[] = [];
    for (let i = 0; i < 20; i++) turns.push(turn(i % 2 ? 'them' : 'me', `t${i}`));
    turns.push(turn('me', 'last'));
    const messages = toChatMessages(turns);
    expect(messages.length).toBeLessThanOrEqual(MAX_MESSAGES);
    expect(messages[0].role).toBe('user');
    expect(messages[messages.length - 1]).toEqual({ role: 'user', content: 'last' });
  });

  it('caps each message and leaves out local notices', () => {
    const messages = toChatMessages([turn('me', 'x'.repeat(5000)), turn('them', 'AI unavailable', true), turn('me', 'again')]);
    expect(messages.map(message => message.content.length)).toEqual([MAX_CONTENT, 5]);
    expect(messages.every(message => message.role === 'user')).toBe(true);
  });

  it('returns nothing when the thread does not end on a question', () => {
    expect(toChatMessages([turn('me', 'q'), turn('them', 'a')])).toEqual([]);
  });
});

describe('clip', () => {
  it('never leaves half a surrogate pair', () => {
    expect(clip('ab😀', 3)).toBe('ab');
    expect(clip('ab😀', 4)).toBe('ab😀');
  });
});

describe('loadConversations', () => {
  beforeEach(() => localStorage.clear());

  it('loads threads stored before alertId existed', () => {
    localStorage.setItem(KEY, JSON.stringify([{ id: 'a', title: 'T', turns: [{ role: 'me', text: 'q' }], updated: 1 }]));
    expect(loadConversations()).toEqual([{ id: 'a', title: 'T', turns: [{ role: 'me', text: 'q' }], updated: 1 }]);
  });

  it('keeps a valid alertId and drops a corrupt one without losing the thread', () => {
    localStorage.setItem(KEY, JSON.stringify([
      { id: 'a', title: 'A', turns: [], updated: 2, alertId: 7 },
      { id: 'b', title: 'B', turns: [], updated: 1, alertId: 'seven' },
    ]));
    const [first, second] = loadConversations();
    expect(first.alertId).toBe(7);
    expect(second.id).toBe('b');
    expect('alertId' in second).toBe(false);
  });

  it('marks the old stub reply as local so it is never sent as context', () => {
    localStorage.setItem(KEY, JSON.stringify([{ id: 'a', title: 'T', updated: 1, turns: [
      { role: 'me', text: 'q' },
      { role: 'them', text: 'Chat will run on the local AI model once its evaluation is complete. Until then…' },
    ] }]));
    expect(toChatMessages([...loadConversations()[0].turns, turn('me', 'next')])).toEqual([
      { role: 'user', content: 'q' }, { role: 'user', content: 'next' },
    ]);
  });

  it('keeps a turn time through a save and load', () => {
    const chat: Conversation = { id: 'a', title: 'T', updated: 5, turns: [
      { role: 'me', text: 'q', at: 1_700_000_000_000 },
      { role: 'them', text: 'down', local: true, at: 1_700_000_060_000 },
    ] };
    saveConversations([chat]);
    expect(loadConversations()).toEqual([chat]);
  });

  it('drops a turn time that is not a finite number, keeping the turn', () => {
    localStorage.setItem(KEY, JSON.stringify([{ id: 'a', title: 'T', updated: 1, turns: [
      { role: 'me', text: 'q', at: 'yesterday' },
      { role: 'them', text: 'a', at: null },
      { role: 'me', text: 'r', at: { n: 1 } },
    ] }]));
    const [chat] = loadConversations();
    expect(chat.turns).toEqual([{ role: 'me', text: 'q' }, { role: 'them', text: 'a' }, { role: 'me', text: 'r' }]);
    expect(chat.turns.some(entry => 'at' in entry)).toBe(false);
  });

  it('falls back to no chats when storage is corrupt', () => {
    localStorage.setItem(KEY, '{not json');
    expect(loadConversations()).toEqual([]);
  });
});

describe('retryTurns', () => {
  it('drops every reply after the last question', () => {
    const turns = [turn('me', 'q1'), turn('them', 'a1'), turn('me', 'q2'), turn('them', 'partial'), turn('them', 'stopped', true)];
    expect(retryTurns(turns)).toEqual(turns.slice(0, 3));
  });

  it('retries a failure notice the same way', () => {
    expect(retryTurns([turn('me', 'q'), turn('them', 'couldn’t answer', true)])).toEqual([turn('me', 'q')]);
  });

  it('keeps a thread that already ends on a question, and refuses one with no question', () => {
    expect(retryTurns([turn('me', 'q')])).toEqual([turn('me', 'q')]);
    expect(retryTurns([turn('them', 'a')])).toBeNull();
    expect(retryTurns([])).toBeNull();
  });
});

describe('relativeTime', () => {
  const now = new Date(2026, 9, 8, 15, 30).getTime();
  const at = (...parts: [number, number, number, number, number]) => new Date(...parts).getTime();

  it('reads recent times as minutes', () => {
    expect(relativeTime(now - 20_000, now)).toBe('just now');
    expect(relativeTime(now + 90_000, now)).toBe('just now');
    expect(relativeTime(now - 2 * 60_000, now)).toBe('2 min ago');
    expect(relativeTime(now - 59 * 60_000, now)).toBe('59 min ago');
  });

  it('uses hours for earlier today, then yesterday, then a short date', () => {
    expect(relativeTime(at(2026, 9, 8, 12, 15), now)).toBe('3 h ago');
    expect(relativeTime(at(2026, 9, 7, 23, 0), now)).toBe('yesterday');
    expect(relativeTime(at(2026, 9, 1, 9, 0), now)).toBe(new Date(2026, 9, 1).toLocaleDateString([], { month: 'short', day: 'numeric' }));
    expect(relativeTime(at(2025, 0, 2, 9, 0), now)).toContain('2025');
  });

  it('says yesterday for late last night, not hours', () => {
    const early = new Date(2026, 9, 8, 1, 0).getTime();
    expect(relativeTime(at(2026, 9, 7, 23, 0), early)).toBe('yesterday');
    expect(relativeTime(at(2026, 9, 8, 0, 40), early)).toBe('20 min ago');
  });
});
