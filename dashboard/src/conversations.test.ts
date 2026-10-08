// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest';
import { clip, loadConversations, MAX_CONTENT, MAX_MESSAGES, toChatMessages, Turn } from './conversations';

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

  it('falls back to no chats when storage is corrupt', () => {
    localStorage.setItem(KEY, '{not json');
    expect(loadConversations()).toEqual([]);
  });
});
