import { afterEach, describe, expect, it, vi } from 'vitest';
/* The server's own file, read as text, so the dashboard's copy of the default can't drift. */
import schema from '../../triage/schema.py?raw';
import { api, DEFAULT_ANSWER_STYLE, getSession, login, onSessionExpired, statusOf, watchStatus } from './api';

/* A response body delivered in the given pieces, as the network may split it. */
function body(...parts: string[]) {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({ start(controller) { parts.forEach(part => controller.enqueue(encoder.encode(part))); controller.close(); } });
}
const question = [{ role: 'user' as const, content: 'hi' }];

afterEach(() => vi.unstubAllGlobals());

describe('chatStream', () => {
  it('reassembles events split across network chunks', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body('{"type":"delta","te', 'xt":"Hel"}\n{"type":"delta","text":"lo"}\n', '{"type":"done","available":true}\n'))));
    const pieces: string[] = [];
    const result = await api.chatStream(question, 7, piece => pieces.push(piece), 'gemma4:26b-a4b');
    expect(pieces).toEqual(['Hel', 'lo']);
    expect(result).toEqual({ available: true });
    const [, init] = (fetch as unknown as { mock: { calls: [string, RequestInit][] } }).mock.calls[0];
    expect(JSON.parse(String(init.body))).toEqual({ messages: question, alert_id: 7, model: 'gemma4:26b-a4b' });
  });

  it('reports an unavailable model', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body('{"type":"delta","text":"Not available."}\n{"type":"done","available":false}\n'))));
    expect(await api.chatStream(question, null, () => {})).toEqual({ available: false });
  });

  it('throws when the stream ends without done, after passing on what arrived', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body('{"type":"delta","text":"Part"}\n'))));
    const pieces: string[] = [];
    await expect(api.chatStream(question, null, piece => pieces.push(piece))).rejects.toThrow();
    expect(pieces).toEqual(['Part']);
  });

  it('rejects off-shape events instead of rendering them', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body('{"type":"delta","text":{"html":"<b>x</b>"}}\n'))));
    await expect(api.chatStream(question, null, () => {})).rejects.toThrow('Unexpected chat event');
  });

  it('carries the HTTP status of a refused request', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"detail":"Alert not found"}', { status: 404 })));
    const failure = await api.chatStream(question, 3, () => {}).catch(error => error);
    expect(statusOf(failure)).toBe(404);
  });
});

describe('expired sessions', () => {
  const signIn = async (token: string) => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ token, username: 'sam', role: 'owner' }))));
    await login('sam', 'pw');
  };

  it('drops the session and tells the app once the server refuses it', async () => {
    await signIn('t1');
    const expired = vi.fn();
    const stop = onSessionExpired(expired);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"detail":"Invalid or expired session"}', { status: 401 })));
    await expect(api.alerts()).rejects.toMatchObject({ status: 401 });
    expect(getSession()).toBeNull();
    expect(expired).toHaveBeenCalledTimes(1);
    stop();
  });

  it('treats a refused status check and chat the same way', async () => {
    const expired = vi.fn();
    const stop = onSessionExpired(expired);
    await signIn('t2');
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 401 })));
    await expect(watchStatus()).rejects.toBeTruthy();
    await signIn('t3');
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 401 })));
    await expect(api.chatStream(question, null, () => {})).rejects.toBeTruthy();
    expect(expired).toHaveBeenCalledTimes(2);
    stop();
  });

  it('keeps the session for a wrong current password', async () => {
    await signIn('t4');
    const expired = vi.fn();
    const stop = onSessionExpired(expired);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"detail":"Current password is incorrect"}', { status: 401 })));
    await expect(api.changePassword('wrong', 'x'.repeat(12))).rejects.toBeTruthy();
    expect(getSession()?.token).toBe('t4');
    expect(expired).not.toHaveBeenCalled();
    stop();
  });

  it('ignores a late refusal for a session that was already replaced', async () => {
    await signIn('old');
    let refuse: (response: Response) => void = () => {};
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(resolve => { refuse = resolve; })));
    const late = api.alerts().catch(error => error);
    await signIn('new');
    const expired = vi.fn();
    const stop = onSessionExpired(expired);
    refuse(new Response('', { status: 401 }));
    expect(statusOf(await late)).toBe(401);
    expect(getSession()?.token).toBe('new');
    expect(expired).not.toHaveBeenCalled();
    stop();
  });

  it('keeps other failures as plain errors', async () => {
    await signIn('t5');
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 500 })));
    await expect(api.alerts()).rejects.toMatchObject({ status: 500 });
    expect(getSession()?.token).toBe('t5');
  });
});

describe('DEFAULT_ANSWER_STYLE', () => {
  it('matches the server default in triage/schema.py', () => {
    const block = schema.match(/^DEFAULT_ANSWER_STYLE = \(\r?\n([\s\S]*?)\r?\n\)/m);
    expect(block).not.toBeNull();
    // Python's adjacent string literals here use only escapes JSON shares (\n and \").
    const server = block![1].split(/\r?\n/).map((line: string) => JSON.parse(line.trim()) as string).join('');
    expect(DEFAULT_ANSWER_STYLE).toBe(server);
  });
});
