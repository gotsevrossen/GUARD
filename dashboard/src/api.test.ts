import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, statusOf } from './api';

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
    const result = await api.chatStream(question, 7, piece => pieces.push(piece));
    expect(pieces).toEqual(['Hel', 'lo']);
    expect(result).toEqual({ available: true });
    const [, init] = (fetch as unknown as { mock: { calls: [string, RequestInit][] } }).mock.calls[0];
    expect(JSON.parse(String(init.body))).toEqual({ messages: question, alert_id: 7 });
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
