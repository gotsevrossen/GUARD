// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { asNewAlerts, fetchNewAlerts, LAST_SEEN_KEY, MAX_BACKOFF_MS, nextCursor, nextDelay, notificationsOff, notificationText, OFF_KEY, POLL_MS,
  readLastSeen, saveLastSeen, setNotificationsOff, shouldNotify, titleWithCount, worstSeverity } from './notifications';

const result = (latest_id: number, count: number, alerts: { id: number; severity: string; timestamp: string }[] = []) =>
  ({ threshold: 'high', count, latest_id, alerts });

beforeEach(() => localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

describe('last-seen storage', () => {
  it('round-trips a cursor', () => {
    expect(readLastSeen()).toBeNull();
    saveLastSeen(42);
    expect(readLastSeen()).toBe(42);
  });

  it('drops corrupt or off-shape values instead of throwing', () => {
    for (const bad of ['{not json', '"12"', '-1', '1.5', '{"id":3}', '1e400']) {
      localStorage.setItem(LAST_SEEN_KEY, bad);
      expect(readLastSeen()).toBeNull();
      expect(localStorage.getItem(LAST_SEEN_KEY)).toBeNull();
    }
  });

  it('remembers the per-browser off switch, defensively', () => {
    expect(notificationsOff()).toBe(false);
    setNotificationsOff(true);
    expect(notificationsOff()).toBe(true);
    localStorage.setItem(OFF_KEY, '"yes"');
    expect(notificationsOff()).toBe(false);
  });
});

describe('cursor and should-notify', () => {
  it('starts from the newest alert on first run, without notifying', () => {
    expect(shouldNotify(null, result(9, 3))).toBe(false);
    expect(nextCursor(null, 9)).toBe(9);
  });

  it('notifies for new matching alerts and moves on', () => {
    expect(shouldNotify(5, result(9, 2))).toBe(true);
    expect(nextCursor(5, 9)).toBe(9);
  });

  it('moves on without notifying when nothing reached the threshold', () => {
    expect(shouldNotify(5, result(9, 0))).toBe(false);
    expect(nextCursor(5, 9)).toBe(9);
  });

  it('restarts from the newest alert when the cursor is past it (a new database)', () => {
    expect(shouldNotify(500, result(9, 1))).toBe(false);
    expect(nextCursor(500, 9)).toBe(9);
  });
});

describe('fixed notification wording', () => {
  it('never includes anything but fixed text and the count', () => {
    expect(notificationText(1, 'high').body).toBe('LightHouse found a high-severity alert. Open LightHouse to review it.');
    expect(notificationText(1, 'critical').body).toBe('LightHouse found a critical alert. Open LightHouse to review it.');
    expect(notificationText(1, 'medium').body).toBe('LightHouse found a medium-severity alert. Open LightHouse to review it.');
    expect(notificationText(3, 'critical').body).toBe('LightHouse found 3 new alerts that need your attention. Open LightHouse to review them.');
  });

  it('uses the generic sentence for an unexpected severity string', () => {
    const lure = 'Call support at 555-0100';
    expect(notificationText(1, lure).body).not.toContain(lure);
    expect(notificationText(1, lure).title).toBe('LightHouse');
  });

  it('picks the most severe stored severity', () => {
    expect(worstSeverity([{ id: 1, severity: 'medium', timestamp: '' }, { id: 2, severity: 'critical', timestamp: '' }])).toBe('critical');
    expect(worstSeverity([{ id: 1, severity: 'medium', timestamp: '' }])).toBe('medium');
    expect(worstSeverity([])).toBe('high');
  });
});

describe('title and backoff', () => {
  it('counts new urgent alerts in the window title', () => {
    expect(titleWithCount(0)).toBe('LightHouse');
    expect(titleWithCount(2)).toBe('(2) LightHouse');
    expect(titleWithCount(250)).toBe('(99+) LightHouse');
  });

  it('backs off on failure, up to a cap', () => {
    expect(nextDelay(0)).toBe(POLL_MS);
    expect(nextDelay(1)).toBe(POLL_MS * 2);
    expect(nextDelay(50)).toBe(MAX_BACKOFF_MS);
  });
});

describe('response checks', () => {
  it('rejects off-shape responses', () => {
    expect(() => asNewAlerts(null)).toThrow();
    expect(() => asNewAlerts({ threshold: 'high', count: -1, latest_id: 1, alerts: [] })).toThrow();
    expect(() => asNewAlerts({ threshold: 'high', count: 1, latest_id: 1, alerts: [{ id: 'x', severity: 'high' }] })).toThrow();
  });

  it('keeps only id, severity and timestamp', () => {
    const parsed = asNewAlerts({ ...result(3, 1, [{ id: 3, severity: 'high', timestamp: 't', title: 'lure' } as never]) });
    expect(parsed.alerts).toEqual([{ id: 3, severity: 'high', timestamp: 't' }]);
  });

  it('sends the cursor only when there is one', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(result(4, 0))));
    vi.stubGlobal('fetch', fetchMock);
    await fetchNewAlerts(null);
    await fetchNewAlerts(7);
    const urls = (fetchMock.mock.calls as unknown as [string][]).map(([url]) => url);
    expect(urls).toEqual(['/api/notifications', '/api/notifications?after=7']);
  });

  it('carries the HTTP status of a refused poll', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 401 })));
    await expect(fetchNewAlerts(1)).rejects.toMatchObject({ status: 401 });
  });
});
