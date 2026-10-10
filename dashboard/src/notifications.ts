/* Desktop alerts for urgent alerts. The Windows services run in session 0 and cannot
   reach the user's desktop, so the open dashboard (it may be minimised) polls
   /api/notifications and notifies itself. The server picks what counts as urgent
   from the user's own threshold; this file only decides when to say so.

   SECURITY: notification text is FIXED wording from this file. Alert titles, IPs,
   device names and AI-written text are attacker-controlled or model-written, and a
   desktop pop-up is exactly where a lure ("Call support at...") would work, so none
   of it is ever shown here. The server does not even send it. */
import { useEffect, useRef } from 'react';
import { getSession, safeParse, sessionRejected } from './api';

export const LAST_SEEN_KEY = 'lighthouse-notify-last-seen';
export const OFF_KEY = 'lighthouse-notify-off';
export const POLL_MS = 45_000;
export const MAX_BACKOFF_MS = 10 * 60_000;
const BASE_TITLE = 'LightHouse';

export type NewAlert = { id: number; severity: string; timestamp: string };
export type NewAlerts = { threshold: string; count: number; latest_id: number; alerts: NewAlert[] };

const isCursor = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

/* Per browser, so a reload does not re-notify for alerts already announced. Corrupt
   storage is dropped and treated as a first run, never a white screen. */
export const readLastSeen = (): number | null => safeParse<number | null>(LAST_SEEN_KEY, null, value => value === null || isCursor(value));
export const saveLastSeen = (id: number) => { try { localStorage.setItem(LAST_SEEN_KEY, JSON.stringify(id)); } catch { /* kept in memory this session */ } };
export const notificationsOff = (): boolean => safeParse<boolean>(OFF_KEY, false, value => typeof value === 'boolean');
export const setNotificationsOff = (off: boolean) => { try { localStorage.setItem(OFF_KEY, JSON.stringify(off)); } catch { /* applies until reload */ } };

/* Where the cursor goes after a poll. First run (no cursor) starts from the newest
   alert instead of announcing the whole history; a cursor past the newest alert (a
   new database) starts again from it. */
export function nextCursor(lastSeen: number | null, latestId: number): number {
  if (lastSeen === null || lastSeen > latestId) return latestId;
  return Math.max(lastSeen, latestId);
}

/* Only announces when there was a cursor to compare against; see nextCursor. */
export const shouldNotify = (lastSeen: number | null, result: NewAlerts) =>
  lastSeen !== null && lastSeen <= result.latest_id && result.count > 0;

/* Exponential backoff on failures, capped, so a stopped API is not hammered. */
export const nextDelay = (failures: number) => Math.min(POLL_MS * 2 ** Math.max(0, failures), MAX_BACKOFF_MS);

const RANK: Record<string, number> = { medium: 1, high: 2, critical: 3 };
/* The most severe of the new alerts, from the stored (sensor-floored) severity.
   Never overstates: a medium-only batch says medium. 'high' only when the list is
   empty or holds nothing recognised, which notificationText words generically. */
export function worstSeverity(alerts: NewAlert[]): string {
  const worst = alerts.reduce<string | null>((found, alert) =>
    (RANK[alert.severity] ?? 0) > (found ? RANK[found] : 0) ? alert.severity : found, null);
  return worst ?? 'high';
}

/* Fixed wording only. An unexpected severity gets the generic sentence. */
export function notificationText(count: number, severity: string): { title: string; body: string } {
  const level = severity === 'critical' ? 'a critical' : severity === 'medium' ? 'a medium-severity' : 'a high-severity';
  return count > 1
    ? { title: 'LightHouse', body: `LightHouse found ${count} new alerts that need your attention. Open LightHouse to review them.` }
    : { title: 'LightHouse', body: `LightHouse found ${level} alert. Open LightHouse to review it.` };
}

export const titleWithCount = (count: number) => (count > 0 ? `(${count > 99 ? '99+' : count}) ${BASE_TITLE}` : BASE_TITLE);

/* Server data, so the shape is checked; anything off is a failed poll. */
export function asNewAlerts(body: unknown): NewAlerts {
  const value = body as NewAlerts | null;
  if (!value || typeof value !== 'object' || typeof value.threshold !== 'string' || !isCursor(value.count) || !isCursor(value.latest_id)
    || !Array.isArray(value.alerts) || !value.alerts.every(alert => !!alert && isCursor(alert.id) && typeof alert.severity === 'string'))
    throw new Error('Unexpected notifications response');
  return { threshold: value.threshold, count: value.count, latest_id: value.latest_id,
    alerts: value.alerts.map(alert => ({ id: alert.id, severity: alert.severity, timestamp: String(alert.timestamp) })) };
}

export async function fetchNewAlerts(after: number | null): Promise<NewAlerts> {
  const query = after === null ? '' : `?after=${after}`;
  const token = getSession()?.token;
  const response = await fetch(`/api/notifications${query}`, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' });
  /* An expired session goes back to sign-in (see api.ts), rather than backing off
     silently while the owner believes they are still being alerted. */
  if (response.status === 401) sessionRejected(token);
  if (!response.ok) throw Object.assign(new Error('Notifications poll failed'), { status: response.status });
  return asNewAlerts(await response.json());
}

export const notificationsSupported = () => typeof window !== 'undefined' && 'Notification' in window;
export const notificationPermission = (): NotificationPermission | 'unsupported' => {
  try { return notificationsSupported() ? Notification.permission : 'unsupported'; } catch { return 'unsupported'; }
};

/* Polls while signed in. New alerts at or above the threshold put a count in the
   window title (works without permission) and, once permission is granted and the
   user has not turned them off, show one desktop notification. Clicking it focuses
   the window and opens Alerts. The count clears when Alerts is opened or the window
   regains focus. */
export function useAlertNotifications({ active, onAlerts, onNew, viewingAlerts }: {
  active: boolean; onAlerts: () => void; onNew: () => void; viewingAlerts: boolean;
}) {
  const unseen = useRef(0);
  /* Latest callbacks without restarting the poll loop on every render. */
  const handlers = useRef({ onAlerts, onNew });
  handlers.current = { onAlerts, onNew };

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let cursor = readLastSeen();
    const setCount = (count: number) => { unseen.current = count; document.title = titleWithCount(count); };
    const clear = () => setCount(0);

    const poll = async () => {
      try {
        const result = await fetchNewAlerts(cursor);
        if (cancelled) return;
        failures = 0;
        if (shouldNotify(cursor, result)) {
          setCount(unseen.current + result.count);
          handlers.current.onNew();
          if (notificationPermission() === 'granted' && !notificationsOff()) {
            const { title, body } = notificationText(result.count, worstSeverity(result.alerts));
            try {
              const shown = new Notification(title, { body, tag: 'lighthouse-urgent', icon: '/assets/lighthouse-logo.png' });
              shown.onclick = () => { window.focus(); handlers.current.onAlerts(); clear(); shown.close(); };
            } catch { /* the title count still shows it */ }
          }
        }
        cursor = nextCursor(cursor, result.latest_id);
        saveLastSeen(cursor);
      } catch {
        failures += 1;
      }
      if (!cancelled) timer = setTimeout(poll, nextDelay(failures));
    };

    window.addEventListener('focus', clear);
    void poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
      window.removeEventListener('focus', clear);
      document.title = BASE_TITLE;
    };
  }, [active]);

  useEffect(() => { if (viewingAlerts && unseen.current) { unseen.current = 0; document.title = BASE_TITLE; } });
}
