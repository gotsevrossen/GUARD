import { Component, ErrorInfo, FormEvent, KeyboardEvent, ReactNode, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { api, AiInstructions, Alert, DEFAULT_ANSWER_STYLE, AuditEntry, ChatMessage, ChatModelChoice, ChatModels, ChatOptions, getSession, login, logout, Monitoring, onSessionExpired, Session, statusOf, UpdateInfo } from './api';
import { clip, Conversation, fullTime, loadConversations, MAX_QUESTION, newId, relativeTime, retryTurns, saveConversations, titleFor, toChatMessages, Turn } from './conversations';
import { notificationPermission, notificationsOff, setNotificationsOff, useAlertNotifications } from './notifications';
import { SensorId, SensorStatus, watchStatus, WatchStatus } from './api';
import './styles.css';
import './sidebar.css';

const advanced = (role?: string) => role === 'analyst' || role === 'admin';
/* Trends: four solid bars, each taller than the last. The other nav icons are line
   icons from ICONS; functions, because ICONS and Icon are declared further down. */
const TrendsIcon = (
  <svg viewBox="0 0 24 24" width={18} height={18} fill="currentColor" aria-hidden="true" focusable="false">
    <rect x="2.5" y="15" width="3.8" height="6.5" rx="1.2" /><rect x="7.7" y="11.5" width="3.8" height="10" rx="1.2" />
    <rect x="12.9" y="7.5" width="3.8" height="14" rx="1.2" /><rect x="18.1" y="3" width="3.8" height="18.5" rx="1.2" />
  </svg>
);
const icons: Record<string, () => ReactNode> = {
  home: () => <Icon name="home" size={18} />, alerts: () => <Icon name="alerts" size={18} />, trends: () => TrendsIcon,
  advanced: () => <Icon name="advanced" size={18} />, settings: () => <Icon name="settings" size={18} />,
  admin: () => <Icon name="admin" size={18} />,
};
const labels: Record<string, string> = { home: 'Home', alerts: 'Alerts', trends: 'Trends', advanced: 'Advanced analytics', settings: 'Settings', admin: 'Admin' };
const URGENT = ['high', 'critical'];
const PROMPTS = ['Summarize my network and security status', 'Explain what my most recent alert means', 'What should I address first?', 'Are there any unusual devices on my network?'];
const AI_NOTE = 'Written on this computer and checked against the alert schema. Nothing left your network.';
/* The alert itself goes to the server by id, where its sensor text is fenced as
   untrusted evidence. Its title is attacker-influenced, so it is not pasted into the
   question, where it would reach the model as the owner's own words. */
const ALERT_QUESTION = 'Explain this alert. What does it mean, and what should I do?';

/* Chat failures are shown in the thread as a reply, never as an error screen. */
function chatFailure(error: unknown, aboutAlert: boolean) {
  const status = statusOf(error);
  if (status === 401) return 'Your sign-in expired. Sign in again, then ask once more.';
  if (status === 404 && aboutAlert) return 'LightHouse can no longer find the alert this chat is about, so it can’t answer here. Start a new chat instead.';
  return 'LightHouse couldn’t answer just now. Try again in a moment.';
}

/* Fixed wording per guidance tier. The server picks the tier from the floored
   severity and the capped confidence; none of this text comes from the model or
   the alert, so nothing an attacker writes into an alert can remove or soften it.
   No sensor fields (device, address) are interpolated for the same reason. */
type Guidance = { eyebrow: string; headline: string; body?: string; steps?: { lead: string; rest: string }[] };
const GUIDANCE: Record<string, Guidance> = {
  caution: {
    eyebrow: 'Double-check',
    headline: 'LightHouse is fairly confident about this, but please double-check before acting.',
    steps: [{ lead: 'Check first:', rest: 'ask whoever uses this device whether they expected this activity at this time. If nobody did, treat the alert as real.' }],
  },
  review: {
    eyebrow: 'Needs a second opinion',
    headline: 'LightHouse isn’t sure about this one.',
    body: 'The explanation below may be wrong, in either direction. Before you change anything, have someone technical (your IT provider or a tech-savvy colleague) look at this alert. Leave it open until they have.',
  },
  get_help: {
    eyebrow: 'Get help now',
    headline: 'Contact your IT provider or a security professional now.',
    body: 'This could be serious, and LightHouse can’t be sure what happened. Call your IT provider, a managed security provider or an incident-response firm, and tell them about this alert. While you wait:',
    steps: [
      { lead: 'Don’t delete files, programs or logs.', rest: 'Whoever investigates will need them.' },
      { lead: 'Don’t reply to, contact or pay anyone demanding money.', rest: '' },
      { lead: 'Write down what you saw:', rest: 'the time, anything on screen, and anything unusual.' },
      { lead: 'Disconnect the affected device from the network', rest: '(unplug its cable or turn off its Wi-Fi) if that won’t stop critical work. Leave it switched on.' },
    ],
  },
};
const CONFIDENCE_LABEL: Record<string, string> = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence' };
const capitalised = (text: string) => text ? text[0].toUpperCase() + text.slice(1) : text;
/* An alert without a tier predates the server change; treat it as unchecked. */
const tierOf = (alert: Alert) => alert.guidance_tier || 'review';
const needsHelp = (alert: Alert) => alert.status === 'open' && tierOf(alert) === 'get_help';
/* Open get-help alerts first, everything else in the server's (newest-first) order. */
const helpFirst = (alerts: Alert[]) => [...alerts.filter(needsHelp), ...alerts.filter(alert => !needsHelp(alert))];

const detailOf = (error: unknown, fallback: string) => {
  const raw = error instanceof Error ? error.message : '';
  try { const parsed = JSON.parse(raw); return typeof parsed?.detail === 'string' ? parsed.detail : fallback; } catch { return fallback; }
};

/* "Today, 11:07 AM" reads faster than a full timestamp on a page where almost
   everything happened today. Older entries fall back to the date. */
function when(timestamp: string) {
  const at = new Date(timestamp);
  if (Number.isNaN(at.getTime())) return timestamp;
  const time = at.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const midnight = new Date(); midnight.setHours(0, 0, 0, 0);
  const days = Math.floor((midnight.getTime() - new Date(at).setHours(0, 0, 0, 0)) / 86400000);
  if (days <= 0) return `Today, ${time}`;
  if (days === 1) return `Yesterday, ${time}`;
  if (days < 7) return `${days} days ago`;
  return at.toLocaleDateString();
}

/* The model writes recommended_action as prose or as a numbered list. Both become
   the same ordered list, with the lead sentence carrying the emphasis. */
function steps(text?: string): { lead: string; rest: string }[] {
  return (text || '').split(/\r?\n+/)
    .map(line => line.replace(/^\s*(?:\d+[.)]|[-*•])\s*/, '').trim())
    .filter(Boolean)
    .map(line => {
      const end = line.search(/[.!?](\s|$)/);
      return end > 0 && end < line.length - 2 ? { lead: line.slice(0, end + 1), rest: line.slice(end + 1).trim() } : { lead: line, rest: '' };
    });
}

const Skeleton = () => (
  <div aria-hidden="true">
    <span className="sk sk-eyebrow" />
    <span className="sk sk-title" />
    <span className="sk sk-title two" />
    <div className="sk-cards"><span className="sk sk-card" /><span className="sk sk-card" /><span className="sk sk-card" /></div>
    <div className="sk-rows">
      {[['w30', 'w70'], ['w55', 'w70'], ['w30', 'w55'], ['w55', 'w70']].map(([a, b], index) => (
        <div className="sk-row" key={index}>
          <span className="sk sk-dot" /><div><span className={`sk sk-line ${a}`} /><span className={`sk sk-line ${b}`} /></div><span className="sk sk-line w12" />
        </div>
      ))}
    </div>
  </div>
);

const Nav = ({ item, tab, setTab }: { item: string; tab: string; setTab: (tab: string) => void }) => (
  <button title={labels[item]} className={tab === item ? 'active' : ''} aria-current={tab === item ? 'page' : undefined} onClick={() => setTab(item)}>
    <span className="nav-icon">{icons[item]()}</span><span className="nav-label">{labels[item]}</span>
  </button>
);

/* Small line icons for icon-only buttons. They draw in currentColor, so each button's
   own colour and hover rules apply; the button carries the accessible name. */
const ICONS = {
  copy: 'M9 9h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1V10a1 1 0 0 1 1-1zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1',
  retry: 'M3 12a9 9 0 1 0 2.64-6.36L3 8.3M3 3v5.3h5.3',
  compose: 'M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7M18.4 2.6a2.1 2.1 0 0 1 3 3L12 15l-4 1 1-4z',
  pause: 'M9 5v14M15 5v14',
  resume: 'M7 4.5v15l12-7.5z',
  power: 'M12 3v9M6.34 6.34a8 8 0 1 0 11.32 0',
  // Sidebar: the owner's picks from the icon options (house by the water, warning
  // sign, magnifier on a pulse, sliders, person with shield, door and arrow, panel).
  home: 'M5 12.5 12 7l7 5.5V17H5zM10.5 17v-3h3v3M2.5 21c1.6-1.2 3.4-1.2 5 0s3.4 1.2 5 0 3.4-1.2 5 0 2.4 1 4 0',
  alerts: 'M12 3.5 21.5 20h-19zM12 10v4.5M12 17.3h.01',
  advanced: 'M17 10.5a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0zM20.5 20.5l-5.3-5.3M6.5 10.5h1.8l1-2.2 2 4.4 1-2.2h1.7',
  settings: 'M4 6h9M17 6h3M4 12h1M9 12h11M4 18h11M19 18h1M17 6a2 2 0 1 1-4 0 2 2 0 0 1 4 0zM9 12a2 2 0 1 1-4 0 2 2 0 0 1 4 0zM19 18a2 2 0 1 1-4 0 2 2 0 0 1 4 0z',
  admin: 'M13 8a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0zM3 20c0-3.6 2.9-6 6.5-6 1.3 0 2.5.3 3.5.9M17.5 13 21 14.3v2.6c0 2-1.5 3.4-3.5 4.1-2-.7-3.5-2.1-3.5-4.1v-2.6z',
  signout: 'M10 4H6.5A1.5 1.5 0 0 0 5 5.5v13A1.5 1.5 0 0 0 6.5 20H10M14.5 8l4 4-4 4M18.5 12h-9',
  sidebar: 'M6 4h12a3 3 0 0 1 3 3v10a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3zM9.5 4v16',
  chevron: 'm6 9 6 6 6-6',
  // Selector choices (the owner's pick of the selector options, "Icon rows").
  thinking: 'M9 18h6M10 21h4M12 3a6 6 0 0 0-3.6 10.8c.7.5 1.1 1.3 1.1 2.1V16h5v-.1c0-.8.4-1.6 1.1-2.1A6 6 0 0 0 12 3z',
  balanced: 'M12 4v16M8 20h8M5 7h14M5 7 2.5 13a2.6 2.6 0 0 0 5 0zM19 7l-2.5 6a2.6 2.6 0 0 0 5 0z',
  quick: 'M13 2 4.5 13.5H11L10 22l8.5-11.5H12z',
  local: 'M5.5 5h13A1.5 1.5 0 0 1 20 6.5v8a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 14.5v-8A1.5 1.5 0 0 1 5.5 5zM2 19.5h20',
  relaxed: 'M4 12h16',
  moderate: 'M4 9h16M4 15h16',
  strict: 'M4 6h16M4 12h16M4 18h16',
  owner: 'M15.5 8a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0zM5 20c0-3.6 3.1-6 7-6s7 2.4 7 6',
  trash: 'M4 7h16M9.5 7V4.5h5V7M6.5 7l1 12.5a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5l1-12.5M10 11v6M14 11v6',
  // Send (the owner's pick from the send button options: line arrow).
  send: 'M12 19V5M5.5 11.5 12 5l6.5 6.5',
};
type IconName = keyof typeof ICONS;
const Icon = ({ name, size = 16 }: { name: IconName; size?: number }) => (
  <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="2"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d={ICONS[name]} /></svg>
);

/* The app's one selector (the owner's pick: "Icon rows"). A button opens a list of
   choices, each with an icon or severity dot, its label and an optional note; the
   chosen one's icon fills green. Colour never stands alone: every choice is named.
   A listbox with aria-activedescendant, so the arrow keys, Home/End, Enter and Esc
   work as in a native select; focus returns to the button on close. Opens upward
   in the chat box, which sits at the bottom of the screen. */
type Choice = { value: string; label: string; note?: string; icon?: IconName; severity?: 'low' | 'med' | 'high'; disabled?: boolean };
function Select({ label, value, choices, onChange, up = false, className = '', disabled = false }: {
  label: string; value: string; choices: Choice[]; onChange: (value: string) => void; up?: boolean; className?: string; disabled?: boolean;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const wrap = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLUListElement>(null);
  const current = choices.find(choice => choice.value === value);
  useEffect(() => {
    if (!open) return;
    menu.current?.focus();
    const outside = (event: PointerEvent) => { if (!wrap.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [open]);
  useEffect(() => { if (disabled) setOpen(false); }, [disabled]);
  const show = () => { if (disabled) return; setActive(Math.max(0, choices.findIndex(choice => choice.value === value))); setOpen(true); };
  const close = () => { setOpen(false); button.current?.focus(); };
  const pick = (index: number) => {
    const choice = choices[index];
    if (!choice || choice.disabled) return;
    close();
    if (choice.value !== value) onChange(choice.value);
  };
  /* Steps over disabled choices; stays put when there is nowhere to go. */
  const move = (from: number, step: number) => {
    for (let index = from + step; index >= 0 && index < choices.length; index += step)
      if (!choices[index].disabled) return setActive(index);
  };
  const keys = (event: KeyboardEvent<HTMLUListElement>) => {
    /* Focus goes back to the button first, so Tab's own move starts from there and
       lands on the next control, rather than on <body> once the list is gone. */
    if (event.key === 'Tab') { button.current?.focus(); setOpen(false); return; }
    if (event.key === 'ArrowDown') move(active, 1);
    else if (event.key === 'ArrowUp') move(active, -1);
    else if (event.key === 'Home') move(-1, 1);
    else if (event.key === 'End') move(choices.length, -1);
    else if (event.key === 'Enter' || event.key === ' ') pick(active);
    else if (event.key === 'Escape') close();
    else return;
    event.preventDefault();
  };
  const mark = (choice: Choice) => choice.severity
    ? <span className={`select-dot ${choice.severity}`} />
    : choice.icon ? <span className="select-icon"><Icon name={choice.icon} size={17} /></span> : null;
  return (
    <div className={`select${up ? ' up' : ''}${className ? ` ${className}` : ''}`} ref={wrap}>
      <button type="button" className="select-trigger" ref={button} disabled={disabled} aria-haspopup="listbox" aria-expanded={open}
        aria-controls={`${id}-menu`} aria-label={`${label}: ${current?.label ?? value}`} title={current?.note}
        onClick={() => (open ? close() : show())}
        onKeyDown={event => { if (['ArrowDown', 'ArrowUp'].includes(event.key)) { event.preventDefault(); show(); } }}>
        {current && mark(current)}
        <span className="select-label">{current?.label ?? value}</span>
        <span className="select-chevron"><Icon name="chevron" size={16} /></span>
      </button>
      {open && (
        <ul className="select-menu" id={`${id}-menu`} role="listbox" tabIndex={-1} ref={menu} aria-label={label}
          aria-activedescendant={`${id}-${active}`} onKeyDown={keys}>
          {choices.map((choice, index) => (
            <li key={choice.value} id={`${id}-${index}`} role="option" aria-selected={choice.value === value} aria-disabled={choice.disabled || undefined}
              className={index === active ? 'active' : undefined} onPointerMove={() => { if (!choice.disabled) setActive(index); }} onClick={() => pick(index)}>
              {mark(choice)}
              <span className="select-text"><span>{choice.label}</span>{choice.note && <small>{choice.note}</small>}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* Chat model choices carry their icon by id; a model the list does not know (an older
   saved setting) still shows, by its id. */
const MODEL_ICONS: Record<string, IconName> = { 'gpt-oss:120b': 'thinking', 'llama4:latest': 'balanced', 'gemma4:26b-a4b': 'quick', local: 'local' };
function modelChoices(list: ChatModelChoice[], current: string, unknownLabel: string, disabled?: (choice: ChatModelChoice) => boolean): Choice[] {
  const known = list.some(choice => choice.id === current);
  return [
    ...(known ? [] : [{ value: current, label: unknownLabel, icon: 'balanced' as IconName }]),
    ...list.map(choice => ({ value: choice.id, label: choice.label, note: choice.note, icon: MODEL_ICONS[choice.id] ?? 'balanced', disabled: disabled?.(choice) })),
  ];
}
const THRESHOLDS: Choice[] = [
  { value: 'medium', label: 'Medium', note: 'More alerts reach you', severity: 'med' },
  { value: 'high', label: 'High', note: 'High and critical alerts', severity: 'high' },
  { value: 'critical', label: 'Critical', note: 'Only the most serious', severity: 'high' },
];
const SENSITIVITIES: Choice[] = [
  { value: 'relaxed', label: 'Relaxed', note: 'Fewer, surer alerts', icon: 'relaxed' },
  { value: 'balanced', label: 'Balanced', note: 'Recommended', icon: 'moderate' },
  { value: 'strict', label: 'Strict', note: 'Flags more borderline activity', icon: 'strict' },
];
const ROLES: Choice[] = [
  { value: 'owner', label: 'Owner', note: 'Plain-English explanations', icon: 'owner' },
  { value: 'analyst', label: 'Analyst', note: 'Also sees raw evidence', icon: 'advanced' },
  { value: 'admin', label: 'Admin', note: 'Also manages users and settings', icon: 'admin' },
];

/* Only the list scrolls once it outgrows the rail, so the brand, nav and the bottom
   items stay put. Each row has a delete button on its right, shown on hover or
   keyboard focus; the thread still being answered has none, so its answer always
   has somewhere to land. */
function Chats({ chats, activeId, pendingId, open, remove, focusAway }: {
  chats: Conversation[]; activeId: string | null; pendingId: string | null; open: (id: string) => void;
  remove: (id: string) => boolean; focusAway: () => void;
}) {
  const list = useRef<HTMLDivElement>(null);
  /* The deleted row took keyboard focus with it: land on the chat that took its
     place (or the one above it), or on New chat once the list is empty. */
  const removeAt = (id: string, index: number) => {
    if (!remove(id)) return;
    requestAnimationFrame(() => {
      const rows = list.current?.querySelectorAll<HTMLButtonElement>('button.chat');
      const next = rows?.length ? rows[Math.min(index, rows.length - 1)] : null;
      if (next) next.focus(); else focusAway();
    });
  };
  return (
    <section className="chats">
      <div className="head">
        <span className="nav-label">Recent chats</span>
      </div>
      {chats.length
        ? <div className="list" ref={list}>{chats.map((chat, index) => (
          <div className={`chat-row${chat.id === activeId ? ' active' : ''}`} key={chat.id}>
            <button className="chat" title={chat.title} onClick={() => open(chat.id)}>
              <span className="mark" aria-hidden="true">↗</span><span className="title nav-label">{chat.title}</span>
            </button>
            {chat.id !== pendingId && (
              <button className="chat-delete" type="button" title="Delete chat" aria-label={`Delete chat: ${chat.title}`} onClick={() => removeAt(chat.id, index)}>
                <Icon name="trash" size={15} />
              </button>
            )}
          </div>
        ))}</div>
        : <p className="none nav-label">No chats yet</p>}
    </section>
  );
}

function Login({ onLogin, notice }: { onLogin: (session: Session) => void; notice?: string }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try { onLogin(await login(username, password)); } catch { setError('Check your username and password.'); } finally { setBusy(false); }
  };
  return (
    <main className="login">
      <section>
        <img src="/assets/lighthouse-logo.png" alt="LightHouse" />
        <p className="eyebrow">LightHouse local</p>
        <h1>Understand what your network needs.</h1>
        <p>Your alerts are checked on this computer.</p>
        {notice && <p role="status">{notice}</p>}
        <form onSubmit={submit}>
          <input aria-label="Username" placeholder="Username" autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)} />
          <input aria-label="Password" placeholder="Password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} />
          <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
          {error && <p className="error" role="alert">{error}</p>}
        </form>
      </section>
    </main>
  );
}

function ChangePassword({ session, onDone }: { session: Session; onDone: (session: Session) => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (next !== confirm) { setError('The new passwords do not match.'); return; }
    if (next.length < 12) { setError('Use at least 12 characters.'); return; }
    setBusy(true);
    try { onDone((await api.changePassword(current, next)) || { ...session, must_change_password: false }); }
    catch (failure) { setError(detailOf(failure, 'Could not change the password. Check the current password and try again.')); }
    finally { setBusy(false); }
  };
  return (
    <main className="login">
      <section>
        <img src="/assets/lighthouse-logo.png" alt="LightHouse" />
        <p className="eyebrow">LightHouse local</p>
        <h1>Choose a new password</h1>
        <p>Enter the temporary password you were given, then choose your own.</p>
        <form onSubmit={submit}>
          <input aria-label="Current password" placeholder="Current password" type="password" autoComplete="current-password" required value={current} onChange={e => setCurrent(e.target.value)} />
          <input aria-label="New password" placeholder="New password (at least 12 characters)" type="password" autoComplete="new-password" required minLength={12} value={next} onChange={e => setNext(e.target.value)} />
          <input aria-label="Confirm new password" placeholder="Confirm new password" type="password" autoComplete="new-password" required minLength={12} value={confirm} onChange={e => setConfirm(e.target.value)} />
          <button disabled={busy}>{busy ? 'Saving…' : 'Save password'}</button>
          {error && <p className="error" role="alert">{error}</p>}
        </form>
      </section>
    </main>
  );
}

/* Opening an alert usually comes just before "Ask LightHouse about this", so the
   server pre-reads that alert's chat context now and the answer starts sooner. The
   server skips it while the model is busy; here it is at most once a minute per alert
   and model. It warms the model the chat box has picked, as the composer does. */
const alertWarmedAt = new Map<string, number>();
const warmAlert = (id: number, model: string | null) => {
  const key = `${id}:${model ?? ''}`;
  const now = Date.now();
  if (now - (alertWarmedAt.get(key) || 0) < 60_000) return;
  alertWarmedAt.set(key, now);
  api.chatWarm(id, model);
};

/* One alert, open or closed. A native details element, so it expands without
   script and stays keyboard-operable. */
function AlertItem({ alert, showStatus, canSeeEvidence, act, ask, evidence, warm }: {
  alert: Alert; showStatus?: boolean; canSeeEvidence: boolean;
  act: Act; ask: Ask; evidence: Evidence; warm: (id: number) => void;
}) {
  /* A failed change or evidence load says so here, beside the buttons. A 401 has
     already sent the app back to sign-in (api.ts), so it needs no notice. */
  const [problem, setProblem] = useState('');
  const attempt = (work: () => Promise<void>, failed: string) => {
    setProblem('');
    work().catch(error => { if (statusOf(error) !== 401) setProblem(failed); });
  };
  const isOpen = alert.status === 'open';
  const tier = tierOf(alert);
  /* Only while the alert is open: a resolved alert telling the owner to call for
     help "now" is noise. Reopening it brings the banner back. */
  const guidance = isOpen ? GUIDANCE[tier] : undefined;
  const confidence = CONFIDENCE_LABEL[alert.confidence || 'low'] || CONFIDENCE_LABEL.low;
  return (
    <details className="alert" onToggle={event => { if (event.currentTarget.open) warm(alert.id); }}>
      <summary>
        <span className={`dot ${alert.severity}`} />
        <div>
          <span className={`sev ${alert.severity}`}>{capitalised(alert.severity)} severity · {confidence}</span>
          {needsHelp(alert) && <span className="pill get_help">Get help now</span>}
          {showStatus && <span className="pill">{alert.status}</span>}
          <b>{alert.title}</b>
          <p>{alert.explanation}</p>
        </div>
        <span className="when">{when(alert.timestamp)}</span>
        <span className="chev" aria-hidden="true">▾</span>
      </summary>
      <div className="detail">
        {guidance && (
          <div className={`guidance ${tier}`}>
            <p className="eyebrow">{guidance.eyebrow}</p>
            <strong>{guidance.headline}</strong>
            {guidance.body && <p>{guidance.body}</p>}
            {guidance.steps && (tier === 'get_help'
              ? <ol>{guidance.steps.map((step, index) => <li key={index}><b>{step.lead}</b>{step.rest && ` ${step.rest}`}</li>)}</ol>
              : guidance.steps.map((step, index) => <p key={index}><b>{step.lead}</b> {step.rest}</p>))}
          </div>
        )}
        <p className="eyebrow">What this means</p>
        <p>{alert.explanation}</p>
        {steps(alert.recommended_action).length > 0 && <>
          {/* For get-help alerts the professional comes first; the model's own
              suggestion is kept, but demoted below the fixed guidance. */}
          <p className="eyebrow">{tier === 'get_help' ? 'LightHouse’s suggestion — check with your IT provider first' : 'Recommended steps'}</p>
          <ol>{steps(alert.recommended_action).map((step, index) => <li key={index}><b>{step.lead}</b>{step.rest && ` ${step.rest}`}</li>)}</ol>
        </>}
        <div className="actions">
          {isOpen
            ? <>
              <button className="btn" onClick={() => attempt(() => act(alert.id, 'resolved'), CHANGE_FAILED)}>Mark resolved</button>
              <button className="btn quiet" onClick={() => attempt(() => act(alert.id, 'dismissed'), CHANGE_FAILED)}>Dismiss</button>
            </>
            : <button className="btn quiet" onClick={() => attempt(() => act(alert.id, 'open'), CHANGE_FAILED)}>Reopen</button>}
          <button className="btn quiet" onClick={() => ask(ALERT_QUESTION, alert)}>Ask LightHouse about this</button>
          {canSeeEvidence && <button className="btn quiet" onClick={() => attempt(() => evidence(alert), EVIDENCE_FAILED)}>Show evidence</button>}
        </div>
        {problem && <p className="notice" role="status">{problem}</p>}
        <p className="ai-note">{AI_NOTE}</p>
      </div>
    </details>
  );
}

/* Passing an alert always opens a new thread about that alert. */
type Ask = (question: string, about?: Alert) => void;
type Act = (id: number, status: string) => Promise<void>;
type Evidence = (alert: Alert) => Promise<void>;
const CHANGE_FAILED = 'LightHouse couldn’t update this alert. Try again in a moment.';
const EVIDENCE_FAILED = 'LightHouse couldn’t load the evidence for this alert. Try again in a moment.';
type PageProps = {
  alerts: Alert[]; canSeeEvidence: boolean;
  /* true when the alert list could not be loaded: an empty list must not read as "all clear" */
  alertsFailed: boolean; reload: () => void;
  act: Act; ask: Ask; evidence: Evidence; warm: (id: number) => void;
  /* Background monitoring: shown to everyone; the switch is passed only to admins. */
  monitoring?: Monitoring | null; monitoringBusy?: boolean; toggleMonitoring?: () => void; shutDown?: () => void;
};

/* "Is LightHouse watching?": the live state of each sensor, for every role, from
   GET /api/status. Each page that shows it asks once and re-asks every minute,
   since a sensor going quiet is exactly what this has to catch.
   undefined = still checking, null = the check failed. */
const STATUS_REFRESH_MS = 60_000;
function useWatchStatus(): WatchStatus | null | undefined {
  const [status, setStatus] = useState<WatchStatus | null | undefined>(undefined);
  useEffect(() => {
    let live = true;
    const load = () => { watchStatus().then(next => { if (live) setStatus(next); }).catch(() => { if (live) setStatus(null); }); };
    load();
    const timer = window.setInterval(load, STATUS_REFRESH_MS);
    return () => { live = false; window.clearInterval(timer); };
  }, []);
  return status;
}

/* What the Windows install actually reads. Zeek and Wazuh were the Linux build's sensors. */
const SENSORS: { id: SensorId; name: string; about: string; noun: string }[] = [
  { id: 'network', name: 'Suricata', about: 'Network traffic: known attacks and suspicious connections', noun: 'network sensor' },
  { id: 'computer', name: 'Sysmon', about: 'This computer: programs starting, network connections, file and registry changes', noun: 'computer sensor' },
  { id: 'sign_ins', name: 'Windows Security log', about: 'Sign-ins, failed sign-ins, account changes and cleared logs', noun: 'sign-in monitor' },
  { id: 'local_ai', name: 'Local AI', about: 'Explains each new alert in plain English, on this computer', noun: 'built-in AI' },
];
const nounOf = (id: SensorId) => SENSORS.find(sensor => sensor.id === id)?.noun || 'sensor';
/* The pill always names the state, so colour is never the only signal. */
function stateLabel(sensor: SensorStatus): string {
  if (sensor.state === 'not_installed') return sensor.id === 'local_ai' ? 'Unavailable' : 'Not installed';
  return { working: 'Working', not_reporting: 'Not reporting', paused: 'Paused' }[sensor.state];
}
function heardAt(at: Date): string {
  const time = at.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  return at.toDateString() === new Date().toDateString() ? time : `${at.toLocaleDateString([], { month: 'short', day: 'numeric' })}, ${time}`;
}
const listOf = (words: string[]) => words.length < 2 ? words.join('') : `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;

/* The Home card's one line, true to what the sensors last said. */
function watchLine(watch: WatchStatus | null | undefined): string {
  if (watch === undefined) return 'Checking your monitoring…';
  if (watch === null) return 'LightHouse could not check its sensors just now.';
  if (watch.overall === 'paused') return 'Monitoring is switched off for now.';
  const problems = watch.sensors.filter(sensor => sensor.id !== 'local_ai' && sensor.state !== 'working');
  if (!problems.length) {
    const ai = watch.sensors.find(sensor => sensor.id === 'local_ai');
    return ai && ai.state !== 'working' ? 'All monitoring is working. The built-in AI is unavailable, so a person should review new alerts.' : 'All monitoring is working.';
  }
  if (problems.length > 1) return `The ${listOf(problems.map(sensor => nounOf(sensor.id)))} aren't reporting. Ask your IT contact to check them.`;
  const [problem] = problems;
  const noun = nounOf(problem.id);
  if (problem.state === 'not_installed') return `The ${noun} isn't set up on this computer. Ask your IT contact to check it.`;
  return problem.lastHeard ? `The ${noun} hasn't reported since ${heardAt(problem.lastHeard)}. Ask your IT contact to check it.`
    : `The ${noun} isn't reporting. Ask your IT contact to check it.`;
}

/* Paused counts from either source, so the strip and the card always agree even when
   /api/monitoring fails but /api/status still says so. */
function HealthCard({ watch, paused, urgent, alertsFailed }: { watch: WatchStatus | null | undefined; paused: boolean; urgent: number; alertsFailed: boolean }) {
  const check = !paused && watch?.overall === 'attention';
  /* "Good" only on a real answer: a failed check or a failed alert load can't vouch for anything. */
  const [title, line] = paused ? ['Paused', 'Monitoring is switched off for now.']
    : alertsFailed ? ['Can’t check', 'LightHouse couldn’t load your alerts. Try again in a moment.']
    : urgent ? ['Review alerts', watchLine(watch)]
    : check ? ['Needs a check', watchLine(watch)]
    : watch === null ? ['Can’t check', watchLine(watch)]
    : watch === undefined ? ['Checking…', watchLine(watch)]
    : ['Good', watchLine(watch)];
  return <div><small>Health status</small><strong>{title}</strong><p>{line}</p></div>;
}

/* Settings' "Monitoring sources": each sensor's live state, for every role. */
function MonitoringSources() {
  const watch = useWatchStatus();
  return (
    <>
      <h3>Monitoring sources</h3>
      <div className="panel">
        {SENSORS.map(({ id, name, about }) => {
          const sensor = watch?.sensors.find(entry => entry.id === id);
          /* Not working and not a known, deliberate state: solid like "Get help now". */
          const alarm = !!sensor && id !== 'local_ai' && (sensor.state === 'not_reporting' || sensor.state === 'not_installed');
          return (
            <div className="field" key={id}>
              <div>
                <b>{name}</b><p>{about}</p>
                {sensor && <p>{sensor.message}{sensor.lastHeard && id !== 'local_ai' ? ` Last heard from ${heardAt(sensor.lastHeard)}.` : ''}</p>}
              </div>
              <span className={alarm ? 'pill get_help' : 'pill'}>{sensor ? stateLabel(sensor) : watch === undefined ? 'Checking…' : 'Unknown'}</span>
            </div>
          );
        })}
      </div>
      {watch === null && <p className="notice" role="status">LightHouse could not check its sensors just now. It tries again every minute.</p>}
    </>
  );
}

function Home({ alerts, alertsFailed, reload, canSeeEvidence, act, ask, evidence, warm, monitoring, monitoringBusy, toggleMonitoring, shutDown }: PageProps) {
  const watch = useWatchStatus();
  const open = alerts.filter(alert => alert.status === 'open');
  const urgent = open.filter(alert => URGENT.includes(alert.severity)).length;
  const paused = !!monitoring?.paused || watch?.overall === 'paused';
  /* A sensor that has stopped reporting must not sit under "looks healthy" and a
     green "Monitoring active": that false reassurance is the worst failure here. The
     same goes for a status check that failed (null) or hasn't answered yet
     (undefined), paused monitoring, and an alert list that didn't load. */
  const sensorTrouble = watch?.overall === 'attention' && !paused;
  const unchecked = watch === null && !paused;
  const checking = watch === undefined && !paused;
  const count = alertsFailed ? 'Alerts couldn’t load' : `${open.length} open alert${open.length === 1 ? '' : 's'}`;
  const [dot, strip, detail] = paused ? ['off', 'Monitoring paused', 'Not watching this computer or network until resumed']
    : urgent ? ['warn', 'Attention needed', count]
    : sensorTrouble ? ['warn', 'A sensor isn’t reporting', 'See Settings › Monitoring sources']
    : unchecked ? ['off', 'Can’t check monitoring', 'LightHouse tries again every minute']
    : checking ? ['off', 'Checking monitoring…', count]
    : alertsFailed ? ['off', 'Monitoring active', count]
    : ['', 'Monitoring active', count];
  return (
    <div>
      <section className="welcome">
        <p className="eyebrow">Network overview</p>
        <h1>{alertsFailed ? <>Couldn’t load<br />your alerts</>
          : urgent ? <>{urgent} item{urgent === 1 ? '' : 's'} deserve{urgent === 1 ? 's' : ''}<br />your attention</>
          : paused ? <>Monitoring<br />is paused</>
          : sensorTrouble ? <>Monitoring<br />needs a check</>
          : unchecked ? <>Couldn’t check<br />your monitoring</>
          : checking ? <>Checking<br />your network</>
          : <>Your network<br />looks healthy</>}</h1>
        {alertsFailed && <p role="status">LightHouse couldn’t load your alerts. Try again in a moment.</p>}
        <div className="health">
          <i className={dot} />
          <b>{strip}</b>
          <small>{detail}</small>
          {alertsFailed && <button className="btn quiet" type="button" onClick={reload}>Try again</button>}
          {toggleMonitoring && monitoring?.available && (
            <button className="btn quiet" type="button" disabled={monitoringBusy} onClick={toggleMonitoring}>
              {monitoringBusy ? 'Working…' : monitoring.paused ? 'Resume monitoring' : 'Pause monitoring'}
            </button>
          )}
          {shutDown && monitoring?.available && (
            <button className="btn quiet" type="button" disabled={monitoringBusy} onClick={shutDown}>Shut down</button>
          )}
        </div>
      </section>
      <section className="cards lead">
        <HealthCard watch={watch} paused={paused} urgent={urgent} alertsFailed={alertsFailed} />
        <div><small>Open alerts</small><strong>{alertsFailed ? '—' : open.length}</strong><p>Items that have not been resolved.</p></div>
        <div><small>High priority</small><strong>{alertsFailed ? '—' : urgent}</strong><p>Potentially urgent activity.</p></div>
      </section>
      <section className="recent">
        <div className="head"><p className="eyebrow">Recent activity</p><h2>Latest alerts</h2></div>
        {helpFirst(alerts).slice(0, 4).map(alert => <AlertItem key={alert.id} alert={alert} showStatus canSeeEvidence={canSeeEvidence} act={act} ask={ask} evidence={evidence} warm={warm} />)}
        {!alerts.length && (alertsFailed
          ? <div className="empty-state"><b>Alerts unavailable</b><p>LightHouse couldn’t load your alerts. Try again in a moment.</p></div>
          : <div className="empty-state"><b>Nothing to review</b><p>No alerts yet. When LightHouse spots something, it appears here with a plain-English explanation and what to do next.</p></div>)}
      </section>
      <section className="common-questions">
        <p className="eyebrow">Common questions</p>
        <div className="prompt-cards">
          {PROMPTS.map(prompt => <button type="button" key={prompt} onClick={() => ask(prompt)}>{prompt} <b aria-hidden="true">↗</b></button>)}
        </div>
      </section>
    </div>
  );
}

/* LightHouse's "working" mark: the green speaker dot turns into a small round tank of
   water. Two swells roll through it at different speeds, drops splash off the crest,
   the water bobs, and an arc runs round the rim like a loading ring. Brand greens
   only; static under reduced motion. Each swell spans two periods of the 26-unit
   circle, so sliding it one period loops seamlessly. */
function WaveMark({ label = 'LightHouse is replying' }: { label?: string | null }) {
  const clip = `wave-clip-${useId().replace(/:/g, '')}`;
  // label null: decorative, where text beside it already announces the progress.
  const a11y = label === null ? { 'aria-hidden': true } : { role: 'status', 'aria-label': label };
  return (
    <span className="mark wave-mark" {...a11y}>
      <svg viewBox="0 0 26 26" aria-hidden="true" focusable="false">
        <defs><clipPath id={clip}><circle cx="13" cy="13" r="11" /></clipPath></defs>
        <circle className="tank" cx="13" cy="13" r="11" />
        <g clipPath={`url(#${clip})`}>
          <g className="water">
            <g className="drops"><circle cx="9" cy="12.5" r="1" /><circle cx="13.5" cy="12" r=".8" /><circle cx="17.5" cy="12.5" r=".9" /></g>
            <g className="swell back"><path d="M0 14 Q6.5 11.5 13 14 T26 14 T39 14 T52 14 V26 H0 Z" /></g>
            <g className="swell front"><path d="M0 15 Q6.5 17.5 13 15 T26 15 T39 15 T52 15 V26 H0 Z" /></g>
          </g>
        </g>
        <circle className="rim" cx="13" cy="13" r="12" />
        <circle className="ring" cx="13" cy="13" r="12" pathLength="100" />
      </svg>
    </span>
  );
}

const paragraphs = (text: string) => text.split(/\n+/).map((line, index) => <p key={index}>{line}</p>);

/* Said beside the loader while LightHouse works, a little like a progress log: the
   first lines say what is actually happening, the rest keep the wait company. */
const THINKING_LINES = ['Checking the evidence…', 'Weighing how serious it is…', 'Scanning the horizon…',
  'Polishing the lens…', 'Charting safe waters…', 'Putting it in plain English…'];

function ThinkingWords({ provider, aboutAlert }: { provider: string; aboutAlert: boolean }) {
  const lines = useMemo(() => [
    provider === 'purdue' ? 'Asking Purdue GenAI Studio…' : provider === 'local' ? 'Waking the local AI…' : 'Getting ready to answer…',
    aboutAlert ? 'Reading this alert…' : 'Reading your recent alerts…',
    ...THINKING_LINES,
    ...(provider === 'local' ? ['Thinking on this computer. This can take a minute…'] : []),
  ], [provider, aboutAlert]);
  const [index, setIndex] = useState(0);
  /* The two "what is happening" lines show once; after that the rest loop. */
  useEffect(() => {
    const timer = setInterval(() => setIndex(current => (current + 1 < lines.length ? current + 1 : 2)), 2600);
    return () => clearInterval(timer);
  }, [lines]);
  /* aria-hidden: the loader's own status label speaks; a line every few seconds would be noise. */
  return <span className="thinking-words" aria-hidden="true">{lines[index]}</span>;
}

/* The Clipboard API needs a secure context; 127.0.0.1 normally counts as one, but
   if it is refused the old select-and-copy route still works. Focus goes back to
   the button, so a keyboard user is not left on a hidden textarea. */
async function copyText(text: string): Promise<boolean> {
  try { if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return true; } } catch { /* fall back */ }
  const focused = document.activeElement as HTMLElement | null;
  const area = document.createElement('textarea');
  try {
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed'; area.style.opacity = '0'; area.style.pointerEvents = 'none';
    document.body.appendChild(area);
    area.select();
    return document.execCommand('copy');
  } catch { return false; } finally { area.remove(); focused?.focus(); }
}

const reducedMotion = () => { try { return !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches; } catch { return false; } };
const isoTime = (at: number) => { const date = new Date(at); return Number.isNaN(date.getTime()) ? undefined : date.toISOString(); };

/* "2 min ago" has to move on by itself while the thread sits open. */
function useNow(every = 60_000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), every); return () => clearInterval(timer); }, [every]);
  return now;
}

/* An open conversation. Nothing labels the speaker: a question sits in its own
   card on the right, the answer runs as plain text on the left. While the model
   works, the animated WaveMark and a status line sit above its words as they
   arrive; once the answer is complete, only the text remains, with a quiet row of
   actions (copy, retry on the last answer) and when it was written. */
function Thread({ chat, thinking, streamed, provider, busy, retry }: {
  chat: Conversation; thinking: boolean; streamed: string; provider: string; busy: boolean; retry: () => void;
}) {
  const now = useNow();
  const [copied, setCopied] = useState<{ index: number; ok: boolean } | null>(null);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(null), 2000);
    return () => clearTimeout(timer);
  }, [copied]);
  const copy = async (index: number, text: string) => setCopied({ index, ok: await copyText(text) });

  const lastIndex = chat.turns.length - 1;
  return (
    <div>
      <p className="eyebrow">Chat</p>
      <h2>{chat.title}</h2>
      <div className="thread">
        {chat.turns.map((turn, index) => {
          const at = turn.at !== undefined ? isoTime(turn.at) : undefined;
          if (turn.role === 'me') {
            return <div className="turn me" key={index} title={at && fullTime(turn.at!)}>{paragraphs(turn.text)}</div>;
          }
          /* local notices are the app's own words, not an answer worth copying */
          const canCopy = !turn.local;
          const canRetry = index === lastIndex;
          return (
            <div className="turn them" key={index}>
              {paragraphs(turn.text)}
              {(canCopy || canRetry || at) && (
                <div className="turn-actions">
                  {canCopy && (
                    <button type="button" className="icon-btn" aria-label="Copy answer" title="Copy" onClick={() => copy(index, turn.text)}>
                      <Icon name="copy" />
                    </button>
                  )}
                  {canRetry && (
                    <button type="button" className="icon-btn" aria-label="Retry answer" title="Retry" disabled={busy} onClick={retry}>
                      <Icon name="retry" />
                    </button>
                  )}
                  {at && <time dateTime={at} title={fullTime(turn.at!)}>{relativeTime(turn.at!, now)}</time>}
                  {canCopy && <span className="copied" role="status">{copied?.index === index ? (copied.ok ? 'Copied' : 'Couldn’t copy') : ''}</span>}
                </div>
              )}
            </div>
          );
        })}
        {thinking && (
          <div className="turn them">
            <div className="thinking">
              <WaveMark />
              {!streamed.trim() && <ThinkingWords provider={provider} aboutAlert={chat.alertId !== undefined} />}
            </div>
            {streamed.trim() && paragraphs(streamed.trimStart())}
          </div>
        )}
      </div>
    </div>
  );
}

function Alerts({ alerts, alertsFailed, reload, canSeeEvidence, act, ask, evidence, warm }: PageProps) {
  const [filter, setFilter] = useState('all');
  const counts = {
    all: alerts.length,
    open: alerts.filter(alert => alert.status === 'open').length,
    resolved: alerts.filter(alert => alert.status === 'resolved').length,
    dismissed: alerts.filter(alert => alert.status === 'dismissed').length,
  };
  const visible = helpFirst(filter === 'all' ? alerts : alerts.filter(alert => alert.status === filter));
  return (
    <div>
      <p className="eyebrow">Alerts</p>
      <h1>Security<br />activity</h1>
      <p className="lede">Open an alert for a plain-English explanation and the steps LightHouse suggests.</p>
      <div className="chips">
        {(['all', 'open', 'resolved', 'dismissed'] as const).map(key => (
          <button key={key} className={filter === key ? 'on' : ''} aria-pressed={filter === key} onClick={() => setFilter(key)}>
            {key[0].toUpperCase() + key.slice(1)} {counts[key]}
          </button>
        ))}
      </div>
      <section className="recent">
        {alertsFailed && <>
          <p className="notice" role="status">LightHouse couldn’t load your alerts. Try again in a moment.</p>
          <div className="row-end"><button className="btn quiet" type="button" onClick={reload}>Try again</button></div>
        </>}
        {visible.map(alert => <AlertItem key={alert.id} alert={alert} showStatus canSeeEvidence={canSeeEvidence} act={act} ask={ask} evidence={evidence} warm={warm} />)}
        {!visible.length && !alertsFailed && <div className="empty-state"><b>Nothing to review</b><p>No alerts match this filter.</p></div>}
      </section>
    </div>
  );
}

type TrendRow = { day: string; severity: string; count: number };

function Trends({ alerts }: { alerts: Alert[] }) {
  const [rows, setRows] = useState<TrendRow[] | null>(null);
  useEffect(() => { api.trends().then(setRows).catch(() => setRows([])); }, []);

  /* Seven columns: the last seven calendar days ending today, in this computer's
     time, each stacked high over medium over unknown over low. Unknown means the AI's
     answer couldn't be checked and a person should review it, so it is grey, never
     the reassuring green of low. A quiet day is an empty column,
     not a missing one. The server sends local 'YYYY-MM-DD' days; they are matched as
     strings and named from a local Date, because new Date('YYYY-MM-DD') means UTC
     midnight, which is the evening before in the US and named every day one early.
     The chart is 200px tall, so a unit is 200/scale pixels. */
  const days = useMemo(() => {
    const byDay = new Map<string, { low: number; unknown: number; medium: number; high: number }>();
    for (const row of rows || []) {
      const bucket = byDay.get(row.day) || { low: 0, unknown: 0, medium: 0, high: 0 };
      if (URGENT.includes(row.severity)) bucket.high += row.count;
      else if (row.severity === 'medium') bucket.medium += row.count;
      else if (row.severity === 'low') bucket.low += row.count;
      else bucket.unknown += row.count;
      byDay.set(row.day, bucket);
    }
    const today = new Date();
    return Array.from({ length: 7 }, (_, index) => {
      const at = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 6 + index);
      const day = `${at.getFullYear()}-${String(at.getMonth() + 1).padStart(2, '0')}-${String(at.getDate()).padStart(2, '0')}`;
      const bucket = byDay.get(day) || { low: 0, unknown: 0, medium: 0, high: 0 };
      return { day, name: at.toLocaleDateString([], { weekday: 'short' }), ...bucket, total: bucket.low + bucket.unknown + bucket.medium + bucket.high };
    });
  }, [rows]);

  if (!rows) return <Skeleton />;
  /* Even, so the middle gridline's label is exact. */
  const most = Math.max(4, ...days.map(day => day.total));
  const scale = most % 2 ? most + 1 : most;
  const px = (count: number) => `${Math.round((count / scale) * 200)}px`;
  const week = days.reduce((sum, day) => sum + day.total, 0);
  const duplicates = alerts.reduce((sum, alert) => sum + (alert.duplicate_count || 0), 0);

  return (
    <div>
      <p className="eyebrow">Trends</p>
      <h1>Alert activity<br />over time</h1>
      <p className="lede">The last seven days of triaged alerts, grouped by the severity LightHouse assigned.</p>
      <section className="cards">
        <div><small>Alerts this week</small><strong>{week}</strong><p>Across the days shown below.</p></div>
        <div><small>Currently open</small><strong>{alerts.filter(alert => alert.status === 'open').length}</strong><p>Items that have not been resolved.</p></div>
        <div><small>Duplicates suppressed</small><strong>{duplicates}</strong><p>Folded into existing alerts.</p></div>
      </section>

      {week ? (
        <div className="chart">
          <div className="legend">
            <span><i />Low</span><span className="u"><i />Unknown</span><span className="m"><i />Medium</span><span className="h"><i />High</span>
          </div>
          <div className="plot" style={{ ['--days' as string]: days.length }}>
            <div className="grid">
              <i style={{ top: 0 }} /><b style={{ top: 0 }}>{scale}</b>
              <i style={{ top: '50%' }} /><b style={{ top: '50%' }}>{scale / 2}</b>
              <i style={{ top: '100%' }} /><b style={{ top: '100%' }}>0</b>
            </div>
            {days.map(day => (
              <div className="col" key={day.day}>
                {day.high > 0 && <span className="h" style={{ height: px(day.high) }}><em>{day.name} · {day.high} high</em></span>}
                {day.medium > 0 && <span className="m" style={{ height: px(day.medium) }}><em>{day.name} · {day.medium} medium</em></span>}
                {day.unknown > 0 && <span className="u" style={{ height: px(day.unknown) }}><em>{day.name} · {day.unknown} unknown (needs review)</em></span>}
                {day.low > 0 && <span style={{ height: px(day.low) }}><em>{day.name} · {day.low} low</em></span>}
              </div>
            ))}
          </div>
          <div className="xaxis" style={{ ['--days' as string]: days.length }}>{days.map(day => <span key={day.day}>{day.name}</span>)}</div>
          <details className="table">
            <summary>Table view</summary>
            <table>
              <tbody>
                <tr><th>Day</th><th>Low</th><th>Unknown</th><th>Medium</th><th>High</th><th>Total</th></tr>
                {days.map(day => <tr key={day.day}><td>{day.name}</td><td>{day.low}</td><td>{day.unknown}</td><td>{day.medium}</td><td>{day.high}</td><td>{day.total}</td></tr>)}
              </tbody>
            </table>
          </details>
        </div>
      ) : rows.length
        ? <div className="empty-state"><b>A quiet week</b><p>No alerts in the last seven days.</p></div>
        : <div className="empty-state"><b>No activity yet</b><p>Trend data appears once alerts have been processed.</p></div>}
    </div>
  );
}

type Health = { database?: string; model?: string; platform?: string; disk_free_bytes?: number };
type Device = { device: string; events: number; last_seen: string };

const gigabytes = (bytes?: number) => (bytes ? `${(bytes / 1e9).toFixed(0)} GB` : '—');

function useHealth() {
  const [health, setHealth] = useState<Health>();
  useEffect(() => { api.health().then(setHealth).catch(() => setHealth({})); }, []);
  return health;
}

/* The plain-English lead-in above a raw record: the alert's own triage explanation,
   so the owner reads what the record shows before the JSON. Model output, so it is
   only ever rendered as React text; no new AI call is made for it. */
function evidenceLead(selected: any): string {
  const text = (value: unknown) => (typeof value === 'string' ? value.trim() : '');
  const explanation = text(selected?.triage?.explanation);
  if (explanation) return `What this shows: ${explanation}`;
  const action = text(selected?.triage?.recommended_action);
  return action
    ? `LightHouse has no plain-English summary for this record yet. Its suggested next step: ${action}`
    : 'LightHouse has no plain-English summary for this record yet.';
}

function Advanced({ selected, jump, jumped }: { selected: any; jump: boolean; jumped: () => void }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const health = useHealth();
  const evidence = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { api.devices().then(setDevices).catch(() => setDevices([])); }, []);
  const ready = !!devices && !!health;
  /* Arriving from "Show evidence" lands on the record, not the top of the page. Only
     .sheet scrolls, and scrollIntoView moves that scroller. Focus follows (without a
     second scroll) so keyboard users land there too. Once per click: a later visit to
     this tab starts at the top as usual. */
  useEffect(() => {
    if (!jump || !ready) return;
    evidence.current?.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
    heading.current?.focus({ preventScroll: true });
    jumped();
  }, [jump, ready]);
  if (!devices || !health) return <Skeleton />;
  const events = devices.reduce((sum, device) => sum + device.events, 0);
  return (
    <div>
      <p className="eyebrow">Advanced</p>
      <h1>Technical<br />workspace</h1>
      <p className="lede">Raw evidence and model reasoning behind each triaged alert. Analyst and admin only.</p>
      <section className="cards">
        <div><small>Events ingested</small><strong>{events.toLocaleString()}</strong><p>Across every monitoring source.</p></div>
        <div><small>Model</small><strong>{health.model || '—'}</strong><p>Running locally, no external calls.</p></div>
        <div><small>Devices seen</small><strong>{devices.length}</strong><p>Distinct hosts in the alert record.</p></div>
      </section>

      <h3>Device activity</h3>
      <table className="list">
        <tbody>
          <tr><th>Device</th><th>Events</th><th>Last seen</th></tr>
          {devices.slice(0, 12).map(device => (
            <tr key={device.device}><td><b>{device.device}</b></td><td>{device.events.toLocaleString()}</td><td>{when(device.last_seen)}</td></tr>
          ))}
          {!devices.length && <tr><td colSpan={3} className="muted">No device activity recorded yet.</td></tr>}
        </tbody>
      </table>

      {/* The record itself first, introduced in plain words; the model's working after it. */}
      <section id="alert-evidence" ref={evidence} aria-labelledby="alert-evidence-title">
        <h3 id="alert-evidence-title" ref={heading} tabIndex={-1}>Selected alert evidence</h3>
        {selected ? <>
          <p className="lede"><b>{selected.title}</b></p>
          <p className="muted">{evidenceLead(selected)}</p>
          <pre className="evidence">{JSON.stringify(selected.raw, null, 2)}</pre>
          <h3>Model reasoning</h3>
          <p className="muted">{selected.triage?.reasoning || 'No additional reasoning provided.'}</p>
          <h3>Confidence</h3>
          <p className="muted">
            Final: {selected.triage?.confidence || '—'} · Model’s own: {selected.triage?.model_confidence
              || (selected.triage?.confidence_reasons?.some?.((reason: { code: string }) => reason.code === 'model_unavailable') ? 'none (no model output)' : 'not recorded')} · Guidance: {selected.triage?.guidance_tier || '—'}
          </p>
          <table className="list">
            <tbody>
              <tr><th>Downgrade</th><th>Why</th></tr>
              {(Array.isArray(selected.triage?.confidence_reasons) ? selected.triage.confidence_reasons : []).map((reason: { code: string; detail: string }, index: number) => (
                <tr key={index}><td><b>{reason.code}</b></td><td>{reason.detail}</td></tr>
              ))}
              {!selected.triage?.confidence_reasons?.length && <tr><td colSpan={2} className="muted">No code checks lowered the model’s confidence.</td></tr>}
            </tbody>
          </table>
          <h3>What the model could not determine</h3>
          <p className="muted">{selected.triage?.uncertainty || 'The model did not say.'}</p>
          <h3>MITRE ATT&amp;CK</h3>
          <p className="muted">{selected.mitre?.join(' · ') || 'Not supplied by this source.'}</p>
        </> : <p className="muted">Open an alert and choose “Show evidence” to bring its raw record here.</p>}
      </section>

      <h3>System health</h3>
      <div className="panel">
        <div className="field"><div><b>Database</b><p>Local SQLite store for alerts and explanations.</p></div><span className="pill">{health.database || 'unknown'}</span></div>
        <div className="field"><div><b>Model</b><p>Runs locally on this computer, no external calls.</p></div><span className="pill">{health.model || '—'}</span></div>
        <div className="field"><div><b>Disk free</b><p>Free space on the drive LightHouse runs from.</p></div><span className="pill">{gigabytes(health.disk_free_bytes)}</span></div>
      </div>
    </div>
  );
}

/* Desktop alerts for this browser. Permission is only ever asked from this button,
   never on page load. A page cannot take permission back, so "off" is remembered
   here instead; the window title still counts new alerts either way. */
function DesktopAlerts() {
  const [permission, setPermission] = useState(notificationPermission);
  const [off, setOff] = useState(notificationsOff);
  const [asking, setAsking] = useState(false);
  const turnOn = async () => {
    setOff(false); setNotificationsOff(false);
    if (permission !== 'default') return;
    setAsking(true);
    try { setPermission(await Notification.requestPermission()); } catch { setPermission(notificationPermission()); }
    finally { setAsking(false); }
  };
  const turnOff = () => { setOff(true); setNotificationsOff(true); };
  const on = permission === 'granted' && !off;
  const state = permission === 'unsupported' ? 'This window cannot show desktop alerts; new urgent alerts still show as a count in its title.'
    : permission === 'denied' ? 'Desktop alerts are blocked for LightHouse. Allow notifications for this site in Microsoft Edge settings to turn them on.'
    : on ? 'On for this computer.' : 'Off for this computer.';
  return (
    <div className="field">
      <div>
        <b>Desktop alerts</b>
        <p>Alerts at or above your threshold pop up while LightHouse is open (it can be minimised).</p>
        <p role="status">{state}</p>
      </div>
      {permission !== 'unsupported' && permission !== 'denied' && (on
        ? <button type="button" className="btn quiet" onClick={turnOff}>Turn off desktop alerts</button>
        : <button type="button" className="btn" onClick={turnOn} disabled={asking}>Turn on desktop alerts</button>)}
    </div>
  );
}

function Settings({ isAdmin, onChatModelChange }: { isAdmin: boolean; onChatModelChange: () => void }) {
  const [preferences, setPreferences] = useState<Record<string, string> | null>(null);
  const [saved, setSaved] = useState('');
  useEffect(() => { api.preferences().then(setPreferences).catch(() => setPreferences({})); }, []);
  if (!preferences) return <Skeleton />;
  /* Shown at once; put back if the save fails, so the control never claims a setting
     the server doesn't have. */
  const change = (key: string, value: string) => {
    const before = preferences[key];
    setPreferences(current => ({ ...current, [key]: value }));
    api.setPreference(key, value).then(() => setSaved('Saved on this computer.')).catch(() => {
      setPreferences(current => {
        const next = { ...current };
        if (before === undefined) delete next[key]; else next[key] = before;
        return next;
      });
      setSaved('Could not save that preference, so it is back to what it was. Try again in a moment.');
    });
  };
  return (
    <div>
      <p className="eyebrow">Settings</p>
      <h1>Your<br />preferences</h1>
      <p className="lede">These apply to your account only. Options for everyone on this computer live under Admin.</p>
      <div className="panel">
        <div className="field">
          <div><b>Notification threshold</b><p>The lowest severity that will reach you.</p></div>
          <Select label="Notification threshold" value={preferences.notification_threshold || 'high'} choices={THRESHOLDS}
            onChange={value => change('notification_threshold', value)} />
        </div>
        <DesktopAlerts />
        <div className="field">
          <div><b>Alert sensitivity</b><p>How readily borderline activity becomes an alert.</p></div>
          <Select label="Alert sensitivity" value={preferences.alert_sensitivity || 'balanced'} choices={SENSITIVITIES}
            onChange={value => change('alert_sensitivity', value)} />
        </div>
        <div className="field">
          <div><b>Plain-English explanations</b><p>Show the model&rsquo;s summary above the technical detail.</p></div>
          <span className="pill">On</span>
        </div>
      </div>
      {isAdmin && <ChatModelSection onChange={onChatModelChange} />}
      <MonitoringSources />
      {saved && <p className="notice" role="status">{saved}</p>}
    </div>
  );
}

/* The admin's own notes for the AI. Its own section with its own loading, so a
   failed fetch shows a plain message here instead of taking the Admin page down.
   The server caps, normalises and fences these; the built-in rules come first. */
function AiInstructionsSection({ onSaved }: { onSaved: () => void }) {
  const [saved, setSaved] = useState<AiInstructions | null>(null);
  const [failed, setFailed] = useState(false);
  const [business, setBusiness] = useState('');
  const [style, setStyle] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const id = useId();
  const show = (value: AiInstructions) => { setSaved(value); setBusiness(value.business); setStyle(value.style); };
  useEffect(() => { api.aiInstructions().then(show).catch(() => setFailed(true)); }, []);
  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNotice('');
    try { show(await api.setAiInstructions(business, style)); setNotice('Saved. LightHouse uses these from the next answer on.'); onSaved(); }
    catch (failure) { setNotice(detailOf(failure, 'Could not save the AI instructions. Try again.')); }
    finally { setBusy(false); }
  };
  const box = (key: string, label: string, help: string, value: string, change: (value: string) => void, max: number) => (
    <div className="field stacked">
      <div><label htmlFor={`${id}-${key}`}><b>{label}</b></label><p id={`${id}-${key}-help`}>{help}</p></div>
      <textarea id={`${id}-${key}`} aria-describedby={`${id}-${key}-help`} rows={4} maxLength={max} value={value} onChange={event => change(event.target.value)} />
      <small className="count">{value.length} / {max}</small>
    </div>
  );
  return (
    <>
      <h3>AI instructions</h3>
      <p className="lede">LightHouse’s built-in safety rules always come first; these notes add to them. Longer notes make the AI on this computer slower to start answering. When chat uses Purdue GenAI Studio, these notes are sent along with each question.</p>
      <div className="panel">
        {failed ? <p className="muted">LightHouse couldn’t load the AI instructions. Reload the page to try again.</p>
          : !saved ? <p className="muted">Loading…</p>
          : (
            <form onSubmit={save}>
              {box('business', 'About this business', 'Used by chat and alert triage. For example: what the business does, the key computers, and who your IT contact is.', business, setBusiness, saved.max_chars)}
              {box('style', 'How to answer', 'Used by chat only. LightHouse starts with a default style; edit it, for example “keep answers under 60 words” or “name our IT contact, Sam, when help is needed”. Clearing the box and saving turns the default style off.', style, setStyle, saved.max_chars)}
              <div className="row-end">
                <button className="btn quiet" type="button" disabled={busy || style === DEFAULT_ANSWER_STYLE} onClick={() => { setStyle(DEFAULT_ANSWER_STYLE); setNotice('Default answer style restored. Save to use it.'); }}>Restore default</button>
                <button className="btn" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
              </div>
            </form>
          )}
      </div>
      {notice && <p className="notice" role="status">{notice}</p>}
    </>
  );
}

/* The default chat model, for everyone. Admin only (the server enforces it), because
   choosing "Local (slow)" here keeps every question on this computer: the chat box
   then offers no online models. Otherwise anyone may pick per question beside Send. */
function ChatModelSection({ onChange }: { onChange: () => void }) {
  const [models, setModels] = useState<ChatModels | null>(null);
  const [failed, setFailed] = useState(false);
  const [notice, setNotice] = useState('');
  useEffect(() => { api.chatModels().then(setModels).catch(() => setFailed(true)); }, []);
  const choose = async (id: string) => {
    setNotice('');
    try {
      await api.setChatModel(id);
      setModels(current => current && { ...current, current: id });
      onChange();
      const label = models?.choices.find(choice => choice.id === id)?.label || id;
      setNotice(`Chat now uses ${label} by default, from the next question on.`);
    } catch (failure) {
      setNotice(detailOf(failure, 'Could not change the chat model.'));
    }
  };
  return (
    <>
      <h3>Chat AI</h3>
      <div className="panel">
        <div className="field">
          <div><b>Default chat model</b><p>{failed ? 'LightHouse couldn’t load the chat settings. Reload the page to try again.'
            : !models ? 'Loading…'
            : models.key_configured
            ? 'For everyone. Online models answer through Purdue GenAI Studio in seconds: each question and a short summary of the related alerts are sent there. Alert checking always stays on this computer. Choose Local (slow) to keep every question on this computer.'
            : 'Add a Purdue GenAI Studio key to use its faster models (see the README). Until then, chat runs on this computer.'}</p></div>
          {models && (
            <Select label="Default chat model" value={models.key_configured ? models.current : 'local'} onChange={choose}
              choices={modelChoices(models.choices, models.current, models.current, choice => choice.id !== 'local' && !models.key_configured)} />
          )}
        </div>
      </div>
      {notice && <p className="notice" role="status">{notice}</p>}
    </>
  );
}

type User = { id: number; username: string; role: string; must_change_password: boolean };
/* The account setup creates; removing it would only bring it back (the server refuses). */
const BUILT_IN_ADMIN = 'admin';
const roleLabel = (value?: string | null) => ROLES.find(choice => choice.value === value)?.label;

/* One plain-English line per logged action. Targets are usernames, alert ids or a
   chat model id, all server-checked; an alert is named by id because its title is
   sensor text that an attacker can write. */
function activityText(entry: AuditEntry): string {
  const target = entry.target ?? '';
  const [from, to] = (entry.detail ?? '').split('->');
  switch (entry.action) {
    case 'sign_in': return 'Signed in';
    case 'sign_in_failed': return entry.username ? 'Failed to sign in (wrong password)' : 'Failed sign-in with an unknown username';
    case 'password_changed': return 'Changed their own password';
    case 'alert_status':
      return to === 'dismissed' ? `Dismissed alert #${target}` : to === 'resolved' ? `Resolved alert #${target}`
        : to === 'open' ? `Reopened alert #${target}` : `Changed alert #${target}`;
    case 'monitoring_paused': return 'Paused monitoring';
    case 'monitoring_resumed': return 'Resumed monitoring';
    case 'shut_down': return 'Shut LightHouse down';
    case 'ai_instructions_changed': return 'Changed the AI instructions';
    case 'chat_model_changed': return target === 'local' ? 'Set chat to run on this computer only' : `Set the default chat model to ${target}`;
    case 'update_install_started': return 'Started installing an update';
    case 'user_created': return `Added ${target} as ${roleLabel(entry.detail) ?? 'a user'}`;
    case 'user_role_changed': return `Changed ${target}’s access from ${roleLabel(from) ?? 'another level'} to ${roleLabel(to) ?? 'another level'}`;
    case 'user_password_reset': return `Reset ${target}’s password`;
    case 'user_removed': return `Removed ${target}`;
    case 'user_signed_out': return `Signed ${target} out everywhere`;
    case 'genai_key_set': return 'Stored a Purdue GenAI Studio key';
    case 'genai_key_cleared': return 'Removed the Purdue GenAI Studio key';
    default: return 'Something LightHouse doesn’t recognise';
  }
}

/* Who did what, newest first. Its own section with its own loading, like the AI
   instructions, so a failed fetch never takes the Admin page down. `refresh`
   changes after the admin's own changes on this page, so they show at once. */
function ActivitySection({ refresh }: { refresh: number }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [more, setMore] = useState(false);
  /* Which load failed decides the message: the newest page (first load or a refresh
     after a change) or an older page from "Show older". */
  const [failed, setFailed] = useState<'' | 'latest' | 'older'>('');
  const [loading, setLoading] = useState(false);
  const now = useNow();
  useEffect(() => {
    api.activity().then(page => { setEntries(page.entries); setMore(page.more); setFailed(''); }).catch(() => setFailed('latest'));
  }, [refresh]);
  const older = async () => {
    if (!entries?.length) return;
    setLoading(true);
    try { const page = await api.activity(entries[entries.length - 1].id); setEntries([...entries, ...page.entries]); setMore(page.more); setFailed(''); }
    catch { setFailed('older'); }
    finally { setLoading(false); }
  };
  return (
    <>
      <h3>Activity</h3>
      <p className="lede">Who signed in, changed an alert, paused monitoring or changed settings and users. Kept on this computer; it can’t be edited.</p>
      {failed && !entries ? <p className="muted">LightHouse couldn’t load the activity. Reload the page to try again.</p>
        : !entries ? <p className="muted">Loading…</p>
        : !entries.length ? <p className="muted">Nothing recorded yet.</p>
        : (
          <table className="list">
            <tbody>
              <tr><th>When</th><th>Who</th><th>What</th></tr>
              {entries.map(entry => {
                const at = Date.parse(entry.timestamp);
                const iso = isoTime(at);
                return (
                  <tr key={entry.id}>
                    <td>{iso ? <time dateTime={iso} title={fullTime(at)}>{relativeTime(at, now)}</time> : '—'}</td>
                    {/* the server's name for changes made with the command-line tools (cloud_key,
                        reset_password); dashboard usernames can't contain brackets */}
                    <td><b>{entry.username === '(this computer)' ? 'This computer (command line)' : entry.username || 'Unknown'}</b></td>
                    <td>{activityText(entry)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      {failed && entries && <p className="notice" role="status">{failed === 'older'
        ? 'Couldn’t load older activity. Try again.'
        : 'LightHouse couldn’t refresh the activity, so the newest changes may be missing. Reload the page to try again.'}</p>}
      {more && <div className="row-end"><button className="btn quiet" type="button" disabled={loading} onClick={older}>{loading ? 'Loading…' : 'Show older'}</button></div>}
    </>
  );
}

function Admin({ session }: { session: Session }) {
  const [users, setUsers] = useState<User[] | null>(null);
  const [usersFailed, setUsersFailed] = useState(false);
  const [adding, setAdding] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('owner');
  const [notice, setNotice] = useState('');
  const [resetting, setResetting] = useState<User | null>(null);
  const [temporary, setTemporary] = useState('');
  const [busy, setBusy] = useState(false);
  const [activityKey, setActivityKey] = useState(0);
  const health = useHealth();
  const loadUsers = () => api.users().then(list => { setUsers(list); setUsersFailed(false); })
    .catch(() => { setUsersFailed(true); setUsers(current => current ?? []); });
  useEffect(() => { loadUsers(); }, []);
  if (!users || !health) return <Skeleton />;
  const create = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setNotice('');
    try {
      await api.createUser(username, password, role);
      setUsername(''); setPassword(''); setRole('owner'); setAdding(false);
      setNotice('User created. They will be asked to choose their own password at first sign-in.');
      await loadUsers();
      setActivityKey(key => key + 1);
    } catch (failure) {
      setNotice(detailOf(failure, 'Unable to create user. Check the username and password requirements.'));
    } finally { setBusy(false); }
  };
  /* Every change here ends the user's sessions on the server; the confirm says so. */
  const manage = async (action: () => Promise<unknown>, done: string, failed: string) => {
    setBusy(true);
    setNotice('');
    try { await action(); setNotice(done); await loadUsers(); setActivityKey(key => key + 1); return true; }
    catch (failure) { setNotice(detailOf(failure, failed)); return false; }
    finally { setBusy(false); }
  };
  const changeRole = (user: User, next: string) => {
    const label = roleLabel(next) ?? next;
    if (!window.confirm(`Change ${user.username}’s access to ${label}? They will be signed out and need to sign in again.`)) return;
    void manage(() => api.setRole(user.id, next), `${user.username} is now ${label}. They were signed out everywhere.`,
      'Could not change the access level.');
  };
  const signOut = (user: User) => {
    if (!window.confirm(`Sign ${user.username} out on every device? They can sign in again with their password.`)) return;
    void manage(() => api.signOutUser(user.id), `${user.username} was signed out everywhere.`, 'Could not sign that user out.');
  };
  const remove = (user: User) => {
    if (!window.confirm(`Remove ${user.username}? They are signed out at once and can no longer sign in. This can’t be undone.`)) return;
    void manage(() => api.removeUser(user.id), `${user.username} was removed.`, 'Could not remove that user.');
  };
  const reset = async (event: FormEvent) => {
    event.preventDefault();
    if (!resetting) return;
    if (!window.confirm(`Reset ${resetting.username}’s password? They will be signed out and must choose a new password at next sign-in.`)) return;
    const ok = await manage(() => api.resetPassword(resetting.id, temporary),
      `${resetting.username}’s password was reset. They were signed out and must choose a new one at next sign-in.`,
      'Could not reset the password. It needs at least 12 characters.');
    if (ok) { setResetting(null); setTemporary(''); }
  };
  const startReset = (user: User) => { setResetting(user); setTemporary(''); setAdding(false); setNotice(''); };
  return (
    <div>
      <p className="eyebrow">Administration</p>
      <h1>Local<br />users</h1>
      <p className="lede">Accounts exist only on this computer. There is no cloud directory to sync with.</p>
      {usersFailed && <p className="notice" role="status">LightHouse couldn’t load the user list. Reload the page to try again.</p>}
      <table className="list">
        <tbody>
          <tr><th>User</th><th>Role</th><th>Password</th><th /></tr>
          {users.map(user => {
            const self = user.username === session.username;
            return (
              <tr key={user.id}>
                <td><b>{user.username}</b></td>
                {/* Your own access is changed by another admin, so nobody locks themselves out by accident. */}
                <td>{self ? roleLabel(user.role) ?? user.role
                  : <Select label={`Access level for ${user.username}`} value={user.role} choices={ROLES} disabled={busy} onChange={next => changeRole(user, next)} />}</td>
                <td>{user.must_change_password ? 'Change required' : 'Set'}</td>
                <td>{self ? <span className="pill">You</span> : (
                  <>
                    <button className="btn quiet" type="button" disabled={busy} onClick={() => startReset(user)}>Reset password</button>{' '}
                    <button className="btn quiet" type="button" disabled={busy} onClick={() => signOut(user)}>Sign out</button>{' '}
                    {user.username !== BUILT_IN_ADMIN && (
                      <button className="btn quiet" type="button" disabled={busy} onClick={() => remove(user)}>Remove</button>
                    )}
                  </>
                )}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {resetting && (
        <div className="panel">
          <form onSubmit={reset}>
            <div className="field">
              <div><b>Temporary password for {resetting.username}</b><p>At least 12 characters. They replace it at next sign-in; every device they’re signed in on is signed out.</p></div>
              <input required minLength={12} maxLength={72} type="password" autoComplete="new-password" aria-label={`Temporary password for ${resetting.username}`} value={temporary} onChange={event => setTemporary(event.target.value)} />
            </div>
            <div className="row-end">
              <button className="btn quiet" type="button" onClick={() => { setResetting(null); setTemporary(''); }}>Cancel</button>
              <button className="btn" disabled={busy}>Reset password</button>
            </div>
          </form>
        </div>
      )}
      {adding ? (
        <div className="panel">
          <form onSubmit={create}>
            <div className="field">
              <div><b>Username</b><p>Letters, digits, dot, dash and underscore.</p></div>
              <input required minLength={3} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9._-]*" autoComplete="off" aria-label="Username" value={username} onChange={event => setUsername(event.target.value)} />
            </div>
            <div className="field">
              <div><b>Temporary password</b><p>At least 12 characters. They replace it at first sign-in.</p></div>
              <input required minLength={12} maxLength={72} type="password" autoComplete="new-password" aria-label="Temporary password" value={password} onChange={event => setPassword(event.target.value)} />
            </div>
            <div className="field">
              <div><b>Access level</b><p>Owners see explanations; analysts and admins also see raw evidence.</p></div>
              <Select label="Access level" value={role} choices={ROLES} onChange={setRole} />
            </div>
            <div className="row-end">
              <button className="btn quiet" type="button" onClick={() => { setAdding(false); setNotice(''); }}>Cancel</button>
              <button className="btn" disabled={busy}>{busy ? 'Creating…' : 'Create user'}</button>
            </div>
          </form>
        </div>
      ) : <div className="row-end"><button className="btn" onClick={() => { setAdding(true); setResetting(null); }}>Add user</button></div>}
      {notice && <p className="notice" role="status">{notice}</p>}

      <AiInstructionsSection onSaved={() => setActivityKey(key => key + 1)} />

      <h3>This computer</h3>
      <div className="panel">
        <div className="field"><div><b>Platform</b><p>The version of Windows LightHouse is running on.</p></div><span className="pill">{health.platform || 'unknown'}</span></div>
        <div className="field"><div><b>Model</b><p>Triages alerts on this computer, no external calls.</p></div><span className="pill">{health.model || '—'}</span></div>
        <div className="field"><div><b>Disk free</b><p>Free space on the drive LightHouse runs from.</p></div><span className="pill">{gigabytes(health.disk_free_bytes)}</span></div>
      </div>

      <ActivitySection refresh={activityKey} />
    </div>
  );
}

const NO_CHAT_CHOICES: ChatOptions = { provider: 'local', choices: [], current: 'local' };
const PICKED_MODEL_KEY = 'lighthouse-chat-model';
/* How close to the bottom counts as "at the bottom" again, so following resumes
   without having to land on the very last pixel. */
const FOLLOW_SLACK_PX = 48;
/* The chat provider can change under an open window (an admin stores or removes the
   GenAI Studio key, or picks another default), and the footer must keep telling the
   truth about where a question goes. */
const CHAT_OPTIONS_REFRESH_MS = 60_000;
/* 'unknown': the provider could not be fetched, so the footer claims neither way. */
type Provider = 'purdue' | 'local' | 'unknown';
const EXPIRED_NOTICE = 'Your sign-in expired. Please sign in again.';

/* An off-shape server response that breaks one page shows a plain message there,
   instead of white-screening the whole app; the sidebar stays usable. Keyed by the
   page, so moving to another page starts it fresh. */
class PageBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state: { failed: boolean } = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: unknown, info: ErrorInfo) { console.error('A dashboard page failed to render.', error, info.componentStack); }
  render() {
    return this.state.failed
      ? <div className="empty-state" role="status"><b>Something went wrong on this page.</b><p>Reload to try again.</p></div>
      : this.props.children;
  }
}

/* Who is signed in. Everything that belongs to a user lives in Dashboard below. */
function App() {
  const [session, setSession] = useState(getSession());
  const [expired, setExpired] = useState(false);
  /* Any request refused with 401 (api.ts) lands here: back to sign-in with a plain
     reason, rather than pages quietly reading the refusal as "nothing to show". */
  useEffect(() => onSessionExpired(() => { setSession(null); setExpired(true); }), []);
  if (!session) return <Login notice={expired ? EXPIRED_NOTICE : ''} onLogin={next => { setExpired(false); setSession(next); }} />;
  if (session.must_change_password) return <ChangePassword session={session} onDone={setSession} />;
  /* Keyed on the token, so every sign-in starts from a clean slate: the open page,
     the selected evidence, alerts and chats of whoever used this window before never
     carry over to the next account (an analyst's raw evidence to an owner, say). */
  return <Dashboard key={session.token} session={session} signOut={async () => { await logout(); setSession(null); }} />;
}

function Dashboard({ session, signOut }: { session: Session; signOut: () => Promise<void> }) {
  const [tab, setTab] = useState('home');
  const [collapsed, setCollapsed] = useState(false);
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [alertsFailed, setAlertsFailed] = useState(false);
  const [selected, setSelected] = useState<any>();
  const [chats, setChats] = useState<Conversation[]>(() => loadConversations(session.username));
  const [activeId, setActiveId] = useState<string | null>(null);
  /* The thread waiting on the model. One question at a time: inference is CPU-bound,
     so a second request would only queue behind the first. The ref guards against a
     double send landing before the state update has rendered. */
  const [pendingId, setPendingId] = useState<string | null>(null);
  const pending = useRef<string | null>(null);
  const warmedAt = useRef<Record<string, number>>({});
  const newChatButton = useRef<HTMLButtonElement>(null);
  const thinking = pendingId !== null;
  /* The answer so far, while it streams in. Kept out of the stored conversations
     until it is complete, so localStorage is written once per answer, not per word. */
  const [streamed, setStreamed] = useState('');
  const [message, setMessage] = useState('');
  /* A question from a prompt card or an alert that arrived while an answer was still
     coming: it waits in the composer, and remembers where it came from so sending it
     later still starts the right thread. */
  const queued = useRef<{ text: string; about?: Alert } | null>(null);
  /* The owner's pick for Send: a quick squeeze and spring back on the press that
     actually sends (not on an empty or held-back one). Restarted on every send. */
  const sendButton = useRef<HTMLButtonElement>(null);
  const pressSend = () => {
    const button = sendButton.current;
    if (!button) return;
    button.classList.remove('pressed');
    void button.offsetWidth;
    button.classList.add('pressed');
  };
  const canSeeEvidence = advanced(session.role);
  const isAdmin = session.role === 'admin';
  /* The page actually shown. The nav only offers what the role allows, and this makes
     sure no other route (a stale tab) can show it either. The server enforces roles. */
  const view = (tab === 'advanced' && !canSeeEvidence) || (tab === 'admin' && !isAdmin) ? 'home' : tab;
  /* The page follows an answer down as it streams in, like a chat app. Scrolling up
     at all stops following, so the owner can read back undisturbed; scrolling back
     down to the bottom picks it up again. Only .sheet scrolls (the signed-off frame).
     Moving up is always the owner: following itself only ever scrolls down. */
  const sheet = useRef<HTMLDivElement>(null);
  const following = useRef(true);
  const lastTop = useRef(0);
  const sheetScrolled = () => {
    const el = sheet.current;
    if (!el) return;
    if (el.scrollTop < lastTop.current - 1) following.current = false;
    else if (el.scrollHeight - el.scrollTop - el.clientHeight <= FOLLOW_SLACK_PX) following.current = true;
    lastTop.current = el.scrollTop;
  };

  /* .sheet is one scroller shared by every page and thread, so a new page starts at
     its top and a thread opens on its newest message, rather than wherever the last
     one was left. Before paint, so the old position never flashes. */
  useLayoutEffect(() => {
    const el = sheet.current;
    if (!el) return;
    el.scrollTop = view === 'home' && activeId !== null ? el.scrollHeight : 0;
    lastTop.current = el.scrollTop;
    following.current = true;
  }, [view, activeId]);

  /* Before paint, so each new piece of the answer never flashes below the fold. */
  const watching = pendingId !== null && pendingId === activeId && view === 'home';
  useLayoutEffect(() => {
    const el = sheet.current;
    if (el && watching && following.current) el.scrollTop = el.scrollHeight;
  }, [streamed, watching]);

  /* A failed load is kept apart from an empty list: "no alerts" would read as "all
     clear". A failed refresh keeps the alerts already shown. */
  const load = () => api.alerts()
    .then(list => { if (!Array.isArray(list)) throw new Error('Unexpected alerts response'); setAlerts(list); setAlertsFailed(false); })
    .catch(() => { setAlertsFailed(true); setAlerts(current => current ?? []); });
  useEffect(() => { load(); }, []);
  /* Desktop alerts for new alerts at or above this user's threshold (the server reads
     it from their settings). Fixed wording only; see notifications.ts. A new urgent
     alert also refreshes the list, and clicking the pop-up opens Alerts. */
  useAlertNotifications({ active: true, onNew: load,
    onAlerts: () => { setActiveId(null); setTab('alerts'); }, viewingAlerts: view === 'alerts' });
  /* Who answers chat by default ('purdue' once a GenAI Studio key is stored), and
     the models the chat box may pick instead. Asked again every minute and whenever
     the window regains focus. The pick is remembered per browser; one no longer
     offered falls back to the default, as it does on the server. */
  const [chatOptions, setChatOptions] = useState<ChatOptions | null>(null);
  const refreshChatOptions = () => { api.chatProvider().then(setChatOptions).catch(() => setChatOptions(null)); };
  useEffect(() => {
    refreshChatOptions();
    const timer = window.setInterval(refreshChatOptions, CHAT_OPTIONS_REFRESH_MS);
    window.addEventListener('focus', refreshChatOptions);
    return () => { window.clearInterval(timer); window.removeEventListener('focus', refreshChatOptions); };
  }, []);
  const [picked, setPicked] = useState<string | null>(() => { try { return localStorage.getItem(PICKED_MODEL_KEY); } catch { return null; } });
  const pick = (id: string) => { setPicked(id); try { localStorage.setItem(PICKED_MODEL_KEY, id); } catch { /* still used this session */ } };
  const options = chatOptions ?? NO_CHAT_CHOICES;
  const canPick = options.choices.length > 1;
  const chosen = canPick && picked !== null && options.choices.some(choice => choice.id === picked) ? picked : options.current;
  /* What a question is sent with: null leaves it to the server's default. */
  const model = canPick ? chosen : null;
  const provider: Provider = canPick ? (chosen === 'local' ? 'local' : 'purdue') : chatOptions ? chatOptions.provider : 'unknown';
  /* Background monitoring, and the admin's switch to pause it (e.g. leaving the office). */
  const [monitoring, setMonitoring] = useState<Monitoring | null>(null);
  const [monitoringBusy, setMonitoringBusy] = useState(false);
  useEffect(() => { api.monitoring().then(setMonitoring).catch(() => setMonitoring(null)); }, []);
  const toggleMonitoring = async () => {
    if (!monitoring) return;
    const pausing = !monitoring.paused;
    if (pausing && !window.confirm('Pause monitoring? LightHouse will stop watching your network and this computer until you resume it, even after a restart.')) return;
    setMonitoringBusy(true);
    try { setMonitoring(await api.setMonitoring(pausing)); }
    catch (failure) { if (statusOf(failure) !== 401) window.alert(detailOf(failure, 'LightHouse could not change monitoring. Try again.')); }
    finally { setMonitoringBusy(false); }
  };
  /* Everything off, the dashboard included, until LightHouse is opened again. */
  const [stopped, setStopped] = useState(false);
  const shutDown = async () => {
    if (!window.confirm('Shut down LightHouse? Monitoring, the local AI and this dashboard stop, and stay off after a restart, until you open LightHouse again from the Start menu or desktop.')) return;
    setMonitoringBusy(true);
    try { await api.shutdown(); setStopped(true); }
    catch (failure) { if (statusOf(failure) !== 401) window.alert(detailOf(failure, 'LightHouse could not shut down. Try again.')); }
    finally { setMonitoringBusy(false); }
  };
  /* Checked on every load of the dashboard (the server caches GitHub's answer);
     admins are the ones who can install, so only they are asked. */
  const [release, setRelease] = useState<UpdateInfo | null>(null);
  useEffect(() => {
    if (isAdmin) api.updates().then(info => setRelease(info.available ? info : null)).catch(() => setRelease(null));
  }, []);

  /* Every change goes through the latest state, never a render's snapshot: a reply
     or a title can land long after the user has moved to another thread. */
  const update = (change: (current: Conversation[]) => Conversation[]) => setChats(current => {
    const next = change(current);
    saveConversations(session.username, next);
    return next;
  });

  /* The model's title replaces the fallback, but only on a thread that still exists. */
  const nameChat = (id: string, question: string) => {
    api.chatTitle(clip(question, MAX_QUESTION), model)
      .then(title => { if (title) update(current => current.map(entry => entry.id === id ? { ...entry, title: titleFor(title) } : entry)); })
      .catch(() => { /* the fallback title stays */ });
  };

  /* Streams one answer into thread `id`. Shared by a new question and by Retry, so
     both keep the same guards: one answer at a time, words shown as they arrive, a
     cut-off answer keeps what was written, and failures arrive as replies rather
     than errors. Resolves true when the model itself answered. */
  const stream = async (id: string, messages: ChatMessage[], alertId: number | null): Promise<boolean> => {
    pending.current = id;
    following.current = true;
    setPendingId(id);
    setStreamed('');
    let answered = false;
    let received = '';
    try {
      let replies: Turn[];
      try {
        const result = await api.chatStream(messages, alertId, piece => { received += piece; setStreamed(received); }, model);
        answered = result.available && received.trim() !== '';
        const text = received.trim();
        /* the AI-unavailable notice is fixed server text, not the model's words */
        replies = !text ? [{ role: 'them', text: chatFailure(null, false), local: true }]
          : [result.available ? { role: 'them', text } : { role: 'them', text, local: true }];
      } catch (failure) {
        /* A stream cut off midway keeps what the model already wrote. */
        const partial = received.trim();
        replies = partial
          ? [{ role: 'them', text: partial }, { role: 'them', text: 'LightHouse stopped before finishing this answer. Try asking again.', local: true }]
          : [{ role: 'them', text: chatFailure(failure, alertId !== null), local: true }];
      }
      const at = Date.now();
      update(current => current.map(entry => entry.id === id ? { ...entry, turns: [...entry.turns, ...replies.map(reply => ({ ...reply, at }))], updated: at } : entry));
    } finally {
      pending.current = null;
      setPendingId(null);
      setStreamed('');
    }
    return answered;
  };

  /* Answers the thread's last question again: every reply after it (answer, cut-off
     answer, failure notice) is dropped and a new one streamed. The title stays. */
  const retry = (id: string) => {
    if (pending.current) return;
    const chat = chats.find(entry => entry.id === id);
    const turns = chat && retryTurns(chat.turns);
    if (!chat || !turns) return;
    update(current => {
      const stored = current.find(entry => entry.id === id);
      if (!stored) return current;
      return [{ ...stored, turns: retryTurns(stored.turns) ?? stored.turns, updated: Date.now() }, ...current.filter(entry => entry.id !== id)];
    });
    void stream(id, toChatMessages(turns), chat.alertId ?? null);
  };

  /* Gone from this browser for good, so it asks first, like the app's other
     permanent actions. Deleting the open thread returns to Home. True once deleted. */
  const deleteChat = (id: string) => {
    if (id === pending.current) return false;
    if (!window.confirm('Delete this chat? This can’t be undone.')) return false;
    update(current => current.filter(entry => entry.id !== id));
    if (id === activeId) setActiveId(null);
    return true;
  };

  /* A question either continues the open thread or starts a new one; either way it
     is one row in the sidebar, never one row per message. `fresh` starts a new thread
     even with one open (a queued prompt card). Only a send from the composer clears
     the composer; a prompt card or an alert's button never wipes a typed draft. While
     an answer is still coming nothing is sent: a card's or alert's question waits in
     an empty composer instead of being dropped. */
  const ask = (question: string, about?: Alert, fromComposer = false, fresh = false) => {
    const text = question.trim();
    if (!text) return;
    if (pending.current) {
      if (!fromComposer && !message.trim()) { setMessage(text); queued.current = { text, about }; }
      setActiveId(pending.current); setTab('home');
      return;
    }
    const turn: Turn = { role: 'me', text, at: Date.now() };
    const existing = !about && !fresh && activeId ? chats.find(chat => chat.id === activeId) : undefined;
    const chat: Conversation = existing
      ? { ...existing, turns: [...existing.turns, turn], updated: Date.now() }
      : { id: newId(), title: titleFor(about?.title || text), turns: [turn], updated: Date.now(), ...(about ? { alertId: about.id } : {}) };
    const messages = toChatMessages(chat.turns);
    const alertId = chat.alertId ?? null;
    setActiveId(chat.id);
    setTab('home');
    if (fromComposer) setMessage('');
    update(current => {
      const stored = current.find(entry => entry.id === chat.id);
      return [stored ? { ...stored, turns: [...stored.turns, turn], updated: chat.updated } : chat, ...current.filter(entry => entry.id !== chat.id)];
    });
    void stream(chat.id, messages, alertId).then(answered => {
      /* Named after the answer, not alongside it, so the title never queues ahead of
         the reply on the one local model. A thread opened from an alert keeps the
         alert's name: its question is generic, so the model could not do better. */
      if (!existing && !about && answered) nameChat(chat.id, text);
    });
  };
  const askFromPage: Ask = (question, about) => ask(question, about);

  /* Failures reach the alert that asked (AlertItem shows them); load() has its own. */
  const act: Act = async (id, status) => { await api.setStatus(id, status); load(); };
  /* Set by "Show evidence" and cleared by Advanced once it has scrolled to the record. */
  const [jumpToEvidence, setJumpToEvidence] = useState(false);
  const showEvidence: Evidence = async alert => { const detail = await api.detail(alert.id); setSelected(detail); setJumpToEvidence(true); setTab('advanced'); };

  if (stopped) return (
    <main className="login">
      <section role="status">
        <img src="/assets/lighthouse-logo.png" alt="LightHouse" />
        <p className="eyebrow">LightHouse</p>
        <h1>LightHouse is shut down.</h1>
        <p>Monitoring and the local AI are off, and stay off after a restart. To start again, open LightHouse from the Start menu or desktop. You can close this window.</p>
      </section>
    </main>
  );

  const startChat = () => { setActiveId(null); setTab('home'); };
  const pageProps: PageProps = { alerts: alerts || [], alertsFailed, reload: load, canSeeEvidence, act, ask: askFromPage, evidence: showEvidence,
    warm: id => warmAlert(id, model), monitoring, monitoringBusy,
    toggleMonitoring: isAdmin ? toggleMonitoring : undefined,
    shutDown: isAdmin ? shutDown : undefined };
  const chat = chats.find(entry => entry.id === activeId);
  const primary = ['home', 'alerts', 'trends', ...(canSeeEvidence ? ['advanced'] : [])];
  /* While a reply is pending the draft stays editable but is not sent. A draft that is
     still exactly a queued card's or alert's question keeps that question's origin. */
  const submit = () => {
    if (thinking || !message.trim()) return;
    pressSend();
    const origin = queued.current?.text === message.trim() ? queued.current : null;
    queued.current = null;
    ask(message, origin?.about, true, !!origin);
  };
  const send = (event: FormEvent) => { event.preventDefault(); submit(); };
  /* Clicking into the composer lets the local model read its instructions and the
     alert context while the owner types, so the answer only waits on the question.
     At most once a minute per conversation context, never during an answer. */
  const warm = () => {
    if (thinking) return;
    const key = `${chat?.alertId ?? 'general'}:${model ?? ''}`;
    const now = Date.now();
    if (now - (warmedAt.current[key] || 0) < 60_000) return;
    warmedAt.current[key] = now;
    api.chatWarm(chat?.alertId ?? null, model);
  };
  const keydown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); submit(); }
  };

  const page = () => {
    if (!alerts) return <Skeleton />;
    if (view === 'home') return chat
      ? <Thread key={chat.id} chat={chat} thinking={pendingId === chat.id} streamed={pendingId === chat.id ? streamed : ''} provider={provider}
        busy={thinking} retry={() => retry(chat.id)} />
      : <Home {...pageProps} />;
    if (view === 'alerts') return <Alerts {...pageProps} />;
    if (view === 'trends') return <Trends alerts={alerts} />;
    if (view === 'advanced') return <Advanced selected={selected} jump={jumpToEvidence} jumped={() => setJumpToEvidence(false)} />;
    if (view === 'settings') return <Settings isAdmin={isAdmin} onChatModelChange={refreshChatOptions} />;
    if (view === 'admin') return <Admin session={session} />;
    return null;
  };

  return (
    <div className={`app${collapsed ? ' collapsed' : ''}`}>
      <aside>
        <div className="rail-top">
          <button className="collapse" title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!collapsed}
            onClick={() => setCollapsed(!collapsed)}><Icon name="sidebar" size={20} /></button>
          {/* Quick actions beside the toggle while the rail is open. Pause and Shut
              down reuse the Home card's handlers and confirmations; the server still
              decides who may use them. */}
          {!collapsed && <>
            <button className="rail-btn" type="button" ref={newChatButton} title="New chat" aria-label="New chat" onClick={startChat}><Icon name="compose" size={20} /></button>
            {isAdmin && monitoring?.available && <>
              <button className="rail-btn" type="button" disabled={monitoringBusy} onClick={toggleMonitoring}
                title={monitoring.paused ? 'Resume monitoring' : 'Pause monitoring'} aria-label={monitoring.paused ? 'Resume monitoring' : 'Pause monitoring'}>
                <Icon name={monitoring.paused ? 'resume' : 'pause'} size={20} />
              </button>
              <button className="rail-btn" type="button" disabled={monitoringBusy} onClick={shutDown} title="Shut down LightHouse" aria-label="Shut down LightHouse">
                <Icon name="power" size={20} />
              </button>
            </>}
          </>}
        </div>
        <div className="brand">
          <img src="/assets/lighthouse-logo.png" alt="LightHouse" />
          <span className="txt"><b>LightHouse</b><span>Guiding You to Safer Shores</span></span>
        </div>
        <nav>{primary.map(item => <Nav key={item} item={item} tab={view} setTab={setTab} />)}</nav>
        <Chats chats={chats} activeId={activeId} pendingId={pendingId} open={id => { setActiveId(id); setTab('home'); }} remove={deleteChat}
          focusAway={() => newChatButton.current?.focus()} />
        <nav className="bottom">
          <Nav item="settings" tab={view} setTab={setTab} />
          {isAdmin && <Nav item="admin" tab={view} setTab={setTab} />}
          {/* Named for screen readers and on hover, so it keeps a name when the
              collapsed rail hides the label. */}
          <button type="button" aria-label="Sign out" title="Sign out" onClick={() => { void signOut(); }}>
            <span className="nav-icon"><Icon name="signout" size={18} /></span><span className="nav-label">Sign out</span>
          </button>
        </nav>
      </aside>

      <main className={view === 'home' ? 'with-dock' : ''}>
        <div className="sheet" ref={sheet} onScroll={sheetScrolled}>
          <PageBoundary key={`${view}:${activeId ?? ''}`}>{page()}</PageBoundary>
        </div>
        <div className="dock">
          <form onSubmit={send}>
            <textarea rows={1} value={message} onChange={event => setMessage(event.target.value)} onKeyDown={keydown} onFocus={warm}
              aria-label="Ask LightHouse" placeholder={chat ? 'Reply to LightHouse…' : 'Ask LightHouse about your network…'} />
            {canPick && (
              <Select className="model-pick" label="AI model for this question" value={chosen} onChange={pick} up
                choices={modelChoices(options.choices, options.current, 'Default')} />
            )}
            <button type="submit" className="send" ref={sendButton} aria-label="Send chat" disabled={thinking}
              onAnimationEnd={event => event.currentTarget.classList.remove('pressed')}><Icon name="send" size={20} /></button>
          </form>
          {/* Says plainly where a question goes: the owner opted in to GenAI Studio, and
              each question carries a short summary of the related alerts there. When
              the provider couldn't be checked, it claims neither way. */}
          <small>{provider === 'purdue'
            ? 'LightHouse is AI, it can make mistakes. Answers by Purdue GenAI Studio (online): your question and a summary of the related alerts are sent there. Alert checking stays on this computer.'
            : provider === 'local'
            ? 'LightHouse is AI, it can make mistakes. Chats stay on this computer for your privacy.'
            : 'LightHouse is AI, it can make mistakes.'}</small>
        </div>
      </main>
      {release && <UpdateDialog info={release} onClose={() => setRelease(null)} />}
    </div>
  );
}

/* Shown on each load while a newer release exists. A native modal dialog: focus is
   trapped and Esc closes it without script of our own. "Update now" has the server
   download, verify and install the release (triage/updates.py); the page follows
   along and reloads once LightHouse is back. The release-page link is the server's,
   checked again here to be this project's GitHub releases page. */
const RELEASES = 'https://github.com/gotsevrossen/LightHouse/releases/';
const UPDATE_POLL_MS = 3000;
const UPDATE_GIVE_UP_MS = 30 * 60 * 1000;
type UpdatePhase = 'offer' | 'downloading' | 'installing' | 'restarting' | 'failed' | 'slow';
const UPDATE_STEP: Record<UpdatePhase, string> = {
  offer: '',
  downloading: 'Downloading the update and checking it is genuine…',
  installing: 'Installing. LightHouse closes for a few minutes and comes back on its own.',
  restarting: 'Installing. LightHouse closes for a few minutes and comes back on its own.',
  failed: '',
  slow: 'This is taking longer than expected. Reload this page in a few minutes.',
};
function UpdateDialog({ info, onClose }: { info: UpdateInfo; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  // The server says "failed" on load when the last update from here did not take.
  const [phase, setPhase] = useState<UpdatePhase>(info.install?.state === 'failed' ? 'failed' : 'offer');
  const [error, setError] = useState(info.install?.state === 'failed' ? info.install.error || '' : '');
  useEffect(() => { if (dialog.current && !dialog.current.open) dialog.current.showModal(); }, []);
  const busy = phase === 'downloading' || phase === 'installing' || phase === 'restarting';
  useEffect(() => {
    if (!busy) return;
    let stopped = false;
    let wentDown = false;
    const started = Date.now();
    const tick = async () => {
      if (stopped) return;
      if (Date.now() - started > UPDATE_GIVE_UP_MS) { setPhase('slow'); return; }
      if (!wentDown) {
        try {
          const state = (await api.updates()).install;
          if (state?.state === 'failed') { setError(state.error || 'The update could not be installed.'); setPhase('failed'); return; }
          if (state?.state === 'installing') setPhase('installing');
        } catch { wentDown = true; setPhase('restarting'); }
      } else if (await api.serverUp()) { window.location.reload(); return; }
      if (!stopped) window.setTimeout(tick, UPDATE_POLL_MS);
    };
    const timer = window.setTimeout(tick, UPDATE_POLL_MS);
    return () => { stopped = true; window.clearTimeout(timer); };
  }, [busy]);
  const install = async () => {
    setError('');
    try {
      const state = await api.installUpdate();
      setPhase(state.state === 'installing' ? 'installing' : 'downloading');
    } catch (failure) { setError(detailOf(failure, 'LightHouse could not start the update. Try again.')); setPhase('failed'); }
  };
  const openPage = () => {
    if (info.url?.startsWith(RELEASES)) window.open(info.url, '_blank', 'noopener');
    dialog.current?.close();
  };
  return (
    <dialog ref={dialog} className="update" onClose={onClose} onCancel={event => { if (busy) event.preventDefault(); }} aria-labelledby="update-title">
      {busy
        ? <p className="eyebrow with-mark"><WaveMark label={null} />Updating</p>
        : <p className="eyebrow">Update available</p>}
      <h2 id="update-title">LightHouse {info.latest}</h2>
      {phase === 'offer' && <p>You have {info.current}. {info.installable
        ? 'LightHouse can download and install it for you; your alerts, accounts and settings are kept.'
        : 'Download the new installer and run it; your alerts, accounts and settings are kept.'}</p>}
      {(busy || phase === 'slow') && <p role="status">{UPDATE_STEP[phase]}</p>}
      {phase === 'failed' && <p role="status">{error}</p>}
      {!busy && <div className="row-end">
        <button className="btn quiet" type="button" onClick={() => dialog.current?.close()}>Later</button>
        {phase === 'failed' && info.installable && <button className="btn quiet" type="button" onClick={openPage}>Open release page</button>}
        {info.installable && phase !== 'slow'
          ? <button className="btn" type="button" onClick={install}>{phase === 'failed' ? 'Try again' : 'Update now'}</button>
          : <button className="btn" type="button" onClick={openPage}>Open release page</button>}
      </div>}
    </dialog>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
