import { FormEvent, KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { api, Alert, getSession, login, logout, Session, statusOf } from './api';
import { clip, Conversation, loadConversations, MAX_QUESTION, newId, saveConversations, titleFor, toChatMessages, Turn } from './conversations';
import './styles.css';
import './sidebar.css';

const advanced = (role?: string) => role === 'analyst' || role === 'admin';
const icons: Record<string, string> = { home: '⌂', alerts: '!', trends: '↗', advanced: '⌘', settings: '⚙', admin: '♙' };
const labels: Record<string, string> = { home: 'Home', alerts: 'Alerts', trends: 'Trends', advanced: 'Advanced analytics', settings: 'Settings', admin: 'Admin' };
const URGENT = ['high', 'critical'];
const PROMPTS = ['Summarize my network and security status', 'Explain what my most recent alert means', 'What should I address first?', 'Are there any unusual devices on my network?'];
const AI_NOTE = 'Written on this appliance and checked against the alert schema. Nothing left your network.';
/* The alert itself goes to the server by id, where its sensor text is fenced as
   untrusted evidence. Its title is attacker-influenced, so it is not pasted into the
   question, where it would reach the model as the owner's own words. */
const ALERT_QUESTION = 'Explain this alert. What does it mean, and what should I do?';

/* Chat failures are shown in the thread as a reply, never as an error screen. */
function chatFailure(error: unknown, aboutAlert: boolean) {
  const status = statusOf(error);
  if (status === 401) return 'Your sign-in has expired. Sign out, sign in again, and then ask once more.';
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
  <button title={labels[item]} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>
    <span className="nav-icon">{icons[item]}</span><span className="nav-label">{labels[item]}</span>
  </button>
);

function Chats({ chats, activeId, open, start }: { chats: Conversation[]; activeId: string | null; open: (id: string) => void; start: () => void }) {
  return (
    <section className="chats">
      <div className="head">
        <span className="nav-label">Recent chats</span>
        <button className="new nav-label" type="button" title="New chat" aria-label="New chat" onClick={start}>+</button>
      </div>
      {chats.length
        ? chats.map(chat => (
          <button className={`chat${chat.id === activeId ? ' active' : ''}`} key={chat.id} title={chat.title} onClick={() => open(chat.id)}>
            <span className="mark" aria-hidden="true">↗</span><span className="title nav-label">{chat.title}</span>
          </button>
        ))
        : <p className="none nav-label">No chats yet</p>}
    </section>
  );
}

function Login({ onLogin }: { onLogin: (session: Session) => void }) {
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
        <p>Security guidance stays on this appliance.</p>
        <form onSubmit={submit}>
          <input aria-label="Username" placeholder="Username" autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)} />
          <input aria-label="Password" placeholder="Password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} />
          <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
          {error && <p className="error">{error}</p>}
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
        <p>This appliance printed a one-time password to the server console on first start. Replace it before the dashboard opens.</p>
        <form onSubmit={submit}>
          <input aria-label="Current password" placeholder="Current password" type="password" autoComplete="current-password" required value={current} onChange={e => setCurrent(e.target.value)} />
          <input aria-label="New password" placeholder="New password (at least 12 characters)" type="password" autoComplete="new-password" required minLength={12} value={next} onChange={e => setNext(e.target.value)} />
          <input aria-label="Confirm new password" placeholder="Confirm new password" type="password" autoComplete="new-password" required minLength={12} value={confirm} onChange={e => setConfirm(e.target.value)} />
          <button disabled={busy}>{busy ? 'Saving…' : 'Save password'}</button>
          {error && <p className="error">{error}</p>}
        </form>
      </section>
    </main>
  );
}

/* One alert, open or closed. A native details element, so it expands without
   script and stays keyboard-operable. */
function AlertItem({ alert, showStatus, canSeeEvidence, act, ask, evidence }: {
  alert: Alert; showStatus?: boolean; canSeeEvidence: boolean;
  act: (id: number, status: string) => void; ask: Ask; evidence: (alert: Alert) => void;
}) {
  const isOpen = alert.status === 'open';
  const tier = tierOf(alert);
  /* Only while the alert is open: a resolved alert telling the owner to call for
     help "now" is noise. Reopening it brings the banner back. */
  const guidance = isOpen ? GUIDANCE[tier] : undefined;
  const confidence = CONFIDENCE_LABEL[alert.confidence || 'low'] || CONFIDENCE_LABEL.low;
  return (
    <details className="alert">
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
              <button className="btn" onClick={() => act(alert.id, 'resolved')}>Mark resolved</button>
              <button className="btn quiet" onClick={() => act(alert.id, 'dismissed')}>Dismiss</button>
            </>
            : <button className="btn quiet" onClick={() => act(alert.id, 'open')}>Reopen</button>}
          <button className="btn quiet" onClick={() => ask(ALERT_QUESTION, alert)}>Ask LightHouse about this</button>
          {canSeeEvidence && <button className="btn quiet" onClick={() => evidence(alert)}>Show evidence</button>}
        </div>
        <p className="ai-note">{AI_NOTE}</p>
      </div>
    </details>
  );
}

/* Passing an alert always opens a new thread about that alert. */
type Ask = (question: string, about?: Alert) => void;
type PageProps = {
  alerts: Alert[]; canSeeEvidence: boolean;
  act: (id: number, status: string) => void; ask: Ask; evidence: (alert: Alert) => void;
};

function Home({ alerts, canSeeEvidence, act, ask, evidence }: PageProps) {
  const open = alerts.filter(alert => alert.status === 'open');
  const urgent = open.filter(alert => URGENT.includes(alert.severity)).length;
  return (
    <div>
      <section className="welcome">
        <p className="eyebrow">Network overview</p>
        <h1>{urgent ? <>{urgent} item{urgent === 1 ? '' : 's'} deserve{urgent === 1 ? 's' : ''}<br />your attention</> : <>Your network<br />looks healthy</>}</h1>
        <div className="health">
          <i className={urgent ? 'warn' : ''} />
          <b>{urgent ? 'Attention needed' : 'Monitoring active'}</b>
          <small>{open.length} open alert{open.length === 1 ? '' : 's'}</small>
        </div>
      </section>
      <section className="cards lead">
        <div><small>Health status</small><strong>{urgent ? 'Review alerts' : 'Good'}</strong><p>Monitoring sources are ready to report.</p></div>
        <div><small>Open alerts</small><strong>{open.length}</strong><p>Items that have not been resolved.</p></div>
        <div><small>High priority</small><strong>{urgent}</strong><p>Potentially urgent activity.</p></div>
      </section>
      <section className="recent">
        <div className="head"><p className="eyebrow">Recent activity</p><h2>Latest alerts</h2></div>
        {helpFirst(alerts).slice(0, 4).map(alert => <AlertItem key={alert.id} alert={alert} canSeeEvidence={canSeeEvidence} act={act} ask={ask} evidence={evidence} />)}
        {!alerts.length && <div className="empty-state"><b>Nothing to review</b><p>No alerts yet. Run fixture replay to seed the local demo.</p></div>}
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

/* An open conversation. Nothing labels the speaker: a question sits in its own
   card on the right, the answer runs as plain text on the left. */
function Thread({ chat, thinking }: { chat: Conversation; thinking: boolean }) {
  return (
    <div>
      <p className="eyebrow">Chat</p>
      <h2>{chat.title}</h2>
      <div className="thread">
        {chat.turns.map((turn, index) => (
          <div className={`turn ${turn.role}`} key={index}>
            {turn.role === 'them' && <span className="mark" aria-hidden="true" />}
            {turn.text.split(/\n+/).map((line, line_index) => <p key={line_index}>{line}</p>)}
          </div>
        ))}
        {thinking && <div className="turn them"><span className="mark" aria-hidden="true" /><span className="typing" role="status" aria-label="LightHouse is replying"><i /><i /><i /></span></div>}
      </div>
    </div>
  );
}

function Alerts({ alerts, canSeeEvidence, act, ask, evidence }: PageProps) {
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
          <button key={key} className={filter === key ? 'on' : ''} onClick={() => setFilter(key)}>
            {key[0].toUpperCase() + key.slice(1)} {counts[key]}
          </button>
        ))}
      </div>
      <section className="recent">
        {visible.map(alert => <AlertItem key={alert.id} alert={alert} showStatus canSeeEvidence={canSeeEvidence} act={act} ask={ask} evidence={evidence} />)}
        {!visible.length && <div className="empty-state"><b>Nothing to review</b><p>No alerts match this filter.</p></div>}
      </section>
    </div>
  );
}

type TrendRow = { day: string; severity: string; count: number };

function Trends({ alerts }: { alerts: Alert[] }) {
  const [rows, setRows] = useState<TrendRow[] | null>(null);
  useEffect(() => { api.trends().then(setRows).catch(() => setRows([])); }, []);

  /* Seven columns, one per day, each stacked high over medium over low. The chart
     is 200px tall, so a unit is 200/scale pixels. */
  const days = useMemo(() => {
    const byDay = new Map<string, { low: number; medium: number; high: number }>();
    for (const row of rows || []) {
      const bucket = byDay.get(row.day) || { low: 0, medium: 0, high: 0 };
      if (URGENT.includes(row.severity)) bucket.high += row.count;
      else if (row.severity === 'medium') bucket.medium += row.count;
      else bucket.low += row.count;
      byDay.set(row.day, bucket);
    }
    return [...byDay.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-7)
      .map(([day, bucket]) => ({ day, ...bucket, total: bucket.low + bucket.medium + bucket.high }));
  }, [rows]);

  if (!rows) return <Skeleton />;
  const scale = Math.max(4, ...days.map(day => day.total));
  const px = (count: number) => `${Math.round((count / scale) * 200)}px`;
  const label = (day: string) => { const at = new Date(day); return Number.isNaN(at.getTime()) ? day : at.toLocaleDateString([], { weekday: 'short' }); };
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

      {days.length ? (
        <div className="chart">
          <div className="legend">
            <span><i />Low</span><span className="m"><i />Medium</span><span className="h"><i />High</span>
          </div>
          <div className="plot" style={{ ['--days' as string]: days.length }}>
            <div className="grid">
              <i style={{ top: 0 }} /><b style={{ top: 0 }}>{scale}</b>
              <i style={{ top: '50%' }} /><b style={{ top: '50%' }}>{Math.round(scale / 2)}</b>
              <i style={{ top: '100%' }} /><b style={{ top: '100%' }}>0</b>
            </div>
            {days.map(day => (
              <div className="col" key={day.day}>
                {day.high > 0 && <span className="h" style={{ height: px(day.high) }}><em>{label(day.day)} · {day.high} high</em></span>}
                {day.medium > 0 && <span className="m" style={{ height: px(day.medium) }}><em>{label(day.day)} · {day.medium} medium</em></span>}
                {day.low > 0 && <span style={{ height: px(day.low) }}><em>{label(day.day)} · {day.low} low</em></span>}
              </div>
            ))}
          </div>
          <div className="xaxis" style={{ ['--days' as string]: days.length }}>{days.map(day => <span key={day.day}>{label(day.day)}</span>)}</div>
          <details className="table">
            <summary>Table view</summary>
            <table>
              <tbody>
                <tr><th>Day</th><th>Low</th><th>Medium</th><th>High</th><th>Total</th></tr>
                {days.map(day => <tr key={day.day}><td>{label(day.day)}</td><td>{day.low}</td><td>{day.medium}</td><td>{day.high}</td><td>{day.total}</td></tr>)}
              </tbody>
            </table>
          </details>
        </div>
      ) : <div className="empty-state"><b>No activity yet</b><p>Trend data appears once alerts have been processed.</p></div>}
    </div>
  );
}

type Health = { database?: string; model?: string; platform?: string; load_average?: number[] | null; disk_free_bytes?: number };
type Device = { device: string; events: number; last_seen: string };

const gigabytes = (bytes?: number) => (bytes ? `${(bytes / 1e9).toFixed(0)} GB` : '—');
const loads = (health?: Health) => (health?.load_average ? health.load_average.map(value => value.toFixed(2)).join(' · ') : '—');

function useHealth() {
  const [health, setHealth] = useState<Health>();
  useEffect(() => { api.health().then(setHealth).catch(() => setHealth({})); }, []);
  return health;
}

function Advanced({ selected }: { selected: any }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const health = useHealth();
  useEffect(() => { api.devices().then(setDevices).catch(() => setDevices([])); }, []);
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

      <h3>Appliance health</h3>
      <div className="panel">
        <div className="field"><div><b>Database</b><p>Local SQLite store for alerts and explanations.</p></div><span className="pill">{health.database || 'unknown'}</span></div>
        <div className="field"><div><b>Model</b><p>Runs locally on this computer, no external calls.</p></div><span className="pill">{health.model || '—'}</span></div>
        <div className="field"><div><b>Load average</b><p>1 / 5 / 15 minutes.</p></div><span className="pill">{loads(health)}</span></div>
        <div className="field"><div><b>Disk free</b><p>Retention trims raw events after 30 days.</p></div><span className="pill">{gigabytes(health.disk_free_bytes)}</span></div>
      </div>

      <h3>Selected alert evidence</h3>
      {selected ? <>
        <p className="lede">{selected.title} — model reasoning</p>
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
        <pre className="evidence">{JSON.stringify(selected.raw, null, 2)}</pre>
      </> : <p className="muted">Open an alert and choose “Show evidence” to bring its raw record here.</p>}
    </div>
  );
}

function Settings() {
  const [preferences, setPreferences] = useState<Record<string, string> | null>(null);
  const [saved, setSaved] = useState('');
  useEffect(() => { api.preferences().then(setPreferences).catch(() => setPreferences({})); }, []);
  if (!preferences) return <Skeleton />;
  const change = (key: string, value: string) => {
    setPreferences({ ...preferences, [key]: value });
    api.setPreference(key, value).then(() => setSaved('Saved on this appliance.')).catch(() => setSaved('Could not save that preference.'));
  };
  return (
    <div>
      <p className="eyebrow">Settings</p>
      <h1>Your<br />preferences</h1>
      <p className="lede">These apply to your account only. Appliance-wide options live under Admin.</p>
      <div className="panel">
        <div className="field">
          <div><b>Notification threshold</b><p>The lowest severity that will reach you.</p></div>
          <select value={preferences.notification_threshold || 'high'} onChange={event => change('notification_threshold', event.target.value)}>
            <option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
          </select>
        </div>
        <div className="field">
          <div><b>Alert sensitivity</b><p>How readily borderline activity becomes an alert.</p></div>
          <select value={preferences.alert_sensitivity || 'balanced'} onChange={event => change('alert_sensitivity', event.target.value)}>
            <option value="relaxed">Relaxed</option><option value="balanced">Balanced</option><option value="strict">Strict</option>
          </select>
        </div>
        <div className="field">
          <div><b>Plain-English explanations</b><p>Show the model&rsquo;s summary above the technical detail.</p></div>
          <span className="pill">On</span>
        </div>
      </div>
      <h3>Monitoring sources</h3>
      <div className="panel">
        <div className="field"><div><b>Suricata</b><p>eve.json &mdash; alert events</p></div><span className="pill">Configured</span></div>
        <div className="field"><div><b>Zeek</b><p>conn, dns and notice logs, JSON output</p></div><span className="pill">Configured</span></div>
        <div className="field"><div><b>Wazuh</b><p>alerts.json export</p></div><span className="pill">Configured</span></div>
      </div>
      {saved && <p className="notice" role="status">{saved}</p>}
    </div>
  );
}

type User = { id: number; username: string; role: string; must_change_password: boolean };

function Admin({ session }: { session: Session }) {
  const [users, setUsers] = useState<User[] | null>(null);
  const [adding, setAdding] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('owner');
  const [notice, setNotice] = useState('');
  const health = useHealth();
  const loadUsers = () => api.users().then(setUsers).catch(() => setUsers([]));
  useEffect(() => { loadUsers(); }, []);
  if (!users || !health) return <Skeleton />;
  const create = async (event: FormEvent) => {
    event.preventDefault();
    setNotice('');
    try {
      await api.createUser(username, password, role);
      setUsername(''); setPassword(''); setRole('owner'); setAdding(false);
      setNotice('User created. They will be asked to choose their own password at first sign-in.');
      await loadUsers();
    } catch (failure) {
      setNotice(detailOf(failure, 'Unable to create user. Check the username and password requirements.'));
    }
  };
  return (
    <div>
      <p className="eyebrow">Administration</p>
      <h1>Local<br />users</h1>
      <p className="lede">Accounts exist only on this appliance. There is no cloud directory to sync with.</p>
      <table className="list">
        <tbody>
          <tr><th>User</th><th>Role</th><th>Password</th><th /></tr>
          {users.map(user => (
            <tr key={user.id}>
              <td><b>{user.username}</b></td>
              <td>{user.role[0].toUpperCase() + user.role.slice(1)}</td>
              <td>{user.must_change_password ? 'Change required' : 'Set'}</td>
              <td>{user.username === session.username ? <span className="pill">You</span> : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {adding ? (
        <div className="panel">
          <form onSubmit={create}>
            <div className="field">
              <div><b>Username</b><p>Letters, digits, dot, dash and underscore.</p></div>
              <input required minLength={3} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9._-]*" autoComplete="off" aria-label="Username" value={username} onChange={event => setUsername(event.target.value)} />
            </div>
            <div className="field">
              <div><b>Temporary password</b><p>At least 12 characters. They replace it at first sign-in.</p></div>
              <input required minLength={12} maxLength={256} type="password" autoComplete="new-password" aria-label="Temporary password" value={password} onChange={event => setPassword(event.target.value)} />
            </div>
            <div className="field">
              <div><b>Access level</b><p>Owners see explanations; analysts and admins also see raw evidence.</p></div>
              <select aria-label="Access level" value={role} onChange={event => setRole(event.target.value)}>
                <option value="owner">Owner</option><option value="analyst">Analyst</option><option value="admin">Admin</option>
              </select>
            </div>
            <div className="row-end">
              <button className="btn quiet" type="button" onClick={() => { setAdding(false); setNotice(''); }}>Cancel</button>
              <button className="btn">Create user</button>
            </div>
          </form>
        </div>
      ) : <div className="row-end"><button className="btn" onClick={() => setAdding(true)}>Add user</button></div>}
      {notice && <p className="notice" role="status">{notice}</p>}

      <h3>Appliance</h3>
      <div className="panel">
        <div className="field"><div><b>Platform</b><p>The host this appliance is running on.</p></div><span className="pill">{health.platform || 'unknown'}</span></div>
        <div className="field"><div><b>Model</b><p>Runs locally on this computer, no external calls.</p></div><span className="pill">{health.model || '—'}</span></div>
        <div className="field"><div><b>Load average</b><p>1 / 5 / 15 minutes.</p></div><span className="pill">{loads(health)}</span></div>
        <div className="field"><div><b>Disk free</b><p>Retention trims raw events after 30 days.</p></div><span className="pill">{gigabytes(health.disk_free_bytes)}</span></div>
      </div>
    </div>
  );
}

function App() {
  const [session, setSession] = useState(getSession());
  const [tab, setTab] = useState('home');
  const [collapsed, setCollapsed] = useState(false);
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [selected, setSelected] = useState<any>();
  const [chats, setChats] = useState<Conversation[]>(() => loadConversations());
  const [activeId, setActiveId] = useState<string | null>(null);
  /* The thread waiting on the model. One question at a time: inference is CPU-bound,
     so a second request would only queue behind the first. The ref guards against a
     double send landing before the state update has rendered. */
  const [pendingId, setPendingId] = useState<string | null>(null);
  const pending = useRef<string | null>(null);
  const thinking = pendingId !== null;
  const [message, setMessage] = useState('');

  const load = () => api.alerts().then(setAlerts).catch(() => setAlerts([]));
  useEffect(() => { if (session && !session.must_change_password) load(); }, [session]);

  /* Every change goes through the latest state, never a render's snapshot: a reply
     or a title can land long after the user has moved to another thread. */
  const update = (change: (current: Conversation[]) => Conversation[]) => setChats(current => {
    const next = change(current);
    saveConversations(next);
    return next;
  });

  /* The model's title replaces the fallback, but only on a thread that still exists. */
  const nameChat = (id: string, question: string) => {
    api.chatTitle(clip(question, MAX_QUESTION))
      .then(title => { if (title) update(current => current.map(entry => entry.id === id ? { ...entry, title: titleFor(title) } : entry)); })
      .catch(() => { /* the fallback title stays */ });
  };

  /* A question either continues the open thread or starts a new one; either way it
     is one row in the sidebar, never one row per message. */
  const ask: Ask = (question, about) => {
    const text = question.trim();
    if (!text) return;
    if (pending.current) { setActiveId(pending.current); setTab('home'); return; }
    const turn: Turn = { role: 'me', text };
    const existing = !about && activeId ? chats.find(chat => chat.id === activeId) : undefined;
    const chat: Conversation = existing
      ? { ...existing, turns: [...existing.turns, turn], updated: Date.now() }
      : { id: newId(), title: titleFor(about?.title || text), turns: [turn], updated: Date.now(), ...(about ? { alertId: about.id } : {}) };
    const messages = toChatMessages(chat.turns);
    const alertId = chat.alertId ?? null;
    setActiveId(chat.id);
    setTab('home');
    setMessage('');
    update(current => {
      const stored = current.find(entry => entry.id === chat.id);
      return [stored ? { ...stored, turns: [...stored.turns, turn], updated: chat.updated } : chat, ...current.filter(entry => entry.id !== chat.id)];
    });
    pending.current = chat.id;
    setPendingId(chat.id);
    void (async () => {
      let answered = false;
      try {
        let reply: Turn;
        try {
          const result = await api.chat(messages, alertId);
          answered = result.available;
          /* the AI-unavailable notice is fixed server text, not the model's words */
          reply = result.available ? { role: 'them', text: result.reply } : { role: 'them', text: result.reply, local: true };
        } catch (failure) {
          reply = { role: 'them', text: chatFailure(failure, alertId !== null), local: true };
        }
        update(current => current.map(entry => entry.id === chat.id ? { ...entry, turns: [...entry.turns, reply], updated: Date.now() } : entry));
      } finally {
        pending.current = null;
        setPendingId(null);
      }
      /* Named after the answer, not alongside it, so the title never queues ahead of
         the reply on the one local model. A thread opened from an alert keeps the
         alert's name: its question is generic, so the model could not do better. */
      if (!existing && !about && answered) nameChat(chat.id, text);
    })();
  };

  const act = async (id: number, status: string) => { await api.setStatus(id, status); load(); };
  const showEvidence = async (alert: Alert) => { setSelected(await api.detail(alert.id)); setTab('advanced'); };

  if (!session) return <Login onLogin={setSession} />;
  if (session.must_change_password) return <ChangePassword session={session} onDone={setSession} />;

  const canSeeEvidence = advanced(session.role);
  const pageProps: PageProps = { alerts: alerts || [], canSeeEvidence, act, ask, evidence: showEvidence };
  const chat = chats.find(entry => entry.id === activeId);
  const primary = ['home', 'alerts', 'trends', ...(canSeeEvidence ? ['advanced'] : [])];
  /* While a reply is pending the draft stays editable but is not sent. */
  const send = (event: FormEvent) => { event.preventDefault(); if (!thinking) ask(message); };
  const keydown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); if (!thinking) ask(message); }
  };

  const page = () => {
    if (!alerts) return <Skeleton />;
    if (tab === 'home') return chat ? <Thread chat={chat} thinking={pendingId === chat.id} /> : <Home {...pageProps} />;
    if (tab === 'alerts') return <Alerts {...pageProps} />;
    if (tab === 'trends') return <Trends alerts={alerts} />;
    if (tab === 'advanced') return <Advanced selected={selected} />;
    if (tab === 'settings') return <Settings />;
    if (tab === 'admin') return <Admin session={session} />;
    return null;
  };

  return (
    <div className={`app${collapsed ? ' collapsed' : ''}`}>
      <aside>
        <div className="rail-top">
          <button className="collapse" title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!collapsed}
            onClick={() => setCollapsed(!collapsed)}>☰</button>
        </div>
        <div className="brand">
          <img src="/assets/lighthouse-logo.png" alt="LightHouse" />
          <span className="txt"><b>LightHouse</b><span>Guiding You to Safer Shores</span></span>
        </div>
        <nav>{primary.map(item => <Nav key={item} item={item} tab={tab} setTab={setTab} />)}</nav>
        <Chats chats={chats} activeId={activeId} start={() => { setActiveId(null); setTab('home'); }}
          open={id => { setActiveId(id); setTab('home'); }} />
        <nav className="bottom">
          <Nav item="settings" tab={tab} setTab={setTab} />
          {session.role === 'admin' && <Nav item="admin" tab={tab} setTab={setTab} />}
          <button onClick={async () => { await logout(); setSession(null); }}>
            <span className="nav-icon">⇥</span><span className="nav-label">Sign out</span>
          </button>
        </nav>
      </aside>

      <main className={tab === 'home' ? 'with-dock' : ''}>
        <div className="sheet">{page()}</div>
        <div className="dock">
          <form onSubmit={send}>
            <textarea rows={1} value={message} onChange={event => setMessage(event.target.value)} onKeyDown={keydown}
              aria-label="Ask LightHouse" placeholder={chat ? 'Reply to LightHouse…' : 'Ask LightHouse about your network…'} />
            <button type="submit" aria-label="Send chat" disabled={thinking}>↑</button>
          </form>
          <small>LightHouse is AI, it can make mistakes. Chats stay on this appliance for your privacy.</small>
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
