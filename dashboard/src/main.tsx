import { FormEvent, KeyboardEvent, ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { api, AiInstructions, Alert, ChatMessage, ChatModels, getSession, login, logout, Monitoring, Session, statusOf, UpdateInfo } from './api';
import { clip, Conversation, fullTime, loadConversations, MAX_QUESTION, newId, relativeTime, retryTurns, saveConversations, titleFor, toChatMessages, Turn } from './conversations';
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
};
const Icon = ({ name, size = 16 }: { name: keyof typeof ICONS; size?: number }) => (
  <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="2"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d={ICONS[name]} /></svg>
);

function Chats({ chats, activeId, open }: { chats: Conversation[]; activeId: string | null; open: (id: string) => void }) {
  return (
    <section className="chats">
      <div className="head">
        <span className="nav-label">Recent chats</span>
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

/* Opening an alert usually comes just before "Ask LightHouse about this", so the
   server pre-reads that alert's chat context now and the answer starts sooner. The
   server skips it while the model is busy; here it is at most once a minute per alert. */
const alertWarmedAt = new Map<number, number>();
const warmAlert = (id: number) => {
  const now = Date.now();
  if (now - (alertWarmedAt.get(id) || 0) < 60_000) return;
  alertWarmedAt.set(id, now);
  api.chatWarm(id);
};

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
    <details className="alert" onToggle={event => { if (event.currentTarget.open) warmAlert(alert.id); }}>
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
  /* Background monitoring: shown to everyone; the switch is passed only to admins. */
  monitoring?: Monitoring | null; monitoringBusy?: boolean; toggleMonitoring?: () => void; shutDown?: () => void;
};

function Home({ alerts, canSeeEvidence, act, ask, evidence, monitoring, monitoringBusy, toggleMonitoring, shutDown }: PageProps) {
  const open = alerts.filter(alert => alert.status === 'open');
  const urgent = open.filter(alert => URGENT.includes(alert.severity)).length;
  const paused = !!monitoring?.paused;
  return (
    <div>
      <section className="welcome">
        <p className="eyebrow">Network overview</p>
        <h1>{urgent ? <>{urgent} item{urgent === 1 ? '' : 's'} deserve{urgent === 1 ? 's' : ''}<br />your attention</> : <>Your network<br />looks healthy</>}</h1>
        <div className="health">
          <i className={paused ? 'off' : urgent ? 'warn' : ''} />
          <b>{paused ? 'Monitoring paused' : urgent ? 'Attention needed' : 'Monitoring active'}</b>
          <small>{paused ? 'Not watching this computer or network until resumed' : `${open.length} open alert${open.length === 1 ? '' : 's'}`}</small>
          {toggleMonitoring && monitoring?.available && (
            <button className="btn quiet" type="button" disabled={monitoringBusy} onClick={toggleMonitoring}>
              {monitoringBusy ? 'Working…' : paused ? 'Resume monitoring' : 'Pause monitoring'}
            </button>
          )}
          {shutDown && monitoring?.available && (
            <button className="btn quiet" type="button" disabled={monitoringBusy} onClick={shutDown}>Shut down</button>
          )}
        </div>
      </section>
      <section className="cards lead">
        <div><small>Health status</small><strong>{paused ? 'Paused' : urgent ? 'Review alerts' : 'Good'}</strong><p>{paused ? 'Monitoring is switched off for now.' : 'Monitoring sources are ready to report.'}</p></div>
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

/* LightHouse's "working" mark: the green speaker dot turns into a small round tank of
   water. Two swells roll through it at different speeds, drops splash off the crest,
   the water bobs, and an arc runs round the rim like a loading ring. Brand greens
   only; static under reduced motion. Each swell spans two periods of the 26-unit
   circle, so sliding it one period loops seamlessly. */
function WaveMark({ label = 'LightHouse is replying', spill = false }: { label?: string | null; spill?: boolean }) {
  const clip = `wave-clip-${useId().replace(/:/g, '')}`;
  // label null: decorative, where text beside it already announces the progress.
  const a11y = label === null || spill ? { 'aria-hidden': true } : { role: 'status', 'aria-label': label };
  return (
    <span className={`mark wave-mark${spill ? ' spill' : ''}`} {...a11y}>
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
        {/* What pours out over the right rim. Outside the clipped group, because the
            water that leaves the tank must still be drawn. */}
        {spill && (
          <g className="spill-out">
            <path className="stream" d="M22 11 Q27 10.5 29 16" pathLength="100" />
            <circle style={{ ['--dx' as string]: '6px', ['--dy' as string]: '9px' }} cx="25" cy="12" r="1.2" />
            <circle style={{ ['--dx' as string]: '10px', ['--dy' as string]: '5px' }} cx="25" cy="12" r="1" />
            <circle style={{ ['--dx' as string]: '13px', ['--dy' as string]: '11px' }} cx="25" cy="12" r=".9" />
            <circle style={{ ['--dx' as string]: '8px', ['--dy' as string]: '13px' }} cx="25" cy="12" r=".8" />
          </g>
        )}
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
    provider === 'purdue' ? 'Asking Purdue GenAI Studio…' : 'Waking the local AI…',
    aboutAlert ? 'Reading this alert…' : 'Reading your recent alerts…',
    ...THINKING_LINES,
    ...(provider === 'purdue' ? [] : ['Thinking on this computer. This can take a minute…']),
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
   actions (copy, retry on the last answer) and when it was written.
   Keyed by thread, so switching threads mid-answer never reads as a finish. */
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

  /* The finish: when this thread's answer lands live, the tank tips its water out
     over the right rim, the spill breaks into drops that drift off and fade, and the
     empty tank fades last; then its row folds away so the answer text, already shown
     beneath it, slides up without a jump. Worked out during render, not in an
     effect, so the frame where the answer appears already holds the spilling mark.
     Never on opening an old thread or a reload (thinking starts false), and not at
     all under reduced motion. The timeout is a backstop if animationend never comes. */
  const [wasThinking, setWasThinking] = useState(thinking);
  const [spillAt, setSpillAt] = useState<number | null>(null);
  if (thinking !== wasThinking) {
    setWasThinking(thinking);
    setSpillAt(!thinking && !reducedMotion() ? retryTurns(chat.turns)?.length ?? null : null);
  }
  useEffect(() => {
    if (spillAt === null) return;
    const timer = setTimeout(() => setSpillAt(null), 1500);
    return () => clearTimeout(timer);
  }, [spillAt]);

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
              {spillAt === index && (
                <div className="spill-slot" onAnimationEnd={event => { if (event.target === event.currentTarget) setSpillAt(null); }}>
                  <WaveMark spill />
                </div>
              )}
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

      <h3>Appliance health</h3>
      <div className="panel">
        <div className="field"><div><b>Database</b><p>Local SQLite store for alerts and explanations.</p></div><span className="pill">{health.database || 'unknown'}</span></div>
        <div className="field"><div><b>Model</b><p>Runs locally on this computer, no external calls.</p></div><span className="pill">{health.model || '—'}</span></div>
        <div className="field"><div><b>Load average</b><p>1 / 5 / 15 minutes.</p></div><span className="pill">{loads(health)}</span></div>
        <div className="field"><div><b>Disk free</b><p>Retention trims raw events after 30 days.</p></div><span className="pill">{gigabytes(health.disk_free_bytes)}</span></div>
      </div>
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
        {/* What the Windows install actually reads. Zeek and Wazuh were the Linux build's sensors. */}
        <div className="field"><div><b>Suricata</b><p>Network traffic: known attacks and suspicious connections</p></div><span className="pill">Configured</span></div>
        <div className="field"><div><b>Sysmon</b><p>This computer: programs starting, network connections, file and registry changes</p></div><span className="pill">Configured</span></div>
        <div className="field"><div><b>Windows Security log</b><p>Sign-ins, failed sign-ins, account changes and cleared logs</p></div><span className="pill">Configured</span></div>
      </div>
      {saved && <p className="notice" role="status">{saved}</p>}
    </div>
  );
}

/* The admin's own notes for the AI. Its own section with its own loading, so a
   failed fetch shows a plain message here instead of taking the Admin page down.
   The server caps, normalises and fences these; the built-in rules come first. */
function AiInstructionsSection() {
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
    try { show(await api.setAiInstructions(business, style)); setNotice('Saved. LightHouse uses these from the next answer on.'); }
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
              {box('style', 'How to answer', 'Used by chat only. For example: “use bullet points”.', style, setStyle, saved.max_chars)}
              <div className="row-end"><button className="btn" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></div>
            </form>
          )}
      </div>
      {notice && <p className="notice" role="status">{notice}</p>}
    </>
  );
}

type User = { id: number; username: string; role: string; must_change_password: boolean };

function Admin({ session, onProviderChange }: { session: Session; onProviderChange: (provider: string) => void }) {
  const [users, setUsers] = useState<User[] | null>(null);
  /* Which model answers chat. Admin only, because it decides whether owners'
     questions leave this computer; the server accepts only its curated list. */
  const [models, setModels] = useState<ChatModels | null>(null);
  const [modelNotice, setModelNotice] = useState('');
  useEffect(() => { api.chatModels().then(setModels).catch(() => setModels(null)); }, []);
  const chooseModel = async (id: string) => {
    setModelNotice('');
    try {
      await api.setChatModel(id);
      setModels(current => current && { ...current, current: id });
      onProviderChange(id === 'local' ? 'local' : 'purdue');
      const label = models?.choices.find(choice => choice.id === id)?.label || id;
      setModelNotice(`Chat now uses ${label}, from the next question on.`);
    } catch (failure) {
      setModelNotice(detailOf(failure, 'Could not change the chat model.'));
    }
  };
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

      <h3>Chat AI</h3>
      <div className="panel">
        <div className="field">
          <div><b>Who answers chat</b><p>{models?.key_configured
            ? 'Purdue GenAI Studio models answer online, in seconds. Your alerts always stay on this computer.'
            : 'Add a Purdue GenAI Studio key to use its faster models (see the README). Until then, chat runs on this computer.'}</p></div>
          {models && (
            <select aria-label="Chat model" value={models.key_configured ? models.current : 'local'} onChange={event => chooseModel(event.target.value)}>
              {!models.choices.some(choice => choice.id === models.current) && <option value={models.current}>{models.current}</option>}
              {models.choices.map(choice => (
                <option key={choice.id} value={choice.id} disabled={choice.id !== 'local' && !models.key_configured}>{choice.label}: {choice.note}</option>
              ))}
            </select>
          )}
        </div>
      </div>
      {modelNotice && <p className="notice" role="status">{modelNotice}</p>}

      <AiInstructionsSection />

      <h3>Appliance</h3>
      <div className="panel">
        <div className="field"><div><b>Platform</b><p>The host this appliance is running on.</p></div><span className="pill">{health.platform || 'unknown'}</span></div>
        <div className="field"><div><b>Model</b><p>Triages alerts on this computer, no external calls.</p></div><span className="pill">{health.model || '—'}</span></div>
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
  const warmedAt = useRef<Record<string, number>>({});
  const thinking = pendingId !== null;
  /* The answer so far, while it streams in. Kept out of the stored conversations
     until it is complete, so localStorage is written once per answer, not per word. */
  const [streamed, setStreamed] = useState('');
  const [message, setMessage] = useState('');

  const load = () => api.alerts().then(setAlerts).catch(() => setAlerts([]));
  useEffect(() => { if (session && !session.must_change_password) load(); }, [session]);
  /* Who answers chat: 'purdue' once the owner stored a GenAI Studio key, else local. */
  const [provider, setProvider] = useState('local');
  useEffect(() => {
    if (session && !session.must_change_password) api.chatProvider().then(setProvider).catch(() => setProvider('local'));
  }, [session]);
  /* Background monitoring, and the admin's switch to pause it (e.g. leaving the office). */
  const [monitoring, setMonitoring] = useState<Monitoring | null>(null);
  const [monitoringBusy, setMonitoringBusy] = useState(false);
  useEffect(() => {
    if (session && !session.must_change_password) api.monitoring().then(setMonitoring).catch(() => setMonitoring(null));
  }, [session]);
  const toggleMonitoring = async () => {
    if (!monitoring) return;
    const pausing = !monitoring.paused;
    if (pausing && !window.confirm('Pause monitoring? LightHouse will stop watching your network and this computer until you resume it, even after a restart.')) return;
    setMonitoringBusy(true);
    try { setMonitoring(await api.setMonitoring(pausing)); }
    catch (failure) { window.alert(detailOf(failure, 'LightHouse could not change monitoring. Try again.')); }
    finally { setMonitoringBusy(false); }
  };
  /* Everything off, the dashboard included, until LightHouse is opened again. */
  const [stopped, setStopped] = useState(false);
  const shutDown = async () => {
    if (!window.confirm('Shut down LightHouse? Monitoring, the local AI and this dashboard stop, and stay off after a restart, until you open LightHouse again from the Start menu or desktop.')) return;
    setMonitoringBusy(true);
    try { await api.shutdown(); setStopped(true); }
    catch (failure) { window.alert(detailOf(failure, 'LightHouse could not shut down. Try again.')); }
    finally { setMonitoringBusy(false); }
  };
  /* Checked on every load of the dashboard (the server caches GitHub's answer);
     admins are the ones who can install, so only they are asked. */
  const [release, setRelease] = useState<UpdateInfo | null>(null);
  useEffect(() => {
    if (session?.role === 'admin' && !session.must_change_password)
      api.updates().then(info => setRelease(info.available ? info : null)).catch(() => setRelease(null));
  }, [session]);

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

  /* Streams one answer into thread `id`. Shared by a new question and by Retry, so
     both keep the same guards: one answer at a time, words shown as they arrive, a
     cut-off answer keeps what was written, and failures arrive as replies rather
     than errors. Resolves true when the model itself answered. */
  const stream = async (id: string, messages: ChatMessage[], alertId: number | null): Promise<boolean> => {
    pending.current = id;
    setPendingId(id);
    setStreamed('');
    let answered = false;
    let received = '';
    try {
      let replies: Turn[];
      try {
        const result = await api.chatStream(messages, alertId, piece => { received += piece; setStreamed(received); });
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

  /* A question either continues the open thread or starts a new one; either way it
     is one row in the sidebar, never one row per message. */
  const ask: Ask = (question, about) => {
    const text = question.trim();
    if (!text) return;
    if (pending.current) { setActiveId(pending.current); setTab('home'); return; }
    const turn: Turn = { role: 'me', text, at: Date.now() };
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
    void stream(chat.id, messages, alertId).then(answered => {
      /* Named after the answer, not alongside it, so the title never queues ahead of
         the reply on the one local model. A thread opened from an alert keeps the
         alert's name: its question is generic, so the model could not do better. */
      if (!existing && !about && answered) nameChat(chat.id, text);
    });
  };

  const act = async (id: number, status: string) => { await api.setStatus(id, status); load(); };
  /* Set by "Show evidence" and cleared by Advanced once it has scrolled to the record. */
  const [jumpToEvidence, setJumpToEvidence] = useState(false);
  const showEvidence = async (alert: Alert) => { setSelected(await api.detail(alert.id)); setJumpToEvidence(true); setTab('advanced'); };

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
  if (!session) return <Login onLogin={setSession} />;
  if (session.must_change_password) return <ChangePassword session={session} onDone={setSession} />;

  const canSeeEvidence = advanced(session.role);
  const startChat = () => { setActiveId(null); setTab('home'); };
  const pageProps: PageProps = { alerts: alerts || [], canSeeEvidence, act, ask, evidence: showEvidence, monitoring, monitoringBusy,
    toggleMonitoring: session.role === 'admin' ? toggleMonitoring : undefined,
    shutDown: session.role === 'admin' ? shutDown : undefined };
  const chat = chats.find(entry => entry.id === activeId);
  const primary = ['home', 'alerts', 'trends', ...(canSeeEvidence ? ['advanced'] : [])];
  /* While a reply is pending the draft stays editable but is not sent. */
  const send = (event: FormEvent) => { event.preventDefault(); if (!thinking) ask(message); };
  /* Clicking into the composer lets the local model read its instructions and the
     alert context while the owner types, so the answer only waits on the question.
     At most once a minute per conversation context, never during an answer. */
  const warm = () => {
    if (thinking) return;
    const key = String(chat?.alertId ?? 'general');
    const now = Date.now();
    if (now - (warmedAt.current[key] || 0) < 60_000) return;
    warmedAt.current[key] = now;
    api.chatWarm(chat?.alertId ?? null);
  };
  const keydown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); if (!thinking) ask(message); }
  };

  const page = () => {
    if (!alerts) return <Skeleton />;
    if (tab === 'home') return chat
      ? <Thread key={chat.id} chat={chat} thinking={pendingId === chat.id} streamed={pendingId === chat.id ? streamed : ''} provider={provider}
        busy={thinking} retry={() => retry(chat.id)} />
      : <Home {...pageProps} />;
    if (tab === 'alerts') return <Alerts {...pageProps} />;
    if (tab === 'trends') return <Trends alerts={alerts} />;
    if (tab === 'advanced') return <Advanced selected={selected} jump={jumpToEvidence} jumped={() => setJumpToEvidence(false)} />;
    if (tab === 'settings') return <Settings />;
    if (tab === 'admin') return <Admin session={session} onProviderChange={setProvider} />;
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
            <button className="rail-btn" type="button" title="New chat" aria-label="New chat" onClick={startChat}><Icon name="compose" size={20} /></button>
            {session.role === 'admin' && monitoring?.available && <>
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
        <nav>{primary.map(item => <Nav key={item} item={item} tab={tab} setTab={setTab} />)}</nav>
        <Chats chats={chats} activeId={activeId} open={id => { setActiveId(id); setTab('home'); }} />
        <nav className="bottom">
          <Nav item="settings" tab={tab} setTab={setTab} />
          {session.role === 'admin' && <Nav item="admin" tab={tab} setTab={setTab} />}
          <button onClick={async () => { await logout(); setSession(null); }}>
            <span className="nav-icon"><Icon name="signout" size={18} /></span><span className="nav-label">Sign out</span>
          </button>
        </nav>
      </aside>

      <main className={tab === 'home' ? 'with-dock' : ''}>
        <div className="sheet">{page()}</div>
        <div className="dock">
          <form onSubmit={send}>
            <textarea rows={1} value={message} onChange={event => setMessage(event.target.value)} onKeyDown={keydown} onFocus={warm}
              aria-label="Ask LightHouse" placeholder={chat ? 'Reply to LightHouse…' : 'Ask LightHouse about your network…'} />
            <button type="submit" aria-label="Send chat" disabled={thinking}>↑</button>
          </form>
          {/* Says plainly where a question goes: the owner opted in to GenAI Studio. */}
          <small>{provider === 'purdue'
            ? 'LightHouse is AI, it can make mistakes. Answers by Purdue GenAI Studio (online); your alerts stay on this computer.'
            : 'LightHouse is AI, it can make mistakes. Chats stay on this computer for your privacy.'}</small>
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
