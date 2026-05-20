// securellm-sidebar.jsx — Sidebar conversation history

const { useState: useSidebarState } = React;

const MOCK_CONVERSATIONS = [
  { id: 'c1', title: 'Log4Shell Technical Analysis',       preview: 'CVE-2021-44228 involves a critical JNDI injection…',    ts: new Date(Date.now() - 7200000)   },
  { id: 'c2', title: 'CVE-2024-3400 PAN-OS Breakdown',     preview: 'The vulnerability affects GlobalProtect gateway…',     ts: new Date(Date.now() - 86400000)  },
  { id: 'c3', title: 'CRITICAL vs HIGH Severity Guide',    preview: 'CVSS 9.0–10.0 is classified as CRITICAL severity…',   ts: new Date(Date.now() - 172800000) },
  { id: 'c4', title: 'Apache Vulnerabilities Q2 2024',     preview: 'Several Apache projects were affected including…',     ts: new Date(Date.now() - 259200000) },
  { id: 'c5', title: 'Linux Kernel LPE Techniques',        preview: 'Dirty Pipe and OverlayFS privilege escalation…',       ts: new Date(Date.now() - 604800000) },
];

function ConvItem({ convo, isActive, onClick }) {
  const [hov, setHov] = useSidebarState(false);
  return (
    <div
      onClick={() => onClick(convo.id)}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        padding: '9px 10px',
        borderRadius: '7px',
        cursor: 'pointer',
        marginBottom: '2px',
        background: isActive ? 'rgba(0,212,255,0.07)' : hov ? 'rgba(255,255,255,0.025)' : 'transparent',
        borderLeft: `2px solid ${isActive ? '#00D4FF' : hov ? 'rgba(0,212,255,0.3)' : 'transparent'}`,
        transition: 'all 0.14s ease',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '6px', marginBottom: '3px' }}>
        <span style={{ fontSize: '12px', fontWeight: 600, color: isActive ? '#00D4FF' : '#C8D3E0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', flex: 1, lineHeight: 1.3 }}>
          {convo.title}
        </span>
        <span style={{ fontSize: '9px', color: '#2D3748', flexShrink: 0, paddingTop: '1px' }}>
          {formatRelativeTime(convo.ts)}
        </span>
      </div>
      <p style={{ fontSize: '11px', color: '#374151', margin: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', lineHeight: 1.3 }}>
        {convo.preview}
      </p>
    </div>
  );
}

function Sidebar({ activeConvId, onSelectConv, onNewChat }) {
  return (
    <div style={{ width: 260, flexShrink: 0, background: '#111827', borderRight: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* New conversation button */}
      <div style={{ padding: '14px 12px 8px' }}>
        <NewChatBtn onClick={onNewChat} />
      </div>

      {/* Section label */}
      <div style={{ padding: '6px 14px 5px', fontSize: '9px', fontWeight: 700, color: '#2D3748', letterSpacing: '0.14em', textTransform: 'uppercase' }}>
        Recent
      </div>

      {/* Conversation list */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 8px' }} className="sidebar-scroll">
        {MOCK_CONVERSATIONS.map(c => (
          <ConvItem key={c.id} convo={c} isActive={activeConvId === c.id} onClick={onSelectConv} />
        ))}
      </div>

      {/* Model badge */}
      <div style={{ padding: '12px 12px', borderTop: '1px solid rgba(255,255,255,0.04)', flexShrink: 0 }}>
        <div style={{ background: 'rgba(0,212,255,0.04)', border: '1px solid rgba(0,212,255,0.11)', borderRadius: '8px', padding: '10px 12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
            <svg width="11" height="11" viewBox="0 0 11 11" fill="none">
              <rect x="1" y="2.5" width="9" height="6.5" rx="1.2" fill="none" stroke="#00D4FF" strokeWidth="1"/>
              <path d="M3.5 2.5V1.5M7.5 2.5V1.5" stroke="#00D4FF" strokeWidth="1" strokeLinecap="round"/>
              <rect x="2.5" y="4.5" width="1.8" height="1.8" rx="0.4" fill="#00D4FF" opacity="0.55"/>
              <rect x="6.7" y="4.5" width="1.8" height="1.8" rx="0.4" fill="#00D4FF" opacity="0.55"/>
            </svg>
            <span style={{ fontSize: '11px', fontWeight: 700, color: '#00D4FF', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.04em' }}>
              Llama-3.1-8B
            </span>
          </div>
          <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
            {['LoRA', 'CUDA FP16', '9,992 CVEs'].map(tag => (
              <span key={tag} style={{ fontSize: '9px', color: '#374151', background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.1)', borderRadius: '4px', padding: '2px 6px', fontFamily: "'JetBrains Mono', monospace" }}>
                {tag}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function NewChatBtn({ onClick }) {
  const [hov, setHov] = useSidebarState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{ width: '100%', padding: '8px 12px', background: hov ? 'rgba(0,212,255,0.12)' : 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.18)', borderRadius: '8px', color: '#00D4FF', fontSize: '12px', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '7px', fontFamily: 'Inter, sans-serif', transition: 'all 0.15s' }}
    >
      <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
        <path d="M6.5 1v11M1 6.5h11" stroke="#00D4FF" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
      New Conversation
    </button>
  );
}

Object.assign(window, { Sidebar, MOCK_CONVERSATIONS });
