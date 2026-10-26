"""NCA framework catalogs + ATT&CK mappings.

Saudi NCA publishes a family of mandatory cybersecurity control frameworks.
This module pre-processes them into the GRC seed shape — frameworks +
controls + ATT&CK technique/mitigation mappings — so that:

  - ECC-2:2024  — Essential Cybersecurity Controls (baseline, all entities)
  - CSCC-1:2019 — Critical Systems Cybersecurity Controls (supplements ECC)
  - CCC-1:2020  — Cloud Cybersecurity Controls (split CSP vs CST audience)
  - OTCC-1:2022 — Operational Technology Cybersecurity Controls (ICS/OT)

…all show up in the GRC crosswalk with starter mappings to ATT&CK
Enterprise (and ICS, for OTCC). Mappings are deliberately conservative —
each one is a control whose intent obviously addresses the named TTP —
analysts edit/extend in the UI and those edits land with `source='user'`
so re-running the seeder never overwrites them.

The control catalogs come from NCA's published documents. Where the
document version uses a top-level / subdomain / subcontrol numbering
(e.g. 2-2-1 sits under 2-2 sits under domain 2), each subcontrol carries
`parent_control_id` pointing at the subdomain so the UI can render the
tree.

Controls are listed in the (control_id, parent, family, name, description,
sort_order) tuple shape the existing seeder upserts directly.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------

NCA_FRAMEWORKS: list[dict] = [
    {
        "key": "nca_ecc",
        "label": "NCA Essential Cybersecurity Controls",
        "version": "2:2024",
        "description": (
            "Saudi NCA ECC-2:2024 — mandatory cybersecurity baseline across "
            "five domains (Governance, Defence, Resilience, Third-party & "
            "Cloud, ICS), applicable to all government entities and "
            "national-priority private organisations operating in KSA."
        ),
    },
    {
        "key": "nca_cscc",
        "label": "NCA Critical Systems Cybersecurity Controls",
        "version": "1:2019",
        "description": (
            "Saudi NCA CSCC-1:2019 — supplements ECC for organisations "
            "operating critical systems. Adds elevated requirements for "
            "asset management, IAM, network defence, monitoring, and "
            "incident response."
        ),
    },
    {
        "key": "nca_ccc_csp",
        "label": "NCA Cloud Cybersecurity Controls — CSP",
        "version": "1:2020",
        "description": (
            "Saudi NCA CCC-1:2020 — Cloud Service Provider (CSP) controls. "
            "Obligations on the provider operating cloud infrastructure for "
            "KSA-regulated tenants."
        ),
    },
    {
        "key": "nca_ccc_cst",
        "label": "NCA Cloud Cybersecurity Controls — CST",
        "version": "1:2020",
        "description": (
            "Saudi NCA CCC-1:2020 — Cloud Service Tenant (CST) controls. "
            "Obligations on the customer consuming cloud services that store "
            "or process Saudi-regulated data."
        ),
    },
    {
        "key": "nca_otcc",
        "label": "NCA Operational Technology Cybersecurity Controls",
        "version": "1:2022",
        "description": (
            "Saudi NCA OTCC-1:2022 — cybersecurity controls for industrial "
            "automation & control systems (IACS / OT). Layered on top of "
            "ECC for organisations operating critical OT environments."
        ),
    },
]


# ---------------------------------------------------------------------------
# ECC-2:2024 — Essential Cybersecurity Controls
# ---------------------------------------------------------------------------

NCA_ECC_CONTROLS: list[tuple] = [
    # ---- Domain 1: Cybersecurity Governance ----
    ("1-1",   None,  "Cybersecurity governance", "Cybersecurity strategy", "Define, document, approve, communicate, review.", 110),
    ("1-1-1", "1-1", "Cybersecurity governance", "Strategy defined and approved", "A cybersecurity strategy must be defined, documented and approved by the head of the organisation.", 111),
    ("1-1-2", "1-1", "Cybersecurity governance", "Strategy roadmap and goals", "The strategy must align with the organisation's strategic objectives and include a roadmap.", 112),
    ("1-1-3", "1-1", "Cybersecurity governance", "Strategy reviewed periodically", "The strategy must be reviewed at planned intervals or when significant changes occur.", 113),

    ("1-2",   None,  "Cybersecurity governance", "Cybersecurity management", "Cybersecurity function established and resourced.", 120),
    ("1-2-1", "1-2", "Cybersecurity governance", "Dedicated cybersecurity function", "An independent cybersecurity function must be established within the organisation.", 121),
    ("1-2-2", "1-2", "Cybersecurity governance", "CISO appointed", "The CISO must be a Saudi national, qualified, and report to the head of the organisation or his/her deputy.", 122),
    ("1-2-3", "1-2", "Cybersecurity governance", "Steering committee", "A cybersecurity steering committee must be established and chaired by the head of the organisation or his/her deputy.", 123),

    ("1-3",   None,  "Cybersecurity governance", "Cybersecurity policies and procedures", "Policies and procedures developed, approved, applied and reviewed.", 130),
    ("1-3-1", "1-3", "Cybersecurity governance", "Policies documented and approved", "Cybersecurity policies must be defined, documented, approved and supported by procedures.", 131),
    ("1-3-2", "1-3", "Cybersecurity governance", "Policies enforced", "Policies and procedures must be enforced across the organisation.", 132),
    ("1-3-3", "1-3", "Cybersecurity governance", "Policies reviewed periodically", "Policies and procedures must be reviewed at planned intervals.", 133),

    ("1-4",   None,  "Cybersecurity governance", "Cybersecurity roles and responsibilities", "Cybersecurity roles defined across the organisation.", 140),
    ("1-4-1", "1-4", "Cybersecurity governance", "Roles defined", "Roles and responsibilities for cybersecurity must be defined, documented, approved and communicated.", 141),

    ("1-5",   None,  "Cybersecurity governance", "Cybersecurity risk management", "Risk management methodology defined and applied.", 150),
    ("1-5-1", "1-5", "Cybersecurity governance", "Risk methodology defined", "A documented cybersecurity risk management methodology must be defined.", 151),
    ("1-5-2", "1-5", "Cybersecurity governance", "Risk register maintained", "Cybersecurity risks must be identified, assessed and treated at least annually.", 152),

    ("1-6",   None,  "Cybersecurity governance", "Cybersecurity in IT project management", "Cybersecurity requirements embedded in IT projects.", 160),
    ("1-6-1", "1-6", "Cybersecurity governance", "Cybersecurity in projects", "Cybersecurity requirements must be defined and applied across IT/IS project life cycles.", 161),
    ("1-6-2", "1-6", "Cybersecurity governance", "Cybersecurity in software dev/acquisition", "Cybersecurity requirements must be defined in software development and acquisition.", 162),

    ("1-7",   None,  "Cybersecurity governance", "Compliance with cybersecurity laws and regulations", "Compliance with national and applicable obligations.", 170),
    ("1-7-1", "1-7", "Cybersecurity governance", "Compliance ensured", "The organisation must comply with national legislative and regulatory cybersecurity requirements.", 171),

    ("1-8",   None,  "Cybersecurity governance", "Periodical cybersecurity review and audit", "Review and audit at planned intervals.", 180),
    ("1-8-1", "1-8", "Cybersecurity governance", "Cybersecurity review", "Cybersecurity reviews must be performed by the cybersecurity function at planned intervals.", 181),
    ("1-8-2", "1-8", "Cybersecurity governance", "Cybersecurity audit", "Cybersecurity audits must be performed by independent parties.", 182),

    ("1-9",   None,  "Cybersecurity governance", "Cybersecurity in human resources", "Cybersecurity addressed across the employment lifecycle.", 190),
    ("1-9-1", "1-9", "Cybersecurity governance", "Pre-employment screening", "Cybersecurity obligations must be addressed prior to employment, including background checks for sensitive roles.", 191),
    ("1-9-2", "1-9", "Cybersecurity governance", "Cybersecurity during employment", "Cybersecurity requirements must be enforced during employment, including acceptable-use compliance.", 192),
    ("1-9-3", "1-9", "Cybersecurity governance", "Cybersecurity after termination", "Cybersecurity obligations must be enforced after termination or role change (revocation, NDA).", 193),

    ("1-10",   None,   "Cybersecurity governance", "Cybersecurity awareness and training program", "Awareness program and specialised training.", 200),
    ("1-10-1", "1-10", "Cybersecurity governance", "Awareness program", "A cybersecurity awareness program must be developed and delivered to all staff.", 201),
    ("1-10-2", "1-10", "Cybersecurity governance", "Specialised training", "Cybersecurity professionals must receive specialised training appropriate to their role.", 202),

    # ---- Domain 2: Cybersecurity Defence ----
    ("2-1",   None,  "Cybersecurity defence", "Asset management", "Inventory, classification, ownership of assets.", 210),
    ("2-1-1", "2-1", "Cybersecurity defence", "Asset inventory", "An accurate and updated inventory of information and technology assets must be maintained.", 211),
    ("2-1-2", "2-1", "Cybersecurity defence", "Asset ownership and classification", "Assets must have assigned owners and a classification reflecting confidentiality, integrity, availability.", 212),
    ("2-1-3", "2-1", "Cybersecurity defence", "Acceptable use of assets", "Acceptable use of assets must be defined and enforced.", 213),

    ("2-2",   None,  "Cybersecurity defence", "Identity and access management", "Identification, authentication, authorisation, review.", 220),
    ("2-2-1", "2-2", "Cybersecurity defence", "Unique user identification", "Every user must have a unique identifier; shared accounts are prohibited except in justified, monitored cases.", 221),
    ("2-2-2", "2-2", "Cybersecurity defence", "Authentication including MFA", "Multi-factor authentication must be enforced for privileged accounts and remote access.", 222),
    ("2-2-3", "2-2", "Cybersecurity defence", "Authorisation and least privilege", "Access must follow least-privilege and need-to-know principles, with privileged-access management for admin roles.", 223),
    ("2-2-4", "2-2", "Cybersecurity defence", "Periodic access reviews", "User and privileged-account access rights must be reviewed at planned intervals (e.g. quarterly).", 224),
    ("2-2-5", "2-2", "Cybersecurity defence", "Account lifecycle", "Account provisioning, modification and deprovisioning processes must be enforced.", 225),

    ("2-3",   None,  "Cybersecurity defence", "Information system and information processing facilities protection", "Hardening, patching, EDR, configuration baselines.", 230),
    ("2-3-1", "2-3", "Cybersecurity defence", "Secure configuration baselines", "Secure configuration baselines must be defined and applied to all systems.", 231),
    ("2-3-2", "2-3", "Cybersecurity defence", "Patch management", "A patch management process must ensure timely application of security patches.", 232),
    ("2-3-3", "2-3", "Cybersecurity defence", "Anti-malware / EDR", "Anti-malware and/or EDR controls must be deployed on endpoints and servers.", 233),
    ("2-3-4", "2-3", "Cybersecurity defence", "Removable media controls", "Use of removable media must be restricted and scanned.", 234),

    ("2-4",   None,  "Cybersecurity defence", "Email protection", "Anti-phishing, AV, content filtering, DMARC.", 240),
    ("2-4-1", "2-4", "Cybersecurity defence", "Email filtering", "Email systems must be protected by anti-spam, anti-malware and content filtering.", 241),
    ("2-4-2", "2-4", "Cybersecurity defence", "Email domain authentication", "Email authentication mechanisms (SPF, DKIM, DMARC) must be configured.", 242),
    ("2-4-3", "2-4", "Cybersecurity defence", "Phishing awareness", "Users must receive recurring awareness training and phishing simulations.", 243),

    ("2-5",   None,  "Cybersecurity defence", "Network security management", "Segmentation, firewall, IDS/IPS, wireless, web filtering.", 250),
    ("2-5-1", "2-5", "Cybersecurity defence", "Network segmentation", "Networks must be logically segmented based on trust zones and asset criticality.", 251),
    ("2-5-2", "2-5", "Cybersecurity defence", "Firewall and IPS", "Perimeter firewalls and IDS/IPS must be deployed and tuned.", 252),
    ("2-5-3", "2-5", "Cybersecurity defence", "Wireless security", "Wireless networks must use strong authentication and encryption; guest networks must be isolated.", 253),
    ("2-5-4", "2-5", "Cybersecurity defence", "Browsing and web filtering", "Web filtering and secure browsing controls must be enforced for internet access.", 254),
    ("2-5-5", "2-5", "Cybersecurity defence", "Secure remote access", "Remote access must use secure channels (VPN with MFA) and be logged.", 255),

    ("2-6",   None,  "Cybersecurity defence", "Mobile devices security", "MDM, BYOD policy, mobile threat defence.", 260),
    ("2-6-1", "2-6", "Cybersecurity defence", "Mobile device management", "Corporate mobile devices must be enrolled in MDM with policy enforcement and remote wipe capability.", 261),
    ("2-6-2", "2-6", "Cybersecurity defence", "BYOD controls", "BYOD policy must enforce separation of personal/work data and minimum security baselines.", 262),

    ("2-7",   None,  "Cybersecurity defence", "Data and information protection", "Classification, DLP, encryption, disposal.", 270),
    ("2-7-1", "2-7", "Cybersecurity defence", "Data classification", "Data must be classified per its sensitivity (e.g. public/internal/confidential/top secret).", 271),
    ("2-7-2", "2-7", "Cybersecurity defence", "Data leakage prevention", "DLP controls must protect classified data in transit, at rest and on endpoints.", 272),
    ("2-7-3", "2-7", "Cybersecurity defence", "Secure data disposal", "Secure media sanitisation must be applied prior to disposal or re-use.", 273),
    ("2-7-4", "2-7", "Cybersecurity defence", "Encryption of data at rest", "Sensitive data at rest must be encrypted per approved standards.", 274),

    ("2-8",   None,  "Cybersecurity defence", "Cryptography", "Cryptographic key management, approved standards.", 280),
    ("2-8-1", "2-8", "Cybersecurity defence", "Cryptographic standards", "Cryptographic controls must use only approved algorithms and key lengths.", 281),
    ("2-8-2", "2-8", "Cybersecurity defence", "Key management", "Cryptographic keys must be generated, stored, rotated and destroyed securely.", 282),

    ("2-9",   None,  "Cybersecurity defence", "Backup and recovery management", "Backups, testing, offline copies.", 290),
    ("2-9-1", "2-9", "Cybersecurity defence", "Backups of critical data", "Critical systems and data must be backed up at planned intervals.", 291),
    ("2-9-2", "2-9", "Cybersecurity defence", "Backup restoration testing", "Backup restoration must be tested at planned intervals.", 292),
    ("2-9-3", "2-9", "Cybersecurity defence", "Immutable/offline backups", "Backups must be protected against tampering (immutability and/or offline storage).", 293),

    ("2-10",   None,   "Cybersecurity defence", "Vulnerability management", "Scanning, remediation SLAs.", 300),
    ("2-10-1", "2-10", "Cybersecurity defence", "Vulnerability assessment", "Vulnerability assessments must be performed periodically across the technology stack.", 301),
    ("2-10-2", "2-10", "Cybersecurity defence", "Remediation SLAs", "Remediation deadlines must be defined per severity and tracked to closure.", 302),

    ("2-11",   None,   "Cybersecurity defence", "Penetration testing", "Adversarial testing on critical systems.", 310),
    ("2-11-1", "2-11", "Cybersecurity defence", "Penetration testing schedule", "Penetration testing must be conducted at planned intervals on critical systems.", 311),

    ("2-12",   None,   "Cybersecurity defence", "Cybersecurity event logs and monitoring management", "Logging, SIEM, retention, anomaly detection.", 320),
    ("2-12-1", "2-12", "Cybersecurity defence", "Activate logging", "Cybersecurity event logs must be activated on all critical systems and security controls.", 321),
    ("2-12-2", "2-12", "Cybersecurity defence", "Centralised monitoring", "Logs must be aggregated into a centralised monitoring (SIEM) capability.", 322),
    ("2-12-3", "2-12", "Cybersecurity defence", "Use-cases and alerting", "Detection use-cases must be developed and tuned against the organisation's threat model.", 323),
    ("2-12-4", "2-12", "Cybersecurity defence", "Log retention", "Cybersecurity event logs must be retained for at least 12 months.", 324),

    ("2-13",   None,   "Cybersecurity defence", "Cybersecurity incident and threat management", "IR plan, NCA reporting, threat intel sharing.", 330),
    ("2-13-1", "2-13", "Cybersecurity defence", "Incident response plan", "An incident response plan must be defined, approved and tested.", 331),
    ("2-13-2", "2-13", "Cybersecurity defence", "Incident reporting to NCA", "Cybersecurity incidents must be reported to the National Cybersecurity Authority per its procedures.", 332),
    ("2-13-3", "2-13", "Cybersecurity defence", "Threat intelligence sharing", "Cyber threat intelligence must be collected, analysed and shared with relevant national channels.", 333),

    ("2-14",   None,   "Cybersecurity defence", "Physical security", "Physical access controls to ICT facilities.", 340),
    ("2-14-1", "2-14", "Cybersecurity defence", "Data centre access", "Physical access to data centres and sensitive ICT areas must be restricted, logged and monitored.", 341),

    ("2-15",   None,   "Cybersecurity defence", "Web application security", "Secure development, WAF, exposed-app protection.", 350),
    ("2-15-1", "2-15", "Cybersecurity defence", "Web application firewalls", "Internet-facing web applications must be protected by web application firewalls.", 351),
    ("2-15-2", "2-15", "Cybersecurity defence", "Secure web app development", "Web applications must follow secure-development lifecycle requirements (e.g. OWASP ASVS).", 352),
    ("2-15-3", "2-15", "Cybersecurity defence", "MFA on web apps", "Web applications handling sensitive data must enforce MFA for users.", 353),

    # ---- Domain 3: Cybersecurity Resilience ----
    ("3-1",   None,  "Cybersecurity resilience", "Cybersecurity resilience aspects of BCM", "Cybersecurity scenarios in BCM/DR.", 410),
    ("3-1-1", "3-1", "Cybersecurity resilience", "Cybersecurity in BCM", "Cybersecurity requirements must be embedded in business continuity management.", 411),
    ("3-1-2", "3-1", "Cybersecurity resilience", "Cybersecurity DR scenarios", "Cybersecurity disaster-recovery scenarios (including ransomware) must be defined and tested.", 412),
    ("3-1-3", "3-1", "Cybersecurity resilience", "Cyber-resilience drills", "Cyber-resilience drills must be conducted periodically.", 413),

    # ---- Domain 4: Third-Party and Cloud Computing Cybersecurity ----
    ("4-1",   None,  "Third-party and cloud", "Third-party cybersecurity", "Third-party risk, contracts, assessments.", 510),
    ("4-1-1", "4-1", "Third-party and cloud", "Third-party risk management", "Cybersecurity risks of third parties must be identified and managed.", 511),
    ("4-1-2", "4-1", "Third-party and cloud", "Cybersecurity clauses in contracts", "Cybersecurity requirements must be defined in third-party contracts.", 512),
    ("4-1-3", "4-1", "Third-party and cloud", "Periodic third-party assessments", "Third-party cybersecurity posture must be assessed periodically.", 513),

    ("4-2",   None,  "Third-party and cloud", "Cloud computing and hosting cybersecurity", "Hosting localisation, cloud security, CMK.", 520),
    ("4-2-1", "4-2", "Third-party and cloud", "Hosting localisation", "Hosting and cloud services for sensitive national data must be located inside KSA.", 521),
    ("4-2-2", "4-2", "Third-party and cloud", "Customer-managed encryption keys", "Cryptographic keys for cloud-hosted sensitive data must be customer-managed.", 522),
    ("4-2-3", "4-2", "Third-party and cloud", "Cloud cybersecurity requirements", "Cybersecurity requirements specific to cloud (IAM, monitoring, isolation) must be enforced.", 523),

    # ---- Domain 5: Industrial Control Systems Cybersecurity ----
    ("5-1",   None,  "Industrial control systems", "Industrial control systems protection", "OT segmentation, hardening, monitoring.", 610),
    ("5-1-1", "5-1", "Industrial control systems", "OT/IT segmentation", "OT networks must be logically and physically segmented from corporate IT networks.", 611),
    ("5-1-2", "5-1", "Industrial control systems", "OT access controls", "Physical and logical access to OT systems must be strictly controlled.", 612),
    ("5-1-3", "5-1", "Industrial control systems", "OT secure remote access", "Remote access to OT systems must use dedicated, monitored channels.", 613),
    ("5-1-4", "5-1", "Industrial control systems", "OT monitoring", "OT-specific monitoring must be deployed and integrated with the SOC.", 614),
    ("5-1-5", "5-1", "Industrial control systems", "OT backup and recovery", "OT configurations and engineering data must be backed up and tested for restoration.", 615),
]


# ---------------------------------------------------------------------------
# CSCC-1:2019 — Critical Systems Cybersecurity Controls
# Adds elevated requirements on top of ECC for critical systems.
# ---------------------------------------------------------------------------

NCA_CSCC_CONTROLS: list[tuple] = [
    # ---- Domain 1: Cybersecurity Governance ----
    ("CS-1-1",   None,      "Cybersecurity governance", "Cybersecurity strategy (critical systems)", "Critical-systems cybersecurity strategy aligned with the organisation's overall strategy.", 110),
    ("CS-1-1-1", "CS-1-1",  "Cybersecurity governance", "Critical-systems strategy approved", "A critical-systems cybersecurity strategy must be defined and approved.", 111),

    ("CS-1-2",   None,      "Cybersecurity governance", "Cybersecurity policies and procedures (critical systems)", "Dedicated policies for critical systems.", 120),
    ("CS-1-2-1", "CS-1-2",  "Cybersecurity governance", "Critical-systems cybersecurity policy", "Cybersecurity policies for critical systems must be documented, approved and enforced.", 121),

    ("CS-1-3",   None,      "Cybersecurity governance", "Risk management for critical systems", "Risk assessment and treatment for critical systems.", 130),
    ("CS-1-3-1", "CS-1-3",  "Cybersecurity governance", "Critical-systems risk assessment", "Cybersecurity risks of critical systems must be assessed at least annually.", 131),

    # ---- Domain 2: Cybersecurity Defence (the bulk of CSCC) ----
    ("CS-2-1",   None,      "Cybersecurity defence", "Asset management (critical systems)", "Asset inventory and dependencies for critical systems.", 210),
    ("CS-2-1-1", "CS-2-1",  "Cybersecurity defence", "Critical asset register", "A dedicated register of critical systems and their dependencies must be maintained.", 211),

    ("CS-2-2",   None,      "Cybersecurity defence", "Identity and access management (critical systems)", "MFA, PAM, restrictive privileges, JIT access.", 220),
    ("CS-2-2-1", "CS-2-2",  "Cybersecurity defence", "MFA for all critical-system access", "MFA must be enforced for all access to critical systems, not only privileged.", 221),
    ("CS-2-2-2", "CS-2-2",  "Cybersecurity defence", "Privileged access management", "A PAM solution must broker and record all privileged sessions on critical systems.", 222),
    ("CS-2-2-3", "CS-2-2",  "Cybersecurity defence", "Just-in-time admin access", "Standing administrative privileges on critical systems must be eliminated where feasible (just-in-time access).", 223),
    ("CS-2-2-4", "CS-2-2",  "Cybersecurity defence", "Quarterly access reviews", "Access rights to critical systems must be reviewed at least quarterly.", 224),

    ("CS-2-3",   None,      "Cybersecurity defence", "System protection (critical systems)", "Hardening, patching SLAs, EDR.", 230),
    ("CS-2-3-1", "CS-2-3",  "Cybersecurity defence", "Hardening baselines applied", "Critical systems must be hardened per documented baselines and audited.", 231),
    ("CS-2-3-2", "CS-2-3",  "Cybersecurity defence", "Critical-severity patches in 14 days", "Critical security patches must be applied within 14 days of release.", 232),
    ("CS-2-3-3", "CS-2-3",  "Cybersecurity defence", "EDR on all critical endpoints", "EDR/XDR must be deployed on all critical-system endpoints and servers.", 233),

    ("CS-2-4",   None,      "Cybersecurity defence", "Email protection (critical systems)", "Hardened email controls for critical-system users.", 240),
    ("CS-2-4-1", "CS-2-4",  "Cybersecurity defence", "Hardened email filtering", "Advanced anti-phishing (sandboxing, link rewriting) must be enabled.", 241),

    ("CS-2-5",   None,      "Cybersecurity defence", "Network security (critical systems)", "Strict segmentation, jump hosts, monitored egress.", 250),
    ("CS-2-5-1", "CS-2-5",  "Cybersecurity defence", "Hard segmentation", "Critical systems must reside in dedicated network segments with strict ACLs.", 251),
    ("CS-2-5-2", "CS-2-5",  "Cybersecurity defence", "Jump hosts for admin", "Administrative access to critical systems must traverse hardened jump hosts.", 252),
    ("CS-2-5-3", "CS-2-5",  "Cybersecurity defence", "Egress monitoring", "Egress traffic from critical-system segments must be inspected and monitored.", 253),
    ("CS-2-5-4", "CS-2-5",  "Cybersecurity defence", "DDoS protection", "Internet-facing critical systems must be protected by DDoS mitigation services.", 254),

    ("CS-2-6",   None,      "Cybersecurity defence", "Data protection (critical systems)", "Encryption, DLP, classification.", 260),
    ("CS-2-6-1", "CS-2-6",  "Cybersecurity defence", "Encryption in transit and at rest", "All critical-system data must be encrypted in transit and at rest.", 261),
    ("CS-2-6-2", "CS-2-6",  "Cybersecurity defence", "Strict DLP", "DLP must be enforced on egress paths from critical systems.", 262),

    ("CS-2-7",   None,      "Cybersecurity defence", "Cryptography (critical systems)", "Strong, approved cryptography with KMS.", 270),
    ("CS-2-7-1", "CS-2-7",  "Cybersecurity defence", "Approved cryptography only", "Only NCA-approved algorithms and key lengths may be used.", 271),
    ("CS-2-7-2", "CS-2-7",  "Cybersecurity defence", "Hardware-backed key storage", "Keys protecting critical-system data must be stored in HSMs or equivalent.", 272),

    ("CS-2-8",   None,      "Cybersecurity defence", "Backup and recovery (critical systems)", "Tested, offline, geographically distributed backups.", 280),
    ("CS-2-8-1", "CS-2-8",  "Cybersecurity defence", "Offline / air-gapped backups", "Critical-system backups must include offline or immutable copies.", 281),
    ("CS-2-8-2", "CS-2-8",  "Cybersecurity defence", "Monthly restoration tests", "Backup restoration must be tested at least monthly for critical systems.", 282),

    ("CS-2-9",   None,      "Cybersecurity defence", "Vulnerability management (critical systems)", "More frequent scanning + stricter SLAs.", 290),
    ("CS-2-9-1", "CS-2-9",  "Cybersecurity defence", "Monthly vulnerability scans", "Vulnerability scans must run at least monthly on critical systems.", 291),
    ("CS-2-9-2", "CS-2-9",  "Cybersecurity defence", "Active threat-hunting", "Threat-hunting activities must be conducted on critical systems.", 292),

    ("CS-2-10",   None,       "Cybersecurity defence", "Penetration testing (critical systems)", "Twice-yearly red-team / pen-test.", 300),
    ("CS-2-10-1", "CS-2-10",  "Cybersecurity defence", "Semi-annual penetration testing", "Penetration tests of critical systems must be conducted at least twice yearly.", 301),

    ("CS-2-11",   None,       "Cybersecurity defence", "Cybersecurity event logs and monitoring (critical systems)", "24/7 SOC monitoring of critical systems.", 310),
    ("CS-2-11-1", "CS-2-11",  "Cybersecurity defence", "24/7 SOC monitoring", "Cybersecurity event monitoring of critical systems must be performed 24/7.", 311),
    ("CS-2-11-2", "CS-2-11",  "Cybersecurity defence", "Log retention 18+ months", "Cybersecurity event logs from critical systems must be retained for at least 18 months.", 312),

    ("CS-2-12",   None,       "Cybersecurity defence", "Incident response (critical systems)", "Dedicated IR playbooks for critical-system incidents.", 320),
    ("CS-2-12-1", "CS-2-12",  "Cybersecurity defence", "Critical-systems IR playbook", "An IR playbook specific to critical-system incidents must be defined and tested.", 321),
    ("CS-2-12-2", "CS-2-12",  "Cybersecurity defence", "Tabletop exercises", "Critical-systems tabletop exercises must be conducted at least twice yearly.", 322),

    ("CS-2-13",   None,       "Cybersecurity defence", "Web application security (critical systems)", "Hardened web apps + MFA + ASVS.", 330),
    ("CS-2-13-1", "CS-2-13",  "Cybersecurity defence", "Strong WAF on critical web apps", "Critical web applications must be protected by a managed WAF tuned to the application.", 331),
    ("CS-2-13-2", "CS-2-13",  "Cybersecurity defence", "MFA required for users", "User authentication to critical web applications must require MFA.", 332),

    # ---- Domain 3: Cybersecurity Resilience ----
    ("CS-3-1",   None,      "Cybersecurity resilience", "Resilience (critical systems)", "RTO/RPO defined and tested for critical systems.", 410),
    ("CS-3-1-1", "CS-3-1",  "Cybersecurity resilience", "RTO/RPO defined", "Recovery objectives (RTO/RPO) for critical systems must be defined and tested.", 411),
    ("CS-3-1-2", "CS-3-1",  "Cybersecurity resilience", "Ransomware DR scenario", "A ransomware DR scenario for critical systems must be tested annually.", 412),

    # ---- Domain 4: Third-party (critical-system suppliers) ----
    ("CS-4-1",   None,      "Third-party", "Third-party cybersecurity (critical systems)", "Suppliers of critical-system services held to elevated controls.", 510),
    ("CS-4-1-1", "CS-4-1",  "Third-party", "Supplier elevated requirements", "Suppliers that touch critical systems must comply with CSCC equivalents in their environment.", 511),
    ("CS-4-1-2", "CS-4-1",  "Third-party", "Right-to-audit", "Contracts with critical-system suppliers must include cybersecurity right-to-audit clauses.", 512),
]


# ---------------------------------------------------------------------------
# CCC-1:2020 — Cloud Cybersecurity Controls (CSP track)
# ---------------------------------------------------------------------------

NCA_CCC_CSP_CONTROLS: list[tuple] = [
    # ---- Domain 1: Cybersecurity Governance (CSP) ----
    ("CSP-1-1",   None,       "Cybersecurity governance", "Cybersecurity governance (CSP)", "Governance over the cloud platform.", 110),
    ("CSP-1-1-1", "CSP-1-1",  "Cybersecurity governance", "CSP cybersecurity strategy", "CSP must establish a cybersecurity strategy covering its cloud platform.", 111),
    ("CSP-1-1-2", "CSP-1-1",  "Cybersecurity governance", "CSP cybersecurity policies", "Documented policies governing the security of the cloud platform.", 112),

    ("CSP-1-2",   None,       "Cybersecurity governance", "Compliance (CSP)", "Demonstrable compliance via certifications.", 120),
    ("CSP-1-2-1", "CSP-1-2",  "Cybersecurity governance", "Independent assurance", "CSP must demonstrate independent assurance (e.g. ISO 27001, SOC 2) for its platform.", 121),

    # ---- Domain 2: Cybersecurity Defence (CSP) ----
    ("CSP-2-1",   None,       "Cybersecurity defence", "Tenant isolation", "Strong logical and physical isolation between tenants.", 210),
    ("CSP-2-1-1", "CSP-2-1",  "Cybersecurity defence", "Logical isolation", "CSP must enforce strong logical separation between tenants in compute, storage and network.", 211),
    ("CSP-2-1-2", "CSP-2-1",  "Cybersecurity defence", "Hypervisor and control-plane hardening", "Hypervisors and the control plane must be hardened and patched promptly.", 212),

    ("CSP-2-2",   None,       "Cybersecurity defence", "Identity and access management (CSP)", "CSP-side IAM and admin controls.", 220),
    ("CSP-2-2-1", "CSP-2-2",  "Cybersecurity defence", "MFA for all CSP staff", "MFA must be enforced for all CSP staff accessing the platform.", 221),
    ("CSP-2-2-2", "CSP-2-2",  "Cybersecurity defence", "Privileged session recording", "All privileged CSP admin sessions must be brokered and recorded.", 222),
    ("CSP-2-2-3", "CSP-2-2",  "Cybersecurity defence", "Tenant identity options", "CSP must offer tenants strong identity options including MFA and federation.", 223),

    ("CSP-2-3",   None,       "Cybersecurity defence", "Network security (CSP)", "Segmentation, DDoS, firewalls.", 230),
    ("CSP-2-3-1", "CSP-2-3",  "Cybersecurity defence", "DDoS protection for the platform", "CSP must protect the cloud platform against denial-of-service attacks.", 231),
    ("CSP-2-3-2", "CSP-2-3",  "Cybersecurity defence", "Network segmentation services", "CSP must provide tenants with virtual network segmentation primitives.", 232),

    ("CSP-2-4",   None,       "Cybersecurity defence", "Data protection (CSP)", "Encryption, key management, deletion.", 240),
    ("CSP-2-4-1", "CSP-2-4",  "Cybersecurity defence", "Encryption at rest", "Tenant data must be encrypted at rest by default.", 241),
    ("CSP-2-4-2", "CSP-2-4",  "Cybersecurity defence", "Customer-managed keys (CMK)", "CSP must support customer-managed encryption keys (CMK / BYOK / HYOK).", 242),
    ("CSP-2-4-3", "CSP-2-4",  "Cybersecurity defence", "Secure data deletion", "Tenant data must be securely deleted upon request or contract termination.", 243),
    ("CSP-2-4-4", "CSP-2-4",  "Cybersecurity defence", "Data residency in KSA", "Sensitive Saudi-regulated data must remain inside KSA throughout its lifecycle.", 244),

    ("CSP-2-5",   None,       "Cybersecurity defence", "Vulnerability and patch management (CSP)", "Continuous scanning + rapid patching of the platform.", 250),
    ("CSP-2-5-1", "CSP-2-5",  "Cybersecurity defence", "Continuous platform scanning", "CSP must perform continuous vulnerability scanning of the platform.", 251),
    ("CSP-2-5-2", "CSP-2-5",  "Cybersecurity defence", "Critical patching SLA", "Critical vulnerabilities in the platform must be patched within 14 days.", 252),

    ("CSP-2-6",   None,       "Cybersecurity defence", "Logging and monitoring (CSP)", "Platform monitoring and tenant log offering.", 260),
    ("CSP-2-6-1", "CSP-2-6",  "Cybersecurity defence", "Platform monitoring 24/7", "CSP must monitor the cloud platform 24/7 with a SOC.", 261),
    ("CSP-2-6-2", "CSP-2-6",  "Cybersecurity defence", "Tenant log access", "CSP must provide tenants with access to logs relevant to their workloads.", 262),

    ("CSP-2-7",   None,       "Cybersecurity defence", "Incident management (CSP)", "Platform-side IR and tenant notification.", 270),
    ("CSP-2-7-1", "CSP-2-7",  "Cybersecurity defence", "Platform IR plan", "CSP must maintain a documented and tested incident response plan.", 271),
    ("CSP-2-7-2", "CSP-2-7",  "Cybersecurity defence", "Tenant breach notification", "CSP must notify tenants of incidents affecting their data within agreed timelines.", 272),

    # ---- Domain 3: Resilience (CSP) ----
    ("CSP-3-1",   None,       "Cybersecurity resilience", "Resilience (CSP)", "Platform availability and DR.", 410),
    ("CSP-3-1-1", "CSP-3-1",  "Cybersecurity resilience", "Multi-AZ / region availability", "CSP must offer multi-availability-zone deployment for production tenants.", 411),
    ("CSP-3-1-2", "CSP-3-1",  "Cybersecurity resilience", "Platform DR testing", "Platform-level DR procedures must be tested at least annually.", 412),
]


# ---------------------------------------------------------------------------
# CCC-1:2020 — Cloud Cybersecurity Controls (CST / tenant track)
# ---------------------------------------------------------------------------

NCA_CCC_CST_CONTROLS: list[tuple] = [
    # ---- Domain 1: Governance (CST) ----
    ("CST-1-1",   None,       "Cybersecurity governance", "Governance (CST)", "Tenant governance over its cloud usage.", 110),
    ("CST-1-1-1", "CST-1-1",  "Cybersecurity governance", "CSP selection due-diligence", "Tenant must perform documented cybersecurity due-diligence when selecting a CSP.", 111),
    ("CST-1-1-2", "CST-1-1",  "Cybersecurity governance", "Cloud usage policy", "Tenant must define and approve a cloud-usage policy.", 112),

    # ---- Domain 2: Defence (CST) ----
    ("CST-2-1",   None,       "Cybersecurity defence", "Tenant identity and access (CST)", "Identity, MFA, federation, least privilege.", 210),
    ("CST-2-1-1", "CST-2-1",  "Cybersecurity defence", "MFA for tenant admins", "MFA must be enforced for all tenant administrative accounts in the cloud.", 211),
    ("CST-2-1-2", "CST-2-1",  "Cybersecurity defence", "Federated identity preferred", "Tenant access to the cloud should use federated identity from the corporate IdP.", 212),
    ("CST-2-1-3", "CST-2-1",  "Cybersecurity defence", "Conditional access policies", "Risk-based conditional access policies must be configured for cloud access.", 213),
    ("CST-2-1-4", "CST-2-1",  "Cybersecurity defence", "Periodic role reviews", "Cloud IAM role assignments must be reviewed periodically and pruned.", 214),

    ("CST-2-2",   None,       "Cybersecurity defence", "Tenant network controls (CST)", "Cloud network segmentation, NSG, secure connectivity.", 220),
    ("CST-2-2-1", "CST-2-2",  "Cybersecurity defence", "Network segmentation in the cloud", "Tenant must use virtual network segmentation and network security groups to isolate workloads.", 221),
    ("CST-2-2-2", "CST-2-2",  "Cybersecurity defence", "Secure connectivity to cloud", "Connectivity from on-prem to cloud must use private/dedicated channels (e.g. ExpressRoute, Direct Connect).", 222),

    ("CST-2-3",   None,       "Cybersecurity defence", "Tenant data protection (CST)", "Encryption, key management, classification.", 230),
    ("CST-2-3-1", "CST-2-3",  "Cybersecurity defence", "Encryption at rest enabled", "Tenant must enable encryption at rest on all cloud-resident data stores.", 231),
    ("CST-2-3-2", "CST-2-3",  "Cybersecurity defence", "Customer-managed keys", "Tenant must use customer-managed keys for sensitive data classes.", 232),
    ("CST-2-3-3", "CST-2-3",  "Cybersecurity defence", "Data classification in cloud", "Cloud-resident data must be classified per the tenant's classification scheme.", 233),
    ("CST-2-3-4", "CST-2-3",  "Cybersecurity defence", "Public-access reviews", "Tenant must continuously scan for and remediate unintended public exposure of cloud resources.", 234),

    ("CST-2-4",   None,       "Cybersecurity defence", "Tenant configuration management (CST)", "CSPM, hardening baselines, drift detection.", 240),
    ("CST-2-4-1", "CST-2-4",  "Cybersecurity defence", "CSPM deployed", "Tenant must continuously evaluate its cloud configuration against benchmark baselines (CIS / CSP-published).", 241),
    ("CST-2-4-2", "CST-2-4",  "Cybersecurity defence", "Drift detection", "Configuration drift from approved baselines must be detected and remediated.", 242),

    ("CST-2-5",   None,       "Cybersecurity defence", "Tenant monitoring (CST)", "Cloud event logs, alerting, integration with SIEM.", 250),
    ("CST-2-5-1", "CST-2-5",  "Cybersecurity defence", "Activate cloud audit logs", "Tenant must enable management-plane and data-plane audit logging.", 251),
    ("CST-2-5-2", "CST-2-5",  "Cybersecurity defence", "Cloud logs forwarded to SIEM", "Cloud audit and security logs must be forwarded to the central SIEM.", 252),
    ("CST-2-5-3", "CST-2-5",  "Cybersecurity defence", "Cloud detection use-cases", "Cloud-specific detection use-cases (impossible travel, suspicious API calls) must be developed.", 253),

    ("CST-2-6",   None,       "Cybersecurity defence", "Vulnerability and patching (CST)", "Tenant patching of its workloads.", 260),
    ("CST-2-6-1", "CST-2-6",  "Cybersecurity defence", "Patch cloud workloads", "Tenant must patch its IaaS/PaaS workloads on the same SLA as on-prem critical systems.", 261),
    ("CST-2-6-2", "CST-2-6",  "Cybersecurity defence", "Container/image scanning", "Container and VM images used in the cloud must be scanned before deployment.", 262),

    # ---- Domain 3: Resilience (CST) ----
    ("CST-3-1",   None,       "Cybersecurity resilience", "Tenant resilience (CST)", "Tenant-side backup, multi-AZ, DR testing.", 410),
    ("CST-3-1-1", "CST-3-1",  "Cybersecurity resilience", "Tenant backups in the cloud", "Critical cloud-resident data must be backed up and tested for restoration.", 411),
    ("CST-3-1-2", "CST-3-1",  "Cybersecurity resilience", "Multi-AZ for critical workloads", "Critical tenant workloads should be deployed across multiple availability zones.", 412),
]


# ---------------------------------------------------------------------------
# OTCC-1:2022 — Operational Technology Cybersecurity Controls
# ---------------------------------------------------------------------------

NCA_OTCC_CONTROLS: list[tuple] = [
    # ---- Domain 1: Governance ----
    ("OT-1-1",   None,      "Cybersecurity governance", "OT cybersecurity governance", "Governance over OT/IACS security.", 110),
    ("OT-1-1-1", "OT-1-1",  "Cybersecurity governance", "OT cybersecurity policy", "An OT-specific cybersecurity policy must be defined and approved.", 111),
    ("OT-1-1-2", "OT-1-1",  "Cybersecurity governance", "OT risk management", "OT cybersecurity risks must be assessed using an OT-aware methodology (e.g. IEC 62443 risk).", 112),
    ("OT-1-1-3", "OT-1-1",  "Cybersecurity governance", "OT cybersecurity roles", "OT cybersecurity roles and responsibilities (IT/OT/engineering) must be defined.", 113),

    ("OT-1-2",   None,      "Cybersecurity governance", "OT human resources and training", "Awareness and OT-specific skills.", 120),
    ("OT-1-2-1", "OT-1-2",  "Cybersecurity governance", "OT awareness training", "Engineers and operators must receive OT cybersecurity awareness training.", 121),
    ("OT-1-2-2", "OT-1-2",  "Cybersecurity governance", "OT specialised training", "OT cybersecurity staff must receive specialised training on the deployed OT stack.", 122),

    # ---- Domain 2: Defence (the bulk of OTCC) ----
    ("OT-2-1",   None,      "Cybersecurity defence", "OT asset management", "Inventory of OT assets and dependencies.", 210),
    ("OT-2-1-1", "OT-2-1",  "Cybersecurity defence", "OT asset inventory", "An accurate inventory of OT assets (PLCs, RTUs, HMIs, engineering workstations) must be maintained.", 211),
    ("OT-2-1-2", "OT-2-1",  "Cybersecurity defence", "OT asset classification", "OT assets must be classified by criticality, safety impact and data sensitivity.", 212),

    ("OT-2-2",   None,      "Cybersecurity defence", "OT identity and access", "Account control on OT/engineering systems.", 220),
    ("OT-2-2-1", "OT-2-2",  "Cybersecurity defence", "No shared accounts on OT", "Shared accounts on OT systems must be eliminated; where unavoidable, sessions must be recorded.", 221),
    ("OT-2-2-2", "OT-2-2",  "Cybersecurity defence", "MFA for OT remote access", "MFA must be enforced for remote access to OT environments.", 222),
    ("OT-2-2-3", "OT-2-2",  "Cybersecurity defence", "Privileged engineering access", "Engineering workstations and project files must be access-controlled and audited.", 223),

    ("OT-2-3",   None,      "Cybersecurity defence", "OT system protection", "Hardening, anti-malware, USB controls.", 230),
    ("OT-2-3-1", "OT-2-3",  "Cybersecurity defence", "OT hardening baselines", "OT systems must be hardened in line with vendor baselines and the organisation's security standards.", 231),
    ("OT-2-3-2", "OT-2-3",  "Cybersecurity defence", "OT-suitable anti-malware", "Anti-malware suitable for OT (allow-listing, low CPU) must be deployed where supported.", 232),
    ("OT-2-3-3", "OT-2-3",  "Cybersecurity defence", "Removable media controls", "Removable media use in OT must be tightly controlled and scanned at sanctioned kiosks.", 233),
    ("OT-2-3-4", "OT-2-3",  "Cybersecurity defence", "OT patch management", "OT patching must follow a risk-based process aligned with vendor support and operational windows.", 234),

    ("OT-2-4",   None,      "Cybersecurity defence", "OT network security", "Zones/conduits, segmentation, monitored ingress.", 240),
    ("OT-2-4-1", "OT-2-4",  "Cybersecurity defence", "OT zone/conduit segmentation", "OT networks must implement zones and conduits per IEC 62443 with strict ACLs.", 241),
    ("OT-2-4-2", "OT-2-4",  "Cybersecurity defence", "OT/IT DMZ", "All OT/IT traffic must traverse an industrial DMZ with brokered data movement.", 242),
    ("OT-2-4-3", "OT-2-4",  "Cybersecurity defence", "Unidirectional gateways", "Highly critical OT zones should use unidirectional/data-diode gateways for outbound data.", 243),
    ("OT-2-4-4", "OT-2-4",  "Cybersecurity defence", "OT secure remote access", "Remote access to OT must use dedicated jump hosts with MFA and session recording.", 244),
    ("OT-2-4-5", "OT-2-4",  "Cybersecurity defence", "Wireless in OT", "Wireless connectivity in OT must be tightly justified, authenticated and monitored.", 245),

    ("OT-2-5",   None,      "Cybersecurity defence", "OT vulnerability management", "Passive discovery + change-controlled remediation.", 250),
    ("OT-2-5-1", "OT-2-5",  "Cybersecurity defence", "Passive OT vulnerability discovery", "Passive OT vulnerability and asset discovery must be performed (active scans only with change control).", 251),
    ("OT-2-5-2", "OT-2-5",  "Cybersecurity defence", "OT remediation plans", "OT vulnerability remediation plans must be defined with compensating controls when patching is deferred.", 252),

    ("OT-2-6",   None,      "Cybersecurity defence", "OT event logging and monitoring", "OT-aware monitoring integrated with the SOC.", 260),
    ("OT-2-6-1", "OT-2-6",  "Cybersecurity defence", "OT logging activated", "Cybersecurity event logging must be activated on OT systems where supported.", 261),
    ("OT-2-6-2", "OT-2-6",  "Cybersecurity defence", "OT-aware monitoring", "OT-aware monitoring (network behaviour, protocol anomaly) must be deployed.", 262),
    ("OT-2-6-3", "OT-2-6",  "Cybersecurity defence", "SOC integration", "OT monitoring telemetry must be integrated with the enterprise SOC.", 263),
    ("OT-2-6-4", "OT-2-6",  "Cybersecurity defence", "OT detection use-cases", "OT-specific detection use-cases (firmware change, unauthorised PLC programming) must be developed.", 264),

    ("OT-2-7",   None,      "Cybersecurity defence", "OT incident response", "OT-specific IR with safety considerations.", 270),
    ("OT-2-7-1", "OT-2-7",  "Cybersecurity defence", "OT IR playbook", "An OT-specific IR playbook (including safety) must be defined and tested.", 271),
    ("OT-2-7-2", "OT-2-7",  "Cybersecurity defence", "OT tabletop exercises", "OT tabletop / hybrid exercises must be conducted at planned intervals.", 272),

    ("OT-2-8",   None,      "Cybersecurity defence", "OT physical security", "Physical protection of OT facilities and field assets.", 280),
    ("OT-2-8-1", "OT-2-8",  "Cybersecurity defence", "OT physical access controls", "Physical access to OT facilities and field assets must be restricted, logged and monitored.", 281),

    # ---- Domain 3: Resilience ----
    ("OT-3-1",   None,      "Cybersecurity resilience", "OT resilience", "OT backup, recovery, safe-state operations.", 410),
    ("OT-3-1-1", "OT-3-1",  "Cybersecurity resilience", "OT configuration backups", "Engineering configurations, logic and project files must be backed up and verified.", 411),
    ("OT-3-1-2", "OT-3-1",  "Cybersecurity resilience", "Safe-state operations", "Safe-state operating procedures must be defined and tested for cybersecurity events.", 412),

    # ---- Domain 4: Third-party (OT integrators/vendors) ----
    ("OT-4-1",   None,      "Third-party", "OT third-party cybersecurity", "Vendors and integrators of OT systems.", 510),
    ("OT-4-1-1", "OT-4-1",  "Third-party", "OT vendor cybersecurity requirements", "Cybersecurity requirements for OT vendors and system integrators must be defined and enforced contractually.", 511),
    ("OT-4-1-2", "OT-4-1",  "Third-party", "OT vendor remote access controls", "OT vendor remote access must use dedicated channels with MFA, time-boxed and session-recorded.", 512),
]


# ---------------------------------------------------------------------------
# Technique mappings (framework_key, control_id, technique_id, rationale)
# ---------------------------------------------------------------------------

NCA_TECHNIQUE_MAPPINGS: list[tuple[str, str, str, str]] = [
    # ====================================================================
    # ECC-2:2024
    # ====================================================================
    # Domain 1: governance / training — only the awareness subdomain maps to TTPs
    ("nca_ecc", "1-9-1",  "T1078",     "Pre-employment screening reduces insider misuse of valid accounts"),
    ("nca_ecc", "1-10-1", "T1566",     "Awareness reduces phishing success"),
    ("nca_ecc", "1-10-1", "T1566.001", "Awareness reduces spearphishing attachment success"),
    ("nca_ecc", "1-10-1", "T1566.002", "Awareness reduces spearphishing link success"),
    ("nca_ecc", "1-10-1", "T1204",     "Awareness reduces user execution of malicious payloads"),
    ("nca_ecc", "1-10-1", "T1534",     "Awareness reduces internal spearphishing success"),
    # 2-1 Asset management
    ("nca_ecc", "2-1-1",  "T1018",     "Asset inventory reduces blind spots for remote system discovery"),
    ("nca_ecc", "2-1-1",  "T1133",     "Inventory surfaces forgotten external remote services"),
    ("nca_ecc", "2-1-3",  "T1204.002", "Acceptable-use restrictions reduce user-launched malicious files"),
    # 2-2 IAM
    ("nca_ecc", "2-2-1",  "T1078",     "Unique IDs deny shared-account abuse"),
    ("nca_ecc", "2-2-2",  "T1078",     "MFA on privileged + remote accounts blocks valid-account abuse"),
    ("nca_ecc", "2-2-2",  "T1078.004", "MFA for cloud accounts"),
    ("nca_ecc", "2-2-2",  "T1110",     "MFA defeats brute force"),
    ("nca_ecc", "2-2-2",  "T1110.003", "MFA defeats password spraying"),
    ("nca_ecc", "2-2-2",  "T1110.004", "MFA defeats credential stuffing"),
    ("nca_ecc", "2-2-2",  "T1133",     "MFA on remote services"),
    ("nca_ecc", "2-2-3",  "T1098",     "Least privilege bounds account-manipulation impact"),
    ("nca_ecc", "2-2-3",  "T1548",     "Least privilege limits privilege-escalation surface"),
    ("nca_ecc", "2-2-4",  "T1078",     "Periodic reviews surface stale valid-account access"),
    ("nca_ecc", "2-2-5",  "T1136",     "Lifecycle process detects unsanctioned account creation"),
    # 2-3 System protection
    ("nca_ecc", "2-3-1",  "T1543",     "Hardening blocks unsanctioned persistence mechanisms"),
    ("nca_ecc", "2-3-1",  "T1547",     "Hardening locks down autostart locations"),
    ("nca_ecc", "2-3-2",  "T1190",     "Patching closes exploit-of-public-application surface"),
    ("nca_ecc", "2-3-2",  "T1210",     "Patching closes lateral-exploit surface"),
    ("nca_ecc", "2-3-2",  "T1068",     "Patching closes local privilege-escalation vulns"),
    ("nca_ecc", "2-3-3",  "T1059",     "EDR catches scripting-interpreter abuse"),
    ("nca_ecc", "2-3-3",  "T1204",     "EDR / AV catches user-launched malware"),
    ("nca_ecc", "2-3-4",  "T1091",     "Removable-media controls defeat replication through removable media"),
    ("nca_ecc", "2-3-4",  "T1052",     "Removable-media controls block exfil over physical medium"),
    # 2-4 Email
    ("nca_ecc", "2-4-1",  "T1566",     "Email filtering blocks phishing"),
    ("nca_ecc", "2-4-1",  "T1566.001", "Email filtering catches spearphishing attachments"),
    ("nca_ecc", "2-4-1",  "T1566.002", "Email filtering catches spearphishing links"),
    ("nca_ecc", "2-4-2",  "T1534",     "SPF/DKIM/DMARC defeat brand-spoofing internal spearphishing"),
    ("nca_ecc", "2-4-3",  "T1566",     "Phishing awareness reduces phishing success rate"),
    # 2-5 Network security
    ("nca_ecc", "2-5-1",  "T1021",     "Segmentation limits lateral movement over remote services"),
    ("nca_ecc", "2-5-1",  "T1210",     "Segmentation limits exploitation of remote services"),
    ("nca_ecc", "2-5-2",  "T1071",     "Firewall + IPS catches C2 application-layer traffic"),
    ("nca_ecc", "2-5-2",  "T1041",     "Egress firewall + IPS catches exfil over C2"),
    ("nca_ecc", "2-5-2",  "T1095",     "IPS catches non-application-layer C2 protocols"),
    ("nca_ecc", "2-5-4",  "T1071.001", "Web filtering blocks malicious web-protocol C2"),
    ("nca_ecc", "2-5-4",  "T1189",     "Web filtering blocks drive-by compromise sources"),
    ("nca_ecc", "2-5-5",  "T1133",     "VPN+MFA reduces external-remote-services abuse"),
    ("nca_ecc", "2-5-5",  "T1021",     "Brokered remote access reduces lateral movement abuse"),
    # 2-6 Mobile
    ("nca_ecc", "2-6-1",  "T1422",     "MDM reduces mobile OS info-gathering by attackers"),
    ("nca_ecc", "2-6-2",  "T1456",     "BYOD controls reduce drive-by compromise on mobile"),
    # 2-7 Data
    ("nca_ecc", "2-7-2",  "T1041",     "DLP catches data exfil over C2"),
    ("nca_ecc", "2-7-2",  "T1567",     "DLP catches exfil to web service"),
    ("nca_ecc", "2-7-2",  "T1048",     "DLP catches exfil over alternative protocol"),
    ("nca_ecc", "2-7-3",  "T1485",     "Secure disposal denies attacker access to retired media (data destruction recovery)"),
    ("nca_ecc", "2-7-4",  "T1486",     "Encryption at rest reduces value of bulk data theft / ransomware leverage"),
    # 2-8 Crypto
    ("nca_ecc", "2-8-1",  "T1573",     "Approved cryptography reduces encrypted-channel C2 ambiguity (TLS inspection)"),
    ("nca_ecc", "2-8-1",  "T1552.004", "Key management protects private keys from credential theft"),
    # 2-9 Backups
    ("nca_ecc", "2-9-1",  "T1486",     "Backups enable ransomware recovery"),
    ("nca_ecc", "2-9-3",  "T1490",     "Immutable/offline backups defeat inhibit-system-recovery"),
    ("nca_ecc", "2-9-3",  "T1485",     "Immutable backups defeat data-destruction impact"),
    # 2-10 Vuln mgmt
    ("nca_ecc", "2-10-1", "T1190",     "Vulnerability scans surface exploitable public apps"),
    ("nca_ecc", "2-10-1", "T1068",     "Vuln scans surface local privilege-escalation flaws"),
    ("nca_ecc", "2-10-2", "T1190",     "Remediation SLAs shrink the public-app exploit window"),
    # 2-12 Monitoring (huge fan-out)
    ("nca_ecc", "2-12-1", "T1059",     "Process/script logs detect interpreter abuse"),
    ("nca_ecc", "2-12-1", "T1059.001", "PowerShell script-block logging"),
    ("nca_ecc", "2-12-1", "T1059.003", "Windows command-line logging"),
    ("nca_ecc", "2-12-1", "T1003",     "Logging captures LSASS access for credential dumping"),
    ("nca_ecc", "2-12-2", "T1071",     "SIEM hunts catch C2 application-layer beaconing"),
    ("nca_ecc", "2-12-2", "T1021",     "SIEM hunts catch remote-service-based lateral movement"),
    ("nca_ecc", "2-12-2", "T1078",     "SIEM rules surface anomalous valid-account use"),
    ("nca_ecc", "2-12-3", "T1486",     "Ransomware detection use-cases (mass encryption / VSS deletion)"),
    ("nca_ecc", "2-12-3", "T1490",     "Use-cases for backup-deletion / VSS tampering"),
    ("nca_ecc", "2-12-3", "T1218",     "Behavioural use-cases for signed-binary proxy execution"),
    # 2-13 Incident response
    ("nca_ecc", "2-13-1", "T1486",     "IR plan covers ransomware containment + eradication"),
    ("nca_ecc", "2-13-3", "T1190",     "Threat-intel ingest informs defences against newly exploited apps"),
    ("nca_ecc", "2-13-3", "T1566",     "Threat-intel feeds inform phishing defences"),
    # 2-15 Web app security
    ("nca_ecc", "2-15-1", "T1190",     "WAF blocks exploit attempts on public-facing apps"),
    ("nca_ecc", "2-15-2", "T1190",     "Secure SDLC reduces exploitable public-app vulns at source"),
    ("nca_ecc", "2-15-3", "T1110",     "MFA defeats brute force on web app users"),
    # 3-1 Resilience
    ("nca_ecc", "3-1-2",  "T1486",     "DR scenarios for ransomware ensure tested recovery"),
    ("nca_ecc", "3-1-2",  "T1490",     "DR scenarios for backup-tampering / inhibit-recovery"),
    # 4-2 Cloud
    ("nca_ecc", "4-2-2",  "T1486",     "Customer-managed keys reduce blast radius of cloud-platform breach"),
    ("nca_ecc", "4-2-3",  "T1078.004", "Cloud IAM controls reduce cloud-account abuse"),
    ("nca_ecc", "4-2-3",  "T1538",     "Cloud monitoring detects cloud service-dashboard reconnaissance"),
    # 5-1 ICS
    ("nca_ecc", "5-1-1",  "T1021",     "OT/IT segmentation limits remote-services lateral movement into OT"),
    ("nca_ecc", "5-1-3",  "T1133",     "Controlled OT remote access reduces external-remote-services surface"),
    ("nca_ecc", "5-1-4",  "T1071",     "OT monitoring picks up unexpected protocols indicating C2"),

    # ====================================================================
    # CSCC-1:2019
    # ====================================================================
    ("nca_cscc", "CS-2-2-1", "T1078",     "MFA-for-all on critical systems closes valid-account abuse"),
    ("nca_cscc", "CS-2-2-1", "T1110",     "MFA defeats brute force"),
    ("nca_cscc", "CS-2-2-1", "T1110.003", "MFA defeats password spraying"),
    ("nca_cscc", "CS-2-2-2", "T1078",     "PAM brokers/records all valid-account use on critical systems"),
    ("nca_cscc", "CS-2-2-2", "T1098",     "PAM detects/blocks account-manipulation on privileged accounts"),
    ("nca_cscc", "CS-2-2-3", "T1078",     "JIT access eliminates standing privileges available to compromised accounts"),
    ("nca_cscc", "CS-2-2-4", "T1078",     "Quarterly reviews surface stale valid-account access"),
    ("nca_cscc", "CS-2-3-1", "T1543",     "Hardening blocks unsanctioned persistence on critical systems"),
    ("nca_cscc", "CS-2-3-1", "T1547",     "Hardening locks autostart locations on critical systems"),
    ("nca_cscc", "CS-2-3-2", "T1190",     "Tight patch SLAs shrink the public-app exploit window"),
    ("nca_cscc", "CS-2-3-2", "T1068",     "Tight patch SLAs reduce privilege-escalation exposure"),
    ("nca_cscc", "CS-2-3-3", "T1059",     "EDR/XDR catches scripting-interpreter abuse"),
    ("nca_cscc", "CS-2-3-3", "T1003",     "EDR detects LSASS access for credential dumping"),
    ("nca_cscc", "CS-2-3-3", "T1218",     "EDR catches signed-binary proxy execution"),
    ("nca_cscc", "CS-2-4-1", "T1566.001", "Sandboxing detonates spearphishing attachments before delivery"),
    ("nca_cscc", "CS-2-4-1", "T1566.002", "Link rewriting/sandboxing detects spearphishing links"),
    ("nca_cscc", "CS-2-5-1", "T1021",     "Hard segmentation blocks remote-services lateral movement into critical zones"),
    ("nca_cscc", "CS-2-5-1", "T1210",     "Hard segmentation limits exploitation of remote services"),
    ("nca_cscc", "CS-2-5-2", "T1133",     "Jump hosts reduce external-remote-services surface to critical systems"),
    ("nca_cscc", "CS-2-5-2", "T1021",     "Jump hosts force admin lateral movement through choke point"),
    ("nca_cscc", "CS-2-5-3", "T1041",     "Egress monitoring catches exfil over C2"),
    ("nca_cscc", "CS-2-5-3", "T1071",     "Egress monitoring catches C2 application-layer beaconing"),
    ("nca_cscc", "CS-2-5-4", "T1498",     "DDoS protection mitigates network DoS impact"),
    ("nca_cscc", "CS-2-5-4", "T1499",     "DDoS protection mitigates endpoint DoS impact"),
    ("nca_cscc", "CS-2-6-1", "T1486",     "Encryption at rest reduces ransomware leverage on stolen copies"),
    ("nca_cscc", "CS-2-6-2", "T1041",     "DLP on critical-system egress catches exfil over C2"),
    ("nca_cscc", "CS-2-6-2", "T1567",     "DLP catches exfil to web services from critical systems"),
    ("nca_cscc", "CS-2-7-2", "T1552.004", "HSM-protected keys defeat private-key credential theft"),
    ("nca_cscc", "CS-2-8-1", "T1486",     "Offline/air-gapped backups defeat ransomware impact"),
    ("nca_cscc", "CS-2-8-1", "T1490",     "Offline backups defeat inhibit-system-recovery"),
    ("nca_cscc", "CS-2-9-1", "T1190",     "Monthly scans shrink critical-system public-app exploit window"),
    ("nca_cscc", "CS-2-9-2", "T1078",     "Threat-hunting surfaces low-and-slow valid-account abuse"),
    ("nca_cscc", "CS-2-9-2", "T1059.001", "Threat-hunting surfaces obfuscated PowerShell activity"),
    ("nca_cscc", "CS-2-11-1","T1486",     "24/7 SOC catches ransomware activity in critical systems"),
    ("nca_cscc", "CS-2-11-1","T1003",     "24/7 SOC catches credential dumping on critical systems"),
    ("nca_cscc", "CS-2-11-1","T1071",     "24/7 SOC catches C2 beaconing"),
    ("nca_cscc", "CS-2-12-1","T1486",     "Critical-systems IR playbook covers ransomware containment"),
    ("nca_cscc", "CS-2-13-1","T1190",     "WAF tuned to the critical app blocks targeted exploit attempts"),
    ("nca_cscc", "CS-2-13-2","T1110",     "MFA on critical web apps defeats user brute force"),

    # ====================================================================
    # CCC-1:2020 — CSP
    # ====================================================================
    ("nca_ccc_csp", "CSP-2-1-1", "T1611",     "Strong tenant isolation reduces container/VM escape impact"),
    ("nca_ccc_csp", "CSP-2-1-2", "T1611",     "Hardened hypervisor reduces escape-to-host risk"),
    ("nca_ccc_csp", "CSP-2-1-2", "T1190",     "Patched control plane resists exploit of its public APIs"),
    ("nca_ccc_csp", "CSP-2-2-1", "T1078.004", "MFA for CSP staff blocks cloud-account abuse of platform admins"),
    ("nca_ccc_csp", "CSP-2-2-2", "T1078",     "Recorded admin sessions deter/detect valid-account misuse by CSP staff"),
    ("nca_ccc_csp", "CSP-2-2-3", "T1078.004", "Strong tenant identity offerings (MFA/federation) reduce cloud-account abuse"),
    ("nca_ccc_csp", "CSP-2-3-1", "T1498",     "Platform-level DDoS protection mitigates network DoS"),
    ("nca_ccc_csp", "CSP-2-3-2", "T1021",     "Tenant network segmentation primitives limit lateral movement"),
    ("nca_ccc_csp", "CSP-2-4-1", "T1486",     "Default at-rest encryption reduces ransomware value of stolen blobs"),
    ("nca_ccc_csp", "CSP-2-4-2", "T1552.004", "CMK / BYOK keeps tenant keys out of CSP-recoverable storage"),
    ("nca_ccc_csp", "CSP-2-4-3", "T1485",     "Secure deletion denies attacker access to deleted-but-recoverable tenant data"),
    ("nca_ccc_csp", "CSP-2-5-1", "T1190",     "Continuous scanning surfaces exploit-of-public-app surface on the platform"),
    ("nca_ccc_csp", "CSP-2-5-2", "T1190",     "14-day critical patch SLA shrinks the exploit window"),
    ("nca_ccc_csp", "CSP-2-6-1", "T1078.004", "24/7 platform monitoring catches anomalous cloud-account use"),
    ("nca_ccc_csp", "CSP-2-6-2", "T1078.004", "Giving tenants log access lets them detect their own cloud-account abuse"),
    ("nca_ccc_csp", "CSP-2-7-1", "T1486",     "Platform IR plan ensures coordinated ransomware response"),

    # ====================================================================
    # CCC-1:2020 — CST
    # ====================================================================
    ("nca_ccc_cst", "CST-2-1-1", "T1078.004", "MFA for tenant admins blocks cloud-account abuse"),
    ("nca_ccc_cst", "CST-2-1-1", "T1110",     "MFA defeats brute force on tenant admin accounts"),
    ("nca_ccc_cst", "CST-2-1-2", "T1078.004", "Federated identity centralises detection of cloud-account abuse"),
    ("nca_ccc_cst", "CST-2-1-3", "T1078.004", "Conditional access blocks risky/impossible-travel cloud sign-ins"),
    ("nca_ccc_cst", "CST-2-1-4", "T1098",     "Periodic IAM role reviews surface unauthorised account-manipulation"),
    ("nca_ccc_cst", "CST-2-2-1", "T1021",     "Cloud-network segmentation limits lateral movement into critical workloads"),
    ("nca_ccc_cst", "CST-2-2-2", "T1133",     "Private connectivity reduces external-remote-services exposure to cloud workloads"),
    ("nca_ccc_cst", "CST-2-3-1", "T1486",     "Encryption at rest in cloud reduces ransomware leverage on stolen objects"),
    ("nca_ccc_cst", "CST-2-3-2", "T1552.004", "CMK keeps decryption out of CSP-recoverable storage"),
    ("nca_ccc_cst", "CST-2-3-4", "T1530",     "Continuous public-exposure scanning catches data-from-cloud-storage misconfig"),
    ("nca_ccc_cst", "CST-2-4-1", "T1078.004", "CSPM benchmarks detect IAM-policy / public-bucket misconfigs"),
    ("nca_ccc_cst", "CST-2-4-2", "T1098",     "Drift detection surfaces unauthorised account-manipulation"),
    ("nca_ccc_cst", "CST-2-5-1", "T1078.004", "Cloud audit logs capture cloud-account events"),
    ("nca_ccc_cst", "CST-2-5-2", "T1078",     "Forwarding cloud logs to SIEM enables correlated valid-account detection"),
    ("nca_ccc_cst", "CST-2-5-3", "T1078.004", "Impossible-travel / suspicious-API use-cases catch cloud-account abuse"),
    ("nca_ccc_cst", "CST-2-5-3", "T1538",     "Detection use-cases for cloud service-dashboard reconnaissance"),
    ("nca_ccc_cst", "CST-2-6-1", "T1190",     "Patching cloud workloads on critical SLA shrinks public-app exploit window"),
    ("nca_ccc_cst", "CST-2-6-2", "T1525",     "Image scanning catches implant-image persistence in containers"),

    # ====================================================================
    # OTCC-1:2022 (Enterprise techniques where they apply; ICS techniques marked)
    # ====================================================================
    ("nca_otcc", "OT-1-2-1",  "T1566",     "OT awareness training reduces phishing on engineers"),
    ("nca_otcc", "OT-2-2-1",  "T1078",     "Eliminating shared OT accounts removes valid-account abuse path"),
    ("nca_otcc", "OT-2-2-2",  "T1133",     "MFA on OT remote access reduces external-remote-services abuse"),
    ("nca_otcc", "OT-2-2-3",  "T1078",     "Engineering workstation access controls block valid-account abuse"),
    ("nca_otcc", "OT-2-3-1",  "T1543",     "OT hardening blocks unsanctioned persistence services"),
    ("nca_otcc", "OT-2-3-2",  "T1204",     "OT-suitable anti-malware catches user-launched malware on EWS"),
    ("nca_otcc", "OT-2-3-3",  "T1091",     "Strict USB controls defeat replication through removable media into OT"),
    ("nca_otcc", "OT-2-3-3",  "T1092",     "Sanctioned kiosks reduce communication through removable media"),
    ("nca_otcc", "OT-2-3-4",  "T1190",     "Risk-based OT patching shrinks public-app exploit window where applicable"),
    ("nca_otcc", "OT-2-4-1",  "T1021",     "IEC 62443 zones/conduits limit remote-services lateral movement"),
    ("nca_otcc", "OT-2-4-2",  "T1090",     "Industrial DMZ forces traffic through brokered proxy"),
    ("nca_otcc", "OT-2-4-3",  "T1041",     "Unidirectional gateways defeat exfil-over-C2 from critical OT zones"),
    ("nca_otcc", "OT-2-4-4",  "T1133",     "Brokered OT remote access reduces external-remote-services attack surface"),
    ("nca_otcc", "OT-2-4-5",  "T1011",     "Monitored OT wireless limits exfil over other network medium"),
    ("nca_otcc", "OT-2-6-1",  "T1078",     "OT logging captures valid-account use on EWS"),
    ("nca_otcc", "OT-2-6-2",  "T1046",     "OT-aware monitoring catches unexpected network service scanning"),
    ("nca_otcc", "OT-2-6-2",  "T1071",     "Protocol-anomaly monitoring catches C2 traffic over OT links"),
    ("nca_otcc", "OT-2-6-3",  "T1059",     "Forwarded OT EWS logs feed enterprise SIEM scripting-interpreter detection"),
    ("nca_otcc", "OT-2-6-4",  "T1542",     "OT use-cases for firmware change detection (pre-OS boot)"),
    ("nca_otcc", "OT-2-7-1",  "T1486",     "OT IR playbook covers ransomware reaching OT"),
    ("nca_otcc", "OT-2-7-1",  "T1485",     "OT IR playbook covers data-destruction events in OT"),
    ("nca_otcc", "OT-3-1-1",  "T1485",     "Backed-up engineering configs enable recovery from data-destruction"),
    ("nca_otcc", "OT-3-1-1",  "T1490",     "Backed-up configs defeat inhibit-system-recovery on OT"),
    ("nca_otcc", "OT-4-1-2",  "T1133",     "Vendor remote-access controls reduce external-remote-services abuse via integrators"),
]


# ---------------------------------------------------------------------------
# Mitigation mappings (framework_key, control_id, mitigation_id, rationale)
# ---------------------------------------------------------------------------

NCA_MITIGATION_MAPPINGS: list[tuple[str, str, str, str]] = [
    # ECC-2:2024
    ("nca_ecc", "1-10-1", "M1017", "User Training"),
    ("nca_ecc", "2-2-2",  "M1032", "Multi-factor Authentication"),
    ("nca_ecc", "2-2-3",  "M1018", "User Account Management (least privilege)"),
    ("nca_ecc", "2-2-3",  "M1026", "Privileged Account Management"),
    ("nca_ecc", "2-2-4",  "M1018", "User Account Management (periodic review)"),
    ("nca_ecc", "2-3-1",  "M1042", "Disable or Remove Feature or Program (hardening)"),
    ("nca_ecc", "2-3-2",  "M1051", "Update Software (patching)"),
    ("nca_ecc", "2-3-3",  "M1049", "Antivirus / Antimalware (EDR)"),
    ("nca_ecc", "2-3-4",  "M1034", "Limit Hardware Installation (removable media)"),
    ("nca_ecc", "2-4-1",  "M1031", "Network Intrusion Prevention (email gateway)"),
    ("nca_ecc", "2-4-3",  "M1017", "User Training (phishing awareness)"),
    ("nca_ecc", "2-5-1",  "M1030", "Network Segmentation"),
    ("nca_ecc", "2-5-2",  "M1031", "Network Intrusion Prevention"),
    ("nca_ecc", "2-7-2",  "M1057", "Data Loss Prevention"),
    ("nca_ecc", "2-7-4",  "M1041", "Encrypt Sensitive Information"),
    ("nca_ecc", "2-8-1",  "M1041", "Encrypt Sensitive Information"),
    ("nca_ecc", "2-9-1",  "M1053", "Data Backup"),
    ("nca_ecc", "2-9-3",  "M1053", "Data Backup (immutable)"),
    ("nca_ecc", "2-10-1", "M1016", "Vulnerability Scanning"),
    ("nca_ecc", "2-12-1", "M1047", "Audit (logging)"),
    ("nca_ecc", "2-15-1", "M1050", "Exploit Protection (WAF)"),

    # CSCC
    ("nca_cscc", "CS-2-2-1", "M1032", "MFA on critical systems"),
    ("nca_cscc", "CS-2-2-2", "M1026", "Privileged Account Management"),
    ("nca_cscc", "CS-2-3-3", "M1049", "EDR / Antimalware"),
    ("nca_cscc", "CS-2-5-1", "M1030", "Network Segmentation"),
    ("nca_cscc", "CS-2-5-4", "M1037", "Filter Network Traffic (DDoS)"),
    ("nca_cscc", "CS-2-6-1", "M1041", "Encrypt Sensitive Information"),
    ("nca_cscc", "CS-2-6-2", "M1057", "Data Loss Prevention"),
    ("nca_cscc", "CS-2-8-1", "M1053", "Data Backup (offline/immutable)"),
    ("nca_cscc", "CS-2-9-1", "M1016", "Vulnerability Scanning"),
    ("nca_cscc", "CS-2-11-1","M1047", "Audit (24/7 monitoring)"),

    # CCC CSP
    ("nca_ccc_csp", "CSP-2-2-1", "M1032", "MFA for CSP staff"),
    ("nca_ccc_csp", "CSP-2-3-1", "M1037", "Filter Network Traffic (DDoS)"),
    ("nca_ccc_csp", "CSP-2-4-1", "M1041", "Encrypt Sensitive Information"),
    ("nca_ccc_csp", "CSP-2-6-1", "M1047", "Audit (24/7 platform monitoring)"),

    # CCC CST
    ("nca_ccc_cst", "CST-2-1-1", "M1032", "MFA for tenant admins"),
    ("nca_ccc_cst", "CST-2-1-3", "M1036", "Account Use Policies (conditional access)"),
    ("nca_ccc_cst", "CST-2-2-1", "M1030", "Network Segmentation"),
    ("nca_ccc_cst", "CST-2-3-1", "M1041", "Encrypt Sensitive Information"),
    ("nca_ccc_cst", "CST-2-3-4", "M1047", "Audit (public-exposure scanning)"),
    ("nca_ccc_cst", "CST-2-5-1", "M1047", "Audit (cloud audit logs)"),

    # OTCC
    ("nca_otcc", "OT-2-2-2",  "M1032", "MFA on OT remote access"),
    ("nca_otcc", "OT-2-3-2",  "M1049", "Antivirus / Antimalware on EWS"),
    ("nca_otcc", "OT-2-3-3",  "M1034", "Limit Hardware Installation (removable media)"),
    ("nca_otcc", "OT-2-4-1",  "M1030", "Network Segmentation (zones/conduits)"),
    ("nca_otcc", "OT-2-4-2",  "M1030", "Network Segmentation (IDMZ)"),
    ("nca_otcc", "OT-2-4-4",  "M1032", "MFA on OT remote access"),
    ("nca_otcc", "OT-2-6-1",  "M1047", "Audit (OT logging)"),
    ("nca_otcc", "OT-3-1-1",  "M1053", "Data Backup (engineering configs)"),
]


NCA_CONTROLS_BY_FW: dict[str, list[tuple]] = {
    "nca_ecc":     NCA_ECC_CONTROLS,
    "nca_cscc":    NCA_CSCC_CONTROLS,
    "nca_ccc_csp": NCA_CCC_CSP_CONTROLS,
    "nca_ccc_cst": NCA_CCC_CST_CONTROLS,
    "nca_otcc":    NCA_OTCC_CONTROLS,
}


__all__ = [
    "NCA_FRAMEWORKS",
    "NCA_CONTROLS_BY_FW",
    "NCA_TECHNIQUE_MAPPINGS",
    "NCA_MITIGATION_MAPPINGS",
]
