from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="Vulnerability Assessment",
    aliases=["vuln", "vulnerability assessment", "va", "vulnerability scan", "assess"],
    description="Comprehensive vulnerability assessment: port scan → service enum → CVE matching → web scanning",
    steps=[
        WorkflowStep(tool="nmap",      goal="full port and service version scan of {target}",              reason="Foundation of any vulnerability assessment"),
        WorkflowStep(tool="nuclei",    goal="CVE and misconfiguration template scan of {target}",          reason="Fast automated CVE detection", priority="high"),
        WorkflowStep(tool="nikto",     goal="web vulnerability scan of {target}",                          reason="Common web misconfigurations",                  condition="if HTTP found"),
        WorkflowStep(tool="smbmap",    goal="SMB share enumeration and vulnerability check on {target}",   reason="SMB is a high-value attack surface",            condition="if SMB found"),
        WorkflowStep(tool="enum4linux",goal="Windows/Samba enumeration of {target}",                      reason="User and share enumeration",                   condition="if SMB found"),
        WorkflowStep(tool="searchsploit", goal="search for known exploits matching services on {target}",  reason="Map discovered services to public exploits"),
        WorkflowStep(tool="wpscan",    goal="WordPress vulnerability assessment of {target}",              reason="WordPress-specific CVEs",                      condition="if WordPress detected"),
    ],
)
