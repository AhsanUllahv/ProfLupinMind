from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="Comprehensive Pentest",
    aliases=["comprehensive", "full pentest", "full", "everything", "complete", "all"],
    description="Full end-to-end penetration test: recon → scanning → enumeration → exploitation → post-exploitation",
    steps=[
        WorkflowStep(tool="subfinder",   goal="enumerate all subdomains for {target}",                            reason="Expand attack surface before scanning"),
        WorkflowStep(tool="httpx",       goal="probe all discovered assets of {target}",                          reason="Identify live hosts and services"),
        WorkflowStep(tool="nmap",        goal="full port and service scan of {target}",                           reason="Discover all open ports and service versions"),
        WorkflowStep(tool="whatweb",     goal="fingerprint web technologies on {target}",                         reason="CMS and framework detection for targeted testing", condition="if HTTP found"),
        WorkflowStep(tool="wafw00f",     goal="detect WAF protecting {target}",                                   reason="Adapt payloads to bypass WAF",                   condition="if HTTP found"),
        WorkflowStep(tool="nuclei",      goal="comprehensive CVE and misconfiguration scan of {target}",          reason="Fast automated vulnerability detection", priority="high"),
        WorkflowStep(tool="nikto",       goal="web vulnerability scan of {target}",                              reason="Common misconfigurations and low-hanging fruit",  condition="if HTTP found"),
        WorkflowStep(tool="gobuster",    goal="directory and file discovery on {target}",                         reason="Hidden content and attack surface",               condition="if HTTP found"),
        WorkflowStep(tool="sqlmap",      goal="SQL injection testing on {target}",                                reason="Critical injection vulnerabilities",              condition="if forms found"),
        WorkflowStep(tool="enum4linux",  goal="Windows/SMB enumeration of {target}",                             reason="Users, shares, domain info",                     condition="if SMB found"),
        WorkflowStep(tool="hydra",       goal="credential testing on login services at {target}",                 reason="Weak password discovery",                        condition="if login service found"),
        WorkflowStep(tool="searchsploit",goal="search public exploits for {target} services",                     reason="Map services to known exploits"),
    ],
    aggressive=True,
)
