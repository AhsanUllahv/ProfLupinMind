from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="CTF Mode",
    aliases=["ctf", "capture the flag", "ctf mode", "ctf recon"],
    description="Fast CTF workflow: aggressive recon → all services → web fuzzing → common CTF techniques",
    steps=[
        WorkflowStep(
            tool="rustscan",
            goal="fast scan all 65535 ports on {target} and pass results to nmap for service detection",
            reason="Rustscan is fastest for CTF — finds all ports quickly",
            condition="always",
        ),
        WorkflowStep(
            tool="gobuster",
            goal="aggressively brute force directories and files on {target} using a large CTF wordlist",
            reason="CTF flags are often hidden in non-obvious web paths",
            condition="if port 80 open",
        ),
        WorkflowStep(
            tool="ffuf",
            goal="fuzz for hidden files with common CTF extensions (.txt, .bak, .zip, .old) on {target}",
            reason="Backup files and source leaks are common in CTF web challenges",
            condition="if port 80 open",
        ),
        WorkflowStep(
            tool="enum4linux",
            goal="enumerate all SMB info, shares, and users on {target}",
            reason="CTF boxes often have SMB with flag files or user creds",
            condition="if SMB found",
        ),
        WorkflowStep(
            tool="nikto",
            goal="scan {target} for web vulnerabilities and exposed sensitive files",
            reason="Quick check for common web misconfigs in CTF boxes",
            condition="if port 80 open",
        ),
        WorkflowStep(
            tool="wpscan",
            goal="enumerate WordPress users, plugins, and vulnerabilities on {target}",
            reason="WordPress CTF boxes often have exploitable plugins or weak creds",
            condition="if WordPress detected",
        ),
        WorkflowStep(
            tool="hydra",
            goal="brute force SSH login on {target} using top CTF credentials",
            reason="Default and weak credentials are common in CTF boxes",
            condition="if port 22 open",
            priority="medium",
        ),
    ],
)
