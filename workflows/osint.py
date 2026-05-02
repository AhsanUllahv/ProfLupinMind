from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="OSINT Gathering",
    aliases=["osint", "passive recon", "domain recon", "passive", "intelligence gathering"],
    description="Passive OSINT: subdomain discovery → DNS enumeration → email harvesting → web fingerprinting",
    steps=[
        WorkflowStep(
            tool="whois",
            goal="look up registration info, registrar, contacts, and nameservers for {target}",
            reason="WHOIS reveals ownership, contacts, and infrastructure details",
            condition="always",
        ),
        WorkflowStep(
            tool="subfinder",
            goal="passively discover all subdomains of {target} using public sources",
            reason="Subdomain enumeration expands the attack surface dramatically",
            condition="always",
        ),
        WorkflowStep(
            tool="amass",
            goal="perform deep subdomain enumeration and DNS mapping for {target}",
            reason="Amass uses more sources than subfinder for thorough coverage",
            condition="always",
        ),
        WorkflowStep(
            tool="dnsenum",
            goal="enumerate DNS records, zone transfers, and subdomains for {target}",
            reason="DNS records reveal infrastructure, MX servers, and internal naming",
            condition="always",
        ),
        WorkflowStep(
            tool="theHarvester",
            goal="harvest emails, subdomains, IPs, and employee names for {target} from all public sources",
            reason="Email addresses and employee names are valuable for phishing and credential stuffing",
            condition="always",
        ),
        WorkflowStep(
            tool="whatweb",
            goal="fingerprint web technologies, CMS, and third-party services on {target}",
            reason="Technology stack reveals vulnerabilities and attack vectors",
            condition="always",
        ),
        WorkflowStep(
            tool="wafw00f",
            goal="detect and identify any WAF protecting {target}",
            reason="WAF detection informs bypass strategies for later testing",
            condition="always",
        ),
    ],
)
