from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="Network Reconnaissance",
    aliases=["network", "recon", "network recon", "full recon", "scan network", "host discovery"],
    description="Comprehensive network recon: port scan → service enum → SMB → SNMP → web surfaces",
    steps=[
        WorkflowStep(
            tool="nmap",
            goal="scan {target} for all open ports, running services, versions, and OS fingerprint",
            reason="Full port and service scan is the foundation of every engagement",
            condition="always",
        ),
        WorkflowStep(
            tool="whatweb",
            goal="identify web technologies and server info on {target}",
            reason="Web fingerprinting on discovered HTTP services",
            condition="if port 80 open",
        ),
        WorkflowStep(
            tool="nikto",
            goal="scan {target} web server for vulnerabilities and misconfigurations",
            reason="Web vulnerability scan on discovered HTTP service",
            condition="if port 80 open",
        ),
        WorkflowStep(
            tool="enum4linux",
            goal="enumerate SMB shares, users, groups, and OS info on {target}",
            reason="SMB often leaks critical Windows environment information",
            condition="if SMB found",
        ),
        WorkflowStep(
            tool="smbmap",
            goal="map all accessible SMB shares and permissions on {target}",
            reason="Find readable/writable shares that can be leveraged",
            condition="if SMB found",
        ),
        WorkflowStep(
            tool="snmpwalk",
            goal="enumerate SNMP OIDs on {target} using community string public",
            reason="Default SNMP community strings expose device configs and routing tables",
            condition="if port 161 open",
        ),
        WorkflowStep(
            tool="nbtscan",
            goal="scan the subnet around {target} for NetBIOS names and MAC addresses",
            reason="Discovers additional Windows hosts not found by initial scan",
            condition="always",
        ),
    ],
)
