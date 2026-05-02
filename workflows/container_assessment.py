from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="Container Security Assessment",
    aliases=["container", "docker", "container security", "docker security", "image scan"],
    description="Container security: image scanning → runtime analysis → Docker daemon → escape paths → IaC",
    steps=[
        WorkflowStep(tool="trivy",       goal="scan container image {target} for CVEs and secrets",              reason="CVE and secret detection in image layers", priority="high"),
        WorkflowStep(tool="checkov",     goal="Dockerfile and docker-compose security review for {target}",      reason="Privileged containers, exposed sockets, root users"),
        WorkflowStep(tool="nmap",        goal="scan Docker daemon and registry ports at {target}",               reason="Exposed Docker API (2375, 2376, 5000)"),
        WorkflowStep(tool="nuclei",      goal="container exposure template scan of {target}",                    reason="Exposed registries, dashboards, APIs"),
        WorkflowStep(tool="kube-hunter", goal="container orchestration security check at {target}",              reason="Check for container escape paths", condition="if Kubernetes found"),
    ],
)
