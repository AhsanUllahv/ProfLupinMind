from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="Kubernetes Security Assessment",
    aliases=["kubernetes", "k8s", "kube", "container orchestration", "k8s assessment"],
    description="Kubernetes security: cluster discovery → misconfiguration → container escape → RBAC → network policy",
    steps=[
        WorkflowStep(tool="nmap",        goal="scan for exposed Kubernetes API server at {target}",              reason="Find exposed k8s API (6443, 8443, 10250)"),
        WorkflowStep(tool="kube-hunter", goal="penetration test Kubernetes cluster at {target}",                 reason="Active cluster exploitation and misconfiguration", priority="high"),
        WorkflowStep(tool="kube-bench",  goal="CIS Kubernetes benchmark assessment of {target}",                 reason="Node and master component hardening check"),
        WorkflowStep(tool="trivy",       goal="scan all container images in {target} cluster",                   reason="CVEs in running containers"),
        WorkflowStep(tool="checkov",     goal="Kubernetes manifest and Helm chart security scan for {target}",   reason="RBAC, PodSecurityPolicy, network policy"),
        WorkflowStep(tool="nuclei",      goal="Kubernetes exposure template scan of {target}",                   reason="Exposed dashboards, etcd, kubelet API"),
    ],
)
