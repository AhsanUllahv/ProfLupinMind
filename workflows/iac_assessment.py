from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="Infrastructure as Code Security Assessment",
    aliases=["iac", "terraform", "cloudformation", "ansible", "iac security", "infrastructure code"],
    description="IaC security review: Terraform → CloudFormation → Kubernetes manifests → Dockerfiles → secrets",
    steps=[
        WorkflowStep(tool="checkov",  goal="static security scan of all IaC files at {target}",                 reason="Hundreds of built-in security checks", priority="high"),
        WorkflowStep(tool="trivy",    goal="scan IaC files and images referenced in {target} for misconfigs",   reason="Trivy supports Terraform, Docker, K8s"),
        WorkflowStep(tool="nuclei",   goal="git repository exposure check for {target}",                         reason="Leaked secrets in committed IaC code"),
    ],
)
