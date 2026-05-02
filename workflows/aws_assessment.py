from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="AWS Cloud Security Assessment",
    aliases=["aws", "amazon", "cloud aws", "aws assessment", "s3 scan"],
    description="AWS security assessment: asset discovery → misconfiguration → IAM → S3 → compute → CIS benchmark",
    steps=[
        WorkflowStep(tool="subfinder",  goal="enumerate all subdomains and cloud assets for {target}",            reason="Discover full AWS attack surface"),
        WorkflowStep(tool="httpx",      goal="probe live cloud assets for {target}",                              reason="Identify active cloud services"),
        WorkflowStep(tool="nuclei",     goal="AWS misconfiguration scan of {target}",                             reason="S3 public buckets, exposed APIs, IMDSv1", priority="high"),
        WorkflowStep(tool="prowler",    goal="CIS AWS benchmark assessment for {target}",                         reason="Comprehensive AWS security posture check"),
        WorkflowStep(tool="checkov",    goal="IaC security scan of {target} Terraform/CloudFormation",           reason="Infrastructure code vulnerabilities"),
        WorkflowStep(tool="trivy",      goal="container and ECR image scan for {target}",                         reason="CVEs in deployed containers"),
    ],
)
