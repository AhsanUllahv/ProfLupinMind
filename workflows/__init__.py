from workflows.web_pentest        import WORKFLOW as WEB_PENTEST
from workflows.network_recon      import WORKFLOW as NETWORK_RECON
from workflows.ctf_mode           import WORKFLOW as CTF_MODE
from workflows.osint              import WORKFLOW as OSINT
from workflows.api_testing        import WORKFLOW as API_TESTING
from workflows.vuln_assessment    import WORKFLOW as VULN_ASSESSMENT
from workflows.network_pentest    import WORKFLOW as NETWORK_PENTEST
from workflows.binary_exploit     import WORKFLOW as BINARY_EXPLOIT
from workflows.aws_assessment     import WORKFLOW as AWS_ASSESSMENT
from workflows.kubernetes_assessment import WORKFLOW as KUBERNETES_ASSESSMENT
from workflows.container_assessment  import WORKFLOW as CONTAINER_ASSESSMENT
from workflows.iac_assessment     import WORKFLOW as IAC_ASSESSMENT
from workflows.comprehensive      import WORKFLOW as COMPREHENSIVE

ALL_WORKFLOWS = [
    WEB_PENTEST,
    NETWORK_RECON,
    CTF_MODE,
    OSINT,
    API_TESTING,
    VULN_ASSESSMENT,
    NETWORK_PENTEST,
    BINARY_EXPLOIT,
    AWS_ASSESSMENT,
    KUBERNETES_ASSESSMENT,
    CONTAINER_ASSESSMENT,
    IAC_ASSESSMENT,
    COMPREHENSIVE,
]


def find_workflow(user_input: str):
    text = user_input.lower().strip()
    for wf in ALL_WORKFLOWS:
        if any(alias in text for alias in wf.aliases):
            return wf
    return None


def list_workflows() -> str:
    lines = []
    for i, wf in enumerate(ALL_WORKFLOWS, 1):
        lines.append(f"  {i:2}. {wf.name} — {wf.description[:70]}")
        lines.append(f"      Keywords: {', '.join(wf.aliases[:4])}")
    return "\n".join(lines)
