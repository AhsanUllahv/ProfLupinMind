from workflows.base import Workflow, WorkflowStep

WORKFLOW = Workflow(
    name="API Security Testing",
    aliases=["api", "api testing", "rest api", "graphql", "api security"],
    description="REST/GraphQL API security: endpoint discovery → parameter fuzzing → injection → auth testing",
    steps=[
        WorkflowStep(tool="httpx",          goal="fingerprint API at {target} — status codes, headers, tech stack",    reason="Understand API structure before testing"),
        WorkflowStep(tool="arjun",          goal="discover hidden parameters on {target} API endpoints",                reason="Parameter pollution and injection entry points"),
        WorkflowStep(tool="ffuf",           goal="fuzz API endpoints at {target} for hidden routes",                    reason="Undocumented endpoints are often unsecured"),
        WorkflowStep(tool="sqlmap",         goal="SQL injection test on {target} API parameters",                       reason="APIs often skip input validation", condition="if parameters found"),
        WorkflowStep(tool="jwt-analyzer",   goal="analyse and attack JWT tokens from {target}",                         reason="JWT misconfiguration is common in APIs",  condition="if JWT found"),
        WorkflowStep(tool="nuclei",         goal="API vulnerability template scan on {target}",                         reason="CVE and misconfiguration matching", priority="high"),
        WorkflowStep(tool="graphql-scanner",goal="GraphQL introspection and injection on {target}",                     reason="GraphQL often exposes full schema",          condition="if GraphQL detected"),
    ],
)
