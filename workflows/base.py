from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class WorkflowStep:
    tool: str
    goal: str                    # natural language goal passed to brain for command generation
    reason: str                  # shown to user explaining why this step
    condition: str = "always"    # "always" or a trigger description
    priority: str = "high"       # high | medium | low


@dataclass
class Workflow:
    name: str
    aliases: List[str]           # keywords user can type to select this workflow
    description: str
    steps: List[WorkflowStep]
    aggressive: bool = False     # True = includes exploitation steps

    def format_goal(self, step: WorkflowStep, target: str) -> str:
        return step.goal.replace("{target}", target)
