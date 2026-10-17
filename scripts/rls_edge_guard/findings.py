from __future__ import annotations

from dataclasses import dataclass

BLOCK, WARN = "block", "warn"


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    fix: str = ""

    def format(self, root: str = "") -> str:
        path = self.file
        if root and path.startswith(root.rstrip("/") + "/"):
            path = path[len(root.rstrip("/")) + 1:]
        text = f"{path}:{self.line}  {self.rule} [{self.severity}] {self.message}"
        if self.fix:
            text += f"\n    fix: {self.fix}"
        return text


def render(findings: list, root: str = "") -> str:
    order = sorted(findings, key=lambda f: (f.severity != BLOCK, f.file, f.line, f.rule))
    return "\n".join(f.format(root) for f in order)
