from fastapi import FastAPI, Request
import re

app = FastAPI()

@app.post("/release-gate")
async def release_gate(req: Request):
    data = await req.json()
    violations = []

    target = data.get("target")
    event = data.get("event")
    ref = data.get("ref")
    workflow = data.get("workflow", {})
    image = data.get("image", {})

    # 1. Permissions check
    perms = workflow.get("permissions", {})
    if (
        len(perms) != 3
        or perms.get("contents") != "read"
        or perms.get("packages") != "write"
        or perms.get("id-token") != "none"
    ):
        violations.append("EXCESS_PERMISSION")

    # 2. PR Trigger check
    if (
        workflow.get("trigger") == "pull_request_target"
        or (event == "pull_request" and workflow.get("trigger") != "pull_request")
    ):
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests & Matrix
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action Pinning
    actions = workflow.get("actions", [])
    for act in actions:
        if act.get("owner") != "actions":
            action_ref = act.get("ref", "")
            if not re.match(r"^[0-9a-f]{40}$", action_ref):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Multi-stage image
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Non-root user
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secret mode
    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # 8. Critical CVEs
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. Digest pinning
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production rules
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"
    return {"decision": decision, "violations": violations}