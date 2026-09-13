from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = (
    Path(".github/workflows/pr-requirements.yml"),
    Path(".github/workflows/pr-check-command.yml"),
    Path(".github/workflows/pr-requirements-backfill.yml"),
)
ISSUE_LOOKUP = "const { data: issue } = await github.rest.issues.get({"
ASSIGNEE_LOOKUP = "const assigneeLogins ="
PULL_REQUEST_GUARD = "if (issue.pull_request)"
INVALID_REASON = "invalidReason: 'pull request, not an issue'"


def _policy_errors(text: str) -> list[str]:
    errors: list[str] = []
    lookup_offsets = []
    offset = 0

    while True:
        offset = text.find(ISSUE_LOOKUP, offset)
        if offset == -1:
            break
        lookup_offsets.append(offset)
        offset += len(ISSUE_LOOKUP)

    if not lookup_offsets:
        return ["no Issues API lookup found"]

    for index, lookup_offset in enumerate(lookup_offsets):
        next_lookup = lookup_offsets[index + 1] if index + 1 < len(lookup_offsets) else len(text)
        assignee_offset = text.find(ASSIGNEE_LOOKUP, lookup_offset, next_lookup)
        if assignee_offset == -1:
            errors.append(f"lookup {index + 1} has no assignee evaluation")
            continue

        decision_block = text[lookup_offset:assignee_offset]
        guard_offset = decision_block.find(PULL_REQUEST_GUARD)
        if guard_offset == -1:
            errors.append(f"lookup {index + 1} has no pull-request guard before assignee evaluation")
            continue

        guarded_block = decision_block[guard_offset:]
        if "continue;" not in guarded_block:
            errors.append(f"lookup {index + 1} does not skip pull-request records")
        if INVALID_REASON not in guarded_block:
            errors.append(f"lookup {index + 1} does not explain why the reference is invalid")

    if "i.invalidReason" not in text:
        errors.append("failure output does not render invalid-reference reasons")

    return errors


def test_pr_requirement_workflows_reject_pull_request_records() -> None:
    for relative_path in WORKFLOWS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        errors = _policy_errors(text)
        if errors:
            raise AssertionError(f"{relative_path}: {'; '.join(errors)}")


def test_policy_validator_rejects_a_removed_guard() -> None:
    for relative_path in WORKFLOWS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        guard_offset = text.index(PULL_REQUEST_GUARD)
        assignee_offset = text.index(ASSIGNEE_LOOKUP, guard_offset)
        mutated = text[:guard_offset] + text[assignee_offset:]

        errors = _policy_errors(mutated)
        if not any("no pull-request guard" in error for error in errors):
            raise AssertionError(f"validator accepted an unguarded lookup in {relative_path}")
