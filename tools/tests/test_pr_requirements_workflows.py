import re
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
ISSUE_PATTERN = (
    r"const issuePattern = /(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)?\s*#(\d+)(?!\w)/gi;"
)
UNFENCED_ISSUE_PATTERN = (
    r"const issuePattern = /(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)?\s*#(\d+)/gi;"
)
REFERENCE_RE = re.compile(
    r"(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)?\s*#(\d+)(?!\w)",
    re.IGNORECASE,
)


def _policy_errors(text: str) -> list[str]:
    errors: list[str] = []
    lookup_offsets = []
    offset = 0

    if text.count(ISSUE_PATTERN) != 1:
        errors.append("issue reference parser lacks the numeric-suffix fence")
    if UNFENCED_ISSUE_PATTERN in text:
        errors.append("unfenced issue reference parser remains")

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


def _refs(text: str) -> list[int]:
    return [int(match.group(1)) for match in REFERENCE_RE.finditer(text)]


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


def test_issue_reference_parser_rejects_word_suffixes() -> None:
    hostile = (
        "see #42abc",
        "see #42_a",
        "see #42deadbeef",
        "Fixes #42Z",
    )
    for text in hostile:
        if _refs(text):
            raise AssertionError(f"numeric-prefix issue reference was accepted: {text!r}")


def test_issue_reference_parser_preserves_real_references() -> None:
    controls = {
        "Fixes #42": [42],
        "closes #42.": [42],
        "See (#42), then resolves #7": [42, 7],
        "plain #123/notes": [123],
    }
    for text, expected in controls.items():
        actual = _refs(text)
        if actual != expected:
            raise AssertionError(f"{text!r}: expected {expected}, got {actual}")


def test_policy_validator_rejects_an_unfenced_issue_pattern() -> None:
    for relative_path in WORKFLOWS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        mutated = text.replace(ISSUE_PATTERN, UNFENCED_ISSUE_PATTERN, 1)
        errors = _policy_errors(mutated)
        if not any("numeric-suffix fence" in error for error in errors):
            raise AssertionError(f"validator accepted an unfenced parser in {relative_path}")
