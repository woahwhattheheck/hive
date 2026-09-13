from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ISSUES_AVAILABLE_GUARD = "github.event.repository.has_issues != false"
WORKFLOWS = (
    Path(".github/workflows/pr-requirements.yml"),
    Path(".github/workflows/pr-check-command.yml"),
    Path(".github/workflows/pr-requirements-backfill.yml"),
)


def test_linked_issue_policies_skip_when_repository_issues_are_disabled() -> None:
    for relative_path in WORKFLOWS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        if text.count(ISSUES_AVAILABLE_GUARD) != 1:
            raise AssertionError(
                f"{relative_path}: expected exactly one repository issue-availability guard"
            )


def test_issue_availability_guard_is_a_job_condition() -> None:
    for relative_path in WORKFLOWS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        guard_offset = text.index(ISSUES_AVAILABLE_GUARD)
        runs_on_offset = text.index("runs-on:")
        steps_offset = text.index("steps:")

        if guard_offset > runs_on_offset or guard_offset > steps_offset:
            raise AssertionError(
                f"{relative_path}: issue-availability guard must fence the job before execution"
            )
