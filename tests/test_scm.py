"""Plain-assert checks for the GitHub App write client.

Run: uv run python tests/test_scm.py     (no network, no credentials, no Docker)

The last test is the important one: it asserts the ABSENCE of force/merge/approve/
delete-ref by introspection. Absence is the safety property, so it is tested
structurally rather than trusted to review.
"""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.interface import scm
from docket.interface.scm import FileChange, GitHubApp, ScmError, _fake_config, _FakeTransport

HEAD = "a" * 40
OTHER = "b" * 40
CONFIG = _fake_config()  # one throwaway RSA key for the whole file


def client(**kwargs) -> tuple[GitHubApp, _FakeTransport]:
    fake = _FakeTransport(**{"refs": {"main": OTHER}, **kwargs})
    return GitHubApp(config=CONFIG, transport=fake), fake


def refusal(call) -> ScmError:
    try:
        call()
    except ScmError as exc:
        return exc
    raise AssertionError("expected a refusal, got none")


def test_create_branch_refuses_default_and_protected() -> None:
    app, _ = client(default_branch="main")
    assert refusal(lambda: app.create_branch("o/r", "main", HEAD)).code == "default_branch"

    app, _ = client(protected=("release",), refs={"main": OTHER, "release": OTHER})
    assert refusal(lambda: app.create_branch("o/r", "release", HEAD)).code == "branch_protected"


def test_existing_ref_is_adopted_only_when_the_sha_matches() -> None:
    app, fake = client(refs={"main": OTHER, "docket/fix/1-abcd1234": HEAD})
    adopted = app.create_branch("o/r", "docket/fix/1-abcd1234", HEAD)
    assert adopted == {"ref": "docket/fix/1-abcd1234", "sha": HEAD, "created": False}

    # Same branch, different commit: somebody else moved it. Overwriting would need a
    # force update, and there is no method for that.
    moved = refusal(lambda: app.create_branch("o/r", "docket/fix/1-abcd1234", "c" * 40))
    assert moved.code == "branch_stale", moved.code
    assert fake.refs["docket/fix/1-abcd1234"] == HEAD, "a stale branch is left alone"


def test_commit_files_refuses_ci_config_and_secrets() -> None:
    app, fake = client(refs={"main": OTHER, "fix": HEAD})
    for path in (".github/workflows/ci.yml", ".env", "app/.env.production",
                 "deploy/server.pem", "ssh/id_rsa", "a/b/.gitlab-ci.yml",
                 "certs/x.p12", "../../etc/passwd"):
        exc = refusal(lambda p=path: app.commit_files(
            "o/r", "fix", [FileChange(p, "x")], "m"))
        assert exc.code == "refused_path", (path, exc.code)
    # A symlink or submodule entry is refused too — a "text file" must be a text file.
    assert refusal(lambda: app.commit_files(
        "o/r", "fix", [FileChange("a.py", "x", mode="120000")], "m")).code == "bad_change"
    assert fake.commits == [], "nothing was written on any refusal"

    ok = app.commit_files("o/r", "fix", [FileChange("app/main.py", "print(1)\n")], "m")
    assert fake.refs["fix"] == ok["sha"]


def test_every_write_refuses_a_read_only_repo() -> None:
    app, fake = client(push=False)
    writes = (lambda: app.create_branch("o/r", "fix", HEAD),
              lambda: app.commit_files("o/r", "main", [FileChange("a.py", "x")], "m"),
              lambda: app.open_pr("o/r", "fix", "main", "t", "b"),
              lambda: app.create_check_run("o/r", HEAD, conclusion="success"),
              lambda: app.update_check_run("o/r", 1, conclusion="success"),
              lambda: app.create_review_comment("o/r", 1, "a.py", 2, "b"))
    for write in writes:
        assert refusal(write).code == "repo_read_only"
    assert not fake.commits and not fake.check_runs and not fake.created_pulls
    # ...and reads still work, which is the point of distinguishing the two.
    assert app.repo_permissions("o/r") == {"admin": False, "push": False, "pull": True}


def test_annotations_are_batched_at_fifty() -> None:
    app, fake = client()
    rows = [{"path": "a.py", "start_line": i, "end_line": i,
             "annotation_level": "warning", "message": "x"} for i in range(1, 61)]
    app.create_check_run("o/r", HEAD, conclusion="failure", annotations=rows)
    sent = [len(call["output"]["annotations"]) for call in fake.check_runs]
    assert sent == [50, 10], sent


def _module_functions():
    """Every function and method DEFINED in scm.py, with its qualified name."""
    for name, value in vars(scm).items():
        if inspect.isfunction(value) and value.__module__ == scm.__name__:
            yield name, value
        elif inspect.isclass(value) and value.__module__ == scm.__name__:
            for method_name, method in vars(value).items():
                if inspect.isfunction(method):
                    yield f"{name}.{method_name}", method


def test_no_force_no_merge_no_approve_no_delete_ref() -> None:
    """The invariant: those capabilities do not exist in this module.

    Structural on purpose. A future contributor adding `force=True` to satisfy a stuck
    re-run fails here rather than in review, which is the only place absence can be
    enforced once nobody remembers why it was absent.
    """
    banned_words = ("merge", "approve", "delete", "force", "squash", "rebase", "push_force")
    checked = 0
    for qualname, function in _module_functions():
        checked += 1
        leaf = qualname.split(".")[-1].lower()
        assert not any(word in leaf for word in banned_words), \
            f"{qualname} names a capability this client must not have"
        for parameter in inspect.signature(function).parameters:
            assert "force" not in parameter.lower(), f"{qualname} takes {parameter!r}"
    assert checked > 15, f"introspection found only {checked} functions — it broke"

    for name in ("merge_pr", "merge", "approve", "approve_pr", "create_review",
                 "delete_ref", "delete_branch", "force_push", "update_ref_force"):
        assert not hasattr(GitHubApp, name), f"GitHubApp.{name} must not exist"
        assert not hasattr(scm, name), f"scm.{name} must not exist"

    # The client must also never send a force flag, whatever it is called: the only
    # ref-moving call is the plain fast-forward in commit_files.
    # Everything after the module docstring, which is allowed to say the word.
    source = Path(scm.__file__).read_text().split('"""', 2)[-1]
    assert '"force"' not in source and "force=True" not in source, \
        "no request body in this module may carry a force flag"


if __name__ == "__main__":
    test_create_branch_refuses_default_and_protected()
    test_existing_ref_is_adopted_only_when_the_sha_matches()
    test_commit_files_refuses_ci_config_and_secrets()
    test_every_write_refuses_a_read_only_repo()
    test_annotations_are_batched_at_fifty()
    test_no_force_no_merge_no_approve_no_delete_ref()
    print("test_scm: ok")
