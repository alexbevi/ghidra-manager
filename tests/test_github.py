from ghidra_manager.github import GitHubClient


def test_explicit_empty_environment_does_not_inherit_github_token(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GH_TOKEN", "host-token")

    assert GitHubClient(environ={}).token is None
