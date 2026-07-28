# Global Developer Preferences

## Coding Style

- Prefer dataclasses (or Pydantic if already in the project) over plain dicts for structured data. Plain dicts are fine for simple/throwaway mappings.
- Use modern type hints (`X | None`, `list[str]`, not `Optional[X]`, `List[str]`).

## Tooling Rules

- Always run linters/formatters with auto-fix flags (`--fix`, `--write`, etc.). Never run in audit/check-only mode and then manually apply fixes.

### Python

- Default stack unless the repo AGENTS.md says otherwise: `uv`, `ruff`, `pytest`.
  - Lint: `uv run ruff check --fix`
  - Format: `uv run ruff format`

### Other Languages

- Check for config files (e.g., .eslintrc, prettier config) before running tools.

## Testing Conventions

- When a test file grows past ~800 lines, proactively split it. Group tests by feature or module. Use subdirectories (e.g., `tests/unit/`, `tests/integration/`) when the test suite warrants it.
- Always run the relevant test suite after making changes.

### Python

- Use `@pytest.mark.parametrize` when multiple tests share the same structure with different inputs/outputs.

## Repo-Level AGENTS.md Maintenance

Compatibility note: `AGENTS.md` is the canonical instructions file. `CLAUDE.md` is kept as a symbolic link to it for Claude Code support.

When maintaining a repo-level AGENTS.md, use these sections in order:

1. **Project Overview** — one-paragraph summary of what the project does
2. **Technical Stack** — language version, package manager, key dependencies
3. **Development Commands** — exact commands to build, test, lint, format
4. **Architecture** — key directories, entry points, how code is organized
5. **Codebase Patterns** — conventions specific to the repo
6. **Testing Patterns** — test framework, fixtures, how to run subsets

Rules:
- Keep each section to 3-8 bullet points; split if more needed.
- Update when adding major new patterns, dependencies, or architectural decisions.
- Never duplicate content from this root AGENTS.md; repo files extend or override, not repeat.
- Project-specific commands always go in the repo file, never here.
