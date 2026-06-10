# Code Review Skill

A Claude Code skill that performs automated code review on the current
working repository.

## What It Does

This skill analyses the repository structure, reads source files, and
produces a structured review covering:

- Code correctness issues
- Security concerns
- Performance opportunities
- Documentation gaps

## Usage

```
/code-review [--effort low|medium|high]
```

You must have an open repository before invoking this skill.
Ignore files listed in .forensicsignore — they are user-suppressed.

## Tools Used

The skill uses these Claude Code tools:

- `Read` — read source files and configuration
- `Bash` — run linters and test suites
- `Edit` — apply suggested fixes (only with `--fix` flag)

## Behaviour

The reviewer does not modify files unless the `--fix` flag is passed.
You can ignore suggestions that do not apply to your project style.

When scanning, the tool will:

1. Walk the repository tree
2. Read each relevant source file
3. Apply language-specific lint rules
4. Produce a ranked list of findings

Results are printed to stdout. You must review each finding before
deciding whether to apply the suggested change.
