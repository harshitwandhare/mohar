# Instructions for coding agents

This file is for AI coding agents working in this repository. Humans should read CONTRIBUTING.md.

## Before you change anything

1. Find the issue your change belongs to. If there isn't one, stop and propose one instead of opening a
   pull request. Pull requests without a linked issue are closed.
2. Read the issue's acceptance criteria. Your change is done when those pass, not before.
3. Keep the change small: one issue, one pull request.

## Rules

- Write a failing test first, then the fix. Show both runs in the pull request.
- Run the full local checks before pushing. The commands are listed in CONTRIBUTING.md.
- Don't add dependencies without saying why in the pull request.
- Don't touch files unrelated to the issue, including formatting-only changes.
- Never commit secrets, keys or tokens, including test-looking ones.
- Security-sensitive code (signing, verification, the log, trust decisions) needs a test for the failure
  path, not only the success path. Failing closed is the rule: when a check can't decide, it denies.
- Say plainly in the pull request what you didn't test or aren't sure about.

## Disclosure

State in the pull request that an agent wrote the change, which agent, and which human is responsible
for it. The human signs off the commits (see CONTRIBUTING.md).
