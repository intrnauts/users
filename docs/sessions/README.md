# Session records

At the end of each working session, write a record of what happened: what was finished, what wasn't and why, and anything worth remembering. One file per day, `YYYY-MM-DD.md`. If two sessions fall on the same day, add to that day's file.

Adopted 2026-10-20 (standing issue #22). Each record goes in through a PR into `dev` that refers to #22 but **isn't linked** to it, so the issue stays open.

This repo is public. Security work that is still open is tracked in private advisories, and a record names an advisory only as "the draft advisory", never an affected application that hasn't been patched yet.

## Format

Keep it short and factual. Every item names its issue or PR, so the record works as an index into GitHub.

```markdown
# Session record — YYYY-MM-DD

One or two sentences: what the session set out to do and how it went.

## Finished
Grouped by theme. Each item: what changed, and the issue/PR (repo#N) that records it.

## Not finished
What was started or planned but didn't get done, and why (blocked, waiting, deferred, decided against).

## Decisions
Choices made during the session that later work depends on.

## Learned
Gotchas and surprises, the things you'd want to know next time.

## Next
Where to pick up.
```

Omit a section that would be empty.
