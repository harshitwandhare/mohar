# Benchmark

This page reports how Mohar's trust rules behave on simulated agents, next to three simpler ways of
deciding the same actions. The harness is `crates/mohar-bench` in the repository; the tables under
Results are written by it, and a test fails when they no longer match what it produces. Design section
10 lists what the benchmark is meant to measure.

## Method

Twenty simulated agents work for 63 simulated days on three capabilities, six actions per capability per
day, which is 181,440 actions per policy over eight seeds. The capabilities are `edit` (low risk,
reversible), `deps` (medium risk, reversible) and `deploy` (high risk, irreversible, never above
Supervised).

The agents come in four kinds, five of each, with a fixed real pass rate: good (98%), middling (87%),
poor (75%) and drifting (98% for four weeks, then 70%). Whether an action passes is decided by hashing
the seed, the agent, the capability and the action number, so every policy sees the same tasks.

When a policy asks a person, the person stops half of the failing actions before they run and refuses
them as wrong, which counts against the agent as a minor failure, as `mohar refuse --wrong` does in the
daemon. Everything that runs is verified. A failure that ran is an incident.

A promotion is false when the agent's real pass rate at that moment is below what the level stands for:
80% for Supervised and 95% for Trusted. Time to demotion counts the actions a drifting agent ran at its
old level after its quality dropped, until it was demoted.

The prediction part is separate. One simulated person is asked about 400 `edit` escalations per seed,
with a fixed yes rate per file (100%, 99%, 97%, 95% and 20%). The answer model learns only from answers
the person gave, and one prediction in twenty still goes to the person as a check. The simulation knows
what the person would have said, so agreement is measured on every prediction, not only on the checks.

The lesson part is separate too. The same twenty agents work as above, and five more misleading agents
join them. A misleading agent's real work always passes, but it fails 10% of its actions on purpose, so
every lesson it gets written is a planted one; the others are honest. Every outcome is verified here,
with no person stopping a failure first, and the lessons go into the real lesson book
(`mohar_core::lessons::Book`) the way the daemon fills it: each failure writes a signed lesson, a
failure on `deploy` (S3) quarantines the agent's earlier lessons, and a pass fixes the agent's open
lessons on that capability. A person promotes one fixed lesson in ten to the team, spots half of the
planted ones among them and leaves those out, and releases each quarantine a day after it opens. The
counts are taken when the run ends: a lesson is kept when some agent is still given it.

## Baselines

- `always_ask`: every action goes to a person.
- `static_allowlist`: `edit` runs without asking; everything else goes to a person.
- `aggregate_score`: Mohar's promotion and demotion rules over one score per agent, pooled across its
  capabilities, the way a single trust score works.
- `mohar`: the same rules with one score per agent per capability (`mohar_core::trust::Ledger`).

For lessons there is one baseline, shared notes: every failure's note is kept and given to every agent,
as an agent memory file that each failure appends to would be.

## Results

Each rate is the mean over the eight seeds, with its 95% Student t interval in parentheses (seven degrees
of freedom, low end clipped at zero). The false promotion count is the total over all seeds.

<!-- results:start -->
| Policy | Prompts per 1,000 actions | Prompts avoided | Failures that ran per 1,000 | Irreversible failures per 1,000 | False promotions |
| --- | --- | --- | --- | --- | --- |
| `always_ask` | 1000.0 (1000.0 to 1000.0) | 0.0% (0.0% to 0.0%) | 71.4 (69.9 to 72.8) | 23.7 | no levels |
| `static_allowlist` | 666.7 (666.7 to 666.7) | 33.3% (33.3% to 33.3%) | 94.8 (92.8 to 96.7) | 23.7 | no levels |
| `aggregate_score` | 959.0 (945.3 to 972.7) | 4.1% (2.7% to 5.5%) | 71.8 (70.4 to 73.2) | 23.7 | 3 of 594, 0.5% (0.0% to 1.8%) |
| `mohar` | 882.6 (874.5 to 890.6) | 11.7% (10.9% to 12.6%) | 73.1 (71.6 to 74.6) | 23.7 | 5 of 645, 0.8% (0.0% to 1.5%) |

| Policy | Drops measured | Median actions to demotion | 90th percentile | Longest | Drop came at Ask first | Never demoted |
| --- | --- | --- | --- | --- | --- | --- |
| `aggregate_score` | 18 | 2 | 4 | 4 | 102 | 0 |
| `mohar` | 78 | 5 | 14 | 25 | 42 | 0 |

Prediction agreement: the answer model answered 326 of 3200 escalations (10.2%). 7 of its predictions still went to the person as checks, and 100.0% of the checks agreed. Over every prediction there were 18.4 wrong yes answers per 1,000. Taken seed by seed, the mean was 5.9, with a 95% interval of 0.0 to 19.9.

| Memory | Lessons kept | Poisoned per 1,000 kept | Seen by another agent | Poisoned per 1,000 of those |
| --- | --- | --- | --- | --- |
| shared notes | 30528 | 148.6 (143.8 to 153.5) | 30528 | 148.6 (143.8 to 153.5) |
| `mohar` lesson book | 12252 | 266.1 (186.2 to 345.9) | 1060 | 153.2 (63.2 to 243.2) |

The agents wrote 30528 lessons, 4538 of them from planted failures. A person promoted 2783 fixed lessons to the team and spotted 226 planted ones before promoting them. When the run ended, 18276 lessons were withheld by an open quarantine, 16788 of them honest.
<!-- results:end -->

## Reading the numbers

Against always asking, Mohar removed about 12% of prompts, and 1.7 more failures per 1,000 actions ran.
The static allowlist removed a third of the prompts, and 23 more failures per 1,000 ran than under
always asking, because it lets every `edit` through whatever the agent's record.

The single aggregate score removed far fewer prompts than per-capability trust did (about 4%), most
likely because one score mixes an agent's good work on one capability with its failures on another. Its
false promotion rate was a little lower than Mohar's in this run. Its median time to demotion was
shorter, but it measured only 18 drops. In 102 of the 120 drops in quality the drifting agent had never
been promoted, so there was nothing to demote.

Irreversible failures are the same under every policy. Mohar sends an irreversible high-risk action to
a person whatever the agent's level, and the three baselines ask about `deploy` every time too.

Before #228 the answer model gave 26 wrong yes answers per 1,000 predictions, more than its 0.98
threshold suggests, and every check agreed. The cause was the calibration. Platt scaling is monotone in
the model's score, and this person's answers fall into two groups: CI at 20% yes, everything else between
95% and 100%. The fit placed the line between the groups well but could not tell the paths inside the
mostly-yes group apart, so `src/cli.rs` (95%) was scored like `docs/` (100%). The model's probability is
now capped at the person's own smoothed yes rate on the capability in the target's top directory,
(yes + 1) / (answers + 2). Wrong yes answers fell to the figure above, and the model answers about half as
many escalations as before. The remaining wrong answers are on `src/cli.rs`, which shares `src/` with a
97% path, so the cap sees one directory at about 96%. Checks still can't show this: with one prediction in
twenty checked, a few hundred predictions give a handful of checks.

The lesson book did not keep planted lessons out better than shared notes. Of the lessons some agent was
still given at the end, 266 per 1,000 were planted, against 149 for shared notes, and of the lessons
another agent was given, 153 per 1,000, about the same. The person left out half of the planted lessons
that came up for promotion, as set, and quarantine undid the gain. A serious failure withholds every
lesson the agent wrote before it, including lessons a person released earlier, so an honest agent that
fails `deploy` often has its history withheld most of the time: 16,788 of 25,990 honest lessons were
withheld when the run ended, against 1,488 of 4,538 planted ones. A misleading agent that fails on
purpose one time in ten fails `deploy` less often than the poor and drifting agents, so more of its
lessons stay. A person who spots a planted lesson also has no way to withdraw it; they can only leave it
out of the team. #236 tracks both.

## Limits

- The agents are simulated. Their pass rates are fixed and their outcomes independent; real agents have
  streaks, and their failures cluster on certain tasks.
- The person stops the same share of failures on every action, and their yes answers are independent
  draws at fixed rates. Real people get tired, change their minds and miss more on some actions than on
  others.
- Eight seeds give wide intervals on the rare events, false promotions above all. The intervals are over
  per-seed means; they don't pair policies on the same tasks, so the differences between policies are
  better estimated than the overlapping intervals suggest.
- In the lesson part every failure is verified and none is stopped first, so it writes more lessons than
  the trust part would. The counts are taken once, when the run ends, not over every lesson an agent was
  given along the way. A planted lesson reads the same as an honest one, so the person spots it at a
  fixed rate, not from what it says.
- There are no results from real agents or real reviewers yet.

## Regenerating

```
MOHAR_WRITE_BENCH=1 cargo test --release -p mohar-bench
```

This rewrites `crates/mohar-bench/results.json` and the tables above. Run it twice: the first run fails
because it compares against the files as they were before it wrote them. A change to the trust rules
that moves a number has to commit the new numbers with it.
