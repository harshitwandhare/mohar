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

## Baselines

- `always_ask`: every action goes to a person.
- `static_allowlist`: `edit` runs without asking; everything else goes to a person.
- `aggregate_score`: Mohar's promotion and demotion rules over one score per agent, pooled across its
  capabilities, the way a single trust score works.
- `mohar`: the same rules with one score per agent per capability (`mohar_core::trust::Ledger`).

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

Prediction agreement: the answer model answered 647 of 3200 escalations (20.2%). 23 of its predictions still went to the person as checks, and 100.0% of the checks agreed. Over every prediction there were 26.3 wrong yes answers per 1,000. Taken seed by seed, the mean was 12.8, with a 95% interval of 0.0 to 27.6.
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

The answer model gave more wrong yes answers (26 per 1,000 predictions over all seeds) than its 0.98
threshold suggests, while every check agreed, so the checks a daemon can see would not have shown it.
The seed-by-seed mean is lower, so the seeds where the model answered more often were also the ones
where it was wrong more often. Issue #228 tracks
finding the cause; until then, prediction should stay off for anyone whose yes rate on a path is close to
the threshold.

## Limits

- The agents are simulated. Their pass rates are fixed and their outcomes independent; real agents have
  streaks, and their failures cluster on certain tasks.
- The person stops the same share of failures on every action, and their yes answers are independent
  draws at fixed rates. Real people get tired, change their minds and miss more on some actions than on
  others.
- Eight seeds give wide intervals on the rare events, false promotions above all. The intervals are over
  per-seed means; they don't pair policies on the same tasks, so the differences between policies are
  better estimated than the overlapping intervals suggest.
- Poisoning that reaches durable memory, listed in the roadmap for this phase, isn't measured yet.
- There are no results from real agents or real reviewers yet.

## Regenerating

```
MOHAR_WRITE_BENCH=1 cargo test --release -p mohar-bench
```

This rewrites `crates/mohar-bench/results.json` and the tables above. Run it twice: the first run fails
because it compares against the files as they were before it wrote them. A change to the trust rules
that moves a number has to commit the new numbers with it.
