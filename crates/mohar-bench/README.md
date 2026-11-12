# mohar-bench

The benchmark harness for Mohar's trust rules (docs/design.md, section 10). It isn't published to
crates.io.

## What it runs

Twenty simulated agents work on three capabilities for nine simulated weeks, six actions per capability
per day. The capabilities are `edit` (low risk, reversible), `deps` (medium risk, reversible) and
`deploy` (high risk, irreversible, never above Supervised). Agents come in four kinds, five of each, with
a known pass rate: good (98%), middling (87%), poor (75%), and drifting (98% for four weeks, then 70%).

Each action's outcome is decided by hashing the seed, the agent, the capability and the action number, so
every policy sees exactly the same tasks. When a policy asks a person, the person stops half of the
failing actions before they run. A stopped action has no outcome, as with a refusal in the daemon.
Everything that runs is verified, and a failure that ran is an incident.

The same tasks go through four policies:

- `always_ask`: every action goes to a person.
- `static_allowlist`: `edit` runs, everything else goes to a person.
- `aggregate_score`: Mohar's rules over one score per agent, pooled across capabilities.
- `mohar`: Mohar's rules, one score per agent per capability (`mohar_core::trust::Ledger`).

## What it reports

`results.json` has, for each policy, prompts and incidents per thousand actions, the share of prompts
avoided compared with always asking, and whether incidents stay at or below the static allowlist's. For
the two policies with levels it also has promotions, false promotions (to a level the agent's real pass
rate doesn't meet: 80% for Supervised, 95% for Trusted), and the number of actions a drifting agent ran
at its old level after its quality dropped, before the demotion showed.

## Regenerating

```
MOHAR_WRITE_BENCH=1 cargo test --release -p mohar-bench
```

`cargo test` fails when `results.json` no longer matches what the harness produces, so a change to the
trust rules that moves a number has to commit the new numbers with it.

## Limits

The agents are simulated, with fixed pass rates and independent outcomes; real agents have streaks, and
their failures cluster on certain tasks. The person's catch rate is one number for every action.
Results are totals over eight seeds, without confidence intervals; the write-up (#54) adds those, and
prediction agreement is still to come (#53).
