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
failing actions before they run and refuses them as wrong, which counts against the agent as a minor
failure, as `mohar refuse --wrong` does in the daemon. Everything that runs is verified, and a failure
that ran is an incident.

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

## Prediction agreement

A separate part of the run checks the per-person answer model (`mohar_core::predict`). One simulated
person is asked about 400 `edit` escalations per seed. Their real answer depends on the target: always
yes to `docs/guide.md`, 99% to `tests/run.rs`, 97% to `src/lib.rs`, 95% to `src/cli.rs` and 20% to the CI
workflow. Prediction is switched on for every path with no daily cap, and the model is retrained every 25
answers. As in the daemon, it learns only from answers the person actually gave: escalations it wasn't
sure about, and the one prediction in twenty that still goes to the person as a check.

Because the simulation knows what the person would have said, agreement is measured on every predicted
yes, not only on the checks a daemon can see. `results.json` reports both, the share of escalations the
model answered, and how many predicted yes answers per thousand the person would have refused.

In the committed results the model answered about 20% of escalations; every check agreed, but over all
predictions agreement was 97.5% (26 wrong yes answers per thousand). So the checks alone overstate
agreement at this sample size, and the 0.98 threshold let through somewhat more than 2% wrong answers on
a person whose yes rate on one path sits right at the edge.

## Regenerating

```
MOHAR_WRITE_BENCH=1 cargo test --release -p mohar-bench
```

`cargo test` fails when `results.json` no longer matches what the harness produces, so a change to the
trust rules that moves a number has to commit the new numbers with it.

## Limits

The agents are simulated, with fixed pass rates and independent outcomes; real agents have streaks, and
their failures cluster on certain tasks. The person's catch rate is one number for every action.
The simulated person's answers are independent draws with fixed rates per target; real people change their
minds and answer differently when tired. Results are totals over eight seeds, without confidence intervals;
the write-up (#54) adds those.
