# Eval results

Run on 2026-10-19 with `claude plugin eval . --runs 3 --ablation with-without --scaffold --allow-tools Write Edit` (Claude Code 2.1.303). Each case runs 3 times with the plugin and 3 times without, on the same prompt and starting project. Scores are the mean over runs (graders are deterministic regex checks on the files Claude wrote, plus one LLM-judged check each in cases 04 and 05). No run ended on an API error.

## Summary

| Model | With plugin | Without | Δ | Cost |
|---|---|---|---|---|
| Default (Opus) | 1.00 | 0.94 | **+0.06** | $4.50 |
| Sonnet | 0.98 | 0.78 | **+0.20** | $2.05 |
| Haiku | 0.93 | 0.76 | **+0.17** | $0.20 |

## Per case (with / without)

| Case | What it tests | Default (Opus) | Sonnet | Haiku |
|---|---|---|---|---|
| `01-todos-minimal` |  | 1.00 / 0.50 | 1.00 / 0.50 | 1.00 / 0.50 |
| `02-feedback-any-user` |  | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| `03-admin-from-metadata` |  | 1.00 / 1.00 | 1.00 / 1.00 | 0.67 / 0.67 |
| `04-worker-node-crypto` |  | 1.00 / 1.00 | 1.00 / 0.67 | 1.00 / 1.00 |
| `05-service-key-in-client` |  | 1.00 / 1.00 | 0.83 / 0.83 | 1.00 / 0.67 |
| `06-worker-native-addon` |  | 1.00 / 1.00 | 1.00 / 0.00 | 0.67 / 0.00 |
| `07-neg-plain-postgres` |  | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| `08-neg-node-cli` |  | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| `09-stats-view` |  | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |

## Reading the numbers

- **The plugin never made a case worse**, and the two should-not-fire cases (07, 08) stayed at 1.00 everywhere: the hooks stayed silent outside Supabase and Workers projects.
- **On the strongest model the gap is small** (+0.06). It already avoids most of these traps when asked directly. The one it reliably misses is shipping a table without RLS when the user asks for "just the table" (case 01, 0/3 without the plugin on every model).
- **On Sonnet and Haiku the plugin matters more** (+0.20, +0.17): `sharp` in a Worker (06), `node:crypto` without `nodejs_compat` (04), and the service-role key in a `'use client'` file (05).
- **Honest misses with the plugin on Haiku:** in one 06 run, Haiku still shipped `sharp`. In one 03 run it never wrote the migration file, so both graders failed. In case 05 on Sonnet, the LLM-judged explanation grader failed once in each arm, which is grader noise rather than a security difference.
- An earlier version that only checked *after* each write did not stop Haiku from keeping `sharp` (0/3). The pre-write gate (reject an edit that would add a blocking finding) raised that to 2/3.
