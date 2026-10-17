---
description: Audit this repo's Supabase migrations, Supabase keys, and Cloudflare Worker code with rls-edge-guard
argument-hint: "[path]"
allowed-tools: Bash(python3:*), Read, Grep, Glob, Edit
---

## Audit output

!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard.py" audit $ARGUMENTS`

## Your task

The output above is from rls-edge-guard's whole-repo audit. It covers every Supabase migration (replayed in order), every Supabase key reference in client code, and every file reachable from each Worker's `main`.

1. Summarize the findings for the user, grouped by severity (`block` first) and then by file. Give the counts.
2. For each `block` finding, explain in one or two sentences what an attacker or the Workers runtime would actually do with it.
3. Propose fixes. Do not edit anything until the user agrees. For migrations that may already be applied, put fixes in a **new** migration instead of editing an old one.
4. If a finding is intended (for example, a public waitlist insert), suggest an ignore comment with a real reason: `-- rls-edge-guard-ignore RLS002: <reason>`.
5. If there are no findings, say so, and note that the audit is static. For proof that policies actually hold, offer the `rls-pgtap-prover` skill.
