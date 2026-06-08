# Pattern NN — <name>

> Copy this file into `patterns/<class>/<slug>.md`. Keep it FOCUSED — one screen of signal, not a textbook.
> If a section is empty, leave the heading with `_TODO_` so the gap is visible (that's how we find our own blind spots).

**Tier:** T0 (regex) · T1 (AST/dataflow) · T2 (cross-component/invariant) · T3 (economic/business-logic) — pick where the
*exploit* lives, not where the *smell* lives. Most real bugs are T2/T3 even when the smell is T1.
**One line:** the bug in a single sentence — *what unsafe assumption + what the attacker does with it*.

## 1. Mechanism
The faulty assumption and how value leaks, ordered by how often it actually bites. Bullets, not prose. Name the exact
functions / state vars / math operations involved so it's greppable later.

## 2. Real examples
Concrete incidents with $ and date. Mark first-hand ones `(first-hand)` — those are our own studied cases and the most
trustworthy. One line each: protocol, what was misvalued/miscounted, how the attacker triggered it.

## 3. The "tell"
The grep/read checklist a human runs to find this in a fresh codebase. Concrete tokens to search; the single
$-question to ask at each hit ("can the attacker move/skip/replay this?"). This is what later becomes a detector.

## 4. Detector idea (static, T0/T1) — det_<name>
What a regex/AST pass can flag — and its **honest limit** (what it will FP/FN on, why it's a *lead* not a *verdict*).
If the real check is cross-file/stateful, say so and push it to §5. Never pretend T0 catches a T2 bug.

## 5. Hypothesis / invariant (T2/T3)
- **Hypothesis:** the question `hypothesize.py` should ask across components.
- **Invariant to fuzz:** the property a Foundry invariant test asserts (snapshot → adversarial action → re-check → assert
  bounded delta). State it as code-able: what to measure, what action breaks it, what bound proves the bug.

## 6. Mitigations to RECOGNIZE (avoid FP)
The defenses that make this pattern a non-finding. If you see one, the lead is dead — stop and move on. Name first-hand
gold-standard examples (e.g. a specific clamped/rate-limited construct) so we recognize a *good* design fast.
