# 🛡️ security-lab

> **White-hat движок для поиска багов в смарт-контрактах** — конвейер, который сам находит свежие
> in-scope цели, прочёсывает их статикой и динамикой, помнит каждый вердикт и показывает весь хант
> одним взглядом.

Думай о нём как о **детективном агентстве для кода**: невод сорсит дела, металлоискатель (статика) +
динамический фузер ищут улики, картотека помнит вердикты, радары следят 24/7, а дашборд — это
оперативный штаб.

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  SOURCE  →  REACH  →  TRIAGE  →  DETECT  →  L4 (я)  →  VERIFY (Gate-0)  →  DISCLOSE     │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

| | | |
|---|---|---|
| 🎯 **46** SOURCE-детекторов | 🧪 **658** golden-тестов (CI-гейт) | 📡 **24/7** облачные радары |
| 🔑 secrets-sweep (Taiko-класс) | 🤖 динамический фуз (ItyFuzz) | 🖥️ дашборд + MCP-платформа |

---

## 🧭 Как работает вся машина

```
  SOURCE  ── где искать ────────────────────────────────────────────────────────────────
    scout.py          contests (C4/Sherlock/Cantina/Hats) + DefiLlama deployed-unaudited +
                      Immunefi (263 прог, in-scope адреса+репо)
    freshfeed.py      НОВО-листингнутый код (DefiLlama listedAt + Sourcify) — стена свежести
    freshdeploy.py    новые контракты от watched-деплоеров/фактори — timing-эдж
        │
  REACH  ── достать код ─────────────────────────────────────────────────────────────────
    fetch_source.py   verified-source по адресу (Etherscan-v2, 64 сети)
    forkdrift.py      форк-ли аудированного base? + substantive-диф дрейфа (баги в audit-drift)
        │
  DETECT ── найти улики ─────────────────────────────────────────────────────────────────
    recon.py          СТАТИКА: 46 детекторов по сорсу → ГДЕ риск (access/oracle/reentrancy/…)
    ityfuzz_lane.py   ДИНАМИКА: fork-фуз с economic-oracle → ПОДТВЕРЖДАЕТ эксплойт (+ работает
                      на unverified bytecode). recon наводит → ItyFuzz доказывает.
    secrets_sweep.py  закоммиченные ключи в репо (дерево + ИСТОРИЯ git) — на масштабе in-scope-репо
        │
  L4 (я) + VERIFY ── доказать и не обмануться ──────────────────────────────────────────
    VERIFY.md         Gate-0 LIVE-FIRST + 8 kill-gates + 10 FP-ловушек («FP хуже miss'а»)
        │
  DISCLOSE          только in-scope + ответственно. egor раскрывает, не я.
```

**Память сшивает всё:** каждый вердикт триажа → `ledger.py`; авто-реестр целей → `registry.py`;
радары пишут work-list в `hunts/_radar/QUEUE.md`, который читается первым делом следующей сессии.

---

## 🧰 Инструменты по лейнам

### SOURCE — сорсинг целей
| Тул | Что делает |
|---|---|
| `scout.py` | contests + DefiLlama (deployed-unaudited) + Immunefi (`--from-immunefi` in-scope репо) |
| `freshfeed.py` | DefiLlama listedAt + Sourcify newest-verified → `FRESH-FEED.md` |
| `freshdeploy.py` | watched-деплоеры/фактори → новые контракты → `FRESH-DEPLOY.md` |
| `contest_monitor.py` | C4/Sherlock/Cantina — алерт на свежий our-zone контест (timing-эдж) |
| `legacy.py` | СОРСИНГ dormant+funded контрактов (инверсия activity; Thetanuts-класс) |

### REACH — достать и сориентироваться
| Тул | Что делает |
|---|---|
| `fetch_source.py` | verified-source по адресу через Etherscan-v2 (64 сети) |
| `forkdrift.py` | форк-ли base (Aave/Compound/Liquity…) + диф дрейфа → роутер |
| `activity.py` | LIVE-FIRST гейт (deployed + active + value? txlist-liveness) |

### DETECT — найти улики
| Тул | Что делает |
|---|---|
| `recon.py` | **СТАТИКА** — 46 детекторов (access-control, spot-oracle, reentrancy, supply, decimal-scale, trust-anchor, vault-share-math, …); FP-тюненные, class-gated, network-agnostic |
| `ityfuzz_lane.py` | **ДИНАМИКА** — обёртка над ItyFuzz: fork-фуз live-адреса, economic-oracle (profit), unverified bytecode. Post-DIG auto-confirm |
| `secrets_sweep.py` | `secrets.py` на масштабе: репо живых протоколов → clone+история → утечки ключей |
| `hypothesize.py` | инвариант-сиды (CORE/ECONOMIC/GAMEFI/BRIDGE) для фуз/символик |
| `scaffold.py` | L3 мульти-движок (Foundry/Echidna/Medusa/Halmos) |

### MEMORY + RADAR — не копать дважды
| Тул | Что делает |
|---|---|
| `ledger.py` | персист-вердикты (fp/known/wontfix/real/todo) — гасит повторный шум |
| `registry.py` | авто-реестр всех триаженных целей (cartography; `--query`, fork-индекс под батч-CVE) |
| `radar.py` | 24/7 радар: impl-upgrade (EIP-1967 slot-diff) + bounty-launch → `QUEUE.md` |
| `calibrate.py` | FEEDBACK-LOOP: исход находок + калибровка clean-вердиктов → precision/recall |

---

## 📡 Радары 24/7 (облако, без Mac/сна)

GitHub Actions крутят радары по крону и коммитят состояние обратно — следующая сессия видит свежее:

| Workflow | Крон | Что сторожит |
|---|---|---|
| `radar.yml` | каждые 3ч | impl-upgrade + bounty-launch по реестру + fresh-deploy + fresh-feed + **lab-state** |
| `secrets.yml` | weekly | secrets-sweep по in-scope репо (`--from-all`: Immunefi + контесты авто-сорс) |
| `watch.yml` | — | parked-лиды: FIRE когда откроется баунти/контест по запаркованной гипотезе |

Утром: `source toolkit/env.sh && python toolkit/brief.py` — дашборд «что свежего» (git + радары +
open-DIG реестра + parked + last fan-out).

---

## 🖥️ Платформа (визуал + взаимодействие над всем движком)

3-слойная, расширяемая (`research/platform/DESIGN-platform.md`): новый тул пишет JSON → виден везде.

```
 КОНТРАКТ   labstate.py → monitor/lab-state.json   (read-through JOIN над всеми кэшами)
   │
 labcore    операции + record_verdict (→ ledger → re-derive)
   │
   ├── lab_mcp.py    MCP-сервер (stdlib, 9 тулов, без pip) — я/claude.ai рулим как инструменты
   └── web/          kanban 5-колонок + радары + findings + parked, через lab_http.py (bridge)
```

```bash
python toolkit/dashboard.py          # → http://127.0.0.1:8787  (дашборд + bridge)
python toolkit/lab_http.py --public --token <секрет>   # LAN/телефон: sanitized, token-gated, без мутаций
```

Дашборд **мутирует** состояние (вердикты пишутся в ledger → re-derive). Один `labcore` под MCP и web →
фронты не дрейфуют. White-hat: remote-режим механически санитайзит чувствительные лиды.

---

## 🔁 Петля самоулучшения

```
  реальный хак  →  переносимый паттерн  →  детектор + golden-тест  →  test/tune на ЖИВОМ коде
                                                      ↑                          │
                                          FP → фикс точности  ←──────────────────┘
```

`shadow.py` меряет ЧЕСТНЫЙ recall на реальных victim-контрактах (DeFiHackLabs/DeFiVulnLabs).
`calibrate.py` калибрует clean-вердикты против публичного ground-truth → precision/recall + слепые пятна.

---

## 🚀 Быстрый старт

```bash
source toolkit/env.sh                 # PATH (forge/solc/brew) + Etherscan-ключ
python toolkit/brief.py               # утренний дашборд: что свежего
python toolkit/scout.py --source all  # сорсить свежую волну целей
python toolkit/recon.py <repo>        # статика по склонированному репо
python toolkit/ityfuzz_lane.py <addr> --chain eth --block N   # динамический фуз (in-scope!)
python toolkit/dashboard.py           # визуальный штаб
python tests/test_detectors.py        # 658 golden-тестов (CI-гейт)
```

---

## 🎯 Честный статус

- **Движок:** собран end-to-end, упакован в скилл `/hunt`, **658 golden-тестов** зелёные (CI-гейт).
- **Находки:** НОЛЬ live-находок с impact на счету — все при строгом VERIFY свелись к
  non-live / hardened / non-callable. Это **честная калибровка**, не маркетинг.
- **Урок:** достижимое пространство доминируют закалённые/аудированные деплои → плотность находок
  упирается в **СВЕЖЕСТЬ**, не в тулинг. Реальный рычаг — быть ПЕРВЫМИ на свежем in-scope коде
  (на это и работают радары), + динамический авто-find (ItyFuzz) на fresh/keyable таргетах.
- **Что реально построено:** reach-ключ (64 сети), fan-out-невод, txlist-liveness, callability-gates,
  DeFiHackLabs-mining, secrets-sweep на масштабе in-scope, и **платформа** (контракт+MCP+web).

---

## ⚖️ White-hat (жёстко)

Только in-scope авторизованные баунти · ответственное раскрытие · **чужие средства не трогаем** ·
динамический фуз — только на ФОРКЕ · известный/исправленный баг ≠ находка · **egor раскрывает, не я**.

---

*Контекст для Claude Code — `CLAUDE.md`. Методология L4 — `toolkit/L4-READ.md` + `toolkit/VERIFY.md`.
Роадмап тулинга — `research/tooling-research/ROADMAP.md`.*
