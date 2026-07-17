# 🛡️ security-lab

[![CI](https://github.com/gorka2354/security-lab/actions/workflows/analyze.yml/badge.svg)](https://github.com/gorka2354/security-lab/actions/workflows/analyze.yml)
[![golden tests](https://img.shields.io/badge/golden%20tests-448%20passing-brightgreen)](tests/test_detectors.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](requirements.txt)

*[English version](README.md)*

> **White-hat движок для поиска багов в смарт-контрактах** — конвейер, который сам находит свежие
> in-scope цели, прочёсывает их статикой и динамикой, помнит каждый вердикт и показывает весь хант
> одним взглядом.

Думай о нём как о **детективном агентстве для кода**: невод сорсит дела, металлоискатель (статика) +
динамический фузер ищут улики, картотека помнит вердикты, радары следят за go-live, а дашборд — это
оперативный штаб.

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  SOURCE  →  REACH  →  TRIAGE  →  DETECT  →  L4 (человек)  →  VERIFY (Gate-0)  →  DISCLOSE│
└──────────────────────────────────────────────────────────────────────────────────────┘
```

| | | |
|---|---|---|
| 🎯 **46** статических детекторов | 🧪 **448** golden-тестов (CI-гейт) | 📡 ежедневный watch parked-лидов |
| 🔑 secrets-sweep (дерево + история git) | 🤖 динамический фуз (ItyFuzz) | 🖥️ дашборд + MCP-платформа |

> **Secret hygiene (проверено):** API-ключ использовался во всех 287 коммитах и **никогда** не был
> закоммичен — `.env`/`*.key` не трекались, ключ встречается в **0** коммитов и **0** файлов дерева.
> Security-репо, который держит свои секреты в чистоте.

---

## 🧭 Как работает вся машина

```
  SOURCE  ── где искать ────────────────────────────────────────────────────────────────
    scout.py          contests (C4/Sherlock/Cantina/Hats) + DefiLlama deployed-unaudited +
                      Immunefi (in-scope адреса + репо)
    freshfeed.py      ново-листингнутый код (DefiLlama listedAt + Sourcify) — стена свежести
    freshdeploy.py    новые контракты от watched-деплоеров/фактори — timing-эдж
        │
  REACH  ── достать код ─────────────────────────────────────────────────────────────────
    fetch_source.py   verified-source по адресу (Etherscan-v2, 64 сети)
    reach_bytecode.py UNVERIFIED-fallback: eth_getCode → восстановить surface из байткода;
                      детектит zkSync/EraVM (EVM-only лейн)
    forkdrift.py      форк-ли аудированного base? + substantive-диф дрейфа (баги в audit-drift)
        │
  DETECT ── найти улики ─────────────────────────────────────────────────────────────────
    recon.py          СТАТИКА: 46 детекторов по сорсу → ГДЕ риск
                      (access / spot-oracle / reentrancy / share-inflation / …)
    ityfuzz_lane.py   ДИНАМИКА: fork-фуз с economic-oracle → ПОДТВЕРЖДАЕТ эксплойт (+ на unverified
                      bytecode). recon наводит → ItyFuzz доказывает.
    decompile_match.py восстановить share-inflation МАТЕМАТИКУ из декомпилированного байткода
    secrets_sweep.py  закоммиченные ключи по in-scope репо (дерево + история git), на масштабе
        │
  L4 (человек) + VERIFY ── доказать и не обмануться ─────────────────────────────────────
    VERIFY.md         Gate-0 LIVE-FIRST + 8 kill-gates + 10 FP-ловушек («FP хуже miss'а»)
        │
  DISCLOSE          только in-scope + ответственно. Раскрывает исследователь, не инструмент.
```

---

## 🧰 Инструменты по лейнам

### DETECT — движок
| Тул | Что делает |
|---|---|
| `recon.py` | **СТАТИКА** — 46 детекторов (access-control, spot-oracle, reentrancy, supply, decimal-scale, trust-anchor, **share-inflation / vault-share-math**, …); FP-тюненные, class-gated, network-agnostic |
| `ityfuzz_lane.py` | **ДИНАМИКА** — обёртка над ItyFuzz: fork-фуз live-адреса, economic-oracle (profit), unverified bytecode |
| `reach_bytecode.py` + `decompile_match.py` | reach + decompile **UNVERIFIED** контракта (surface из байткода → share-inflation math через panoramix/heimdall); EraVM-aware |
| `hypothesize.py` | инвариант-сиды (CORE / ECONOMIC / GAMEFI / BRIDGE) для фуз/символик |
| `secrets_sweep.py` | утечки ключей по in-scope репо (clone + история) |

### SOURCE / REACH / MEMORY
`scout.py` · `freshfeed.py` · `freshdeploy.py` · `contest_monitor.py` (timing-эдж по контестам) ·
`fetch_source.py` (64 сети) · `forkdrift.py` (дрейф аудированного форка) · `activity.py` (LIVE-FIRST гейт) ·
`ledger.py` (персист-вердикты) · `registry.py` (картография целей) · `calibrate.py` (precision/recall фидбэк).

---

## 🎯 Находки (честная калибровка)

Выборка реальной работы — полный лог триажа под `hunts/`:

- **CapyFi** — **live, in-scope** лид oracle-staleness (Gate-0 пройден): закомментированная проверка
  `updatedAt` — это НЕ проверка → окно устаревшей цены (Low–Med). Из промаха заострён `det_oracle`.
- **wager-chess** — **PoC-доказанный HIGH**: on-chain wager-шахматы валидируют аргумент `promotion`
  только для пешек, но применяют его к любой фигуре → легальный ход конём с `promotion=Queen` рождает
  ферзя → мат → кража пота. `wager-chess-poc/` (Foundry 5/5 на реальном движке; деплой на тестнете).
  Дал переносимый паттерн «validation-gap».
- **ThetaNuts** ($2.1M взлом legacy-vault, post-mortem разбор) — воспроизвёл bespoke share-inflation
  как faithful-PoC, **расширил `det_erc4626`** ловить по ФОРМЕ математики (не по имени интерфейса),
  и построил **reach + decompile** лейн: unverified-vault триажится от байткода до самого бага.
- Плюс дисциплинированные **честные negative** (Onchain Heroes, Cambria, Spaceship, Mantle, Lorenzo):
  зрелый закалённый контракт с вердиктом CLEAN — это результат, а не провал.

**Урок:** достижимое пространство доминируют закалённые/аудированные деплои → плотность находок упирается
в **СВЕЖЕСТЬ + скоуп**, не в глубину тулинга. Реальный рычаг — быть ПЕРВЫМ на свежем in-scope коде
(на это работают радары + `freshfeed`) + динамический авто-find (ItyFuzz).

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
python -m pip install -r requirements.txt
python tests/test_detectors.py          # 448 golden-тестов (CI-гейт)
python toolkit/recon.py <repo>          # статика по склонированному репо
python toolkit/scout.py --source all    # сорсить свежую волну целей   (нужен ETHERSCAN_API_KEY)
python toolkit/reach_bytecode.py <addr> <chain>   # surface unverified-контракта
python toolkit/dashboard.py             # → http://127.0.0.1:8787  (визуальный штаб)
```

CI (`.github/workflows/analyze.yml`) гоняет golden-гейт + Slither на каждый push;
`watch.yml` ежедневно опрашивает parked-лиды и аннотирует, когда какой-то срабатывает.

---

## 📁 Структура репозитория

```
toolkit/         движок — 46 статических детекторов + лейны source/reach/dynamic/memory
tests/           448 golden-фикстур (CI-гейт; чистый stdlib, без зависимостей)
hunts/           логи триажа по целям (полный честный лог хантов)
research/        база знаний — паттерны уязвимостей, sector-плейбуки, tooling-ресёрч
*-poc/           самодостаточные Foundry-PoC (nomad, oracle, thetanuts, wager-chess, …)
monitor/ + web/  состояние радаров + дашборд (labcore → MCP + web, один источник правды)
.github/         CI (golden-гейт + Slither) и ежедневный watch parked-лидов
```

---

## ⚖️ White-hat (жёстко)

Только in-scope авторизованные баунти · ответственное раскрытие · **чужие средства не трогаем** ·
динамический фуз — только на ФОРКЕ · известный/исправленный баг ≠ находка · **раскрывает исследователь, не инструмент**.

---

*Контекст для Claude Code — `CLAUDE.md`. Методология L4 — `toolkit/L4-READ.md` + `toolkit/VERIFY.md`.
Роадмап тулинга — `research/tooling-research/ROADMAP.md`.*
