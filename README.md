# 🛡️ security-lab — white-hat bug-hunting движок

Личная система поиска багов в смартконтрактах. Думай о ней как о **детективном агентстве для кода**: облава, металлоискатель, картотека вердиктов, лаборатория и детектив.

## Вид сверху — как работает вся машина

```
      in-scope bounty targets (targets.txt)        git-история (свежесть)
                    |                                       |
      orchestrate.py — ОБЛАВА                    diffscan.py — AUDIT-DRIFT
      скан N репо → ранжирует "cream"            только КОД, изменённый
                    |                            с аудит-тега/даты (там баги)
                    +------------------+------------------+
                                       v
                        recon.py — МЕТАЛЛОИСКАТЕЛЬ (L1)
                        12 детекторов, быстрый триаж, приоритет [!]
                                       |
                        ledger.py — КАРТОТЕКА ВЕРДИКТОВ
                        гасит уже засуженные (FP/known) → вижу только НОВОЕ
                                       | high-signal лиды
         +-----------------------------+-----------------------------+
         v                             v                             v
   analyze.py+Slither           scaffold.py + fuzz             Claude  (L4)
   (L2) AST/dataflow            (L3) краш-тест                 ДЕТЕКТИВ:
   + кросс-корреляция           инвариантов                   реально? known?
         +-----------------------------+-----------------------------+
                                       |
                       вердикт → ledger (шум падает каждый прогон)
                                       v
                  FINDING  →  ответственное раскрытие (bounty)

  +----------------------------------------------------------+
  |  КАРТОТЕКА ЗНАНИЙ (Obsidian "Крипто безопасность")        |
  |  паттерны · эвристики · разборы взломов · findings        |
  |     ^                                                     |
  |     +-- каждый изученный баг  → новый детектор            |
  |         каждая ложная тревога → инструмент точнее         |
  +----------------------------------------------------------+
```

**Цикл самосовершенствования:** изучили реальный баг → добавили в картотеку + детектор → ловим класс на любом репо. Ложная тревога → подтачиваем (за разработку — **13 фиксов точности**, последний — драйвнут тестом). Каждый вердикт пишется в **ledger**, поэтому уже разобранные лиды больше не всплывают — **шум падает с каждым прогоном**. Чем больше примеров — тем умнее система.

**Слои:** L1 быстрый скан (regex) → L2 глубокий анализ (Slither) → L3 краш-тест математики (invariant-фаззинг) → **L4 = я (Claude)** рассуждаю и оркестрирую. Объём (orchestrate) × Свежесть (diffscan) × Глубина (L2/L3) — три оси охоты.

## Два движка → я-верификатор
Система делится на два УНИВЕРСАЛЬНЫХ движка, которые кормят меня (L4), и я подтверждаю/опровергаю:
```
  АНАЛИЗАТОР  (recon/analyze) ─┐  режим РЕВЬЮЕРА: паттерны/структура (что аудит ищет)
                               ├─► Я (L4) ─► PoC / инвариант-фаззинг ─► ✅подтверждено / ❌опровергнуто
  ГИПОТЕЗАТОР (hypothesize)  ──┘  режим АТАКУЮЩЕГО: гипотезы из «данных» (что аудит ПРОПУСКАЕТ)
```
- **«Данные» для гипотез:** статика (инверсные пары, общее состояние) + **их собственные инварианты**
  (комплемент = что они НЕ проверяют) + фаззер (синтетические «юзеры») + on-chain конфиги.
- **Моя роль = верификатор:** гипотезу доказывать инвариантом СИЛЬНЕЕ ихнего, не чтением.
- **Будущее (ROADMAP):** объединить движки — анализатор кормит гипотезатор (структура → авто-гипотезы),
  растить качество обоих. Это путь к багам, которые аудит не нашёл. (метод: vault `Метод - охота гипотезами`)

## Карта папки
```
security-lab/
├─ README.md / CLAUDE.md / ROADMAP.md     ← вход, контекст для меня, роадмап
├─ toolkit/
│   ├─ orchestrate.py     ← ОБЪЁМ: скан многих таргетов + ранг (targets.txt)
│   ├─ diffscan.py        ← СВЕЖЕСТЬ: скан только изменённого кода (audit-drift)
│   ├─ recon.py           ← L1 сканер: 12 детекторов наших эвристик
│   ├─ ledger.py          ← память вердиктов (triage-ledger.json): гасит known FP
│   ├─ analyze.py         ← L2: recon + Slither + кросс-корреляция
│   ├─ scaffold.py        ← L3: генератор invariant-харнесса
│   ├─ targets.txt · security_audit.py · PROMPTS.md · WORKFLOW.md
├─ hunts/               ← логи охот (HUNT.md) + склонированный код (gitignored)
│   ├─ exactly/ infrared/ yo/ stakelink/  (+ yo/oracle-fuzz — deep-invariant)
├─ nomad-poc/ oracle-poc/ invariant-lab/   ← Foundry PoC + invariant-лаба
└─ .github/workflows/   ← CI: security-audit + Slither (L2 на Linux)
```

## 12 детекторов (recon.py)
disabled-signals · access-control · **sibling-inconsistency** · supply-integrity (mint/burn) ·
reentrancy (CEI) · arbitrary-call (approval-drain) · **signature/ecrecover** (replay) ·
**UUPS upgrade-safety** · **unchecked ERC20 return** · **ERC4626 inflation** · oracle 3-guard · dangerous primitives.
Детекторы под access-control (sibling+access) объединены в группу — один вердикт в ledger гасит оба.

## База знаний — отдельно (Obsidian)
`...\Obsidian Vault\Крипто безопасность\` — паттерны, разборы, findings, шаблоны.
**Принцип:** код и охоты → здесь (репо); знания → в Obsidian.

## Быстрый старт
```bash
export PATH="$HOME/.foundry/bin:$PATH"
python toolkit/orchestrate.py                      # ОБЛАВА: скан targets.txt → очередь (с ledger-подавлением)
python toolkit/recon.py <repo>                     # L1 скан одного репо
python toolkit/diffscan.py <repo> --since-days 120 # СВЕЖЕСТЬ: только изменённое за 120 дней
python toolkit/ledger.py add --target X --file F --detector sibling --snippet "function f(...)" --verdict fp --reason "..."
python toolkit/ledger.py stats                     # сколько вердиктов / что гасится
python toolkit/scaffold.py <Contract.sol> <Name>   # сгенерить invariant-харнесс
forge test --root invariant-lab -vvv               # прогнать фаззинг
```
> `diffscan` нужна git-история: orchestrate клонит `--depth 1`, перед diff углубляй
> `git -C <clone> fetch --unshallow --tags`.

## Статус
- ✅ Полный движок: **VOLUME** (orchestrate) × **СВЕЖЕСТЬ** (diffscan) × **DEPTH** (recon → Slither → scaffold+fuzz → L4)
- ✅ 7 классов багов + 7 эвристик в картотеке; **12 детекторов**; закалён **13 фиксами**
- ✅ **Регресс-тесты** (`tests/test_detectors.py`, 29 golden-fixture проверок) — жёсткий гейт в CI: фикс не сломает другой детектор молча
- ✅ **ledger** (память вердиктов) — шум падает каждый прогон; **diffscan** — хантинг по audit-drift
- 🎯 Охоты: Nomad (учебная), Exactly/Infrared/YO/stakelink (триаж), YO oracle (deep-invariant)
- 🔎 Живой лид: `hunts/stakelink/HUNT.md` — оракул-адаптер на mainnet маскирует staleness (impact на доверификации)
- 📌 Бэклог в `ROADMAP.md` (MCP-сервер отложен)
