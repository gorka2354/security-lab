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
                        21 детектор, быстрый триаж, приоритет [!]
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

**Цикл самосовершенствования:** изучили реальный баг → добавили в картотеку + детектор → ловим класс на любом репо. Ложная тревога → подтачиваем (за разработку — **23 фикса точности**, свежие — из живого таргета Morpho Midnight). Каждый вердикт пишется в **ledger**, поэтому уже разобранные лиды больше не всплывают — **шум падает с каждым прогоном**. Чем больше примеров — тем умнее система.

**Пайплайн «паттерн → детектор → инвариант»** (`research/` → `recon.py` → `invariant-lab/`): каждый класс багов изучаем в [`research/patterns/`](research/) (T0→T3 + примеры), статически-ловимое куём в детектор recon, а reasoning-слой (T2/T3) — в **самопроверяющийся invariant-шаблон**. Прогнан на живом коде обоими плечами: детекторное (Morpho Midnight) + инвариантное (реальный OZ ERC4626).

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
- **Мост построен ✅ (секция 5 `hypothesize.py`):** анализатор кормит гипотезатор — recon-флаг функции
  + общее состояние = **авто-предложение emergent-гипотезы ТЕКСТОМ** (детерминированно, без API). На agotchi
  выдал `setERC1155Listing` (recon: access/sibling) ∩ `s.nextERC1155ListingId` (3 writer'а) → готовая гипотеза.
  Генерация = чистая математика; верификация = L4 (я, в интерактиве бесплатно; API нужен лишь автономному режиму).

## Карта папки
```
security-lab/
├─ README.md / CLAUDE.md / ROADMAP.md / PLAYBOOK.md  ← вход · контекст · роадмап · цепочка охоты
├─ toolkit/
│   ├─ scout.py                       ← STAGE-0 ОПТИМИЗАТОР: авто-discovery свежих contest-репо (GH org'ы) + ledger-supp + ранг
│   ├─ orchestrate.py · diffscan.py   ← ОБЪЁМ (скан+ранг targets.txt) · СВЕЖЕСТЬ (audit-drift)
│   ├─ recon.py                       ← L1 сканер: 21 детектор наших эвристик
│   ├─ fetch_source.py · livecheck.py ← LIVE-FIRST: verified-source по адресу · дрейф impl vs аудит
│   ├─ scope.py · analyze.py          ← карта функций/ролей · L2 Slither + кросс-корреляция
│   ├─ hypothesize.py · scaffold.py   ← теории атакующего (их инварианты как данные) · L3 invariant-харнесс
│   ├─ ledger.py · watch.py · pdftext.py  ← память вердиктов · cron-монитор парковок · текст из аудит-PDF
├─ research/            ← БИБЛИОТЕКА ПАТТЕРНОВ (T0→T3): паттерн → детектор → инвариант
│   └─ TEMPLATE.md + patterns/{accounting,pricing,liquidation,signatures}/  (6 паттернов)
├─ invariant-lab/       ← T2/T3: 6 самопроверяющихся invariant-шаблонов (test/templates/) + wire к реальному OZ
├─ hunts/               ← логи охот (HUNT.md) + склонированный код (gitignored)
├─ monitor/watchlist.json  ← припаркованные находки → watch.py следит, [FIRED] при деплое
├─ tests/test_detectors.py ← 134 golden-fixture проверок (CI-гейт)
└─ nomad-poc/ oracle-poc/  ← Foundry PoC
```

## 21 детектор (recon.py)
disabled-signals · access-control · **sibling-inconsistency** · supply-integrity (mint/burn) ·
reentrancy (CEI) · arbitrary-call (approval-drain) · **signature/ecrecover** (replay) ·
**domain-separator** (cross-chain/fork replay) · **UUPS upgrade-safety** · **unchecked ERC20 return** ·
**ERC4626 inflation** · **reward/claim-accounting** (double-claim) · oracle 3-guard (+spot-reserve sub-check) ·
**interest-index inflation** (Aave-fork empty-market) · **liquidation-math** · **weak-randomness** (predictable on-chain RNG, GameFi) ·
**swap-slippage/deadline** (sandwich/MEV) · **mapping-default-trust** (Nomad) · **strict-balance-equality** (force-feed DoS) ·
dangerous primitives · **L2/AA-footguns** (zkSync).
Access-control (sibling+access) объединены в группу — один вердикт гасит оба. Каждый детектор — **lead, не verdict**.
5 новых детекторов + 2 уточнения выкованы из библиотеки паттернов (`research/`) и живых охот; закалён **fix#14–#25**
(последние fix#24/#25 + `det_weak_randomness` — из GameFi-прогона EtherOrcs/Wolf Game).

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
- ✅ 7 классов багов + 7 эвристик в картотеке; **21 детектор**; закалён **31 фиксом** (fix#14–#31; #27/#28 Centrifuge, #29/#30 dreUSD-контест, #31 bare-mint-делегатор из живого Mellow-контеста)
- ✅ **research/** — библиотека из 6 баг-паттернов (T0→T3) + TEMPLATE; пайплайн паттерн → детектор → инвариант
- ✅ **invariant-lab/** — 6 самопроверяющихся invariant-шаблонов + wire к реальному OZ ERC4626 (25 тестов, fmt-чисто)
- ✅ **Регресс-тесты** (`tests/test_detectors.py`, **134** golden-fixture проверок) — жёсткий гейт: фикс не сломает другой детектор молча
- ✅ **ledger** (память вердиктов) — шум падает каждый прогон; **diffscan** — хантинг по audit-drift
- 🎯 Живые тесты пайплайна: **Morpho Midnight** (детекторное плечо → fix#21/#22/#23) · **реальный OZ ERC4626** (инвариантное → находка «экономическая vs абсолютная защита»)
- 🎯 Охоты: Nomad (учебная) + Exactly/YO/Cap/Likwid/TermMax/Crypto-Unicorns/Morpho-Midnight (триаж — все добротны)
- 🔎 Парковка: `monitor/watchlist.json` (Malda LZ bridge + Cap upgrades) → `watch.py` следит
- 📌 Бэклог в `ROADMAP.md` (MCP-сервер отложен)
