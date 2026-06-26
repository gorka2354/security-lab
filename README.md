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
                        41 детектор, быстрый триаж, приоритет [!]
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

**Цикл самосовершенствования:** изучили реальный баг → добавили в картотеку + детектор → ловим класс на любом репо. Ложная тревога → подтачиваем (за разработку — **35 фиксов точности**, свежие — из живых охот: Taiko-разбор → `det_trust_anchor` + калибровки на taiko-mono/zkfair; Thetanuts → `det_vault_share_math`; ZKFair gas-token → `det_decimal_scale`; fix#34 `_checkController` (PowerPool BPool), fix#35 self-burn). Каждый вердикт пишется в **ledger**, поэтому уже разобранные лиды больше не всплывают — **шум падает с каждым прогоном**. Чем больше примеров — тем умнее система.

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
├─ .claude/skills/hunt/SKILL.md       ← `/hunt` — весь пайплайн в одной команде (source→reach→triage→detect→L4-read→verify→prove→record)
├─ toolkit/
│   ├─ scout.py                       ← STAGE-0 ОПТИМИЗАТОР: contests (GH) + DefiLlama (deployed-unaudited, +CORE-repo резолв) + Immunefi via **public-api JSON** (263 прог vs ~198 скрейп; in-scope addrs инлайн + chains + kyc) → ledger-supp + ранг
│   ├─ orchestrate.py · diffscan.py   ← ОБЪЁМ (скан+ранг targets.txt) · СВЕЖЕСТЬ (audit-drift)
│   ├─ recon.py                       ← L1 сканер: 41 детектор наших эвристик
│   ├─ secrets.py                     ← SECRETS-лейн: закоммиченные ключи/креды в дереве + ИСТОРИИ git (Taiko layer-A; язык-агностичен)
│   ├─ legacy.py                      ← СОРСИНГ deprecated-но-funded (Thetanuts-класс): check/from-deployer/from-factory/sweep + --token + age-dormancy
│   ├─ fetch_source.py · livecheck.py ← LIVE-FIRST: verified-source по адресу · дрейф impl vs аудит
│   ├─ forkdrift.py                   ← пост-клон триаж: форк-ли base? + substantive-диф дрейфа + audited-ли? (роутер drift/out-of-scope/economic)
│   ├─ scope.py · analyze.py          ← карта функций/ролей · L2 Slither + кросс-корреляция
│   ├─ hypothesize.py · scaffold.py   ← теории атакующего (их инварианты как данные) · L3 invariant-харнесс
│   ├─ ledger.py · watch.py · pdftext.py  ← память вердиктов · cron-монитор парковок · текст из аудит-PDF
│   ├─ contest_monitor.py             ← ТАЙМИНГ-ЭДЖ: live audit-contests (Cantina/Sherlock/C4) → [NEW]/[FRESH<48ч] → хант первым
│   ├─ registry.py · radar.py         ← **MEMORY+RADAR лейн**: авто-реестр всех триаженных таргетов (zone/chain/fork-base/OWASP-теги, cartography-модель) · радар изменений (impl-upgrade slot-diff + bounty-launch) → `hunts/_radar/QUEUE.md` с прошлыми нотами
│   └─ watch_all.sh · com.security-lab.radar.plist  ← обёртка-планировщик (registry→radar→watch→contests) · launchd-агент (Mac; в облаке — GitHub Actions)
├─ .github/workflows/radar.yml  ← **24/7 радар в облаке**: крон 3ч гоняет registry+radar, коммитит QUEUE.md обратно (без Mac/сна/TCC)
├─ research/            ← БИБЛИОТЕКА ПАТТЕРНОВ (T0→T3) + разборы: паттерн → детектор → инвариант
│   ├─ patterns/{accounting,pricing,liquidation,signatures,gamefi,trust-anchor,bridge}/  (+ bridge sector-playbook, trust-anchor)
│   ├─ registry-radar/  ← PLAN + 11-агентный prior-art ресёрч под MEMORY+RADAR фичу
│   └─ krait-study.md · taiko-sgx-keyleak-study.md · thetanuts-vault-rounding-study.md   ← разборы взломов → детекторы
├─ invariant-lab/       ← T2/T3: 6 самопроверяющихся invariant-шаблонов (test/templates/) + wire к реальному OZ
├─ hunts/               ← логи охот (HUNT.md) + склонированный код (gitignored)
│   ├─ _radar/QUEUE.md  ← session-start work-list (радар пишет, агент читает первым)
│   └─ _parked/parked-leads.md  ← реальные лиды без баунти (Vena/GAIB) → watchlist следит за запуском
├─ monitor/                 ← runtime-стейт (gitignored, кроме watchlist): registry.json/REGISTRY.md · radar-seen.json · ALERTS.md
│   └─ watchlist.json     ← припаркованные находки → watch.py следит, [FIRED] при деплое/баунти
├─ tests/test_detectors.py ← 394 golden-fixture проверок (CI-гейт)
└─ nomad-poc/ oracle-poc/  ← Foundry PoC
```

## 41 детектор (recon.py)
disabled-signals · access-control · **sibling-inconsistency** · supply-integrity (mint/burn) ·
reentrancy (CEI) · arbitrary-call (approval-drain) · **signature/ecrecover** (replay) ·
**domain-separator** (cross-chain/fork replay) · **UUPS upgrade-safety** · **unchecked ERC20 return** ·
**ERC4626 inflation** · **reward/claim-accounting** (double-claim) · oracle 3-guard (+spot-reserve sub-check) ·
**interest-index inflation** (Aave-fork empty-market) · **liquidation-math** · **weak-randomness** (predictable on-chain RNG, GameFi) ·
**swap-slippage/deadline** (sandwich/MEV) · **mapping-default-trust** (Nomad) · **strict-balance-equality** (force-feed DoS) ·
dangerous primitives · **L2/AA-footguns** (zkSync) · **NFT-receiver-hook-reentrancy** (safeMint/safeTransfer callback, #1 GameFi class) ·
downcast-truncation · divide-before-multiply · encodePacked-collision · fee-on-transfer · spot-AMM-as-oracle · self-transfer · pair-reserve ·
unprotected-init · caller-supplied-authority · **trust-anchor** (Taiko: verifier с одним signer/measurement без кворума; zk-SNARK ≠ TEE) ·
**vault-share-math** (Thetanuts: `X*amount/totalSupply` без floor, near-empty manip) · **decimal-scale** (ZKFair: `amount *=//= decimalsFactor` в бридже).
Access-control (sibling+access) объединены в группу — один вердикт гасит оба. Каждый детектор — **lead, не verdict**.
Vyper-файлы recon НЕ сканит, а **громко предупреждает** (не выдаёт false-clean). Закалён **fix#1–#35**
(последние: **#34 `_checkController`** PowerPool BPool, **#35 self-burn** ≠ «anyone can mint»).

## База знаний — отдельно (Obsidian)
`...\Obsidian Vault\Крипто безопасность\` — паттерны, разборы, findings, шаблоны.
**Принцип:** код и охоты → здесь (репо); знания → в Obsidian.

## Быстрый старт
```bash
# /hunt — весь конвейер в одной команде (см. .claude/skills/hunt/SKILL.md): source→reach→triage→detect→L4→verify
export PATH="$HOME/.foundry/bin:$PATH"; export ETHERSCAN_API_KEY="<key>"   # ключ → fetch_source шире Sourcify; на macOS — Foundry+solc через brew (см. toolkit/MAC-LANE.md)
python toolkit/contest_monitor.py                  # ТАЙМИНГ: свежие live-контесты ([NEW]/[FRESH]); cron'абельно
python toolkit/scout.py --source defillama --resolve-top 12   # SOURCE: deployed-unaudited + CORE-repo резолв
python toolkit/scout.py --source immunefi          # SOURCE: in-scope адреса + выплата
python toolkit/fetch_source.py <addr> --chain 1 --proxy --out hunts/_volume/<x>   # REACH: verified-source
python toolkit/forkdrift.py fingerprint <src>      # TRIAGE: форк? audited? → роутер
python toolkit/orchestrate.py                      # ОБЛАВА: скан targets.txt → очередь (с ledger-подавлением)
python toolkit/recon.py <repo>                     # L1 скан одного репо (41 детектор)
python toolkit/secrets.py <repo>                   # SECRETS: закоммиченные ключи в дереве + истории git (Taiko layer-A)
python toolkit/legacy.py sweep --file <addrs>      # СОРСИНГ deprecated-funded (Thetanuts-класс): ранг по value
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
- ✅ **41 детектор**; закалён **35 фиксами** (fix#1–#35; последние: #34 `_checkController` PowerPool BPool, #35 self-burn ≠ mint); recon громко предупреждает на Vyper (анти-false-clean)
- ✅ **Сорсинг-лейны:** `secrets.py` (закоммиченные ключи в дереве+истории git, Taiko layer-A) · `legacy.py` (deprecated-funded, Thetanuts-класс: check/from-deployer/from-factory/sweep + --token) · `scout` bridge-зона
- ✅ **Разборы взломов → детекторы:** Taiko ($1.7M) → `det_trust_anchor` · Thetanuts ($2.1M) → `det_vault_share_math` · ZKFair gas-token → `det_decimal_scale`; **bridge sector-playbook** (Nomad/Wormhole/Ronin/Taiko, detector-vs-L4 карта)
- ✅ **research/** — библиотека из 6 баг-паттернов (T0→T3) + TEMPLATE; пайплайн паттерн → детектор → инвариант
- ✅ **invariant-lab/** — 6 самопроверяющихся invariant-шаблонов + wire к реальному OZ ERC4626 (25 тестов, fmt-чисто)
- ✅ **Регресс-тесты** (`tests/test_detectors.py`, **394** golden-fixture проверки) — жёсткий гейт: фикс не сломает другой детектор молча
- ✅ **ledger** (память вердиктов) — шум падает каждый прогон; **diffscan** — хантинг по audit-drift
- 🎯 Живые тесты пайплайна: **Morpho Midnight** (детекторное плечо → fix#21/#22/#23) · **реальный OZ ERC4626** (инвариантное → находка «экономическая vs абсолютная защита»)
- 🎯 Охоты: Nomad (учебная) + Exactly/YO/Cap/Likwid/TermMax/Crypto-Unicorns/Morpho-Midnight (триаж — все добротны)
- 🔎 Парковка: `monitor/watchlist.json` (Malda LZ bridge + Cap upgrades; Vena/GAIB лиды) → `watch.py` следит
- 🛰️ **MEMORY+RADAR лейн** (новое): `registry.py` — авто-реестр 79 триаженных протоколов (status/zone/chain/fork-base/OWASP + fork-индекс под батч-CVE) · `radar.py` — 24/7 радар (impl-upgrade slot-diff + bounty-launch) → `hunts/_radar/QUEUE.md` с прошлыми нотами; крутится в **GitHub Actions** (крон 3ч). Рециклит утопленный контекст триажа → срезает SOURCE+REACH. Источник усилен: Immunefi via public-api JSON (+33% покрытия, addrs инлайн)
- 📌 Бэклог в `ROADMAP.md` (MCP-сервер отложен)
