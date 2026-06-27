# security-lab — контекст для Claude Code

Это лаборатория для обучения и практики **white-hat поиска багов в смарт-контрактах**.
Когда работаешь здесь — держи в голове следующее.

## Что это и кто я (пользователь)
- egor (`gorka2354`) — быстрый «вайбкодер», осваивает smart-contract security как хобби.
- Тянет азарт поиска багов и «обходов». Сильная тема: gaming / on-chain games. Знает крипту с пользовательской стороны (фарм аирдропов).
- Пишет по-русски (иногда слетает раскладка — `lf lfdfq` = `да давай`; декодируй).

## Воркфлоу охотника (всегда так)
читаем аудит/код → вычленяем переносимый **паттерн** → воспроизводим **PoC в Foundry** →
оцениваем реальный код по чек-листу → оформляем **finding** по шаблону.
**Всё записываем в Obsidian-vault** (см. ниже).

## Где что лежит
- **База знаний (Obsidian):** `C:\Users\pesto\OneDrive\Документы\Obsidian Vault\Крипто безопасность\`
  (MOC + Взломы и разборы / Паттерны уязвимостей / Аудиты разборы / Findings / Инструменты / Ресурсы / Шаблоны).
- **PoC-проекты (здесь):** `security-lab/<case>` (Foundry). Уже есть `nomad-poc`, `oracle-poc`, `invariant-lab`.
- **Тулкит:** `security-lab/toolkit/` — `orchestrate.py` (облава), `diffscan.py` (свежесть),
  `recon.py` (L1, 41 детектор; вкл. `det_trust_anchor` — verifier с одним signer/measurement без кворума,
  Taiko/Raiko layer-B; `det_vault_share_math` — кастомный волт `X*amount/totalSupply` без floor, near-empty
  share-price manip, Thetanuts $2.1M; `det_decimal_scale` — `amount *=//= decimalsFactor` в бридже/враппере,
  dust/round-to-zero + асимметрия round-trip на non-18 токенах, ZKFair gas-token), `secrets.py` (SECRETS-лейн: закоммиченные ключи/креды в дереве + истории git —
  Taiko/Raiko layer-A; история через `git log -G`, нужен полный клон), `ledger.py` (память вердиктов), `scaffold.py` (L3, мульти-движок:
  Foundry/Echidna/Medusa/Halmos), `analyze.py` (L2), `deepdive.py` (per-target bespoke-workspace для
  глубокого копания: differential-модель / bespoke-инвариант / state-machine), `activity.py` (LIVE-FIRST
  Phase-0/1 гейт: code+own-totalSupply+txlist-liveness+active+value? totalSupply==0 -> EMPTY; getLogs может
  false-0 -> Etherscan-v2 txlist authoritative override (death.fun урок); park/skip — ДО чтения И как
  обязательный pre-disclosure Gate-0 в VERIFY.md. ПЕРЕД severity: txlist-liveness + per-function usage +
  custodial-caller check), `legacy.py` (СОРСИНГ deprecated-но-с-деньгами контрактов — инверсия activity:
  ищет dormant+funded = Thetanuts-класс; `check`/`from-deployer`/`from-factory`(txlistinternal)/`sweep`(ранг
  по value), age-based dormancy, keyless RPC, скип EIP-7702 EOA; урок: класс редкий — нужен широкий свип),
  `calibrate.py` (FEEDBACK-LOOP:
  исход каждой находки accepted/disputed/bounty + калибровка clean-вердиктов против публичного
  ground-truth -> precision/recall + слепые пятна; ground-truth по находкам = egor), `fanout_log.py`
  (ПЕРСИСТ fan-out-невода: типизированная таблица `hunts/_fanout/<date>-<label>.md` по type+chain +
  ledger-suppress dead-ends + DIG в todo-очередь; вердикты TRIAGE-level = гипотезы, deep-dive потом руками).
  Динамический слой локально — WSL-лейн (`toolkit/WSL-LANE.md`). Работа с Mac — `toolkit/MAC-LANE.md`
  (CDN github блокируется: ставь Foundry+solc через brew, `forge test --use /opt/homebrew/bin/solc --offline`).
- **Охоты:** `security-lab/hunts/<target>/HUNT.md` — лог триажа (ноты в репо, клоны в `hunts/_volume/` gitignored).

## Правила
- **СТАРТ СЕССИИ:** `source toolkit/env.sh` (ставит PATH: forge/solc/brew + Etherscan-ключ; чинит слетающий PATH)
  → `python toolkit/brief.py` (утренний дашборд: git-синк + radar `QUEUE.md` + open DIGs реестра + parked-лиды +
  last fan-out; `--fetch`/`--contests` для network). Это первое, что гоняем — заменяет ручной сбор «что свежего».
- **White-hat жёстко:** тестируем только in-scope авторизованных баунти; ответственное раскрытие; **чужие средства не трогаем**. Известный/исправленный баг ≠ находка.
- Foundry/solc не в PATH по умолчанию → `source toolkit/env.sh` (или префикс `export PATH="/opt/homebrew/bin:$HOME/.foundry/bin:$PATH"`).
- `forge init` оставляет `script/Counter.s.sol` — удаляй вместе с `src/Counter.sol`.
- Печатаемый вывод — ASCII (Windows-консоль давится юникодом).
- После каждого разбора — обновляй vault (паттерн + эвристику в MOC).
- **Каждый вердикт триажа — в ledger** (`python toolkit/ledger.py add ...`: fp/known/wontfix/todo/real),
  чтобы тот же лид не всплывал дважды. Найденный по паттерну FP → ещё и фикс точности в детекторе.
- Для свежести гони `diffscan` против последнего аудит-тега, а не весь репо (баги в audit-drift).
- **LIVE-FIRST (урок Malda):** баг ценен, только если он в ЗАДЕПЛОЕННОМ + активном + in-scope коде
  (баунти покрывают деплой; не-деплоенный код вне скоупа, могут не задеплоить / сами пофиксят).
  Проверяй статус деплоя в **Phase 0** (bounty-scope адреса + deployments/broadcast/доки/on-chain) и
  фильтруй дрейф/гипотезы по этому — копай ЖИВОЙ код первым. Не-деплоенную находку фиксируй, но не приоритезируй.

## Текущий прогресс
**Движок собран end-to-end И упакован в скилл `/hunt`** (`.claude/skills/hunt/SKILL.md`) — одна команда
проходит весь конвейер:
- **SOURCE:** `scout.py` — contests (GH) + **v2 DefiLlama** (deployed-unaudited, +CORE-repo резолв) +
  **v3.1 Immunefi via public-api JSON** (`bounties.json` — 263 прог vs ~198 скрейп; in-scope addrs инлайн +
  chains + kyc/inviteOnly-флаги; graceful-fallback на HTML); `contest_monitor.py` (**тайминг-эдж**: `--alert` → exit-10 +
  `monitor/ALERTS.md` на НОВЫЙ+СВЕЖИЙ+our-zone контест. **ALWAYS-ON**: Windows-Task `security-lab-contest-watch`
  каждые 4ч (`toolkit/watch_contests.ps1` → desktop balloon; ставить `toolkit/register_contest_watch.ps1`) —
  алертит на свежий контест ДАЖЕ при закрытом Claude → хантим первыми). Сектор расширен на GameFi/гэмблинг/лотереи/предикшн.
- **REACH:** `fetch_source.py` (verified-source по адресу через **Etherscan-v2** — ключ в env (setx, persistent) →
  ВСЕ 64 chains вкл. Abstract/Mantle/Sonic/HyperEVM/zkSync) + **DefiLlama-Adapters** как источник CORE-адресов.
- **TRIAGE:** `forkdrift.py` — форк-ли аудированного base (Lagoon/M^0/Aave/Compound…) + substantive-диф
  дрейфа + audited-ли? → роутер (drift / out-of-scope / economic / greenfield). LIVE-FIRST.
- **DETECT:** `recon.py` (**38 детекторов**, вкл. `det_spot_oracle` = #1 DeFiHackLabs-класс, `det_self_transfer`/
  `det_pair_reserve_mutation` = BSC token-классы, `det_unprotected_init` = front-run ownership-grab,
  `det_caller_supplied_authority` = calldata-order transferFrom drain) +
  `hypothesize.py` (shared-state seeds + CI-gated `INVARIANT_MENU` CORE/ECONOMIC/GAMEFI/BRIDGE — вкл. DeFiHackLabs
  reasoning-tier сиды: stale-solvency/read-only-reentrancy/flashloan-gov/self-liq/caller-auth/bridge-minted<=locked).
  Память `ledger.py` гасит шум.
- **FAN-OUT (масштаб):** Workflow-невод (агент-на-таргет: reach+forkdrift+recon+gate → структурный вердикт →
  я ранжирую); `fanout_log.py` персист (типизированная таблица `hunts/_fanout/` + ledger-suppress + DIG-очередь).
  Доказан на 2 задачах: triage (Abstract/DeFiLlama-волны) + pattern-mining (DeFiHackLabs 751 хак → 53 паттерна).
- **MEMORY+RADAR (рециклит утопленный контекст триажа → срезает SOURCE+REACH):** `registry.py` — авто-реестр
  всех триаженных таргетов из ledger+fanout (cartography-модель: re-derive каждый ран, MERGE по norm_key,
  firstseen/lastupdated; категории zone/chain/fork-base + OWASP-SC теги; **fork-индекс** под батч-CVE) →
  `monitor/registry.json`+`REGISTRY.md`. `radar.py` — **24/7 радар изменений** по реестру: impl-upgrade
  (EIP-1967 slot-diff) + bounty-launch (Immunefi-JSON), адреса+чейны из авторитетного JSON, дедуп `radar-seen.json`,
  exit-10 → **`hunts/_radar/QUEUE.md`** (session-start work-list с ПРОШЛЫМИ НОТАМИ — читаю первым делом).
  Хостинг: **GitHub Actions** `.github/workflows/radar.yml` (крон 3ч, коммитит QUEUE.md обратно; без Mac/сна/TCC —
  локальный launchd-агент TCC-блокается под ~/Desktop). Метрика силы = hit-rate QUEUE→находка (через `calibrate.py`).
- **L4 (я):** `toolkit/L4-READ.md` (4 mindsets × 4 lenses + Feynman + coupled-state) → `toolkit/VERIFY.md`
  (Gate-0 LIVE-FIRST + 8 kill-gates + 10 FP; «FP хуже miss'а»). **ПЕРЕД severity: callability-gates** —
  txlist-liveness + per-function usage + custodial-caller (урок death.fun). Методология заимствована у Krait (MIT).
- **353 golden-тестов** (CI-гейт). Цикл самоулучшения: реальный хак → детектор → **test+tune на ЖИВОМ коде** (не только golden); FP → точность.
  `shadow.py --corpus defihacklabs` меряет ЧЕСТНЫЙ recall на РЕАЛЬНЫХ victim-контрактах (deployed verified source): HIT 3/4=75%
  на T0-покрываемом+reachable срезе (token-классы ловятся), остальное — reasoning-tier / version-drift / unverified.
  (Примеры: `det_self_transfer`/`det_pair_reserve_mutation` — TP на ВЫТЯНУТОМ on-chain коде BY/LPC/GPU + 0 FP на 8 клонах
  (write-back-тэлл вместо cache-read + reflection-gate). `det_caller_supplied_authority` — calldata-гейт убил Aave-lib FP
  (memory-структура `.user` привязана выше = не attacker-controlled), но широкий класс = reasoning-tier: реальные 2026-хаки
  (MAPProtocol/NewMarketTrading) идут через helper/Safe-module, не inline transferFrom — честно зафиксировано, не оверклейм.)

**Находки (честная калибровка):** НОЛЬ live-находок с impact на счету — все при строгом VERIFY свелись к
non-live / hardened / non-callable: Ledgity (not-live: wrapper undeployed/empty), death.fun (real `increaseBet`-баг
+ PoC, но **non-callable** в custodial-модели), eva/mezo/witty/kona (hardened/known), posi-vaults (dead-target).
**Уроки:** (1) достижимое пространство доминируют закалённые/аудированные деплои → finding-density упирается в
**свежесть**, не в тулинг; (2) **callability ≠ code-bug** — проверяй вызываемость (txlist/per-fn/custodial) ДО severity.
Реальный выигрыш сессий — ДВИЖОК: reach-ключ (64 chains), fan-out-невод+персист, txlist-liveness, callability-gates,
DeFiHackLabs-mining + `det_spot_oracle`. Точка продолжения — memory + `research/patterns/defihacklabs-pattern-mining.md`
(детектор/инвариант-backlog: pair-reserve-mutation, self-transfer, unprotected-init, +reasoning-tier invariant-seeds).
