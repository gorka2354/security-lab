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
  `recon.py` (L1, 32 детектора), `ledger.py` (память вердиктов), `scaffold.py` (L3, мульти-движок:
  Foundry/Echidna/Medusa/Halmos), `analyze.py` (L2), `deepdive.py` (per-target bespoke-workspace для
  глубокого копания: differential-модель / bespoke-инвариант / state-machine), `activity.py` (LIVE-FIRST
  Phase-0/1 гейт: active+value? иначе park/skip — ДО глубокого чтения). Динамический слой локально —
  WSL-лейн (`toolkit/WSL-LANE.md`).
- **Охоты:** `security-lab/hunts/<target>/HUNT.md` — лог триажа (ноты в репо, клоны в `hunts/_volume/` gitignored).

## Правила
- **White-hat жёстко:** тестируем только in-scope авторизованных баунти; ответственное раскрытие; **чужие средства не трогаем**. Известный/исправленный баг ≠ находка.
- Foundry стоит, но не в PATH: префикс `export PATH="$HOME/.foundry/bin:$PATH"`.
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
  **v3 Immunefi** (точные in-scope адреса+выплата); `contest_monitor.py` (**тайминг-эдж**: cron алертит на
  свежий контест → хантим первыми). Сектор расширен на GameFi/гэмблинг/лотереи/предикшн.
- **REACH:** `fetch_source.py` (verified-source по адресу; **Etherscan-ключ** в env → покрытие шире Sourcify)
  + **DefiLlama-Adapters** как источник CORE-адресов (не gov-токен).
- **TRIAGE:** `forkdrift.py` — форк-ли аудированного base (Lagoon/M^0/Aave/Compound…) + substantive-диф
  дрейфа + audited-ли? → роутер (drift / out-of-scope / economic / greenfield). LIVE-FIRST.
- **DETECT:** `recon.py` (**32 детектора**) + `hypothesize.py` (shared-state seeds + инвариант-меню
  CORE/ECONOMIC/GAMEFI). Память `ledger.py` гасит шум.
- **L4 (я):** `toolkit/L4-READ.md` (4 mindsets × 4 lenses + Feynman + what's-missing + coupled-state) →
  `toolkit/VERIFY.md` (8 kill-gates + 10 FP-паттернов; «FP хуже miss'а»). Методология заимствована у Krait (MIT).
- **193 golden-теста** (CI-гейт). Цикл самоулучшения: баг → детектор; FP → точность.

**Находки:** 1 подтверждённая — **Ledgity (Medium, PoC)**; остальные (RockSolid/Royco/Stobox/Alchemix/Syntropia/
Monetrix-bench…) свелись к clean/audited/forks. **Урок сессии:** достижимое hunting-пространство доминируют
аудированные/платформенные деплои → finding-density упирается в **свежесть+достижимость** цели, не в тулинг.
Поэтому: contest_monitor ловит свежие контесты, reachability-стек достаёт CORE-код, EV-ставка — live-контесты
(гарантированно недо-ревьюнуты) + GameFi-ниша (твой эдж). Бэклог: Solodit-кросс-реф, `shadow.py`-бенчмарк-харнесс.
Точка продолжения — в memory (`next-scout-v2-underreviewed-targets.md`).
