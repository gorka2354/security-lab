# Hunt log: YO Protocol

## Target
- **Протокол:** YO — ERC4626 yield-волт (депозиты, async-redeem через оператора, fees), Base
- **Код:** `github.com/yoprotocol/core` → `./contracts`. Приватные аудиты (не публичный контест) → больше шансов
- **Баунти:** Immunefi (Crit $5-10k). KYC + PoC + только local-fork (white-hat enforced)
- **Дизайн:** share-price берётся из **YoOracle** (`updateSharePrice` пушит `updater`), а НЕ из totalAssets/totalSupply

> [!warning] White-hat
> Чтение публичного кода + сканер = OSINT (легально). Любая зацепка → проверить known по их аудитам → PoC на local-fork → **ответственное раскрытие через Immunefi**. Не паблик, не эксплуатация.

## Триаж recon-зацепок
| Зацепка | Детектор | Вердикт |
|---|---|---|
| `YoOracle.sol:81` updateSharePrice | sibling | FP — inline-гейт `require(msg.sender == updater)`; **исправил det_sibling** (учитывает inline-auth) |
| `YoVault_V2.sol:270` mint | supply | FP — стандартный ERC4626 backed mint (платишь asset → shares) |

## 🔍 ЛИД #1 — oracle staleness в конвертации волта (ВЫЖИЛ триаж)
**Где:** `YoVault_V2.sol` строки **244, 250, 291, 298** — `(uint256 price,) = IYoOracle.getLatestPrice(...)`.
**Суть:** оракул **возвращает** `(price, timestamp)`, но волт **отбрасывает timestamp** во всех 4 местах и проверяет только `price > 0`. **Нет проверки свежести.**
**Живой код:** `YoVault_V3 is YoVault_V2` и НЕ переопределяет конвертацию → гэп в текущем деплое.
**Импакт:** share-price = цена оракула. Если `updater` встал/задержался → депозиты/redeem по **устаревшей** цене → мисприсинг/дренаж (redeem по stale-high). `maxChangeBps` ограничивает скачок, но НЕ staleness (замёрзшая цена ≠ «изменение»).
**Класс:** [[Оракулы - небезопасное использование Chainlink]] (staleness), наш профильный.

**Статус: ❌ KNOWN — закрыто (не репортим).**

### Верификация
- [x] **Сверка с аудитами YO** → **Hunter Security, 2025-01-21**: ровно этот класс (gap между уходом средств и обновлением оракула/баланса → неверный `totalAssets()` → over-withdraw / over-mint) **уже описан, команда acknowledged**. По Immunefi known/acknowledged = **не eligible**.
- [x] Технически подтвердил: волт отбрасывает timestamp во всех 4 местах, staleness не enforced (наша часть верна).
- Доп. сейфгарды у них: rolling anchor + `maxChangeBps` + auto-pause на больших скачках.

### Вердикт и урок
Лид был **реальный и верно обоснованный** — мы независимо пришли к находке, которую сделали платные аудиторы Hunter Security. **Метод работает.** Но баг **known/acknowledged** → стоп, не репортим. Дисциплина «лид → проверь known → стоп» сработала идеально (спасла от репорта известного бага).

## 🔬 Deep-invariant разбор YoOracle (весь стек end-to-end)
Самодостаточный фаззинг реального `YoOracle` (`oracle-fuzz/`, логика verbatim + Ownable-шим). Вывел **протокол-специфичные** инварианты из логики (не generic):
- **I1** «latest всегда в пределах maxChangeBps от anchor» (ядровая гарантия) → **PASS** (128k вызовов, 0 reverts). Фаззер подтвердил корректность.
- **I2** «latest в пределах maxChangeBps от *начальной* цены» (наивно) → **FAIL** (дрейф 1.33% > 1%). Фаззер нашёл `pushPrice↓→warp→pushPrice↓` → накопительный дрейф через ротацию anchor.

**Вердикт I2:** реальное свойство, но **известный/намеренный дизайн** (maxChangeBps+window задуман для постепенного трекинга доходности, НЕ для абсолютной границы; updater доверенный) → не novel-баг. **Ценность:** фаззер количественно показал «доверенный updater может увести цену неограниченно во времени, не только на maxBps» — это часть trusted-updater risk-surface. Метод (вывести инвариант → фаззить) **отработал на реальном коде**.

## Повторный заход (2026-06-08, batch «новый профиль таргетов»)
Автономный агент **независимо пере-вывел** oracle-staleness лид (L240/246/286/294 в его версии impl) — подтверждает воспроизводимость метода. По памяти этого лога **сразу опознан как KNOWN** (Hunter Security ack) → не репортим. Дисциплина «лид → known → стоп» сработала через hunt-память.

**НОВОЕ (закрывает `manage`-вопрос окончательно):** авторитетная on-chain верификация capability-таблицы RolesAuthority `0x9524…d44D` (406 RoleCapabilityUpdated, replay==live):
- Drain-роль 12 (`USDC.approve` + `WETH.approve/transfer` + array-`manage`) держит **только 3-of-7 операторский Safe** `0x93e5…5927` (Gnosis v1.4.1, threshold=3/7). Не EOA, не public.
- Единственный hot-EOA с `manage` (`0x5c28b54e…`, роли 11/17) **доказуемо** `canCall=0` для USDC/WETH transfer/approve — зафайрволлен на reward-токены.
- 0 public capabilities; `manage(single)` `0xf6e715d0` owner-only (4-of-6 Safe).
- **Вердикт: access correctly bounded — config-critical'а НЕТ.** Worst case = компрометация 3-of-7 Safe (trust-допущение).

**Итог по YO: закрыт.** Единственный код-уровневый гэп (oracle staleness) — known/acknowledged; arbitrary-call surface — безопасно сконфигурен. Не репортим.
