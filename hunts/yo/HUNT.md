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
