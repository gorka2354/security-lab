# Hunt log: Exactly

Шаблон лога охоты (переиспользуй для любого таргета). Заполняется по [[WORKFLOW]].

## Target
- **Протокол:** Exactly — кредитный (fixed/variable rate), **Optimism (L2)**
- **Код:** github.com/exactly/protocol → склонирован в `./protocol`
- **Баунти:** Immunefi — Critical $25k / High $10k
- **Scope:** https://immunefi.com/bug-bounty/exactly/information/

## Прошлые аудиты (что УЖЕ найдено — туда не лезем)
- Coinspect (4+ раунда) + ABDK Consulting
- EXA-1..36: манипуляции наградами, ликвидации, bad debt, оракулы (EXA-15 decimals, EXA-36 liveness)

## Known issues (НЕ eligible — проверять ДО любого репорта!)
- **EXA-36 / deprecated Chainlink API** (`latestAnswer`, нет staleness) — упомянут как known issue
- Сверяться: docs.exact.ly/security/audits

## Лог зацепок
| # | Зацепка | Где | Класс | Статус |
|---|---------|-----|-------|--------|
| 1 | `latestAnswer()` без staleness | `Auditor.sol:356` `assetPrice()` | оракул | ❌ **KNOWN (EXA-36)** — не репортим |
| 2 | сложный reward-аккаунтинг (rounding/averaging) | `StakedEXA.sol` `_update`/`claimWithdraw`/`claim_` | accounting | 🔍 **INVESTIGATING** — нужны инварианты |
| 3 | `harvest()` пермишенлес → `notifyRewardAmount` | `StakedEXA.sol:347` | timing/griefing | 🔍 INVESTIGATING — вероятно by design |
| 4 | ERC4626 inflation surface | `StakedEXA` (ERC4626Upgradeable) | first-depositor | ❓ проверить dead-shares митигацию |

### Лид #1 — детали
`assetPrice()` читает `priceFeed.latestAnswer()` — депрекейтнутая функция, не отдаёт `updatedAt`, значит staleness проверить **нельзя**. Это ровно наш класс (EXA-36).
- ✅ есть `price <= 0` revert
- decimals — через `baseFactor` (масштабирование, ок)
- **ВЕРДИКТ:** технически реальный gap, НО это EXA-36 — он в аудите и среди known issues. На L2 (Optimism) ещё и нет проверки sequencer uptime — но это тот же известный класс.
- → **НЕ находка.** Фильтр «known» сработал и спас от репорта известного бага.

## Audit drift — результаты ✅
`git log` подтвердил: **`StakedEXA.sol` создан 2024-05-08, правился до 2024-08-21** — на год+ позже аудитов (2022–нач.2023). Ядро аудита его НЕ покрывало. Свежие коммиты: crosschain mint/burn, патчи initialize/initialize2, fix double-count в Market. → Это прайм-территория.

Прочитали reward-логику. Контракт **нестандартный и сложный**: штрафы за раннее снятие, взвешенное среднее `avgStart`/`avgIndexes`, много ceil-div (`(n-1)/total+1`) и пропорционального округления в `claimWithdraw`/`claim_`/`_update`.

### Честный вердикт
Это **зацепки, не баги**. Сложный accounting нельзя подтвердить глазами — это будет та же ошибка, что и «нашёл отсутствие проверки = нашёл баг». Такую математику ловят **инвариантным фаззингом**, а не чтением.

## Следующий шаг (правильный инструмент)
- [ ] **Foundry invariant-тесты на StakedEXA** — кодируем инварианты и пусть фаззер их ломает:
  - сумма выплаченных reward'ов ≤ профинансированных (`notifyRewardAmount`)
  - юзер не может заклеймить больше, чем `earned` с учётом штрафа
  - `totalAssets()` / share-аккаунтинг консистентны после deposit/withdraw/transfer
  - никакая последовательность deposit→harvest→claim не даёт юзеру больше его доли
- [ ] Отдельно: проверить ERC4626 inflation (есть ли `_decimalsOffset`/dead-shares)
- [ ] Любую реальную поломку → фильтр known (сверить с прошлыми отчётами) → PoC → репорт
