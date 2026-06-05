# Hunt log: Infrared (Berachain)

## Target
- **Протокол:** Infrared — Berachain liquid staking + reward distribution (iBGT, MultiRewards vaults)
- **Код:** `cantina-competitions/infrared-contracts` → склонирован в `./contracts`
- **Тип:** reward distribution (MultiRewards, Synthetix/curve-style) — под наш invariant-навык
- **Экосистема:** Berachain (менее популярная — больше шансов)

> [!warning] ВАЖНО: это репозиторий аудит-КОНТЕСТА Cantina
> Значит код уже ревьюили десятки участников, а **findings скорее всего опубликованы**. Любую зацепку СНАЧАЛА сверять с результатами контеста (фильтр «known»). Для **обучения** это идеально: можно найти самому, потом проверить себя по публичным findings.

## Их собственные инварианты (`tests/invariant/foundry/InvariantsInfrared.sol`)
- 4 активных (в основном conservation: `ibgt minted == bgt rewards`, `delegated <= balance`).
- **3 ЗАКОММЕНТИРОВАНЫ** (строки 241/253/264) — сигнал ханта.

## Лог зацепок
| # | Зацепка | Где | Класс | Статус |
|---|---------|-----|-------|--------|
| 1 | отключён инвариант «только whitelisted токены распределяются» | `InvariantsInfrared.sol:241` | whitelist bypass | ⚠️ LIKELY MITIGATED — проверка есть в коде |

### Лид #1 — РЕЗУЛЬТАТ раскрутки
Прочитал `RewardsLib.harvestBribes` (строка 208):
```solidity
for (...) { if (!whitelisted[i]) continue; ... }   // строка 220: скипает не-whitelisted
```
→ Проверка whitelist **присутствует**. Плюс по дизайну ibgtVault получает только iBGT/RED (`harvestVault`) и wbera (`collectBribesInWBERA`, брайбы конвертятся через collector). Сценарий «не-whitelisted токен распределяется в ibgtVault» выглядит **закрытым**.

**Вывод:** скорее всего ложная тревога. Отключённый инвариант — артефакт теста (старая версия / тяжёлый setup), а не живой баг. Нормальный исход: большинство зацепок при раскрутке отваливаются. Дисциплина «прочитать код, а не радоваться» сработала.

> [!note] Не до конца закрыто (если возвращаться)
> `whitelisted[]` вычисляется ВЫЗЫВАЮЩИМ (`Infrared.sol` harvestBribes) — trust boundary. Полная проверка = убедиться, что флаги всегда берутся из `whitelistedRewardTokens`. И можно РЕ-АКТИВИРОВАТЬ отключённый инвариант + прогнать фаззер → эмпирически подтвердить.

### Реальный known-finding из этого контеста — РАЗОБРАН ✅
`InfraredV1_5.claimExternalVaultRewards()` — **нет access-control на msg.sender**: любой клеймит external-vault BGT-награды за юзеров, назначивших Infrared оператором.
- **Severity: Medium/Low** (не critical): награды текут в обычную раздачу, не атакующему; нужна прекондиция; импакт операционный/тайминговый. Фикс = `onlyKeeper`.
- **Главная техника:** это РЕГРЕССИЯ — V1_4 гейтил аналог `claimBGTIncentives()` через `onlyKeeper`, V1_5 забыл. Ищется сравнением сиблингов/версий.
- Исправлено в `69019f8`. Вынесено в паттерн → `Паттерны уязвимостей/Сломанный access control`.
- Версия V1_5 не в нашем клоне (тут более ранняя competition-версия); разбор по отчёту Cantina.

### Лид #1 — детали (сильный!)
Закомментированный инвариант + **комментарий самих разработчиков** (строка 243):
> `// non whitelisted token that can be part of the rewards array in the harvestValidator function`

Они сами пишут, что не-whitelisted токен **может попасть в массив наград** при харвесте. Инвариант «такой токен не должен иметь `rewardPerToken > 0`» — **отключён**. Если отключили из-за падения → не-whitelisted токены реально распределяются через `MultiRewards` (ibgtVault).

Whitelist-инфра существует (`infrared.whitelistedRewardTokens`, `Voter.sol:423-427` ревертит для брайбов). Вопрос: проверяет ли её путь харвеста к ibgtVault.

Подозреваемая функция: `RewardsLib.harvestBribes(address[] _tokens)` (берёт произвольный массив токенов) и `harvestBase`.

## Триаж recon-зацепок (наш сканер → я как L4)
Прогнали `recon.py`, прочитал топ-`[!]` продакшен-лиды, рассудил:

| Зацепка | Детектор | Вердикт |
|---|---|---|
| `InfraredBERA.sol:165` mint | supply-integrity | FP — backed deposit-mint (платишь BERA → минт iBERA), не «из ничего» |
| `InfraredBERAWithdrawor.sol:132` execute | reentrancy | FP — внешний вызов = trusted view `keeper()`, не атакуемый колбэк |
| `Infrared.sol:467/481/526/536` harvest | sibling | FP — намеренно public-good; gated-соседи делают ДРУГОЕ (админка) |
| `BribeCollector.sol:70` claimFees | reentrancy | FP — «запись» = локалка в цикле; вызовы = трансферы, CEI не нарушен |

**Итог: 4/4 false positive / by-design.** Реалистично для закалённого репо.

**Уроки триажа (записать в навык):**
- reentrancy-детектор не отличает trusted-view от untrusted-callback → разрешаю я / L2-Slither.
- sibling-FP vs реальный (claimExternalVaultRewards): критерий — **есть ли gated-сиблинг, делающий ТО ЖЕ?**
- supply-детектор верно выносит mint-точки; «backed vs from-nothing» решает рассуждение.

## Следующий шаг
- [ ] Прочитать `RewardsLib.harvestBribes` / `harvestBase` → есть ли whitelist-check перед `addReward`/`notifyRewardAmount` на ibgtVault?
- [ ] **Сверить с публичными findings контеста Cantina** (это known или нет?)
- [ ] Если зацепка реальна и не покрыта явным чеком → восстановить отключённый инвариант, прогнать фаззер (наш навык!), получить контрпример
