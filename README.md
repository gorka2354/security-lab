# 🛡️ security-lab — рабочая папка (bug hunting)

Твой штаб для white-hat поиска багов. Открыл папку — вот что где.

## Карта папки
```
security-lab/
├─ README.md          ← ты здесь (вход)
├─ CLAUDE.md          ← контекст для Claude Code (откроешь меня тут — я всё знаю)
├─ toolkit/
│   ├─ recon.py       ← СКАНЕР: грепает репо по нашим эвристикам, выдаёт приоритезированные зацепки
│   ├─ PROMPTS.md     ← готовые промпты под каждый шаг охоты
│   └─ WORKFLOW.md    ← чек-лист: от зацепки до репорта
├─ hunts/             ← охоты по таргетам
│   └─ exactly/
│       ├─ HUNT.md    ← лог охоты (зацепки + статусы)
│       └─ protocol/  ← склонированный код Exactly
├─ nomad-poc/         ← Foundry PoC: обход проверки (bypass)
└─ oracle-poc/        ← Foundry PoC: оракул staleness
```

## База знаний — отдельно (Obsidian)
`C:\Users\pesto\OneDrive\Документы\Obsidian Vault\Крипто безопасность\`
Там словами: паттерны, разборы взломов, findings, шаблоны, эвристики.
**Принцип:** код и охоты → здесь; знания → в Obsidian.

## Быстрый старт
```bash
export PATH="$HOME/.foundry/bin:$PATH"     # Foundry не в PATH
forge test --root oracle-poc -vvv          # прогнать PoC
```
- Продолжить охоту → `hunts/<target>/HUNT.md`
- Дать мне задачу → скопируй промпт из `toolkit/PROMPTS.md`

## Текущий статус
- ✅ Учебный цикл пройден (Nomad bypass, оракул-staleness) + 2 рабочих PoC
- 🎯 Идёт охота на **Exactly**: лид #1 (`latestAnswer`) = KNOWN (EXA-36); копаем **audit drift**
