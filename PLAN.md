# PacketHammer — План: Разделение Server/Client + Полностью Автономный Прогон

Статус: черновик к исполнению. Документ описывает что и зачем менять. Реализация — отдельными
коммитами по секциям. Прогон должен работать в режиме «первый промпт → финальный результат»
без остановок и без участия человека в середине.

---

## 0. Контекст и цель

PacketHammer — контейнеризированный пайплайн LLM-агентов для инференса сетевых протоколов
(server-режим) и реверса клиентских бинарей (client-режим). Активная конфигурация уже
использует раздельные стеки агентов `server-*` и `client-*`, оба пишут в общий путь
`/workspace/netproto/<target>/...`, Frida MCP уже отдаёт client-tools
(`get_connect_attempts`, `set_connect_redirects`, `get_io_events`).

**Главная цель этого плана:**
1. Довести до конца разделение server/client флоу и исправить выявленные баги корректности.
2. Сделать прогон **полностью автономным**: участие человека — только первый промпт; дальше
   ИИ сам принимает решения, сам себя аппрувит, процесс **не останавливается** до получения
   финального результата.

**Зафиксированные решения пользователя (НЕ менять):**
- `OPENROUTER_API_KEY` остаётся в Dockerfile как есть. Секция про ротацию секрета — отменена.
- Всё содержимое `workspace/` остаётся как есть (сертификаты, ключи, sample-артефакты,
  `netproto/`). Repo-hygiene чистка — отменена.
- Общий корень вывода `/workspace/netproto/<target>/...` не переименовывать и не разделять.
- Раздельные server/client стеки агентов сохраняются; общего analyzer/supervisor нет,
  общая только MCP-инфраструктура.
- `client-peer-emulator` — каноническое имя client-side fake peer.

---

## 1. Результаты аудита (сверено с кодом)

Все пункты ниже подтверждены чтением актуальных файлов, а не по памяти.

### Подтверждённые проблемы корректности

| # | Проблема | Где |
|---|----------|-----|
| A | `client-peer-emulator` стартует TCP-сервер, но не имеет lifecycle-контракта (нет pid, readiness, обработки bind-ошибки, cleanup). Fake peer может умереть по завершении хода субагента, а оркестратор включит redirect на мёртвый порт. | `config/opencode/agents/client-peer-emulator.md:1,9` |
| B | Конфликт владения логами: и `client-orchestrator`, и `client-peer-emulator` дописывают `client_sends.log` и `io_events.log` → дубли/рассинхрон. | `client-orchestrator.md:75` vs `client-peer-emulator.md:12` |
| C | `server-protocol-mapper` объявлен «Read-only on all inputs», но инструктирован дописывать в `/workspace/netproto/knowledge.jsonl`. Противоречие прав. | `server-protocol-mapper.md:1` и `:53` |
| D | `*-analysis-supervisor` возвращает `priority_branches` как live-адреса (`0x<live_addr>`), но сам read-only и не получает `image_base`/`rebase_offset` → не может корректно конвертировать Ghidra-адреса в live. | `server-analysis-supervisor.md:27`; аналогично client |
| E | `client-analysis-supervisor` уже частично пропатчен (есть «CLIENT-SPECIFIC FOCUS», запрет `server-packet-crafter`), но input-контракт всё ещё читает `branches.log` вместо client-улик (`state.json`, `packet_graph.json`, `client_sends.log`, `io_events.log`). | `client-analysis-supervisor.md:15,22` |
| F | Frida resolver-хуки пишут hostname, но не парсят возвращённый addrinfo (передают `null` вместо IP); ассоциация host→IP падает на `_lastResolvedHost`. Поздний connect по хардкод-IP может быть ошибочно приписан устаревшему hostname. | `frida-mcp-server.py:241,490` |
| G | Frida `read()`-хук обновляет `_lastRecv` на любом чтении, включая file IO → server-mode `get_last_recv` загрязняется конфиг/файловыми чтениями. | `frida-mcp-server.py:615-616` |
| H | Frida `set_connect_redirects` обрабатывает AF_INET и ограниченный AF_INET6; невалидные правила могут вернуть `ok` с битым портом, без записи ошибок. | `frida-mcp-server.py:951` |
| I | Frida outbound IO покрывает `send/sendto/SSL_write/первый буфер WSASend`; пропущены `write/writev/sendmsg/SSL_write_ex/BIO_write/мульти-буфер WSASend/async Winsock`. | `frida-mcp-server.py` (секция IO-хуков) |
| J | Легаси-имя в активном коде: docstring «net-instrumenter». | `frida-mcp-server.py:4` |

### Уже сделано (план это переоценивал — корректируем объём работ)

- **Конфиг частично вынесен:** промпты агентов уже лежат в `config/opencode/agents/*.md` и
  COPY'ятся (`Dockerfile:211`). В heredoc остался только `opencode.jsonc` (mcp / provider /
  permission / wiring, строки `213–504`). Значит, пункт «вынести конфиг» почти закрыт —
  остаётся только вынести сам `opencode.jsonc`.
- **`workspace/AGENTS.md` уже роутер**, рядом есть `SERVER_AGENTS.md` и `CLIENT_AGENTS.md`.

### КРИТИЧЕСКИЙ ПРОБЕЛ — автономность (в исходном плане отсутствует)

Требование «первый промпт → финальный результат без остановок» не покрыто. Конкретно:

| # | Пробел | Где |
|---|--------|-----|
| K | Нет неинтерактивной точки входа. `CMD … exec /bin/bash` — интерактивный shell/TUI. Никто не инъектирует первый промпт и не запускает headless-прогон. | `Dockerfile:541` |
| L | Авто-аппрув есть только у 2 оркестраторов. `permission`-блоки заданы лишь для `server-orchestrator` и `client-orchestrator`. У **сабагентов** (instrumenter'ы, peer-emulator, code-analyzer и т.д.), которые реально дёргают bash/frida/ghidra, permission-блоков нет → opencode по умолчанию спросит аппрув → **пайплайн встанет**. | `Dockerfile:396,418` (и отсутствие блоков на сабагентах `437–501`) |
| M | Нет внешнего watchdog-цикла. Единственная «гарантия» безостановочности — фраза `KEEP RUNNING` в промпте оркестратора, адресованная локальной квантованной модели. Нет рестарта при исчерпании контекста, зависании или краше. | `client-orchestrator.md:12` |
| N | Нет явного терминального условия на уровне раннера и доставки финала наружу. Не определено, что считать «готово» и как отдать финальный артефакт. | — |

---

## 2. Изменения корректности (Server/Client флоу)

Формат: Как есть / Проблема / Как будет / Исправление.

### 2.1 Client flow — `client-peer-emulator` lifecycle (проблема A)

- **Как есть:** «Start a TCP server … run it», без контракта жизни процесса.
- **Проблема:** peer умирает в конце хода субагента; redirect уводит на мёртвый порт.
- **Как будет:** peer пишет скрипт, стартует **долгоживущий** локальный процесс, возвращает
  `pid`, `ready=true`, `local_port`, `script_path`; ведёт `peer_events.log`.
- **Исправление в `client-peer-emulator.md`:**
  - Запуск через `nohup`/двойной fork (или `setsid`), процесс переживает завершение хода.
  - Записать pid-файл `<target_dir>/scripts/peer_<seq_id>.pid`.
  - Readiness-проверка: после bind подтвердить `LISTEN` (например, локальный connect-пинг)
    перед возвратом `ready:true`.
  - Bind failure handling: если порт занят и `local_port!=0` → вернуть
    `{"ok":false,"error":"bind_failed","port":N}`; при `local_port=0` выбрать свободный.
  - Cleanup/restart: при повторном `seq_id` сначала убить старый pid из pid-файла.
  - Вернуть JSON последней строкой:
    `{"ok":true,"pid":N,"ready":true,"local_host":"127.0.0.1","local_port":N,"script_path":"...","protocol_observed":"...","tls":{...}}`.

### 2.2 Client flow — владение логами (проблема B)

- **Как есть:** оба агента дописывают `client_sends.log`/`io_events.log`.
- **Как будет:** Frida-истина по payload принадлежит **только** `client-orchestrator`;
  peer-side наблюдения идут в `peer_events.log`.
- **Исправление:**
  - `client-peer-emulator.md`: убрать строку про append в `client_sends.log`/`io_events.log`;
    писать только `peer_events.log` (своя сторона: что peer принял/ответил, SNI/ALPN, cert-bypass).
  - `client-orchestrator.md`: остаётся единственным владельцем `client_sends.log` и
    `io_events.log` (как сейчас на `:75`). Добавить явную фразу «единственный писатель».

### 2.3 Client flow — `client-analysis-supervisor` контракт (проблема E)

- **Как есть:** читает `branches.log`, выдаёт server-style probe-рекомендации.
- **Как будет:** анализ stale connect-триггеров, отсутствующих redirect'ов, пустого IO,
  TLS/cert-блокеров, расхождения `original_dst` vs `redirect_dst`.
- **Исправление в `client-analysis-supervisor.md`:**
  - Сменить input-контракт: читать `state.json`, `packet_graph.json`, `client_sends.log`,
    `io_events.log` (не `branches.log` как основную траекторию).
  - Output: вместо server-«probe AUTH command …» давать client-рекомендации
    (re-trigger connect, проверить redirect-правило, cert-bypass, сменить active_target).
  - Поле адресов: отдавать `priority_ghidra_branches` (Ghidra-адреса), если нет rebase-метаданных
    (см. 2.5).

### 2.4 Server flow — `server-protocol-mapper` права (проблема C)

- **Как есть:** «Read-only on all inputs» + «append … knowledge.jsonl».
- **Как будет:** права и промпт согласованы. **Решение по умолчанию:** разрешить mapper'у
  append именно в `knowledge.jsonl`.
- **Исправление:**
  - В `server-protocol-mapper.md` заменить «Read-only on all inputs» на
    «Read-only на входные логи; единственный разрешённый write — append в
    `/workspace/netproto/knowledge.jsonl`».
  - В `opencode.jsonc` дать mapper'у `edit`-право только на `knowledge.jsonl` (если права
    разруливаются на уровне permission).

### 2.5 Server/Client supervisor — адреса и rebase (проблема D)

- **Как есть:** supervisor отдаёт live-адреса, не имея rebase-входа.
- **Как будет:** supervisor возвращает Ghidra-адреса, если rebase-метаданные не переданы.
- **Исправление (оба supervisor'а):**
  - Либо добавить `image_base` и `rebase_offset` во input-контракт supervisor'а,
  - **либо (по умолчанию)** переименовать выходное поле `priority_branches` →
    `priority_ghidra_branches` и убрать `<live_addr>` из описания. Оркестратор сам
    конвертирует в live по своим rebase-данным.

---

## 3. Frida client oracle и redirect (проблемы F–J)

Файл: `frida-mcp-server.py` (встроенный JS-агент + Python-обёртка MCP).

### 3.1 Точная ассоциация resolver-результата (F)

- **Исправление:** в хуках `getaddrinfo`/`GetAddrInfoW` на `onLeave` при успехе пройти
  связный список `addrinfo`/`hostent`, извлечь реальные IP и вызвать `_recordResolve(host, ip, …)`
  с настоящим IP (сейчас передаётся `null`, `:490`). Fallback на `_lastResolvedHost` использовать
  **только** когда совпадает timestamp/service.

### 3.2 Валидация redirect-правил (H)

- **Исправление в `set_connect_redirects` (`:951`) и JS-стороне:**
  - Валидировать `local_port`, `original_port` (1–65535), формат `host`/`ip`.
  - При невалидном правиле — не возвращать `ok:true`; писать `redirect_errors` или error-запись
    в `connect_attempts`.
  - Корректно обрабатывать IPv6 localhost (`::1`) и mismatch семейства адресов.

### 3.3 Расширение outbound IO хуков (I)

- **Как будет:** v1 пишет общие пути и **явно** репортит неподдержанные; v2 расширяет.
- **Исправление:** добавить хуки `write`, `writev`, `sendmsg` (Linux), `SSL_write_ex`,
  `BIO_write`, агрегацию мульти-буферного `WSASend` и async Winsock completion (Windows).
  Неподдержанные пути логировать как `unsupported_io_path`, не молча терять.

### 3.4 Защита `_lastRecv` от file IO (G)

- **Исправление:** `_lastRecv` обновлять **только** для сокет-fd. Трекать сокет-fd из
  `socket`/`accept`/`connect`; в `read()`-хуке (`:615`) обновлять `_lastRecv` лишь если
  `this._fd` — известный сокет и НЕ присутствует в `_fdPaths` (файловые дескрипторы).

### 3.5 Легаси-имя (J)

- **Исправление:** в docstring `frida-mcp-server.py:4` заменить «net-instrumenter» на
  актуальное «server-instrumenter / client-instrumenter».

---

## 4. Документация и комментарии (косметика, проблема J и докстринги)

- Заменить остаточные легаси-имена (`net-instrumenter`, `packet-crafter`, `protocol-mapper`
  без префикса) в активных доках/комментариях.
- `SKILL.md`, `docs/index.html`, сгенерированные доки — либо обновить, либо явно пометить как
  legacy, чтобы не сбить следующего агента.
- Сохранить `/workspace/netproto/<target>/...` как общий путь вывода во всех текстах.
- `workspace/AGENTS.md` оставить коротким роутером, но **продублировать** критичные
  server/client-инварианты прямо в промптах соответствующих orchestrator/instrumenter
  (на случай если opencode авто-грузит только `AGENTS.md`, а не mode-specific файлы).

---

## 5. Вынос `opencode.jsonc` из Dockerfile (опционально, низкий приоритет)

- **Как есть:** `opencode.jsonc` — большой heredoc в Dockerfile (`213–504`). Промпты агентов
  уже вынесены в `config/opencode/agents/*.md`.
- **Как будет:** `opencode.jsonc` лежит как трекаемый файл-шаблон, Dockerfile его COPY'ит,
  затем инъектит API-ключ из env (строка `:539` остаётся).
- **Исправление:** перенести heredoc в `config/opencode/opencode.jsonc`; заменить heredoc на
  `COPY config/opencode/opencode.jsonc /root/.config/opencode/opencode.jsonc`. Строковые правки
  большого JSON в Dockerfile хрупкие — вынос упрощает поддержку. **Ключ в `apiKey` остаётся
  пустым в файле и подставляется на build из env (как сейчас).**

---

## 6. АВТОНОМНОЕ ИСПОЛНЕНИЕ (главная новая секция)

Цель: участие человека = первый промпт. Дальше — без остановок до финального артефакта.
Четыре независимых механизма; нужны все.

### 6.1 Неинтерактивная точка входа (пробел K)

- **Как есть:** `CMD ["/bin/bash","-c", "... && exec /bin/bash"]` (`Dockerfile:541`) — интерактив.
- **Как будет:** контейнер при старте принимает первый промпт и запускает headless-прогон
  нужного оркестратора без TUI.
- **Исправление:**
  - Добавить `/opt/run-pipeline.sh`, который:
    1. Читает режим (`server`|`client`) и `target` из env (`PH_MODE`, `PH_TARGET`) или argv.
    2. Читает первый промпт из env `PH_PROMPT` или из файла `/workspace/INIT_PROMPT.txt`.
    3. Запускает headless: `opencode run --agent <mode>-orchestrator "<первый промпт>"`
       (точный флаг неинтерактивного запуска свериться по `opencode --help` в образе;
       wrapper уже есть — `Dockerfile:185-192`, использовать его).
  - Новый `CMD`: `["/bin/bash","-c","/opt/start-ghidra-mcp.sh && /opt/check-models.sh && exec /opt/run-pipeline.sh"]`.
  - Для отладки оставить переменную `PH_INTERACTIVE=1`, которая возвращает `exec /bin/bash`.
  - Первый промпт — фиксированный шаблон INIT (как в server-флоу), оркестратор не добавляет
    отсебятины.

### 6.2 Тотальный авто-аппрув инструментов (пробел L) — КРИТИЧНО

- **Как есть:** `permission`-блоки только у 2 оркестраторов; сабагенты без них → opencode
  спросит аппрув на bash/frida/ghidra → стоп.
- **Как будет:** ни один tool-call в пайплайне не требует ручного аппрува.
- **Исправление (любой из двух путей; рекомендуется оба слоя для надёжности):**
  1. **Глобальный авто-аппрув:** в `opencode.jsonc` на верхнем уровне выставить политику
     «не спрашивать» (свериться с актуальной схемой opencode: глобальный `permission` или
     эквивалент авто-allow). Это базовый слой.
  2. **Permission-блоки на каждом сабагенте:** добавить в `opencode.jsonc` для всех
     `*-instrumenter*`, `*-peer-emulator`, `*-code-analyzer`, `*-protocol-mapper`,
     `*-analysis-supervisor` явный `permission` с `allow` на нужные им инструменты
     (instrumenter: frida-live_* + ghidra-headless_* + bash; peer-emulator: bash + edit;
     analyzer: ghidra-headless_* + frida-live_hook_address; mapper: read + edit knowledge.jsonl;
     supervisor: ghidra-headless_list_* + read). Принцип наименьших прав, но **без интерактивных
     запросов**.
  - **Проверка:** прогнать пайплайн без TTY и убедиться, что нет ни одного зависания на
    «approve?». Любой такой зависший вызов — баг этой секции.

### 6.3 Внешний watchdog / restart-loop (пробел M)

- **Как есть:** безостановочность держится только на фразе `KEEP RUNNING` в промпте локальной
  квантованной модели; нет рестарта при исчерпании контекста/зависании/краше.
- **Как будет:** внешний цикл следит за прогоном и продолжает его до достижения терминального
  условия, переживая падения/исчерпание контекста.
- **Исправление — `/opt/run-pipeline.sh` оборачивает прогон в супервизорный цикл:**
  - После каждого запуска `opencode run` проверять терминальное условие (см. 6.4) по
    `state.json`.
  - Если не `done` и не выставлен реальный `tool_blocker`/`exit_reason` — перезапустить
    `opencode run` c **continue-промптом** («продолжи с текущего `state.json`, не сбрасывай
    прогресс»). Оркестраторы уже сохраняют прогресс в `state.json`/`packet_graph.json`, так что
    рестарт идемпотентен.
  - Лимиты безопасности: `PH_MAX_ITERS` (напр. 50) и `PH_WALLCLOCK_SEC` (напр. таймаут на весь
    прогон) — чтобы цикл не крутился вечно при патологии. По достижении лимита — graceful exit
    с `exit_reason="watchdog_limit"`.
  - Детект застоя: если `state.json.steps_total` не растёт N итераций подряд → записать
    `exit_reason="stalled"` и выйти (не крутить пустой цикл).
  - Watchdog НЕ трогает MCP-процессы (инвариант `AGENTS.md:12`) — только перезапускает
    `opencode run`.

### 6.4 Терминальное условие и доставка финала (пробел N)

- **Как есть:** условие выхода описано только в промпте оркестратора, нет машинного критерия
  на уровне раннера и нет выгрузки результата.
- **Как будет:** раннер однозначно определяет «готово» и кладёт финальный артефакт в
  предсказуемое место.
- **Исправление:**
  - **Машинный критерий done** в `run-pipeline.sh`: `state.json.phase == "done"` ИЛИ выставлен
    непустой `exit_reason`/`tool_blocker`.
  - На `done` оркестратор уже зовёт `*-protocol-mapper` → `protocol_model.json`. Раннер после
    выхода собирает **финальный пакет**:
    `/workspace/netproto/<target>/protocol_model.json`, `state.json`, `packet_graph.json`,
    логи (`client_sends.log`/`io_events.log`/`branches.log`/`peer_events.log`), и пишет
    `/workspace/netproto/<target>/RESULT.md` (сводка: режим, target, exit_reason, покрытие,
    путь к модели).
  - Код возврата контейнера: `0` при `phase=done`, ненулевой при блокере/лимите — чтобы внешняя
    автоматизация видела исход.
  - Поскольку `workspace/` смонтирован в хост (`start.sh:22`), финал автоматически доступен
    снаружи без отдельной выгрузки.

---

## 7. План тестирования

### 7.1 Валидация конфига
- `opencode.jsonc` парсится как JSON (встроенный или вынесенный).
- Нет старых активных agent-id: `net-instrumenter`, `packet-crafter`, `protocol-mapper`,
  `code-analyzer`, `analysis-supervisor`, `peer-emulator` (без префикса).
- `server-orchestrator` не может делегировать client-агентов и наоборот (проверка
  `permission.task`).
- **Автономность:** у каждого сабагента, дёргающего bash/frida/ghidra, есть `permission`-блок
  с `allow` (нет пути к интерактивному запросу).

### 7.2 Валидация Frida MCP
- Python AST-parse `frida-mcp-server.py`.
- Встроенный JS — `node --check`.
- `tools/list` включает client-tools (`get_connect_attempts`, `set_connect_redirects`,
  `get_io_events`).

### 7.3 Client-сценарии
- Хардкод-IP клиент: захват оригинального IP/port, redirect на fake peer, сохранены
  `original_dst` и `redirect_dst`.
- Hostname-клиент: распарсен resolver-результат, host→IP корректен, redirect верный.
- TLS-клиент: захват ClientHello/SNI/ALPN на peer и `SSL_write` plaintext когда доступно.
- Redirect failure: `connect_redirect_blocked=true`, нет ложного заявления о покрытии.
- Peer lifecycle: после хода субагента peer-процесс жив (pid из pid-файла отвечает на connect).

### 7.4 Server-сценарии
- Существующий probe-loop использует только server-агентов.
- `get_last_recv` не перезаписывается файловыми чтениями (проблема G).
- Права mapper'а и реальный write в `knowledge.jsonl` совпадают (проблема C).

### 7.5 Автономность (E2E)
- Запуск контейнера без TTY (`docker run` без `-it`) с заданными `PH_MODE`/`PH_TARGET`/
  `PH_PROMPT` доходит до `RESULT.md` без единого ручного аппрува.
- Watchdog: искусственно убить `opencode` в середине — прогон перезапускается с `state.json`,
  прогресс не теряется.
- Лимиты: при искусственном застое цикл завершается с `exit_reason="stalled"`/`watchdog_limit`,
  а не крутится вечно.
- Код возврата контейнера соответствует исходу.

### 7.6 Гигиена
- `workspace/` и API-ключ остаются как есть (по решению пользователя) — НЕ трогать.

---

## 8. Порядок реализации (предлагаемые коммиты)

1. **Frida oracle fixes** (F,G,H,I,J): resolver-парсинг, `_lastRecv` для сокетов,
   валидация redirect, расширение IO-хуков, докстринг.
2. **Client prompts** (A,B,E): peer-emulator lifecycle, владение логами, supervisor-контракт.
3. **Server prompts** (C,D): mapper-права, supervisor-адреса/rebase.
4. **Autonomy** (K,L,M,N): `run-pipeline.sh`, permission-блоки на сабагентах, watchdog,
   терминальное условие + `RESULT.md`, новый `CMD`.
5. **Docs/cosmetics** (раздел 4) и опциональный вынос `opencode.jsonc` (раздел 5).
6. Тесты по разделу 7 на каждом шаге.

---

## 9. Допущения

- Общий корень вывода неизменен: `/workspace/netproto/<target>/...`.
- Раздельные server/client стеки; общая только MCP-инфраструктура.
- Дефолтная client redirect-стратегия — Frida in-process sockaddr rewrite; DNS/hosts только
  fallback.
- `client-peer-emulator` — каноническое имя client-side fake peer.
- `OPENROUTER_API_KEY` и содержимое `workspace/` сохраняются как есть (решение пользователя).
- Точные флаги неинтерактивного `opencode run` и формат глобального авто-аппрува сверяются по
  актуальной версии opencode внутри образа на этапе реализации секции 6.
