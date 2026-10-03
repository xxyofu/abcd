# SOC-аналитик: дайджест ИТ/ИБ

**Период:** 30.09.2026 23:59 – 02.10.2026 23:59 UTC  
**Аудитория:** технический специалист SOC, ежедневный дайджест  
**Интересы:** Атаки на организации России, прежде всего энергетику и промышленность: группировки, методы первоначального доступа, инструменты и индикаторы компрометации. Уязвимости корпоративного ПО с публичными эксплойтами и эксплуатацией в атаках.  
**Стек:** Windows Server, Active Directory, Microsoft Exchange, WSUS, SCCM, Windows Defender, 1С, Bitrix, Astra Linux, РЕД ОС, Confluence, GLPI, TrueConf, ESXi, Fortinet, FortiOS, Cisco, PostgreSQL, Kaspersky

## Главное

- CVE‑2026‑104286 в FortiMail активно эксплуатируется, позволяет неавторизованно записать произвольные файлы и включена в каталог CISA KEV, рекомендуется немедленно установить патч. [bleepingcomputer](https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-fortimail-flaw-exploited-in-zero-day-attacks)
- TrueConf Server имеет критическую уязвимость десериализации (CWE‑502) с CVSS 9.8, позволяющую удалённо выполнить произвольный код без аутентификации; выпущены патчи и экстренные обновления. [tg_cyberok](https://t.me/cyberok_news/258)
- Cisco Catalyst SD‑WAN Manager уязвим к CVE‑2026‑76504, позволяющему обходить аутентификацию и получить права администратора; уязвимость уже используется в дикой среде и включена в CISA KEV. [thehackernews](https://thehackernews.com/2026/10/cisa-adds-exploited-cisco-catalyst-sd.html)
- Citrix NetScaler ADC/Gateway содержит две критические уязвимости (CVE‑2026‑88771 и CVE‑2026‑88772), позволяющие без аутентификации создать учётную запись с правами superuser и выполнить произвольные команды; включены в CISA KEV, доступны патчи. [thehackernews](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html)
- MikroTik RouterOS уязвим к CVE‑2026‑84411, целочисленному переполнению в веб‑интерфейсе, которое позволяет удалённо выполнить код с привилегиями root без аутентификации; уязвимость включена в CISA KEV. [xakep](https://xakep.ru/2026/10/02/cve-2026-84411)

## Атака

### 1. [Ransomware Warlock использует уязвимости SharePoint для доступа к целям](https://www.bleepingcomputer.com/news/security/warlock-ransomware-breach-sharepoint-in-water-telecom-operator-attacks)

**Приоритет: Низкий** · 02.10.2026 · `CVE-2025-49704`, `CVE-2025-49706`, `CVE-2025-53770` · в CISA KEV: CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 · релевантность 4/10 · id `30f3dfe0`

1. Страна жертвы: португалоязычные и испаноязычные страны Европы, Африки и Латинской Америки
2. Наименование группировки: Warlock (также известна как Longlegs)
3. Предполагаемая дата атаки: 22 июля 2025 г.
4. Затронутые отрасли/компании: водоканал (water utility), телекоммуникационный оператор (telecom provider), региональный орган власти, университет
5. Метод первоначального доступа: эксплуатация уязвимостей Microsoft SharePoint (ToolShell)
6. Используемые инструменты злоумышленником: web‑shell, AV/EDR‑killer, BYOVD‑техника с подписанным драйвером K7RKScan (CVE‑2025‑1055), VS Code tunneling, фреймворк NetExec
7. Идентификатор используемых уязвимостей: CVE‑2025‑49704, CVE‑2025‑49706, CVE‑2025‑53770, CVE‑2025‑53771, CVE‑2025‑1055
8. Наличие индикаторов компрометации: да

**Почему важно:** Показан метод начального доступа через SharePoint, который может быть применим и к российским объектам.

**Источники:** [bleepingcomputer](https://www.bleepingcomputer.com/news/security/warlock-ransomware-breach-sharepoint-in-water-telecom-operator-attacks)

### 2. [Backdoor Antino использует Outlook и OneDrive для C2 в кампании China‑Nexus](https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html)

**Приоритет: Низкий** · 02.10.2026 · релевантность 6/10 · id `7d8d9de9`

1. Страна жертвы: Тайвань, Индия, Филиппины, Камбоджа, Пакистан, Таиланд, Мьянма, Сирия
2. Наименование группировки: UAT-11587 (China‑nexus threat actor)
3. Предполагаемая дата атаки: Сентябрь 2025 – Июнь 2026 (пиковый период март‑июнь 2026, концентрированная волна 8‑9 июня 2026)
4. Затронутые отрасли/компании: Государственные организации, политические и законодательные структуры, академические и аналитические институты, think‑tank, гражданское общество, морские, дипломатические и службы безопасности
5. Метод первоначального доступа: Spear‑phishing (подделка отправителя, таргетированные луры)
6. Используемые инструменты злоумышленником: Backdoor Antino (Rust‑компилированный Windows‑бэкдор), C2 через Microsoft Graph (Outlook, OneDrive), JavaScript‑скачиватель, Cargo‑реестры с rsproxy.cn
7. Идентификатор используемых уязвимостей: нет данных
8. Наличие индикаторов компрометации: да

**Почему важно:** Затрагивает Outlook, часто интегрированный с Exchange, который присутствует в целевой инфраструктуре.

**Источники:** [thehackernews](https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html)

## Уязвимость

### 3. [Критическая уязвимость FortiMail (CVE‑2026‑104286) активно эксплуатируется](https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-fortimail-flaw-exploited-in-zero-day-attacks)

**Приоритет: Высокий** · 01.10.2026 · `CVE-2026-104286`, `CVE-2026-85102`, `CVE-2026-93616` · в CISA KEV: CVE-2026-104286 · релевантность 8/10 · id `376c054a`

1. Наименование уязвимости: Critical FortiMail vulnerability
2. Наименование релевантного уязвимого сервиса: FortiMail management interface
3. Краткое описание уязвимости: Path Traversal (CWE-22) and NULL byte handling (CWE-158) allow unauthenticated attacker to write arbitrary files via crafted HTTP/HTTPS requests.
4. Наличие обновления: планируется, пока нет (updates forthcoming for 7.4.9, 7.6.7, 8.0.2)
5. Временные решения: disable IBE feature, restrict management interface access to trusted networks
6. Наличие эксплойта: да
7. Идентификатор уязвимости CVE: CVE-2026-104286, CVE-2026-85102, CVE-2026-93616, CVE-2026-93952, CVE-2026-94127
8. Оценка CVE: 9.8
9. Метрики CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
10. Последствия компрометации сервиса: unauthorized code execution, arbitrary file write, potential remote control of FortiMail appliance

**Почему важно:** FortiMail используется в корпоративных почтовых шлюзах, а уязвимость имеет CVSS 9.8 и уже применяется в нулевых‑днях.

**Источники:** [cisa_kev](https://nvd.nist.gov/vuln/detail/CVE-2026-104286) · [bleepingcomputer](https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-fortimail-flaw-exploited-in-zero-day-attacks) · [thehackernews](https://thehackernews.com/2026/10/critical-fortimail-zero-day-flaw.html) · [1275_ru](https://1275.ru/vulnerability/obhod-kataloga-v-fortimail-uzhe-ispolzuyut-dlya-zapisi-proizvolnyh-faylov-bez-autentifikatsii_42634) · [1275_ru](https://1275.ru/ioc/realnye-ataki-na-pochtovye-shlyuzy-fortimail-zapis-faylov-bez-vhoda-v-sistemu_42637) · [1275_ru](https://1275.ru/vulnerability/cisa-dobavila-v-katalog-aktivno-ekspluatiruemyh-uyazvimostey-obhod-puti-v-fortinet-fortimail_42640) · [tg_secator](https://t.me/true_secator/8672)

### 4. [Критический bypass аутентификации в Cisco Catalyst SD‑WAN Manager (CVE‑2026‑76504)](https://thehackernews.com/2026/10/cisa-adds-exploited-cisco-catalyst-sd.html)

**Приоритет: Высокий** · 01.10.2026 · `CVE-2026-76504` · в CISA KEV: CVE-2026-76504 · релевантность 7/10 · id `5da2a0c8`

1. Наименование уязвимости: Authentication bypass in Cisco Catalyst SD-WAN Manager
2. Наименование релевантного уязвимого сервиса: Cisco Catalyst SD-WAN Manager
3. Краткое описание уязвимости: Hex encoding vulnerability that leads to improper handling of URI encoding in an HTTP request, allowing an unauthenticated remote attacker to bypass authentication and gain admin‑level privileges.
4. Наличие обновления: да
5. Временные решения: Аудит логов /var/log/nms/containers/service-proxy/serviceproxy-access.log и /var/log/nms/vmanage-server.log на запросы j_security_check от неизвестных IP; мониторинг POST‑запросов к URL‑закодированным вариантам "/j_security_check"; проверка признаков эксплуатации.
6. Наличие эксплойта: да
7. Идентификатор уязвимости CVE: CVE-2026-76504
8. Оценка CVE: 9.8
9. Метрики CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
10. Последствия компрометации сервиса: Злоумышленник может обойти аутентификацию, получить доступ к API с привилегиями администратора и управлять конфигурацией и мониторингом сети SD‑WAN.

**Почему важно:** Cisco‑оборудование широко используется в сетевой инфраструктуре, а уязвимость позволяет получить привилегии администратора без аутентификации.

**Источники:** [tg_secator](https://t.me/true_secator/8666) · [thehackernews](https://thehackernews.com/2026/10/cisa-adds-exploited-cisco-catalyst-sd.html) · [securitylab](https://www.securitylab.ru/news/578171.php) · [tg_zerodayalert](https://t.me/ZerodayAlert/858)

### 5. [CISA предупреждает о критической RCE‑уязвимости в MikroTik RouterOS (CVE‑2026‑84411)](https://xakep.ru/2026/10/02/cve-2026-84411)

**Приоритет: Высокий** · 02.10.2026 · `CVE-2026-84411`, `CVE-2026-67279`, `CVE-2026-86060` · в CISA KEV: CVE-2026-67279, CVE-2026-86060 · релевантность 5/10 · id `06e50d27`

1. Наименование уязвимости: Critical RCE vulnerability in MikroTik RouterOS (CVE-2026-84411) and related integer underflow bugs (CVE-2026-67279, CVE-2026-86060, CVE-2026-67276)
2. Наименование релевантного уязвимого сервиса: MikroTik RouterOS (web interface management)
3. Краткое описание уязвимости: Integer underflow in HTTP request handling allows remote code execution with root privileges without authentication and can cause DoS. Additional bugs (CVE-2026-67279, CVE-2026-86060) – MikroTrick – enable full device takeover via SSH if exposed. CVE-2026-67276 is an SSH key spoofing flaw requiring knowledge of account name and public key module.
4. Наличие обновления: Да, обновление до RouterOS 7.24 или новее (7.24.4 stable, 7.23.7 LTS)
5. Временные решения: Ограничить доступ к веб‑интерфейсу из интернета, сегментировать управляющие сети, использовать межсетевые экраны и VPN для удалённого доступа
6. Наличие эксплойта: нет данных
7. Идентификатор уязвимости CVE: CVE-2026-84411, CVE-2026-67279, CVE-2026-86060, CVE-2026-67276
8. Оценка CVE: 9.8 (для CVE-2026-84411)
9. Метрики CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
10. Последствия компрометации сервиса: Удалённое выполнение произвольного кода с правами root, полный контроль над роутером, возможность отказа в обслуживании, захват устройства через SSH

**Почему важно:** Уязвимость позволяет выполнить произвольный код с правами root без аутентификации, что представляет серьёзную угрозу сетевой инфраструктуре.

**Источники:** [xakep](https://xakep.ru/2026/10/02/cve-2026-84411)

### 6. [Citrix NetScaler ADC/Gateway: скрытый веб‑шелл и superuser‑доступ (CVE‑2026‑88771)](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html)

**Приоритет: Высокий** · 01.10.2026 · `CVE-2026-88771`, `CVE-2026-88772` · в CISA KEV: CVE-2026-88771, CVE-2026-88772 · релевантность 5/10 · id `238df8b6`

1. Наименование уязвимости: Improper input validation vulnerability in Citrix NetScaler ADC and NetScaler Gateway
2. Наименование релевантного уязвимого сервиса: Citrix NetScaler ADC / NetScaler Gateway
3. Краткое описание уязвимости: Pre‑authentication command injection allowing unauthenticated attacker to execute arbitrary commands, drop web shells and steal configuration data
4. Наличие обновления: нет данных
5. Временные решения: нет данных
6. Наличие эксплойта: да
7. Идентификатор уязвимости CVE: CVE-2026-88771, CVE-2026-88772
8. Оценка CVE: 9.8 (CVE-2026-88772), 9.5 (CVE-2026-88771)
9. Метрики CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
10. Последствия компрометации сервиса: Удалённое выполнение кода, создание привилегированных аккаунтов, установка веб‑шеллов, кража конфигурационных данных

**Почему важно:** Эксплуатация уязвимости позволяет без аутентификации создать учётную запись с правами superuser, что актуально для защищённых периметров.

**Источники:** [thehackernews](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html) · [tg_zerodayalert](https://t.me/ZerodayAlert/860)

### 7. [CISA сообщает о пяти уязвимостях в системе контроля доступа Armatura One (CVE‑2023‑46604)](https://1275.ru/vulnerability/cisa-preduprezhdaet-o-pyati-uyazvimostyah-v-armatura-one-odna-iz-nih-v-kataloge-aktivno-ekspluatiruemyh_42671)

**Приоритет: Высокий** · 02.10.2026 · `CVE-2023-46604` · релевантность 4/10 · id `516ef5ee`

1. Наименование уязвимости: CVE-2023-46604
2. Наименование релевантного уязвимого сервиса: Armatura One (система контроля физического доступа)
3. Краткое описание уязвимости: Уязвимость позволяет неаутентифицированному злоумышленнику выполнить произвольный код с наивысшими привилегиями в операционной системе.
4. Наличие обновления: нет данных
5. Временные решения: нет данных
6. Наличие эксплойта: да
7. Идентификатор уязвимости CVE: CVE-2023-46604
8. Оценка CVE: 10.0
9. Метрики CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H
10. Последствия компрометации сервиса: полный контроль над системой контроля доступа, возможность обхода защиты и дальнейшего компрометирования сети

**Почему важно:** Одна из уязвимостей позволяет выполнить код с наивысшими привилегиями, что критично для физической безопасности объектов.

**Источники:** [1275_ru](https://1275.ru/vulnerability/cisa-preduprezhdaet-o-pyati-uyazvimostyah-v-armatura-one-odna-iz-nih-v-kataloge-aktivno-ekspluatiruemyh_42671)

### 8. [TrueConf закрывает критическую уязвимость с CVSS 9.8, позволяющую захватить сервер](https://t.me/cyberok_news/258)

**Приоритет: Средний** · 01.10.2026 · `BDU:2026-15756` · релевантность 9/10 · id `4e8fae1c`

1. Наименование уязвимости: TrueConf Server vulnerability (BDU:2026-15756)
2. Наименование релевантного уязвимого сервиса: TrueConf Server
3. Краткое описание уязвимости: Уязвимость в платформе видеоконференций TrueConf Server, позволяющая злоумышленникам атаковать систему через публичную сеть Интернет.
4. Наличие обновления: да
5. Временные решения: Создать резервную копию перед обновлением; при проблемах с запуском – зарегистрировать сервер заново своим ключом.
6. Наличие эксплойта: нет данных
7. Идентификатор уязвимости CVE: нет данных
8. Оценка CVE: нет данных
9. Метрики CVSS: нет данных
10. Последствия компрометации сервиса: может привести к несанкционированному доступу к видеоконференциям, утечке конфиденциальных данных и нарушению работы системы.

**Почему важно:** Уязвимость позволяет получить контроль без учётных данных, затрагивая все версии от 4.5.0.15891 до 5.5.5.10304, что критично для инфраструктуры видеоконференций.

**Источники:** [tg_cyberok](https://t.me/cyberok_news/258) · [tg_cyberok](https://t.me/cyberok_news/261) · [securitylab](https://www.securitylab.ru/news/578245.php) · [tg_zerodayalert](https://t.me/ZerodayAlert/862)

## Инфо

### 9. [Атаки на российские предприятия через ошибки в настройках серверов 1С](https://t.me/purpleshift/222)

**Приоритет: Новости ТГ** · 02.10.2026 · релевантность 9/10 · id `0fd2303a`

1. Краткое содержание: Исследователи отмечают, что тривиальные ошибки в настройках серверов 1С позволяют злоумышленникам запускать командные оболочки через процессы rphost.exe, ragent.exe и rmngr.exe. Описаны признаки компрометации и рекомендации по мониторингу подозрительных дочерних процессов.
2. Ссылки, на которые ссылается пост:
   - `https://securelist[.]ru/investigating-1c-compromise/117167/`

**Почему важно:** Большая часть ERP в России работает на 1С, поэтому уязвимости в её конфигурации представляют высокий риск.

**Источники:** [tg_purpleshift](https://t.me/purpleshift/222)

### 10. [Abuse DCOM‑объектов для скрытого lateral movement (T1021.003) в Windows](https://t.me/poxek/6356)

**Приоритет: Новости ТГ** · 02.10.2026 · релевантность 9/10 · id `ca1121cb`

1. Краткое содержание: Злоумышленники инстанцируют удалённые COM‑объекты через RPC (TCP 135) и динамические порты, используя такие объекты как MMC20.Application. Это позволяет выполнять код в контексте доверенных системных процессов без создания подозрительных служб.
2. Ссылки, на которые ссылается пост:
   - `https://attack.mitre[.]org/techniques/T1021/003/`
   - `https://max[.]ru/poxek`

**Почему важно:** Техника использует легитимные DCOM‑интерфейсы, что актуально для защиты Windows Server и AD.

**Источники:** [tg_poxek](https://t.me/poxek/6356)

### 11. [Отчёт Solar о длительном захвате российской медицинской организации группой «Киберпартизан»](https://t.me/cyberguerre/4484)

**Приоритет: Новости ТГ** · 02.10.2026 · релевантность 7/10 · id `69f5205e`

1. Краткое содержание: Исследователи Solar описали атаку «Киберпартизан» на российскую медицинскую организацию, где злоумышленники оставались в сети почти два года. Атака не была деструктивной, но демонстрирует возможности скрытого присутствия.
2. Ссылки, на которые ссылается пост:
   - `https://rt-solar[.]ru/solar-4rays/blog/7027/`

**Почему важно:** Подтверждает наличие продвинутых атак на российские организации, что важно для мониторинга угроз.

**Источники:** [tg_cyberguerre](https://t.me/cyberguerre/4484)

### 12. [Zammad взломали через две zero‑day, получили root и перешли к Confluence](https://t.me/ZerodayAlert/859)

**Приоритет: Новости ТГ** · 02.10.2026 · релевантность 6/10 · id `6b88b54b`

1. Краткое содержание: Злоумышленники использовали две неизвестные уязвимости в Zammad: одна давала удалённое выполнение кода без учётных данных, вторая повышала привилегии до root. За несколько секунд они получили доступ к Jira, Confluence и другим системам, начав вывод данных.
2. Ссылки, на которые ссылается пост:
   - `https://www.securitylab[.]ru/news/578173.php`

**Почему важно:** Атака демонстрирует быстрый переход от уязвимости в сервисе к критическим корпоративным системам, включая Confluence, входящий в ваш стек.

**Источники:** [tg_zerodayalert](https://t.me/ZerodayAlert/859)

### 13. [Девять техник закрепления вредоносного кода в Linux‑системах](https://xakep.ru/2026/10/02/linux-persistence)

**Приоритет: Новости** · 02.10.2026 · релевантность 6/10 · id `2a01bed1`

1. Краткое содержание: В статье рассмотрены техники, такие как systemd‑service, crontab, user timers, bashrc, udev‑rules и LD_PRELOAD, которые используют реальные образцы малвари для долгосрочного присутствия. Демонстрируется пример реверс‑шелла.

**Почему важно:** Перечислены методы persistence, применимые к Astra Linux и другим российским дистрибутивам.

**Источники:** [xakep](https://xakep.ru/2026/10/02/linux-persistence)

---

**Отбор:** публикаций: 264 · источников: 22 · сюжетов: 243 · дублей объединено: 28 · отсеяно: 5 · в дайджесте: 13 · запросов к LLM: 14 · токенов: 48358 · секунд: 322.0
