# HTTP Headers в Mobile Chrome - Полная документация

## Обзор

Мобильный Chrome отправляет несколько категорий HTTP заголовков. Для anti-fingerprinting системы важно генерировать и подменять все эти заголовки консистентно.

---

## 1. Стандартные HTTP заголовки

### Обязательные (отправляются всегда)

| Header | Описание | Пример для Android |
|--------|----------|-------------------|
| `User-Agent` | Идентификация браузера и устройства | `Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36` |
| `Accept` | Поддерживаемые MIME типы | `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8` |
| `Accept-Language` | Языковые предпочтения | `ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7` |
| `Accept-Encoding` | Поддерживаемые методы сжатия | `gzip, deflate, br, zstd` |
| `Host` | Целевой хост | `example.com` |
| `Connection` | Тип соединения | `keep-alive` |

### Опциональные

| Header | Описание | Когда отправляется |
|--------|----------|-------------------|
| `Referer` | URL предыдущей страницы | При переходе по ссылке |
| `Cookie` | Cookies для домена | Если есть cookies |
| `Cache-Control` | Директивы кэширования | При обновлении страницы: `max-age=0` |
| `Upgrade-Insecure-Requests` | Запрос HTTPS | Обычно `1` |

---

## 2. User-Agent Client Hints (Sec-CH-UA-*)

### Low Entropy (отправляются по умолчанию)

Эти заголовки отправляются **автоматически** без запроса сервера.

| Header | Описание | Пример Android |
|--------|----------|----------------|
| `Sec-CH-UA` | Бренды браузера и версии | `"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"` |
| `Sec-CH-UA-Mobile` | Мобильное устройство | `?1` (true для мобильных) |
| `Sec-CH-UA-Platform` | Платформа ОС | `"Android"` |

### High Entropy (требуют Accept-CH от сервера)

Эти заголовки отправляются **только если сервер запросил их** через `Accept-CH`.

| Header | Описание | Пример Android |
|--------|----------|----------------|
| `Sec-CH-UA-Arch` | Архитектура CPU | `""` (пустая строка на Android!) |
| `Sec-CH-UA-Bitness` | Разрядность | `""` (пустая строка на Android!) |
| `Sec-CH-UA-Full-Version-List` | Полные версии | `"Chromium";v="131.0.6778.200", "Google Chrome";v="131.0.6778.200", "Not_A Brand";v="24.0.0.0"` |
| `Sec-CH-UA-Model` | Модель устройства | `"SM-S918B"` |
| `Sec-CH-UA-Platform-Version` | Версия платформы | `"14.0.0"` |
| `Sec-CH-UA-WoW64` | Windows 32 на 64 | `?0` (всегда false на Android) |
| `Sec-CH-UA-Form-Factors` | Форм-факторы | `"Mobile"` |

### ⚠️ Критические отличия Android от Desktop

```javascript
// Desktop (Windows/Mac/Linux)
"Sec-CH-UA-Arch": "x86"
"Sec-CH-UA-Bitness": "64"

// Android - ПУСТЫЕ СТРОКИ!
"Sec-CH-UA-Arch": ""
"Sec-CH-UA-Bitness": ""
```

---

## 3. Fetch Metadata Headers (Sec-Fetch-*)

Описывают контекст запроса. Важны для детекции ботов!

| Header | Описание | Значения |
|--------|----------|----------|
| `Sec-Fetch-Dest` | Тип ресурса | `document`, `image`, `script`, `style`, `font`, `empty`, `iframe`, `worker` |
| `Sec-Fetch-Mode` | Режим запроса | `navigate`, `cors`, `no-cors`, `same-origin`, `websocket` |
| `Sec-Fetch-Site` | Источник запроса | `same-origin`, `same-site`, `cross-site`, `none` |
| `Sec-Fetch-User` | Инициирован пользователем | `?1` (только для user-initiated навигации) |

### Типичные комбинации

```
# Первый запрос страницы (ввод URL)
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1

# Переход по ссылке (same site)
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

# Переход по внешней ссылке
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1

# Загрузка изображения
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
(Sec-Fetch-User отсутствует!)

# AJAX/Fetch запрос
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
```

---

## 4. Network Information Client Hints

Требуют Accept-CH от сервера.

| Header | Описание | Пример |
|--------|----------|--------|
| `Downlink` | Скорость соединения (Mbps) | `10`, `2.5` |
| `ECT` | Effective Connection Type | `4g`, `3g`, `2g`, `slow-2g` |
| `RTT` | Round Trip Time (ms) | `50`, `150` |
| `Save-Data` | Режим экономии данных | `on` или отсутствует |

---

## 5. Device Client Hints

| Header | Описание | Пример |
|--------|----------|--------|
| `Device-Memory` | RAM устройства (GB) | `4`, `8`, `2` |
| `DPR` | Device Pixel Ratio | `2.75`, `3`, `2` |
| `Viewport-Width` | Ширина viewport | `412`, `360` |

---

## 6. Privacy & Security Headers

| Header | Описание | Значения |
|--------|----------|----------|
| `Sec-GPC` | Global Privacy Control | `1` (если включен) |
| `DNT` | Do Not Track (устаревший) | `1` или отсутствует |

---

## 7. Порядок заголовков (важно для fingerprinting!)

Chrome отправляет заголовки в определённом порядке. Типичный порядок для Mobile Chrome:

```
Host
Connection
sec-ch-ua
sec-ch-ua-mobile
sec-ch-ua-platform
Upgrade-Insecure-Requests
User-Agent
Accept
Sec-Fetch-Site
Sec-Fetch-Mode
Sec-Fetch-User
Sec-Fetch-Dest
Accept-Encoding
Accept-Language
Cookie (если есть)
```

---

## 8. Формат GREASE в Sec-CH-UA

Chrome использует "GREASE" - случайные фейковые бренды для предотвращения детекции:

```
// Chrome 131 pattern
"Not_A Brand";v="24"

// Предыдущие версии использовали разные patterns:
// Chrome 130: "Not?A_Brand";v="24"
// Chrome 120: "Not A(Brand";v="99"
// Chrome 110: " Not A;Brand";v="99"
```

---

## 9. Реализация генерации для вашей системы

### Пример конфигурации для Android устройства

```javascript
const androidHeaders = {
  // Standard
  "User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
  "Accept-Encoding": "gzip, deflate, br, zstd",
  "Connection": "keep-alive",
  "Upgrade-Insecure-Requests": "1",
  
  // Client Hints (low entropy - always sent)
  "Sec-CH-UA": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
  "Sec-CH-UA-Mobile": "?1",
  "Sec-CH-UA-Platform": '"Android"',
  
  // Client Hints (high entropy - if requested)
  "Sec-CH-UA-Arch": '""',  // ПУСТАЯ СТРОКА на Android!
  "Sec-CH-UA-Bitness": '""', // ПУСТАЯ СТРОКА на Android!
  "Sec-CH-UA-Full-Version-List": '"Chromium";v="131.0.6778.200", "Google Chrome";v="131.0.6778.200", "Not_A Brand";v="24.0.0.0"',
  "Sec-CH-UA-Model": '"SM-S918B"',
  "Sec-CH-UA-Platform-Version": '"14.0.0"',
  "Sec-CH-UA-WoW64": "?0",
  
  // Fetch Metadata (for navigation)
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-User": "?1"
};
```

### Соответствие с JS API (navigator.userAgentData)

```javascript
// HTTP Header -> JS API mapping
{
  "Sec-CH-UA": navigator.userAgentData.brands,
  "Sec-CH-UA-Mobile": navigator.userAgentData.mobile, 
  "Sec-CH-UA-Platform": navigator.userAgentData.platform,
  
  // High entropy через getHighEntropyValues()
  "Sec-CH-UA-Arch": highEntropy.architecture,
  "Sec-CH-UA-Bitness": highEntropy.bitness,
  "Sec-CH-UA-Full-Version-List": highEntropy.fullVersionList,
  "Sec-CH-UA-Model": highEntropy.model,
  "Sec-CH-UA-Platform-Version": highEntropy.platformVersion,
  "Sec-CH-UA-WoW64": highEntropy.wow64
}
```

---

## 10. Файлы в комплекте

| Файл | Описание |
|------|----------|
| `http-headers-diagnostic.php` | Полный диагностический инструмент с UI |
| `http-headers-js.html` | JavaScript версия (использует httpbin.org) |
| `echo-headers.php` | API для эхо заголовков (JSON) |

### Использование

1. **http-headers-diagnostic.php** - загрузите на PHP сервер с HTTPS, откройте в мобильном Chrome. Нажмите Refresh для получения high-entropy hints.

2. **http-headers-js.html** - можно открыть локально или разместить где угодно. Собирает данные через JS API + httpbin.org.

3. **echo-headers.php** - API endpoint. Разместите на сервере и делайте запросы для проверки заголовков.

---

## 11. Проверка корректности

Ваша система генерации должна обеспечить:

1. ✅ **Консистентность** - User-Agent и Client Hints должны описывать одно устройство
2. ✅ **Android специфика** - Arch и Bitness должны быть пустыми строками
3. ✅ **GREASE pattern** - должен соответствовать версии Chrome
4. ✅ **Порядок заголовков** - может использоваться для fingerprinting
5. ✅ **Sec-Fetch логика** - должна соответствовать типу запроса
6. ✅ **JS API соответствие** - navigator.userAgentData должен возвращать те же данные

---

## Ссылки

- [User-Agent Client Hints Spec](https://wicg.github.io/ua-client-hints/)
- [MDN: Sec-CH-UA](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA)
- [Chrome Client Hints](https://developer.chrome.com/docs/privacy-security/user-agent-client-hints)
- [Fetch Metadata Spec](https://w3c.github.io/webappsec-fetch-metadata/)
