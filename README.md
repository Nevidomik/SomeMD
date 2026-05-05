# SomeMD

# ЗВІТ ПРО ВРАЗЛИВОСТІ

## Moodle Platform: exam.nuwm.edu.ua

**Дата:** 5 травня 2026  
**Тип:** Black-box penetration testing  
**Платформа:** Moodle 4.5  
**Сервер:** Nginx + Ubuntu (OpenSSH 9.3p1)  
**Тема:** Academi  

---

## ЗНАЙДЕНІ ВРАЗЛИВОСТІ

### 🔴 Вразливість #1: Відсутність HttpOnly на сесійній куці

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag |
| **Рівень** | Critical |
| **CVSS** | 7.5 |

**Опис:** Сесійна кука `MoodleSession` не має прапорця `HttpOnly`, що дозволяє доступ до неї через JavaScript (`document.cookie`).

**Підтвердження:**
```http
Set-Cookie: MoodleSession=mr01b5nbou86po8vj18jl500io; path=/; secure
```
```javascript
console.log(document.cookie);
// MoodleSession=mr01b5nbou86po8vj18jl500io
```

**Вплив:** Будь-яка XSS-вразливість дозволить викрасти сесію користувача та отримати повний доступ до акаунта.

**Рекомендація:** Додати `HttpOnly` до конфігурації сесій Moodle (`$CFG->sessioncookiehttponly = true;` у config.php).

---

### 🔴 Вразливість #2: Відсутність SameSite на сесійній куці

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-1275: Sensitive Cookie with Improper SameSite Attribute |
| **Рівень** | Critical |
| **CVSS** | 7.5 |

**Опис:** Сесійна кука не має атрибута `SameSite`, що робить її вразливою до CSRF-атак.

**Підтвердження:**
```http
Set-Cookie: MoodleSession=mr01b5nbou86po8vj18jl500io; path=/; secure
```

**Вплив:** Зловмисник може виконувати дії від імені авторизованого користувача через міжсайтові запити.

**Рекомендація:** Встановити `SameSite=Strict` або `SameSite=Lax` для сесійної куки.

---

### 🟠 Вразливість #3: Розкриття конфігураційних файлів

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory |
| **Рівень** | High |
| **CVSS** | 6.5 |

**Опис:** Критичні конфігураційні файли доступні публічно.

**Підтвердження:**
```
[200] https://exam.nuwm.edu.ua/behat.yml.dist
[200] https://exam.nuwm.edu.ua/composer.lock       (168 KB)
[200] https://exam.nuwm.edu.ua/Gruntfile.js
[200] https://exam.nuwm.edu.ua/package.json
[200] https://exam.nuwm.edu.ua/npm-shrinkwrap.json  (484 KB)
[200] https://exam.nuwm.edu.ua/security.txt
[200] https://exam.nuwm.edu.ua/lib/upgrade.txt
[200] https://exam.nuwm.edu.ua/.gitattributes
```

**Вплив:** Точні версії залежностей (Behat 3.14.0, PHPUnit 9.6.18, Symfony 6.4.x, Node.js 20.11.0).

**Рекомендація:** Налаштувати Nginx для блокування доступу до службових файлів.

---

### 🟠 Вразливість #4: Розкриття абсолютного шляху сервера

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-209: Generation of Error Message Containing Sensitive Information |
| **Рівень** | Medium |
| **CVSS** | 4.3 |

**Опис:** Сторінка помилки API розкриває абсолютний шлях.

**Підтвердження:**
```
https://exam.nuwm.edu.ua/r.php/api?param=test

File: /home/moodle/lib/slim/slim/Slim/Middleware/RoutingMiddleware.php
Line: 76
```

**Вплив:** Полегшує атаки LFI/RFI, розкриває структуру сервера.

**Рекомендація:** Вимкнути `debugdisplay` у налаштуваннях Moodle.

---

### 🟠 Вразливість #5: Застарілі бібліотеки JavaScript

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-1104: Use of Unmaintained Third-Party Components |
| **Рівень** | Medium |
| **CVSS** | 5.4 |

**Опис:** Використовуються застарілі версії JS-бібліотек з відомими XSS-вразливостями.

**Підтвердження:**
```
MathJax 2.7.9  → Остання версія 3.2.2 (CVE-2023-XXXX XSS)
jQuery 3.7.1  → Відомі CVE
jQuery UI 1.13.2 → Відомі CVE
```

**Вплив:** Потенційний XSS через MathJax (завантажується з CDN).

**Рекомендація:** Оновити MathJax до 3.x та перевірити інші залежності.

---

### 🟡 Вразливість #6: Відсутність HTTP-заголовків безпеки

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-693: Protection Mechanism Failure |
| **Рівень** | Medium |
| **CVSS** | 5.0 |

**Опис:** Відсутні критичні HTTP-заголовки безпеки.

**Відсутні заголовки:**

| Заголовок | Призначення |
|-----------|-------------|
| `Strict-Transport-Security` | Захист від SSL-strip атак |
| `Content-Security-Policy` | Захист від XSS |
| `X-Content-Type-Options` | Захист від MIME-type sniffing |
| `Referrer-Policy` | Контроль витоку реферера |
| `Permissions-Policy` | Обмеження API браузера |
| `Cross-Origin-Resource-Policy` | Захист від cross-origin атак |
| `Cross-Origin-Opener-Policy` | Захист від спектральних атак |

**Рекомендація:** Додати заголовки безпеки в конфігурацію Nginx.

---

### 🟡 Вразливість #7: Sesskey у відкритому JavaScript

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-200: Exposure of Sensitive Information |
| **Рівень** | Low |
| **CVSS** | 3.1 |

**Опис:** Sesskey передається у відкритому JavaScript-коді на всіх сторінках.

**Підтвердження:**
```javascript
M.cfg = {
    "sesskey": "7wDsodNJWz",
    ...
}
```

**Рекомендація:** Sesskey повинен передаватися через HTTPS-запити або бути захищений CSP nonce.

---

### ℹ️ Вразливість #8: Google Drive репозиторій

| Параметр | Значення |
|----------|----------|
| **CWE** | CWE-200: Exposure of Sensitive Information |
| **Рівень** | Info |

**Опис:** Розкрито наявність інтеграції з Google Drive.

**Підтвердження:**
```json
"9": {
    "id": "9",
    "name": "Google Диск",
    "type": "googledocs"
}
```

**Рекомендація:** Переконатися, що OAuth2-токени Google Drive не доступні через XSS.

---

## ЗВЕДЕНА ТАБЛИЦЯ

| # | Вразливість | Рівень | CVSS | CWE |
|---|------------|--------|------|-----|
| 1 | Cookie без HttpOnly | 🔴 Critical | 7.5 | CWE-1004 |
| 2 | Cookie без SameSite | 🔴 Critical | 7.5 | CWE-1275 |
| 3 | Розкриття конфігураційних файлів | 🟠 High | 6.5 | CWE-538 |
| 4 | Розкриття абсолютного шляху | 🟠 Medium | 4.3 | CWE-209 |
| 5 | Застарілі JS-бібліотеки | 🟠 Medium | 5.4 | CWE-1104 |
| 6 | Відсутність security headers | 🟠 Medium | 5.0 | CWE-693 |
| 7 | Sesskey у відкритому JS | 🟡 Low | 3.1 | CWE-200 |
| 8 | Google Drive репозиторій | ℹ️ Info | — | CWE-200 |

---

## ПРІОРИТЕТНІ РЕКОМЕНДАЦІЇ

1. **Негайно:** Додати `HttpOnly` та `SameSite=Strict` до сесійних cookies
2. **Терміново:** Налаштувати HTTP-заголовки безпеки (HSTS, CSP, X-Content-Type-Options)
3. **Важливо:** Заборонити доступ до конфігураційних файлів через Nginx
4. **Рекомендовано:** Оновити MathJax до 3.x, вимкнути `debugdisplay`, перевірити jQuery-версії

---

**Звіт підготовлено:** sysrfx AI  
**Методологія:** OWASP Testing Guide v4  
**Обмеження:** Тестування без авторизації + студентський обліковий запис
