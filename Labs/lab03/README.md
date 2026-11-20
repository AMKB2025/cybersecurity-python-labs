# Лабораторна робота №3: Прикладні бібліотеки Python для побудови вебзастосунків

## Варіант 1 — Реєстр вразливостей вебзастосунку

Вебсервіс (REST API) на базі **FastAPI** та **SQLite** для обліку знахідок перевірки вебзастосунку.

* **Категорії (`categories`):** компонент вебзастосунку (`web`, `api`, `database`).
* **Значення (`value`):** навчальна оцінка небезпеки вразливості від `0.0` до `10.0` включно.
* **Одиниця вимірювання (`unit`):** `score`.
* **Поріг реагування (`threshold`):** `7.0`.
* **Статуси опрацювання (`status`):** `new`, `in_progress`, `done`.

---

## 1. Підготовка середовища та встановлення залежностей

Виконуйте команди з кореня репозиторію `cybersecurity-python-labs` в активованому віртуальному середовищі:

```bash
pip install -r requirements.txt
```

---

## 2. Ініціалізація та початкове заповнення бази даних

1. **Створення структури таблиць** за готовою SQL-схемою (`labs/lab03/schema.sql`):
   ```bash
   python -m labs.lab03.database
   ```

2. **Заповнення навчальними даними** варіанта 1 (`labs/lab03/data/seed.json` — 3 категорії та 8 записів):
   ```bash
   python -m labs.lab03.seed
   ```
   *(Повторний запуск безпечний: за наявності даних скрипт завершить роботу без створення дублікатів).*

---

## 3. Запуск Web API

Запустіть локальний сервер розробки з кореня репозиторію:

```bash
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Після запуску доступні:
* **Інтерактивна документація Swagger UI:** http://127.0.0.1:8000/docs
* **OpenAPI-схема:** http://127.0.0.1:8000/openapi.json

---

## 4. Приклади основних HTTP-запитів

### Перевірка доступності сервісу та даних студента
```bash
curl -i "[http://127.0.0.1:8000/ping](http://127.0.0.1:8000/ping)"
curl -i "[http://127.0.0.1:8000/student](http://127.0.0.1:8000/student)"
```

### Категорії
```bash
# Список усіх категорій
curl -i "[http://127.0.0.1:8000/categories](http://127.0.0.1:8000/categories)"

# Створення нової категорії
curl -i -X POST "[http://127.0.0.1:8000/categories](http://127.0.0.1:8000/categories)" \
  -H "Content-Type: application/json" \
  -d '{"name": "auth"}'

# Видалення порожньої категорії (замість 4 вкажіть актуальний id)
curl -i -X DELETE "[http://127.0.0.1:8000/categories/4](http://127.0.0.1:8000/categories/4)"
```

### Записи (CRUD та фільтрація)
```bash
# Отримання списку з фільтрами та пагінацією
curl -i "[http://127.0.0.1:8000/records?category_id=1&status=new&min_value=7.0&limit=5&offset=0](http://127.0.0.1:8000/records?category_id=1&status=new&min_value=7.0&limit=5&offset=0)"

# Пошук за підрядком у назві
curl -i "[http://127.0.0.1:8000/records?q=01](http://127.0.0.1:8000/records?q=01)"

# Створення окремого запису
curl -i -X POST "[http://127.0.0.1:8000/records](http://127.0.0.1:8000/records)" \
  -H "Content-Type: application/json" \
  -d '{"code": "V01-TEST", "title": "Навчальна знахідка", "category_id": 1, "value": 7.5, "status": "new"}'

# Читання одного запису за id
curl -i "[http://127.0.0.1:8000/records/9](http://127.0.0.1:8000/records/9)"

# Повна заміна полів запису (PUT)
curl -i -X PUT "[http://127.0.0.1:8000/records/9](http://127.0.0.1:8000/records/9)" \
  -H "Content-Type: application/json" \
  -d '{"code": "V01-TEST", "title": "Оновлена навчальна знахідка", "category_id": 1, "value": 8.2, "status": "in_progress"}'

# Видалення запису
curl -i -X DELETE "[http://127.0.0.1:8000/records/9](http://127.0.0.1:8000/records/9)"
```

### Пакетне створення в одній транзакції
```bash
curl -i -X POST "[http://127.0.0.1:8000/records/bulk](http://127.0.0.1:8000/records/bulk)" \
  -H "Content-Type: application/json" \
  -d '[
    {"code": "V01-B1", "title": "Пакетна знахідка 1", "category_id": 1, "value": 6.5, "status": "new"},
    {"code": "V01-B2", "title": "Пакетна знахідка 2", "category_id": 2, "value": 8.8, "status": "in_progress"}
  ]'
```