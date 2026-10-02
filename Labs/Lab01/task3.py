import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime

# Додавання кореневої папки проєкту до системного шляху для імпорту shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Константи
HASH_ALGORITHM = "sha3_512"
MIN_PASSWORD_LENGTH = 12
SALT = str(VARIANT_NUMBER).zfill(5)

# Шляхи до файлів даних
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

# Список 10 користувачів для реєстрації
USERS_TO_REGISTER = (
    ("admin_alice", "SecureAdminPass2026!"),
    ("sec_bob", "CryptoAnalysis#384"),
    ("analyst_clara", "SecurityShield@99"),
    ("auditor_dan", "AuditCompliance*2026"),
    ("dev_edward", "DevEnvironmentPass$1"),
    ("eng_fiona", "FirewallProtect@Key1"),
    ("manager_george", "ManagerClearance^77"),
    ("researcher_helen", "QuantumResearch&88"),
    ("operator_ivan", "IncidentResponse!55"),
    ("guest_julia", "GuestRestrictedPass#0"),
)


class ValidationError(Exception):
    """Користувацький виняток для помилок валідації довжини пароля."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує шістнадцятковий хеш конкатенації пароля та солі за алгоритмом sha3_512."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль закороткий: {len(password)} символів. "
            f"Мінімальна довжина: {MIN_PASSWORD_LENGTH}."
        )

    data_to_hash = (password + salt).encode("utf-8")
    hash_obj = hashlib.new(HASH_ALGORITHM, data=data_to_hash)
    return hash_obj.hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з персональною сіллю та повертає кортеж (логін, хеш)."""
    password_hash = generate_hash(password, salt=SALT)
    return username, password_hash


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    """Створює папку data та записує користувачів у CSV-файл."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])
            for username, password in users_list:
                user_record = create_user(username, password)
                writer.writerow(user_record)
        print(f"Базу користувачів успішно записано у {USERS_CSV_PATH}")
    except OSError as error:
        print(f"Помилка при записі у файл CSV: {error}")
        raise


def read_users_db() -> list[dict[str, str]]:
    """Зчитує користувачів із CSV-файлу та виводить таблицю на екран."""
    try:
        with open(USERS_CSV_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            users_db = list(reader)

        print("\n--- Вміст бази користувачів (users.csv) ---")
        print(f"{'Логін':<20} | {'Хеш пароля (SHA3-512)':<35}")
        print("-" * 60)
        for user in users_db:
            short_hash = f"{user['password_hash'][:30]}..."
            print(f"{user['username']:<20} | {short_hash:<35}")

        return users_db
    except FileNotFoundError:
        print(f"Помилка: файл {USERS_CSV_PATH} не знайдено.")
        raise
    except OSError as error:
        print(f"Помилка вводу/виводу при читанні CSV: {error}")
        raise


def log_event(func):
    """Декоратор, що логує спроби аутентифікації у JSON-файл."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if len(args) > 0 else kwargs.get("username", "unknown")
        result_status = "failure"
        try:
            is_success = func(*args, **kwargs)
            if is_success:
                result_status = "success"
            return is_success
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [username],
                "kwargs": {k: v for k, v in kwargs.items() if k != "password"},
            }

            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                logs = []
                if os.path.exists(LOG_JSON_PATH):
                    try:
                        with open(LOG_JSON_PATH, mode="r", encoding="utf-8") as f:
                            logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []

                logs.append(log_entry)

                with open(LOG_JSON_PATH, mode="w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except OSError as error:
                print(f"Помилка запису логів у JSON: {error}")

    return wrapper


@log_event
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    """Автентифікує користувача, перевіряючи хеш введеного пароля із сіллю."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    try:
        entered_hash = generate_hash(password, salt=SALT)
    except ValidationError:
        return False

    for user in users_db:
        if user["username"] == username:
            return user["password_hash"] == entered_hash

    return False


def run_task3() -> None:
    """Головна функція для виконання та демонстрації."""
    print("=" * 65)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print(f"Завдання 3: Хешування ({HASH_ALGORITHM}), CSV та JSON-лог")
    print(f"Персональна сіль: '{SALT}' | Мін. довжина пароля: {MIN_PASSWORD_LENGTH}")
    print("=" * 65)

    try:
        # 1. Реєстрація користувачів та збереження у CSV
        create_users(USERS_TO_REGISTER)

        # 2. Зчитування та відображення бази даних
        db = read_users_db()

        # 3. Демонстрація автентифікації та логування
        print("\n--- Демонстрація автентифікації та логування у log.json ---")

        # Успішний вхід
        test_user = "admin_alice"
        test_pass = "SecureAdminPass2026!"
        res_ok = login(test_user, test_pass, db)
        print(f"Спроба входу [{test_user}] з правильним паролем: {res_ok}")

        # Невдалий вхід: неправильний пароль
        res_wrong = login(test_user, "WrongPassword2026!", db)
        print(f"Спроба входу [{test_user}] з хибним паролем: {res_wrong}")

        # Невдалий вхід: неіснуючий користувач
        res_none = login("unknown_user", "AnyValidPassword2026!", db)
        print(f"Спроба входу [unknown_user]: {res_none}")

        # 4. Демонстрація обробки винятків (ValidationError та ValueError)
        print("\n--- Перевірка спрацювання винятків ---")
        try:
            generate_hash("short", salt=SALT)
        except ValidationError as err:
            print(f"Перехоплено ValidationError (закороткий пароль): {err}")

        try:
            generate_hash("", salt=SALT)
        except ValueError as err:
            print(f"Перехоплено ValueError (порожній пароль): {err}")

        print(f"\nЖурнал успішно збережено у: {LOG_JSON_PATH}")

    except (FileNotFoundError, OSError) as io_err:
        print(f"Критична файлова помилка: {io_err}")
    except (ValidationError, ValueError) as val_err:
        print(f"Критична помилка валідації: {val_err}")


if __name__ == "__main__":
    run_task3()