import os
import sys

# Додавання кореневої папки проєкту до системного шляху для імпорту shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для Варіанту 1
USERS = {
    "admin001": {
        "role": "administrator",
        "clearance": 4,
        "department": "IT",
        "active": True,
    },
    "user123": {
        "role": "analyst",
        "clearance": 2,
        "department": "Security",
        "active": True,
    },
    "guest789": {
        "role": "guest",
        "clearance": 1,
        "department": "External",
        "active": True,
    },
    "manager456": {
        "role": "manager",
        "clearance": 3,
        "department": "Operations",
        "active": True,
    },
    "contractor99": {
        "role": "contractor",
        "clearance": 1,
        "department": "External",
        "active": False,
    },
}

RESOURCES = [
    ("database_backup", 4),
    ("user_logs", 2),
    ("public_docs", 1),
    ("financial_reports", 3),
    ("system_config", 4),
    ("training_materials", 1),
    ("security_policies", 3),
    ("audit_logs", 4),
    ("employee_data", 3),
    ("temp_files", 1),
]

SECURITY_LEVELS = ("Public", "Internal", "Confidential", "Secret")
BLOCKED_USERS = {"contractor99", "temp_user", "suspended_acc"}


def get_security_level_name(level: int) -> str:
    """Повертає текстову назву рівня безпеки за його числовим індексом."""
    if 1 <= level <= len(SECURITY_LEVELS):
        return SECURITY_LEVELS[level - 1]
    return "Unknown"


def display_resources() -> None:
    """Виводить список усіх ресурсів системи з текстовими рівнями безпеки."""
    print("\n--- Список ресурсів системи ---")
    print(f"{'Назва ресурсу':<25} | {'Рівень безпеки':<15}")
    print("-" * 43)
    for name, level in RESOURCES:
        text_level = get_security_level_name(level)
        print(f"{name:<25} | {text_level:<15}")


def check_access(username: str, resource_name: str, resource_level: int) -> str:
    """Перевіряє доступ конкретного користувача до вказаного ресурсу."""
    # 1. Перевірка наявності користувача в системі
    if username not in USERS:
        return "DENY (User not found)"

    # 2. Перевірка блокування
    if username in BLOCKED_USERS:
        return "DENY (User is blocked)"

    user_info = USERS[username]

    # 3. Перевірка активності облікового запису
    if not user_info.get("active", False):
        return "DENY (Account inactive)"

    # 4 та 5. Перевірка рівня допуску (clearance)
    user_clearance = user_info.get("clearance", 0)
    if user_clearance >= resource_level:
        return "ALLOW"

    return "DENY (Insufficient clearance)"


def run_task2() -> None:
    """Головна функція виконання Завдання 2."""
    print("=" * 65)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("Завдання 2: Багаторівнева система контролю доступу")
    print("=" * 65)

    # Крок 2: Виведення ресурсів із текстовими назвами рівнів
    display_resources()

    # Крок 3 та 4: Перевірка доступу кожного користувача до кожного ресурсу
    print("\n--- Результати перевірки доступу ---")

    # Додаємо тестового неіснуючого користувача для повноти демонстрації правила
    test_user_list = list(USERS.keys()) + ["unknown_user"]

    for user in test_user_list:
        print(f"\nПеревірка для користувача: [{user}]")
        for res_name, res_level in RESOURCES:
            decision = check_access(user, res_name, res_level)
            print(f"user={user:<15} resource={res_name:<20} -> {decision}")


if __name__ == "__main__":
    run_task2()