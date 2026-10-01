import os
import random
import string
import sys

# Додавання кореневої папки проєкту до системного шляху для імпорту shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані
INITIAL_PASSWORDS = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssword",
    "123456",
    "SecurePass!",
    "test",
    "P@ssword123",
    "welcome",
    "StrongP@ss1",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "password",
    "123456",
    "admin",
    "test",
    "welcome",
    "qwerty",
}


def check_criteria_match(password: str) -> dict[str, bool]:
    """Перевіряє відповідність пароля основним критеріям безпеки."""
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in string.punctuation for char in password)
    length_ok = len(password) >= CRITERIA["min_length"]

    return {
        "length": length_ok,
        "digits": has_digit,
        "upper": has_upper,
        "lower": has_lower,
        "special": has_special,
    }


def evaluate_password_strength(
    password: str,
    all_passwords: list[str],
) -> str:
    """Оцінює рівень стійкості пароля"""
    min_len = CRITERIA["min_length"]
    checks = check_criteria_match(password)

    # 1. Заборонений
    if password in FORBIDDEN_PASSWORDS or len(password) < min_len:
        return "Заборонений"

    # Перевірка виконання всіх критеріїв безпеки
    all_secure = (
        checks["length"]
        and checks["digits"]
        and checks["upper"]
        and checks["special"]
    )

    # 2. Дуже сильний (всі критерії, довжина >= min + 4, унікальний у списку)
    if (
        all_secure
        and len(password) >= min_len + 4
        and all_passwords.count(password) == 1
    ):
        return "Дуже сильний"

    # 3. Сильний (всі критерії, але довжина < min + 4 або не унікальний)
    if all_secure and len(password) < min_len + 4:
        return "Сильний"

    # 4. Середній (відповідає min_length та деяким, але не всім критеріям)
    symbol_groups = [
        checks["digits"],
        checks["upper"],
        checks["special"],
        checks["lower"],
    ]
    if checks["length"] and any(symbol_groups) and not all(symbol_groups):
        return "Середній"

    # 5. Слабкий (якщо виконує хоча б один базовий критерій)
    if any(symbol_groups):
        return "Слабкий"

    return "Слабкий"


def run_task1() -> None:
    """Головна функція для виконання аналізу паролів."""
    print("=" * 60)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("Завдання 1: Комплексний аналізатор надійності паролів")
    print("=" * 60)

    # Створюємо копію початкового списку
    passwords = list(INITIAL_PASSWORDS)

    # Генеруємо 3 випадкові індекси та дублюємо вибрані паролі в кінець списку
    random.seed()  # Фіксований seed для повторюваності результатів
    duplicate_indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in duplicate_indices:
        passwords.append(passwords[idx])

    # Виведення результатів аналізу в табличному форматі
    print(f"\n{'№':<3} | {'Пароль':<18} | {'Довжина':<8} | {'Статус':<15}")
    print("-" * 52)

    for i, pwd in enumerate(passwords, start=1):
        status = evaluate_password_strength(pwd, passwords)
        print(f"{i:<3} | {pwd:<18} | {len(pwd):<8} | {status:<15}")


if __name__ == "__main__":
    run_task1()