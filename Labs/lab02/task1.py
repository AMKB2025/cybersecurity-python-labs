import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900
EMAIL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class User:
    """Базовий клас користувача з безпечним збереженням пароля та валідацією email."""

    def __init__(self, username: str, email: str, role: str = "user", active: bool = True) -> None:
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email  # Виклик сетера для валідації через regex
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        """Геттер для отримання email."""
        return self._email

    @email.setter
    def email(self, new_email: str) -> None:
        """Сеттер email з обов'язковою валідацією формату через регулярний вираз."""
        if not isinstance(new_email, str) or not EMAIL_REGEX.match(new_email):
            raise ValueError(f"Некоректний формат email: '{new_email}'.")
        self._email = new_email

    def set_password(self, password: str) -> None:
        """Генерує випадкову сіль та обчислює стійкий PBKDF2-HMAC-SHA256 хеш."""
        if not password or len(password) < 8:
            raise ValueError("Пароль повинен містити щонайменше 8 символів.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль за допомогою стійкого до атак за часом hmac.compare_digest."""
        if not self.__password_hash or not self.__password_salt:
            return False
        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, calculated_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User(username='{self.username}', email='{self.email}', role='{self.role}', status='{status}')"


class Admin(User):
    """Клас адміністратора, що успадковує User та додає управління правами доступу."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | list[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, role="admin", active=active)
        # Уникнення використання mutable default argument
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Надає адміністратору новий дозвіл."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Відкликає дозвіл в адміністратора."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність дозволу."""
        return permission in self.permissions

    def __str__(self) -> str:
        perms_str = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"Admin(username='{self.username}', email='{self.email}', permissions=[{perms_str}])"


class Session:
    """Клас сеансу автентифікації з контролем часу активності в UTC."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        """Оновлює час останньої активності сеансу."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не закінчився термін дії сеансу відносно last_activity."""
        if timeout_sec <= 0:
            raise ValueError("Таймаут повинен бути додатним числом.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class LogEntry:
    """Незмінний запис журналу аудиту подій безпеки."""

    timestamp: datetime
    username: str
    action: str

    def __str__(self) -> str:
        time_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"[{time_str}] User '{self.username}': {self.action}"


class AuditLog:
    """Журнал реєстрації подій безпеки."""

    def __init__(self) -> None:
        self._logs: list[LogEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Фіксує подію в журналі із поточним часом UTC."""
        entry = LogEntry(timestamp=datetime.now(timezone.utc), username=username, action=action)
        self._logs.append(entry)

    def show_all(self) -> list[LogEntry]:
        """Повертає копію списку всіх записів аудиту."""
        return list(self._logs)


class UserAccount:
    """Композитний клас облікового запису (User + Session + AuditLog)."""

    def __init__(
        self,
        user: User,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.audit_log = audit_log if audit_log is not None else AuditLog()
        self.session: Session | None = None

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікація: перевіряє активність, пароль, оновлює сесію та аудит."""
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure: account_inactive_or_wrong_user")
            return False

        if not self.user.check_password(password):
            self.audit_log.add_log(username, "login_failure: invalid_password")
            return False

        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Перевіряє факт аутентифікації та валідність сеансу (не продовжує таймаут)."""
        if self.session is None:
            return False
        return self.session.is_active(timeout_sec=SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершує сеанс користувача та фіксує подію виходу."""
        username = self.user.username
        self.session = None
        self.audit_log.add_log(username, "logout")

    def __getitem__(self, key: str) -> Any:
        """Дозволяє доступ за ключем до дозволених публічних полів (забороняє хеш/сіль)."""
        if key == "user":
            return self.user
        if key == "session":
            return self.session
        if key == "audit_log":
            return self.audit_log
        if key in ("username", "email", "role", "active"):
            return getattr(self.user, key)
        raise KeyError(f"Доступ до ключа '{key}' заборонено або ключ не існує.")

    def __setitem__(self, key: str, value: Any) -> None:
        """Дозволяє безпечну зміну дозволених атрибутів з перевіркою типів."""
        if key == "email":
            if not isinstance(value, str):
                raise TypeError("Email повинен бути рядком.")
            self.user.email = value
        elif key == "active":
            if not isinstance(value, bool):
                raise TypeError("Статус active повинен бути булевим значенням.")
            self.user.active = value
        elif key in ("__password_hash", "__password_salt", "session", "user"):
            raise KeyError(f"Пряма модифікація поля '{key}' через словниковий доступ заборонена.")
        else:
            raise KeyError(f"Невідомий ключ '{key}' для запису.")


def run_oop_demo() -> None:
    """Функція демонстрації роботи об'єктної моделі."""
    print("=" * 70)
    print(" ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1: ООП, БЕЗПЕЧНІ СЕСІЇ ТА АУДИТ")
    print("=" * 70)

    # 1. Створення користувача та встановлення пароля
    print("\n1. Створення користувача та перевірка PBKDF2-HMAC-SHA256:")
    vlad = User(username="vlad_sec", email="vlad.sec@gmail.com", role="analyst")
    vlad.set_password("SuperSecretPass2026!")
    print(f"   Створено: {vlad}")

    # 2. Валідація email через @property
    print("\n2. Перевірка валідації email через @property:")
    try:
        vlad.email = "bad-email-format"
    except ValueError as err:
        print(f"   [Очікуваний перехоплений виняток] {err}")

    # 3. Наслідування: клас Admin та permissions
    print("\n3. Створення адміністратора та керування правами:")
    roman_admin = Admin(
        username="roman_admin",
        email="roman.kovach@gmail.com",
        permissions=["read_logs", "manage_firewall"],
    )
    roman_admin.set_password("AdminMasterPass#2026")
    print(f"   Початковий стан: {roman_admin}")
    roman_admin.grant_permission("export_reports")
    print(f"   Чи є право 'export_reports': {roman_admin.has_permission('export_reports')}")
    roman_admin.revoke_permission("read_logs")
    print(f"   Після змін: {roman_admin}")

    # 4. Композиція: UserAccount, автентифікація та сесії
    print("\n4. Створення UserAccount (композиція), автентифікація та аудит:")
    shared_log = AuditLog()
    account = UserAccount(user=vlad, audit_log=shared_log)

    print("   Спроба входу з хибним паролем...")
    res_wrong = account.login("vlad_sec", "WrongPassword!", ip="192.168.1.15")
    print(f"   Результат входу: {res_wrong}")

    print("   Спроба входу з правильним паролем...")
    res_ok = account.login("vlad_sec", "SuperSecretPass2026!", ip="192.168.1.15")
    print(f"   Результат входу: {res_ok}")
    print(f"   Статус аутентифікації: {account.is_authenticated()}")

    # 5. Тест спеціальних методів __getitem__ та __setitem__
    print("\n5. Тестування спеціальних методів __getitem__ / __setitem__:")
    print(f"   account['username'] -> {account['username']}")
    print(f"   account['email']    -> {account['email']}")
    account["email"] = "vlad.new@gmail.com"
    print(f"   Оновлено через __setitem__: {account['email']}")
    try:
        _ = account["__password_hash"]
    except KeyError as err:
        print(f"   [Захист пароля через __getitem__]: {err}")

    # 6. Завершення сесії та вивід журналу аудиту
    print("\n6. Завершення сеансу (logout) та історія AuditLog:")
    account.logout()
    print(f"   Статус після виходу: {account.is_authenticated()}")

    print("\n--- Записи AuditLog ---")
    for entry in shared_log.show_all():
        print(f"   {entry}")
    print("=" * 70)


if __name__ == "__main__":
    run_oop_demo()