import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

# Регулярний вираз для парсингу рядків стандартного формату Combined/Common Log Format
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^\"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

# Сигнатури базових веб-атак для пошуку в URI запиту
ATTACK_SIGNATURES = {
    "SQLi": re.compile(r"(union\s+select|select\s+.*\s+from|sleep\(|\b(and|or)\b\s+\d+=\d+|')", re.IGNORECASE),
    "Directory Traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/win.ini)", re.IGNORECASE),
    "XSS": re.compile(r"(<script.*?>|alert\(|javascript:|onerror=|<img\s+src=)", re.IGNORECASE),
}


@dataclass(frozen=True)
class LogEntry:
    """Клас даних окремого запису веб-логу."""

    ip: str
    timestamp: datetime
    method: str
    uri: str
    status: int
    size: int


@dataclass(frozen=True)
class AttackAlert:
    """Клас даних виявленої атаки."""

    attack_type: str
    ip: str
    uri: str
    timestamp: str


def setup_logger() -> logging.Logger:
    """Налаштовує консольне логування у стандартному форматі [LEVEL] Message."""
    logger = logging.getLogger("WebLogAnalyzer")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def parse_log_line(line: str) -> LogEntry | None:
    """Розбирає рядок логу за допомогою регулярного виразу та повертає LogEntry."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    try:
        raw_time = data["timestamp"].split()[0]
        dt = datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
        status = int(data["status"])
        size = int(data["size"]) if data["size"].isdigit() else 0
        return LogEntry(
            ip=data["ip"],
            timestamp=dt,
            method=data["method"],
            uri=data["uri"],
            status=status,
            size=size,
        )
    except (ValueError, IndexError):
        return None


def detect_attacks(entry: LogEntry) -> list[AttackAlert]:
    """Перевіряє URI запиту на відповідність відомим сигнатурам атак."""
    alerts = []
    for attack_type, pattern in ATTACK_SIGNATURES.items():
        if pattern.search(entry.uri):
            alerts.append(
                AttackAlert(
                    attack_type=attack_type,
                    ip=entry.ip,
                    uri=entry.uri,
                    timestamp=entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                )
            )
    return alerts


def analyze_logs(
    log_file_path: Path,
    min_status: int = 400,
    top_count: int = 5,
    logger: logging.Logger | None = None,
) -> tuple[list[LogEntry], list[tuple[str, int, dict[int, int]]], list[AttackAlert]]:
    """Виконує повний аналіз лог-файлу: парсинг, підрахунок помилок та виявлення атак."""
    if logger is None:
        logger = setup_logger()

    if not log_file_path.exists():
        logger.error(f"Файл логу не знайдено: {log_file_path}")
        raise FileNotFoundError(f"Файл не знайдено: {log_file_path}")

    logger.info(f"Loading access log from {log_file_path}...")

    entries: list[LogEntry] = []
    error_ip_counter: Counter[str] = Counter()
    ip_status_breakdown: defaultdict[str, Counter[int]] = defaultdict(Counter)
    attacks: list[AttackAlert] = []

    with log_file_path.open(mode="r", encoding="utf-8", errors="replace") as file:
        for line in file:
            entry = parse_log_line(line)
            if entry is None:
                continue

            entries.append(entry)

            # Підрахунок статус-кодів помилок
            if entry.status >= min_status:
                error_ip_counter[entry.ip] += 1
                ip_status_breakdown[entry.ip][entry.status] += 1

            # Пошук атак
            attacks.extend(detect_attacks(entry))

    if entries:
        start_time = min(e.timestamp for e in entries).strftime("%Y-%m-%d %H:%M:%S")
        end_time = max(e.timestamp for e in entries).strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"Processed {len(entries)} log entries from {start_time} to {end_time}.")
    else:
        logger.warning("У файлі логу не знайдено валідних записів.")

    # Формування топу IP з розбивкою по статусах
    top_errors: list[tuple[str, int, dict[int, int]]] = []
    for ip, total_err in error_ip_counter.most_common(top_count):
        breakdown = dict(ip_status_breakdown[ip])
        top_errors.append((ip, total_err, breakdown))

    return entries, top_errors, attacks


def print_cli_summary(
    top_errors: list[tuple[str, int, dict[int, int]]],
    attacks: list[AttackAlert],
    min_status: int,
) -> None:
    """Виводить відформатовані результати аналізу в термінал згідно з прикладом у завданні."""
    status_label = f"({min_status // 100}xx/5xx)" if min_status == 400 else f"(>={min_status})"
    print(f"\n=== Top-{len(top_errors)} IP Addresses with Error Statuses {status_label} ===")
    for ip, total_errors, breakdown in top_errors:
        breakdown_str = ", ".join(f"{code}: {cnt}" for code, cnt in sorted(breakdown.items()))
        print(f"{ip:<16} {total_errors} errors ({breakdown_str})")

    print("\n=== Detected Attack Signatures ===")
    if not attacks:
        print("Аномалій або підозрілих сигнатур атак не виявлено.")
    for alert in attacks:
        print(f"[ALERT] Potential {alert.attack_type} attack from {alert.ip}: \"{alert.uri}\"")


def export_report(
    output_path: Path,
    export_format: str,
    top_errors: list[tuple[str, int, dict[int, int]]],
    attacks: list[AttackAlert],
    total_entries: int,
    logger: logging.Logger,
) -> None:
    """Зберігає структурований звіт у форматі JSON або CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if export_format.lower() == "json":
        report_data = {
            "summary": {
                "total_entries_analyzed": total_entries,
                "detected_attacks_count": len(attacks),
            },
            "top_error_ips": [
                {"ip": ip, "total_errors": total, "status_breakdown": breakdown}
                for ip, total, breakdown in top_errors
            ],
            "detected_attacks": [asdict(a) for a in attacks],
        }
        with output_path.open(mode="w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)

    elif export_format.lower() == "csv":
        with output_path.open(mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Section", "Type_Or_IP", "Details", "Extra"])
            for ip, total, breakdown in top_errors:
                writer.writerow(["TOP_ERROR_IP", ip, f"Total Errors: {total}", str(breakdown)])
            for alert in attacks:
                writer.writerow(["ATTACK_ALERT", alert.ip, alert.attack_type, alert.uri])

    logger.info(f"Analysis report saved to {output_path}")


def build_arg_parser() -> argparse.ArgumentParser:
    """Створює та налаштовує парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        description="CLI-утиліта для аналізу логів веб-сервера (Nginx/Apache Access Log) - Варіант 1."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        required=True,
        help="Шлях до текстового файлу access.log для аналізу.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("labs/lab02/data/data_v01/web_analysis_report.json"),
        help="Шлях для збереження вихідного звіту (за замовчуванням: labs/lab02/data/data_v01/web_analysis_report.json).",
    )
    parser.add_argument(
        "--min-status",
        type=int,
        default=400,
        help="Мінімальний HTTP-статус для врахування помилок (за замовчуванням: 400).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Кількість топових IP-адрес для виведення (за замовчуванням: 5).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Формат вивантаження звіту: json або csv (за замовчуванням: json).",
    )
    return parser


def main() -> None:
    """Головна точка входу CLI-утиліти."""
    parser = build_arg_parser()
    args = parser.parse_args()
    logger = setup_logger()

    try:
        entries, top_errors, attacks = analyze_logs(
            log_file_path=args.log_file,
            min_status=args.min_status,
            top_count=args.top,
            logger=logger,
        )

        print_cli_summary(top_errors, attacks, min_status=args.min_status)

        export_report(
            output_path=args.output,
            export_format=args.format,
            top_errors=top_errors,
            attacks=attacks,
            total_entries=len(entries),
            logger=logger,
        )
    except FileNotFoundError as err:
        logger.error(str(err))
        sys.exit(1)
    except Exception as err:  # noqa: BLE001
        logger.critical(f"Непередбачена помилка: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()