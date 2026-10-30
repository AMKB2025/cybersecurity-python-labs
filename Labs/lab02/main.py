import argparse
import sys
from pathlib import Path

from labs.lab02.task1 import run_oop_demo
from labs.lab02.task2 import (
    analyze_logs,
    export_report,
    print_cli_summary,
    setup_logger,
)


def build_cli_parser() -> argparse.ArgumentParser:
    """Створює головний CLI-парсер із підкомандами demo та analyze."""
    parser = argparse.ArgumentParser(
        description="Лабораторна робота №2: CLI-утиліти для задач кібербезпеки."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Режим роботи")

    # Підкоманда demo (Завдання 1)
    subparsers.add_parser("demo", help="Запустити демонстрацію об'єктної моделі (Завдання 1).")

    # Підкоманда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser(
        "analyze", help="Запустити аналізатор логів веб-сервера (Завдання 2)."
    )
    analyze_parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("labs/lab02/data/data_v01/access.log"),
        help="Шлях до файлу access.log.",
    )
    analyze_parser.add_argument(
        "--output",
        type=Path,
        default=Path("labs/lab02/data/data_v01/web_analysis_report.json"),
        help="Шлях до вихідного звіту.",
    )
    analyze_parser.add_argument(
        "--min-status",
        type=int,
        default=400,
        help="Мінімальний HTTP-статус для врахування помилок (за замовчуванням: 400).",
    )
    analyze_parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Кількість топових IP-адрес із помилками (за замовчуванням: 5).",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Формат вивантаження звіту (json/csv).",
    )

    return parser


def main() -> None:
    """Точка входу програми."""
    parser = build_cli_parser()
    args = parser.parse_args()

    if args.command == "demo":
        run_oop_demo()

    elif args.command == "analyze":
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