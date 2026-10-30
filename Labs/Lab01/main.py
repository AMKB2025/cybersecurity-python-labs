import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "../../"))

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER
from task1 import run_task1
from task2 import run_task2
from task3 import run_task3


def main() -> None:
    print("=" * 70)
    print(" Лабораторна робота №1")
    print(f" Студент: {STUDENT_NAME}")
    print(f" Група:   {GROUP_NAME}")
    print(f" Варіант: {VARIANT_NUMBER}")
    print("=" * 70)

    run_task1()

    run_task2()

    run_task3()

if __name__ == "__main__":
    main()