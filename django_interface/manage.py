#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

# add the project path into the sys.path
PROJECT_PATH = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.append(PROJECT_PATH)


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_interface.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
