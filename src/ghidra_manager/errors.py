"""User-facing manager errors."""


class ManagerError(RuntimeError):
    """An expected operational failure that should not show a traceback."""
