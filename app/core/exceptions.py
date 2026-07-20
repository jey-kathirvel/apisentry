from typing import Any


class APIError(Exception):
    def __init__(
        self,
        status_code: int,
        message: str,
        error_code: str = "api_error",
        details: Any = None,
    ) -> None:
        self.status_code = status_code
        self.message = message
        self.error_code = error_code
        self.details = details

        super().__init__(message)
