from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message


async def api_error_handler(request: Request, error: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={"code": error.code, "message": error.message},
    )
