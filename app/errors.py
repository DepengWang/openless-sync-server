from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        current_revision: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.current_revision = current_revision


def protocol_error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    current_revision: str | None = None,
) -> JSONResponse:
    error = {
        "code": code,
        "message": message[:200],
        "requestId": request.state.request_id,
    }
    if current_revision is not None:
        error["currentRevision"] = current_revision
    return JSONResponse(
        status_code=status_code,
        content={"error": error},
    )


async def api_error_handler(request: Request, error: ApiError) -> JSONResponse:
    return protocol_error_response(
        request,
        error.status_code,
        error.code,
        error.message,
        error.current_revision,
    )
