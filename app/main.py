from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.deps import AuthContext, CsrfError, NotAuthenticated, PasswordChangeRequired, PermissionDenied, get_auth_context
from app.routers import account, admin, articles, auth
from app.security.sessions import clear_session_cookie
from app.templating import templates

app = FastAPI(title="Moduł 1 - uwierzytelnianie i autoryzacja", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

app.include_router(auth.router)
app.include_router(account.router)
app.include_router(admin.router)
app.include_router(articles.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(NotAuthenticated)
def handle_not_authenticated(request: Request, exc: NotAuthenticated):
    url = "/login?expired=1" if exc.reason == "expired" else "/login"
    response = RedirectResponse(url, status_code=303)
    clear_session_cookie(response)
    return response


@app.exception_handler(PasswordChangeRequired)
def handle_password_change_required(request: Request, exc: PasswordChangeRequired):
    return RedirectResponse("/account/change-password", status_code=303)


@app.exception_handler(PermissionDenied)
def handle_permission_denied(request: Request, exc: PermissionDenied):
    return templates.TemplateResponse(request, "403.html", {}, status_code=403)


@app.exception_handler(CsrfError)
def handle_csrf_error(request: Request, exc: CsrfError):
    return templates.TemplateResponse(
        request, "403.html", {"message": "Niepoprawny token CSRF. Odśwież stronę i spróbuj ponownie."}, status_code=403
    )


@app.get("/")
def index(request: Request, password_changed: int = 0, ctx: AuthContext = Depends(get_auth_context)):
    return templates.TemplateResponse(request, "index.html", {"ctx": ctx, "password_changed": password_changed})
