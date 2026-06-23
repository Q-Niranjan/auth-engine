import logging

import redis.asyncio as redis
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.config import settings
from auth_engine.core.redis import get_redis
from auth_engine.core.templates import jinja_env
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import UserCreate
from auth_engine.services.auth_service import AuthService
from auth_engine.services.session_service import SessionService

logger = logging.getLogger(__name__)
ui_router = APIRouter(include_in_schema=False)


@ui_router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> HTMLResponse:
    tmpl = jinja_env.get_template("oidc/register.html")
    return HTMLResponse(content=tmpl.render(app_name=settings.APP_NAME))


@ui_router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request) -> HTMLResponse:
    tmpl = jinja_env.get_template("oidc/forgot.html")
    return HTMLResponse(content=tmpl.render(app_name=settings.APP_NAME))


@ui_router.get("/login", response_class=RedirectResponse)
async def login_redirect(request: Request) -> RedirectResponse:
    # Redirect root /login to the main dashboard OAuth login flow
    return RedirectResponse(url="/api/v1/auth/oauth/authengine/login", status_code=302)


@ui_router.post("/register", response_model=None)
async def register_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> RedirectResponse | HTMLResponse:
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)

    try:
        user_in = UserCreate(email=email, password=password, first_name=name)
        await auth_service.register_user(user_in)
        return RedirectResponse(url="/login", status_code=302)
    except ValueError as e:
        tmpl = jinja_env.get_template("oidc/register.html")
        return HTMLResponse(
            content=tmpl.render(app_name=settings.APP_NAME, error=str(e)),
            status_code=400,
        )


@ui_router.post("/forgot-password")
async def forgot_password_submit(
    request: Request,
    email: str = Form(...),
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> HTMLResponse:
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)

    try:
        # Assuming default tenant for UI
        await auth_service.initiate_password_reset(email, None)
        tmpl = jinja_env.get_template("oidc/forgot.html")
        return HTMLResponse(
            content=tmpl.render(
                app_name=settings.APP_NAME,
                success_message="If the email exists, a reset link will be sent.",
            ),
            status_code=200,
        )
    except ValueError as e:
        tmpl = jinja_env.get_template("oidc/forgot.html")
        return HTMLResponse(
            content=tmpl.render(app_name=settings.APP_NAME, error=str(e)),
            status_code=400,
        )


@ui_router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str) -> HTMLResponse:
    tmpl = jinja_env.get_template("oidc/reset_password.html")
    return HTMLResponse(content=tmpl.render(app_name=settings.APP_NAME, token=token))


@ui_router.post("/reset-password", response_model=None)
async def reset_password_submit(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> RedirectResponse | HTMLResponse:
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)

    tmpl = jinja_env.get_template("oidc/reset_password.html")

    if password != confirm_password:
        return HTMLResponse(
            content=tmpl.render(
                app_name=settings.APP_NAME,
                token=token,
                error="Passwords do not match.",
            ),
            status_code=400,
        )

    try:
        await auth_service.confirm_password_reset(token, password)
        # Success, redirect to login
        return RedirectResponse(url="/login", status_code=302)
    except ValueError as e:
        return HTMLResponse(
            content=tmpl.render(app_name=settings.APP_NAME, token=token, error=str(e)),
            status_code=400,
        )


@ui_router.get("/verify-email", response_class=HTMLResponse)
async def verify_email_page(
    request: Request,
    token: str,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> HTMLResponse:
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)

    tmpl = jinja_env.get_template("oidc/verify_email.html")

    try:
        await auth_service.verify_email(token)
        return HTMLResponse(
            content=tmpl.render(app_name=settings.APP_NAME, success=True),
            status_code=200,
        )
    except ValueError as e:
        return HTMLResponse(
            content=tmpl.render(app_name=settings.APP_NAME, success=False, error=str(e)),
            status_code=400,
        )
