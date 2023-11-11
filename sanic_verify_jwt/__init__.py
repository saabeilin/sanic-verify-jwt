import logging
import re
import typing
from functools import wraps

import jwt
import sanic
from sanic import Sanic, exceptions
from sanic.log import error_logger

logger = logging.getLogger(__name__)


class SanicVerifyJWT:
    def __init__(
        self,
        app: typing.Optional[sanic.Sanic] = None,
        secret_key: typing.Optional[str] = None,
        algorithms: typing.Optional[typing.List[str]] = None,
        issuer: typing.Optional[str] = None,
        audience: typing.Optional[typing.Union[str, typing.List[str]]] = None,
    ):
        self.algorithms = algorithms
        self.secret_key = secret_key
        self.issuer = issuer
        self.audience = audience
        self.protect_all = False
        self.protect_all_exclude: list[str] = []
        self.protect_all_scopes: list[str] = []
        if app is not None:
            self.init_app(app)
        self._app = app

    def init_app(self, app: Sanic) -> None:
        """hook on request start etc."""
        self.algorithms = self.algorithms or app.config.get("JWT_ALGORITHMS", ["HS256"])
        self.secret_key = self.secret_key or app.config.get("JWT_SECRET_KEY")
        self.issuer = self.issuer or app.config.get("JWT_ISSUER")
        self.audience = self.audience or app.config.get("JWT_AUDIENCE")
        self.protect_all = app.config.get("JWT_PROTECT_ALL", False)
        self.protect_all_exclude = app.config.get(
            "JWT_PROTECT_ALL_EXCLUDE", ["/.health"]
        )
        self.protect_all_scopes = app.config.get("JWT_PROTECT_ALL_SCOPES", [])
        app.register_middleware(self.open_session, "request")

    async def open_session(self, request: sanic.Request) -> None:
        request.ctx.jwt = None

        if request.token:
            try:
                request.ctx.jwt = jwt.decode(
                    request.token,
                    self.secret_key,
                    issuer=self.issuer,
                    audience=self.audience,
                    algorithms=self.algorithms,
                )
            except jwt.PyJWTError:
                error_logger.exception("Failed to verify JWT")
                raise exceptions.Unauthorized("Auth required.")

        if self.protect_all:
            if self.protect_all_exclude:
                for excluded in self.protect_all_exclude:
                    if excluded == request.path or re.match(excluded, request.path):
                        logger.debug("Excluding %s matches %s", request.path, excluded)
                        return
            if not await self._is_authenticated(
                request, scopes=self.protect_all_scopes
            ):
                raise exceptions.Unauthorized("Auth required.")

    async def _is_authenticated(
        self,
        request: sanic.Request,
        scopes: typing.Optional[typing.Union[str, typing.List[str]]] = None,
    ) -> bool:
        if not request.ctx.jwt:
            return False

        if scopes:
            if isinstance(scopes, str):
                scopes = [
                    scopes,
                ]
            jwt_scopes = request.ctx.jwt["scope"].split()
            return set(scopes) ^ set(jwt_scopes) == set(scopes)

        return True

    def auth_required(
        self, *, scopes: typing.Optional[typing.Union[str, typing.List[str]]] = None
    ):
        def _auth_decorator(handler: typing.Callable):  # TODO: fix type hints
            @wraps(handler)
            async def wrapper(request, *args, **kwargs):
                if not await self._is_authenticated(request, scopes=scopes):
                    raise exceptions.Unauthorized("Auth required.")

                return await handler(request, *args, **kwargs)

            return wrapper

        return _auth_decorator
