import logging
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
        app: sanic.Sanic = None,
        secret_key: str = None,
        algorithms: typing.Optional[typing.List[str]] = None,
        issuer: typing.Optional[str] = None,
        audience: typing.Optional[typing.Union[str, typing.List[str]]] = None,
    ):
        self.algorithms = algorithms
        self.secret_key = secret_key
        self.issuer = issuer
        self.audience = audience
        # self.protect_all = False
        # self.protect_all_exclude = []
        # self.protect_all_scopes = []
        if app is not None:
            self.init_app(app)
        self._app = app

    def init_app(self, app: Sanic):
        """hook on request start etc."""
        self.algorithms = self.algorithms or app.config.get("JWT_ALGORITHMS", ["HS256"])
        self.secret_key = self.secret_key or app.config.get("JWT_SECRET_KEY")
        self.issuer = self.issuer or app.config.get("JWT_ISSUER")
        self.audience = self.audience or app.config.get("JWT_AUDIENCE")
        app.register_middleware(self.open_session, "request")

    async def open_session(self, request: sanic.Request) -> None:
        if not request.token:
            logger.debug("No auth token found")
            request.ctx.jwt = None
            return
        try:
            decoded = jwt.decode(
                request.token,
                self.secret_key,
                issuer=self.issuer,
                audience=self.audience,
                algorithms=self.algorithms,
            )
            request.ctx.jwt = decoded
        except jwt.PyJWTError:
            error_logger.exception("Failed to verify JWT")
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
        self, *, audience: typing.Optional[typing.Union[str, typing.List[str]]] = None
    ):
        def _auth_decorator(handler: typing.Callable):  # TODO: fix type hints
            @wraps(handler)
            async def wrapper(request, *args, **kwargs):
                if not await self._is_authenticated(request, scopes=audience):
                    raise exceptions.Unauthorized("Auth required.")

                return await handler(request, *args, **kwargs)

            return wrapper

        return _auth_decorator
