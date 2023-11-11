import dataclasses
import datetime
import uuid
from unittest.mock import MagicMock

import jwt
import pytest
import sanic
from sanic.exceptions import Unauthorized
from sanic.request import Request

from sanic_verify_jwt import SanicVerifyJWT


@dataclasses.dataclass
class Config:
    JWT_SECRET_KEY = "secret-key"
    JWT_ISSUER = "test-issuer"
    JWT_AUDIENCE = "test-audience"
    JWT_PROTECT_ALL = True


@pytest.yield_fixture
def app():
    app = sanic.Sanic(f"test-{str(uuid.uuid4())}")
    app.config.update(Config.__dict__)
    SanicVerifyJWT(app)

    @app.get("/")
    async def get_all(request):
        return sanic.json({"result": "ok"})

    yield app


def test_401(app):
    _, response = app.test_client.get("/")
    assert response.status == 401


def test_200(app):
    token = jwt.encode(
        {
            "iat": datetime.datetime.now(tz=datetime.timezone.utc),
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=365),
            "iss": Config.JWT_ISSUER,
            "aud": Config.JWT_AUDIENCE,
            # "scope": " ".join(scopes or []),
        },
        Config.JWT_SECRET_KEY,
    )
    headers = {"Authorization": f"Bearer {token}"}

    _, response = app.test_client.get("/", headers=headers)
    assert response.status == 200


@pytest.fixture
def mock_sanic_app():
    return MagicMock()


@pytest.fixture
def mock_request():
    request = MagicMock(spec=Request)
    request.token = None
    request.ctx.jwt = {}
    return request


def test_SanicVerifyJWT_init(mock_sanic_app):
    jwt_verifier = SanicVerifyJWT(app=mock_sanic_app)
    assert jwt_verifier._app == mock_sanic_app


#
# def test_SanicVerifyJWT_open_session_no_token(mock_sanic_app, mock_request):
#     jwt_verifier = SanicVerifyJWT(app=mock_sanic_app)
#     jwt_verifier.open_session(mock_request)
#     assert mock_request.ctx.jwt is None


@pytest.mark.asyncio
async def test_SanicVerifyJWT_open_session_with_invalid_token(
    mock_sanic_app, mock_request
):
    jwt_verifier = SanicVerifyJWT(app=mock_sanic_app)
    mock_request.token = "invalid_token"
    with pytest.raises(Unauthorized):
        await jwt_verifier.open_session(mock_request)


@pytest.mark.asyncio
async def test_SanicVerifyJWT_authenticated_no_jwt(mock_sanic_app, mock_request):
    jwt_verifier = SanicVerifyJWT(app=mock_sanic_app)
    assert not await jwt_verifier._is_authenticated(mock_request)


@pytest.mark.asyncio
async def test_SanicVerifyJWT_authenticated_with_jwt_no_scope(
    mock_sanic_app, mock_request
):
    jwt_verifier = SanicVerifyJWT(app=mock_sanic_app)
    mock_request.ctx.jwt = {"scope": "read"}
    assert await jwt_verifier._is_authenticated(mock_request)
