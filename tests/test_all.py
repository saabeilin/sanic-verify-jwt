import dataclasses
import datetime
import uuid

import jwt
import pytest
import sanic

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
