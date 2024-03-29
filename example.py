import datetime

import jwt
from sanic import Sanic
import sanic.response

from sanic_verify_jwt import SanicVerifyJWT

ISSUER = "urn:authority.myapp.io"
AUDIENCE = "urn:services.myapp.io"
SECRET_KEY = "my-org-secret-key-read-from-keyvault"
SCOPES = ["profile:read", "profile:write"]


app = Sanic("SanicVerifyJWT-Example")
config_dict = dict(
    JWT_SECRET_KEY=SECRET_KEY,
    JWT_AUDIENCE=AUDIENCE,
    JWT_ISSUER=ISSUER,
    JWT_PROTECT_ALL=True,
)
app.update_config(config_dict)

auth = SanicVerifyJWT(app)

jwt_token = jwt.encode(
    {
        "iat": datetime.datetime.now(tz=datetime.timezone.utc),
        "exp": (
            datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(hours=1)
        ),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "scope": " ".join(SCOPES),
        # **(payload or {}),
    },
    SECRET_KEY,
)


@app.route("/")
async def index(request: sanic.Request) -> sanic.response.JSONResponse:
    return sanic.response.json({"message": "Go to /protected", "jwt_token": jwt_token})


@app.route("/protected")
@auth.auth_required()
async def protected(request: sanic.Request) -> sanic.response.JSONResponse:
    return sanic.response.json(request.ctx.jwt)


@app.route("/.health")
async def health(request: sanic.Request) -> sanic.response.JSONResponse:
    return sanic.response.json(request.ctx.jwt)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, auto_reload=True)
