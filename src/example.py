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
auth = SanicVerifyJWT(app, secret_key=SECRET_KEY, audience=AUDIENCE, issuer=ISSUER)

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
async def index(request):
    return sanic.response.json({"message": f"Go to /protected", "jwt_token": jwt_token})


@app.route("/protected")
@auth.auth_required()
async def protected(request):
    return sanic.response.json(request.ctx.jwt)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, auto_reload=True)
