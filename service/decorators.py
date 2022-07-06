import jwt
from flask import request, abort

from constants import JWT_ALG, JWT_SECRET


def auth_requered(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)

        data_for_token = request.headers["Authorization"]
        token = data_for_token.split("Bearer")[-1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        return func(*args, **kwargs)

    return wrapper


def admin_requered(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)

        data_for_token = request.headers["Authorization"]
        token = data_for_token.split("Bearer")[-1]

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        else:
            if data["role"] == "admin":
                return func(*args, **kwargs)

        abort(403)

    return wrapper