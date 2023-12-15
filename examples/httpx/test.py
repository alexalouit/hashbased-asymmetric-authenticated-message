import os
from hashlib import sha1

from app import client
from pytest_httpserver import HTTPServer
from signoff import parse_message, verify
from werkzeug.wrappers import Request, Response

public_key: bytes = bytes.fromhex(os.getenv("PUBLIC_KEY"))

HTTPServer.DEFAULT_LISTEN_PORT = 8000


def handler(request: Request):
    try:
        signoff_signature: bytes = bytes.fromhex(
            request.headers.get("x-signoff-signature")
        )

        nonce, signer, signature = parse_message(signoff_signature)
    except (TypeError, ValueError):
        return Response(status=401)

    request_body: bytes = request.get_data()

    hasher = sha1()
    hasher.update(request_body)
    message: bytes = hasher.digest()

    verification: bool = verify(public_key, nonce, signature, message)

    if not verification:
        return Response(status=401)

    return Response("Hello World!", status=200)


def test_signoff_success_without_request_body(httpserver: HTTPServer):
    httpserver.expect_request("/foo").respond_with_handler(handler)
    response = client.get("http://localhost:8000/foo")

    assert response.status_code == 200
    assert response.text == "Hello World!"


def test_signoff_success_with_request_body(httpserver: HTTPServer):
    httpserver.expect_request("/foo").respond_with_handler(handler)
    body: dict = {"name": "Bob"}
    response = client.post("http://localhost:8000/foo", json=body)

    assert response.status_code == 200
    assert response.text == "Hello World!"
