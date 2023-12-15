import os
from json import dumps
from secrets import token_bytes, token_hex

import pytest
from app import app
from fastapi.testclient import TestClient
from signoff import sign

client = TestClient(app)

private_key: bytes = bytes.fromhex(os.getenv("PRIVATE_KEY"))


def test_signoff_success_without_request_body():
    signature = sign(private_key, "bob")
    headers: dict = {
        "x-signoff-signature": signature.hex(),
    }

    response = client.get("/foo", headers=headers)

    assert response.status_code == 200
    assert response.text == "Hello World!"

    signature = sign(private_key, "bob", hash_method="SHA-1")
    headers: dict = {
        "x-signoff-signature": signature.hex(),
    }

    response = client.get("/foo", headers=headers)

    assert response.status_code == 200
    assert response.text == "Hello World!"

    signature = sign(private_key, "bob", hash_method="SHA-256")
    headers: dict = {
        "x-signoff-signature": signature.hex(),
    }

    response = client.get("/foo", headers=headers)

    assert response.status_code == 200
    assert response.text == "Hello World!"


def test_signoff_success_with_request_body():
    body: dict = {"name": "Bob"}
    message: bytes = dumps(body, sort_keys=True).encode()
    signature = sign(private_key, "bob", message)
    headers: dict = {
        "x-signoff-signature": signature.hex(),
    }

    response = client.post("/bar", json=body, headers=headers)

    assert response.status_code == 200
    assert response.text == "Hello Bob!"


def test_signoff_failure_without_signature():
    body: dict = {"name": "Bob"}

    response = client.get("/foo")
    assert response.status_code == 401

    response = client.post("/bar", json=body)
    assert response.status_code == 401


def test_signoff_failure_with_invalid_signature():
    body: dict = {"name": "Bob"}
    headers = {
        "x-signoff-signature": token_hex(128),
    }

    response = client.get("/foo", headers=headers)
    assert response.status_code == 401

    response = client.post("/bar", json=body, headers=headers)
    assert response.status_code == 401


def test_signoff_failure_with_long_signer():
    with pytest.raises(ValueError):
        sign(private_key, token_hex(1024))


def test_signoff_failure_with_long_nonce():
    signature: bytes = int(62353).to_bytes(length=2, byteorder="big") + token_bytes(127)

    headers = {
        "x-signoff-signature": signature.hex(),
    }

    response = client.get("/foo", headers=headers)
    assert response.status_code == 401


def test_signoff_failure_with_invalid_hash():
    with pytest.raises(ValueError):
        sign(private_key, hash_method="foo")
