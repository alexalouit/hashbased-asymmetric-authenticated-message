import os
from hashlib import sha1

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import PlainTextResponse
from signoff import parse_message, verify
from starlette.types import Message

load_dotenv()


app = FastAPI(docs_url=None, redoc_url=None)

public_key: bytes = bytes.fromhex(os.getenv("PUBLIC_KEY"))


async def set_body(request: Request, body: bytes):
    async def receive() -> Message:
        return {"type": "http.request", "body": body}

    request._receive = receive


async def get_body(request: Request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body


@app.middleware("http")
async def add_signoff(request: Request, call_next):
    try:
        signoff_signature: bytes = bytes.fromhex(
            request.headers.get("x-signoff-signature")
        )

        nonce, signer, signature = parse_message(signoff_signature)
    except (TypeError, ValueError):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    await set_body(request, await request.body())
    request_body: bytes = await get_body(request)

    hasher = sha1()
    hasher.update(request_body)
    message: bytes = hasher.digest()

    verification: bool = verify(public_key, nonce, signature, message)

    if not verification:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    response = await call_next(request)
    return response


@app.get("/foo")
async def get_alice():
    return PlainTextResponse("Hello World!")


@app.post("/bar")
async def post_bar(request: Request):
    request_body: dict = await request.json()
    return PlainTextResponse("Hello %s!" % request_body["name"])
