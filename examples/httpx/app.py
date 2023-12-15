from os import getenv

from dotenv import load_dotenv
from httpx import Client
from signoff import sign

load_dotenv()

private_key: bytes = bytes.fromhex(getenv("PRIVATE_KEY"))


def add_signoff(request):
    message: bytes = request.read()
    signature = sign(private_key, "bob", message)

    request.headers["x-signoff-signature"] = signature.hex()


client = Client(event_hooks={"request": [add_signoff]})
