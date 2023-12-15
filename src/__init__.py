from hashlib import sha1
from secrets import token_bytes

from construct import Bytes, ConstructError, GreedyBytes, Int8ub, Struct
from rsa import VerificationError
from rsa import sign as rsa_sign
from rsa import verify as rsa_verify
from rsa.key import PrivateKey, PublicKey

ComposedSignature = Struct(
    "nonce" / GreedyBytes,
    "data" / GreedyBytes,
)

ComposedMessage = Struct(
    "nonce_length" / Int8ub,
    "nonce" / Bytes(lambda ctx: ctx.nonce_length),
    "signer_length" / Int8ub,
    "signer" / Bytes(lambda ctx: ctx.signer_length),
    "signature" / GreedyBytes,
)


def compose_signature(nonce: bytes, data: bytes) -> bytes:
    composed_signature = ComposedSignature.build(
        {
            "nonce": nonce,
            "data": data,
        }
    )

    return composed_signature


def compose_message(nonce: bytes, signer: bytes, signature: bytes) -> bytes:
    composed_message = ComposedMessage.build(
        {
            "nonce_length": len(nonce),
            "nonce": nonce,
            "signer_length": len(signer),
            "signer": signer,
            "signature": signature,
        }
    )

    return composed_message


def parse_message(signature: bytes) -> [bytes, str, bytes]:
    try:
        parsed_message: dict = ComposedMessage.parse(signature)
    except ConstructError as exc:
        raise ValueError from exc

    return (
        parsed_message["nonce"],
        parsed_message["signer"].decode("utf-8"),
        parsed_message["signature"],
    )


def verify(public_key: bytes, nonce: bytes, signature: bytes, message: bytes) -> bool:
    message: bytes = compose_signature(nonce, message)

    try:
        key = PublicKey.load_pkcs1_openssl_der(public_key)
        rsa_verify(message, signature, key)

        return True
    except VerificationError:
        return False


def nonce(nonce_length: int | None = None) -> bytes:
    return token_bytes(nonce_length or 16)


def sign(
    private_key: bytes,
    signer: str | None = None,
    message: bytes | None = None,
    nonce_length: int | None = None,
    hash_method: str | None = None,
) -> bytes:
    if signer and 1 < len(signer) > 255:
        raise ValueError("Signer length must be between 1 and 255")

    if nonce_length and 1 < len(nonce_length) > 255:
        raise ValueError("Nonce length must be between 1 and 255")

    hash_method_list: list = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]

    if hash_method and hash_method not in hash_method_list:
        raise ValueError("Invalid hash method")

    random: bytes = nonce(nonce_length)
    hasher = sha1()
    hasher.update(message or b"")
    data = hasher.digest()

    composed_signature = compose_signature(random, data)
    key = PrivateKey.load_pkcs1(private_key, "DER")
    signature = rsa_sign(composed_signature, key, hash_method or "SHA-512")

    message = compose_message(random, signer.encode() or b"_", signature)

    return message
