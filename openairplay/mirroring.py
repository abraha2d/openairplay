from hashlib import sha512

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import log
from .utils import SimpleRepr
from .receiver_device import AirplayReceiver

class OpenAirPlayMirroringClient(SimpleRepr):
    def __init__(
            self,
            receiver: AirplayReceiver,
        ):
        self.receiver = receiver

    async def start(self):
        # Start pairing process
        log.debug(f"setup mirroring session with {self.receiver.name} ...")
        info = await self.receiver._get_server_info()
        rc = await self.receiver._get_pyatv_rtsp_session()

        # Do /pair-setup
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()

        pair_setup_response = await rc.exchange(
            "POST", "/pair-setup",
            content_type="application/octet-stream",
            body=public_key,
        )
        srv_public_key = pair_setup_response.body

        # Do /pair-verify
        ecdh_private_key = X25519PrivateKey.generate()
        ecdh_public_key = ecdh_private_key.public_key().public_bytes_raw()

        pair_verify_response = await rc.exchange(
            "POST", "/pair-verify",
            content_type="application/octet-stream",
            body=b'\x01\x00\x00\x00' + ecdh_public_key + public_key,
        )
        srv_ecdh_public_key = pair_verify_response.body[:32]
        encrypted_signature = pair_verify_response.body[32:]

        # Setup AES-128-CTR
        ecdh_shared_key = ecdh_private_key.exchange(
            X25519PublicKey.from_public_bytes(srv_ecdh_public_key)
        )

        key = sha512(b"Pair-Verify-AES-Key" + ecdh_shared_key).digest()[:16]
        iv = sha512(b"Pair-Verify-AES-IV" + ecdh_shared_key).digest()[:16]

        cipher = Cipher(algorithms.AES128(key), modes.CTR(iv))
        encryptor = cipher.encryptor()

        # Verify that handshake was successful
        signature = encryptor.update(encrypted_signature)
        message = srv_ecdh_public_key + ecdh_public_key
        Ed25519PublicKey.from_public_bytes(srv_public_key).verify(signature, message)

        # Do 2nd /pair-verify
        message = ecdh_public_key + srv_ecdh_public_key
        signature = private_key.sign(message)
        encrypted_signature = encryptor.update(signature)

        await rc.exchange(
            "POST", "/pair-verify",
            content_type="application/octet-stream",
            body=b'\x00\x00\x00\x00' + encrypted_signature,
        )

        # TODO: Do /fp-setup with 16 bytes, expect 142 bytes
        # TODO: Do /fp-setup with 164 bytes, expect 32 bytes
