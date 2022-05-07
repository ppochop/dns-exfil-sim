from tdns.exfil import base


class kessel(base):
    def __init__(self, respond=True, udp=True):
        super().__init__(respond, udp)
        self.encrypted_data = b''

    def decode(self, text: str):
        return bytes.fromhex(text)

    def decrypt(self, key: bytes, text: bytes):

        def KSA(key):
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % 4]) % 256
                S[i], S[j] = S[j], S[i]
            return S

        def PRGA(S):
            i = 0
            j = 0
            while True:
                i = (i + j) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                yield S[(S[i] + S[j]) % 256]

        plaintext = b''.join([(c ^ k).to_bytes(1, 'little')
                             for c, k in zip(text, PRGA(KSA(key)))])
        return plaintext.decode()

    def process(self, msg):
        text = msg.question[0].name.to_text().split('.')[:-3]
        self.encrypted_data += self.decode(''.join(text))
        if self.encrypted_data[-1] == ord(b';'):  # received all data
            key = self.encrypted_data[-5:-1]
            decrypted = self.decrypt(key, self.encrypted_data[:-9])
            print(decrypted)
            self.encrypted_data = b''
