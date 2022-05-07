from math import log2

from bitstring import Bits

from tdns.exfil import base


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
