from tdns.exfil import base


class frameworkpos(base):

    def __init__(self, xor_key=0xf2, **kwargs):
        super().__init__(**kwargs)
        self.xor_key = xor_key

    def decode(self, text):
        return ''.join([chr(int(text[i:i+2], base=16) ^ self.xor_key) for i in range(0, len(text), 2)])

    def beacon(self, hostname, host_ip):
        print(
            f"target info: ip={self.decode(host_ip)} hostname={self.decode(hostname)}")

    def alert(self, proc_name, _):
        print(f"process name: {self.decode(proc_name)}")

    def card(self, card_num, card_info):
        print(
            f"track 2 data: ;{self.decode(card_num)}={self.decode(card_info)}?")

    def process(self, msg):
        text = msg.question[0].name.to_text().split('.')
        id = text[0]
        req_type = text[1]
        if req_type not in ['alert', 'beacon']:
            req_type = 'card'
            text = text[1:]
        else:
            text = text[2:]

        print(f"from id={id} received {req_type}:", end=' ')
        # call `beacon`, `alert` or `card` function
        self.__getattribute__(req_type)(text[0], text[1])
