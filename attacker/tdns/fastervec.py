from base64 import b64decode

from tdns.exfil import base


class fastervec(base):
    def __init__(self, udp, respond=False):
        super().__init__(respond, udp)

    def decode(self, text: bytes):
        return b64decode(text)

    def process(self, msg):
        innocent_string = msg.question[0].name.to_text().split('.', 1)[0]
        fin_list = [b'' for _ in range(len(msg.additional))]
        for answer in msg.additional:
            num = answer.name.to_text()[len(innocent_string):].split('.', 1)[0]
            fin_list[int(num)] = list(answer.items)[0].strings[0]
        to_dec = b''.join(fin_list)
        print(f'Received:\n{self.decode(to_dec).decode()}')
