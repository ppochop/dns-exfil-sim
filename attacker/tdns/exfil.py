import socket

import dns.query
import dns.message

RESPONSE_ADDRESS = '' # fill with the address that should be sent as answer

class base:
    def __init__(self, respond=True, udp=True):
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.respond = respond
        self.udp = udp

    def s_udp(self):
        while True:
            msg, time, from_addr = dns.query.receive_udp(self.sock)
            if self.respond:
                resp = dns.message.make_response(msg)
                resp.answer.append(dns.rrset.from_text(
                    msg.question[0].name, 0, 1, 1, RESPONSE_ADDRESS))
                dns.query.send_udp(self.sock, resp, from_addr)
            try:
                self.process(msg)
            except Exception as e:
                print(f'Exception occured, skipping: {e}')

    def s_tcp(self):
        self.sock.listen()
        msg: dns.message.Message
        while True:
            conn, addr = self.sock.accept()
            with conn:
                msg, time = dns.query.receive_tcp(conn)
                if self.respond:
                    resp = dns.message.make_response(msg)
                    resp.additional.clear()
                    resp.answer.append(dns.rrset.from_text(
                        msg.question[0].name, 0, 1, 1, RESPONSE_ADDRESS))
                    dns.query.send_tcp(conn, resp)
            try:
                self.process(msg)
            except Exception as e:
                print(f'Exception occured, skipping: {e}')

    def __call__(self):
        self.sock.bind(('', 53))
        print('Ready.')
        if self.udp:
            self.s_udp()
        else:
            self.s_tcp()







