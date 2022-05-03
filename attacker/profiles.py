from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import tdns.exfil

"""
Following profiles will try to decode every incoming query as the respective vector. Response will be sent to the queries.
"""

def frameworkpos():
    return tdns.exfil.frameworkpos(respond=True)


def multigrainpos():
    private_key: RSAPrivateKey
    with open('server/tdns/private.pem', 'rb') as keyfile:
        private_key = load_pem_private_key(
            keyfile.read(),
            password=None
        )

    return tdns.exfil.multigrainpos(private_key, respond=True)


def ebury():
    return tdns.exfil.ebury()


def fastervec():
    return tdns.exfil.fastervec(udp=True, respond=True)


def kessel():
    return tdns.exfil.kessel()


def stealthyvec():
    with open('wordlists/domains.txt', 'r') as dom_file:
        domains = dom_file.read().splitlines()
    with open('wordlists/words.txt', 'r') as words_file:
        words = words_file.read().splitlines()
    return tdns.exfil.stealthyvec(domains, words)


"""
Following profiles only respond to incoming queries with no data extraction.
"""

def respond_udp():
    responder = tdns.exfil.base()
    responder.process = lambda _: None
    return responder


def respond_tcp():
    responder = tdns.exfil.base(udp=False)
    responder.process = lambda _: None
    return responder

