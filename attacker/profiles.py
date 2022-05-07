from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from tdns.exfil import base
from tdns.frameworkpos import frameworkpos as fpos
from tdns.multigrainpos import multigrainpos as mpos
from tdns.ebury import ebury as ebry
from tdns.kessel import kessel as kssl
from tdns.fastervec import fastervec as fvec
from tdns.stealthyvec import stealthyvec as svec

"""
Following profiles will try to decode every incoming query as the respective vector. Response will be sent to the queries.
"""

def frameworkpos():
    return fpos(respond=True)


def multigrainpos():
    private_key: RSAPrivateKey
    with open('attacker/tdns/private.pem', 'rb') as keyfile:
        private_key = load_pem_private_key(
            keyfile.read(),
            password=None
        )

    return mpos(private_key, respond=True)


def ebury():
    return ebry()


def fastervec():
    return fvec(udp=True, respond=True)


def kessel():
    return kssl()


def stealthyvec():
    with open('wordlists/domains.txt', 'r') as dom_file:
        domains = dom_file.read().splitlines()
    with open('wordlists/words.txt', 'r') as words_file:
        words = words_file.read().splitlines()
    return svec(domains, words)


"""
Following profiles only respond to incoming queries with no data extraction.
"""

def respond_udp():
    responder = base()
    responder.process = lambda _: None
    return responder


def respond_tcp():
    responder = base(udp=False)
    responder.process = lambda _: None
    return responder
