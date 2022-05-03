from faker import Faker
from random import randint, choice, choices


class custom:

    def __init__(self):
        self.fake = Faker()
    
    def track_two(self, card_type=None):
        # card_type; holder_name; card_number expiry; cvc        
        info = self.fake.credit_card_full(card_type).split('\n')
        number = info[2][:-6]
        exp = info[2][-5:].split('/')
        exp.reverse()
        exp = ''.join(exp)

        # see track 2 format: https://en.wikipedia.org/wiki/Magnetic_stripe_card#Track_2
        # without lrc
        return f";{number}={exp}{randint(1, 9)}{choice([0, 2, 4])}{randint(0, 7)}{info[3][-3:]}?"

    def volume_serial_number(self):
        values = '0123456789abcdef'
        pre = ''.join(choices(values, k=4))
        post = ''.join(choices(values, k=4))
        return '-'.join([pre, post])
