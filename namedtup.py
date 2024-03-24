""" imports """
from dataclasses import dataclass
from collections import namedtuple

@dataclass
class Maths:
    """ just basic maths """
    Settings = namedtuple('settings',[
        'hash_upper',
        'hash_list'
    ])
    settings =  None
    same: float
    double: float
    square: float
    cube: float

    def do_it(self):
        """ double a number """
        self.double = self.double * 2
        self.square = self.square ** 2
        self.cube = self.cube ** 3

maths = Maths(same=1, double=2, square=3, cube=4.4)

print(maths)
maths.do_it()
print(maths)
maths.same=22/7
maths.do_it()
maths.settings = maths.Settings(True, ['md5', 'sha1'])
print(maths)
print(maths.settings.hash_upper)
