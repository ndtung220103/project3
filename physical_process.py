
from minicps.devices import Tank

from utils import  TANK_SECTION
from utils import STATE


import sys
import time


LEVEL = ('level',)
PUMP = ('pump',)

class RawWaterTank(Tank):

    def pre_loop(self):

        self.set(LEVEL, 1)
        self.set(PUMP, 1)

    def main_loop(self):

        while True:

            level = float(self.get(LEVEL))
            print(f"level : {level}")
            pump  = int(self.get(PUMP))
            print(f"pump : {pump}")

            if pump == 1:
                level += 1
            if level > 0.4:
                level -= 0.4
            
            self.set(LEVEL,level)
            time.sleep(1)


if __name__ == '__main__':

    rwt = RawWaterTank(
        name='rwt',
        state=STATE,
        protocol=None,
        section=TANK_SECTION,
        level=1
    )
