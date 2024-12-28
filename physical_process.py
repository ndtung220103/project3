
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

            if(pump == 1):
                self.set(LEVEL, level + 1)
            
            self.set(LEVEL, level)
            if (level > 0.4):
                self.set(LEVEL,level - 0.4)
            time.sleep(2)


if __name__ == '__main__':

    rwt = RawWaterTank(
        name='rwt',
        state=STATE,
        protocol=None,
        section=TANK_SECTION,
        level=1
    )
