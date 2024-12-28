from minicps.devices import HMI
from utils import HMI_PROTOCOL, STATE, PLC1_ADDR
import random
import time

ALERT = ('alert',)
PUMP = ('pump',)

class MyHMI(HMI):

    def main_loop(self, sleep=2):
        time.sleep(10)
        count = 0
        while True:
            # Receive the current alert state from PLC1
            alert = int(self.receive(ALERT, PLC1_ADDR))
            print(f"Received ALERT value: {alert}")

            if (alert == 2):
                print("Water is over.Turning off the pump.")
                self.send(PUMP, 0, PLC1_ADDR)  # Turn off the pump
                if(count == 0):
                    count = random.randint(10, 20)
                    print(f"Generated count: {count}")
            elif(alert == 1):
                print(f"Water is high")
            else:
                print(f"Water is normal")

            if(count > 0):
                count = count -1
            else:
                count = 0
                self.send(PUMP, 1, PLC1_ADDR)  # Turn on the pump

            time.sleep(sleep)

if __name__ == "__main__":
    hmi = MyHMI(
        name="hmi",
        protocol=HMI_PROTOCOL,
        state=STATE
    )
    hmi.main_loop()
