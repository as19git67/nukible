# simnukifob
Simulates a Nuki.io Fob (runs on Raspberry PI on node.js - needs bluetooth dongle)
It pairs with a nuki smartlock and performs a unlock command.

Note that this code is preliminary and my cause unexpected results.

# Installation
I'm running the nuki fob simulator on a Raspberry PI 2 and on a Raspberry PI 3 with node.js version 4.4.4 and on the PI 2 there is a bluetooth dongle connected via USB.

## Install Node.js

```sh
wget https://nodejs.org/dist/v4.4.4/node-v4.4.4-linux-armv6l.tar.gz (Raspberry PI 2)
wget https://nodejs.org/dist/v4.4.4/node-v4.4.4-linux-armv7l.tar.gz (Raspberry PI 3)

tar xvfz node-v4.4.4-linux-armvXl.tar.gz
cd node-v4.4.4-linux-armvXl
sudo cp -R * /usr/local/
```
## Bluetooth connection to the Nuki SmartLock

```sh
sudo apt-get install bluetooth bluez libbluetooth-dev libudev-dev git
```

### Running without root/sudo

Run the following command:

```sh
sudo setcap cap_net_raw+eip $(eval readlink -f `which node`)
```

This grants the ```node``` binary ```cap_net_raw``` privileges, so it can start/stop BLE advertising.

__Note:__ The above command requires ```setcap``` to be installed, it can be installed using the following:

 * apt: ```sudo apt-get install libcap2-bin```

(see https://github.com/sandeepmistry/noble#running-on-linux)

## Get node modules
In the cloned repository run:
```sh
npm install
```

## Run it
To run the simulator call node with main.js. If running the first time it pairs with the nuki lock (currently tried only with a simulation of the lock (https://github.com/as19git67/simnuki)) and then performs a unlock command.

```sh
node main.js
```
