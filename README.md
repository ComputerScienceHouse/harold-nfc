# Harold-NFC
A NFC system that scans tags, identifies user via GateKeeper, and plays personalized audio through Audiophiler.

```mermaid
graph LR
    A["NFC Tag"] --> B["PN532 Reader (UART)"]
    B --> C["GateKeeperMemberListener"]
    C --> D["User Resolution"]
    D --> E["Audio Pipeline"]
    E --> F["Local Scan Sound"]
    E --> G["Audiophiler"]
```
## Dependencies

1. FFmpeg (for audio playback)
2. libnfc (NFC communication)
3. An environment file containing the Gatekeeper credentials.

## Systemd Setup

Harold NFC can be run as a background service using `systemd`.
```
[Unit]
Description=Harold NFC
After=network-online.target sound.target
Wants=network-online.target
[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/gatekeeper/harold-nfc
EnvironmentFile=/home/pi/gatekeeper/harold-nfc/.env
ExecStart=/home/pi/gatekeeper/harold-nfc/target/release/harold-nfc

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## GPIOs

```mermaid
graph TD
    A["Raspberry Pi"] 

    A --> B["3.3V (Pin 1)"]
    A --> C["GND (Pin 6)"]
    A --> D["TX (GPIO14, Pin 8)"]
    A --> E["RX (GPIO15, Pin 10)"]

    D --> F["RX (PN532)"]
    E --> G["TX (PN532)"]
    B --> H["VCC (PN532)"]
    C --> I["GND (PN532)"]
```
