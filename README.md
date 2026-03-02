# AirSnitcher

> **Original tool by [Daniel Card (mr-r3b00t)](https://github.com/mr-r3b00t/AirSnitcher)**
> Based on NDSS 2026 research by [Mathy Vanhoef et al.](https://github.com/vanhoefm/airsnitch)
> Paper: [AirSnitch: Demystifying and Breaking Client Isolation in Wi-Fi Networks](https://papers.mathyvanhoef.com/ndss2026-airsnitch.pdf)

This fork contains a patched `install.sh` with the following improvements over the original:

| # | Fix | Impact |
|---|-----|--------|
| 1 | Build failures logged to `/tmp/airsnitch-build.log` instead of silently swallowed | Easier debugging |
| 2 | Monitor mode capability verified before install proceeds | Catches incompatible adapters early |
| 3 | rfkill soft/hard block checked and auto-resolved | Prevents silent failures on laptops |
| 4 | NetworkManager persistently unmanaged for test interfaces | Stops NM fighting wpa_supplicant during attacks |
| 5 | Upstream airsnitch commit pinned + recorded at `/opt/airsnitch/.install-commit` | Reproducible installs |
| 6 | Web UI binds to `127.0.0.1` only; systemd unit hardened | Reduces exposure on client networks |
| 7 | Symlinks use `rm -f` before `ln -s` | Avoids stale file collisions on reinstall |
| 8 | `stop.sh` uses PID file instead of fragile `pkill` pattern | Clean process management |

## Usage

```bash
chmod +x install.sh && sudo ./install.sh
```

With NetworkManager interface release at test time:
```bash
sudo AIRSNITCH_IFACES="wlan1 wlan2" airsnitch-web
```

Pin to a specific upstream commit:
```bash
AIRSNITCH_COMMIT=abc1234 sudo ./install.sh
```

## Credits

All credit for the original AirSnitcher wrapper goes to **[mr-r3b00t (Daniel Card)](https://github.com/mr-r3b00t)**.
All credit for the underlying AirSnitch attack tooling goes to **[Mathy Vanhoef](https://github.com/vanhoefm)** and the NDSS 2026 research team.

This fork only modifies the installer script for reliability and pentest field use.
