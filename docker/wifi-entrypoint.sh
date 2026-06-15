#!/bin/bash
set -e

# Desbloqueia rádios Wi-Fi/BT para ferramentas como airmon-ng e airodump-ng
rfkill unblock wifi 2>/dev/null || true
rfkill unblock all 2>/dev/null || true

exec sleep infinity
