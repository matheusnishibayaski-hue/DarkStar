#!/bin/bash
echo "=== Interfaces wireless (iw) ==="
iw dev 2>/dev/null || echo "(nenhuma interface wireless detectada)"

echo ""
echo "=== Interfaces (iwconfig) ==="
iwconfig 2>/dev/null | grep -v "no wireless" || true

echo ""
echo "=== RFKill ==="
rfkill list 2>/dev/null || true

echo ""
echo "=== Adaptadores USB Wi-Fi ==="
if command -v lsusb >/dev/null 2>&1; then
  lsusb 2>/dev/null | grep -iE 'wireless|wlan|802\.11|realtek|ralink|atheros|mediatek|alfa|tp-link' || echo "(nenhum dongle USB Wi-Fi detectado)"
else
  echo "lsusb não disponível"
fi

echo ""
echo "=== Modo monitor disponível ==="
for iface in $(iw dev 2>/dev/null | awk '/Interface/ {print $2}'); do
  if iw phy "$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/ {print $2}')" info 2>/dev/null | grep -q "monitor"; then
    echo "$iface: suporta monitor mode"
  else
    echo "$iface: sem monitor mode"
  fi
done 2>/dev/null || echo "(verifique se há interface wireless conectada)"
