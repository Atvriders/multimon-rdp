#!/bin/sh
# Dynamically generates an xorg.conf with NUM_MONITORS dummy screens
# side-by-side under Xinerama, then starts Xorg + guacd.

rm -f /tmp/.X99-lock

NUM_MON="${NUM_MONITORS:-2}"
MON_W="${MON_W:-1920}"
MON_H="${MON_H:-1080}"

echo "[guacd] Configuring ${NUM_MON} monitor(s) at ${MON_W}x${MON_H}"

XCONF=/tmp/xorg.conf

# ── Build xorg.conf ──────────────────────────────────────────────────────────
{
  printf 'Section "ServerLayout"\n'
  printf '    Identifier "layout"\n'
  i=0
  while [ "$i" -lt "$NUM_MON" ]; do
    printf '    Screen %d "Screen%d" %d 0\n' "$i" "$i" "$((i * MON_W))"
    i=$((i + 1))
  done
  printf '    Option "Xinerama" "on"\n'
  printf 'EndSection\n\n'

  i=0
  while [ "$i" -lt "$NUM_MON" ]; do
    printf 'Section "Monitor"\n'
    printf '    Identifier "Monitor%d"\n' "$i"
    printf '    HorizSync   28-80\n'
    printf '    VertRefresh 48-75\n'
    printf 'EndSection\n\n'

    printf 'Section "Device"\n'
    printf '    Identifier "Device%d"\n' "$i"
    printf '    Driver "dummy"\n'
    printf '    VideoRam 131072\n'
    [ "$i" -gt 0 ] && printf '    Screen %d\n' "$i"
    printf 'EndSection\n\n'

    printf 'Section "Screen"\n'
    printf '    Identifier "Screen%d"\n' "$i"
    printf '    Device "Device%d"\n' "$i"
    printf '    Monitor "Monitor%d"\n' "$i"
    printf '    DefaultDepth 24\n'
    printf '    SubSection "Display"\n'
    printf '        Depth 24\n'
    printf '        Modes "%dx%d"\n' "$MON_W" "$MON_H"
    printf '        Virtual %d %d\n' "$MON_W" "$MON_H"
    printf '    EndSubSection\n'
    printf 'EndSection\n\n'

    i=$((i + 1))
  done
} > "$XCONF"

echo "[guacd] xorg.conf:"
cat "$XCONF"

# ── Start Xorg ───────────────────────────────────────────────────────────────
Xorg :99 -config "$XCONF" -nolisten tcp -novtswitch &

i=0
while [ "$i" -lt 60 ]; do
  sleep 0.1
  DISPLAY=:99 xrandr >/dev/null 2>&1 && break
  i=$((i + 1))
done

export DISPLAY=:99

echo "[guacd] X11 monitor layout:"
xrandr --listmonitors 2>/dev/null || xrandr 2>/dev/null || true

exec guacd -f -l "${GUACD_PORT:-4822}" -b 0.0.0.0
