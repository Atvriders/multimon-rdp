#!/bin/sh
# Start Xorg with one large dummy framebuffer, then carve it into N XRandR 1.5
# software monitors. FreeRDP reads these via XRRGetMonitors and sends a proper
# TS_UD_CS_MONITOR PDU to Windows — so Windows sees N real separate monitors,
# each with its own taskbar, start menu, and system tray.

rm -f /tmp/.X99-lock

NUM_MON="${NUM_MONITORS:-2}"
MON_W="${MON_W:-1920}"
MON_H="${MON_H:-1080}"
TOTAL_W=$((NUM_MON * MON_W))

echo "[guacd] Configuring ${NUM_MON} monitor(s) at ${MON_W}x${MON_H} (framebuffer: ${TOTAL_W}x${MON_H})"

XCONF=/tmp/xorg.conf

# Single dummy screen sized to fit all monitors side-by-side.
# VideoRam 65536 = 64 MB (enough for 5760x1080x32).
cat > "$XCONF" << XEOF
Section "Monitor"
    Identifier  "Monitor0"
    HorizSync   1-1000
    VertRefresh 1-1000
EndSection

Section "Device"
    Identifier  "Device0"
    Driver      "dummy"
    VideoRam    65536
EndSection

Section "Screen"
    Identifier  "Screen0"
    Device      "Device0"
    Monitor     "Monitor0"
    DefaultDepth 24
    SubSection "Display"
        Depth   24
        Modes   "${TOTAL_W}x${MON_H}"
        Virtual ${TOTAL_W} ${MON_H}
    EndSubSection
EndSection
XEOF

Xorg :99 -config "$XCONF" -nolisten tcp -novtswitch &

# Wait for Xorg to accept connections
i=0
while [ "$i" -lt 100 ]; do
    sleep 0.1
    DISPLAY=:99 xrandr >/dev/null 2>&1 && break
    i=$((i + 1))
done

export DISPLAY=:99

# Physical size at 96 DPI (px / 96 * 25.4 mm = px * 254 / 960)
PH_W=$(( MON_W * 254 / 960 ))
PH_H=$(( MON_H * 254 / 960 ))

# Create N XRandR 1.5 software monitors.
# FreeRDP enumerates these via XRRGetMonitors and sends them to Windows as
# separate monitors in the TS_UD_CS_MONITOR PDU.
i=0
while [ "$i" -lt "$NUM_MON" ]; do
    X=$((i * MON_W))
    xrandr --setmonitor "MONITOR${i}" "${MON_W}/${PH_W}x${MON_H}/${PH_H}+${X}+0" none
    echo "[guacd] Created MONITOR${i} at +${X}+0"
    i=$((i + 1))
done

echo "[guacd] Monitor layout:"
xrandr --listmonitors

exec guacd -f -l "${GUACD_PORT:-4822}" -b 0.0.0.0
