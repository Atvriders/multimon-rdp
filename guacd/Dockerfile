FROM guacamole/guacd:1.5.0

USER root

# Xorg + dummy driver gives FreeRDP real virtual monitors via Xinerama.
# No xrandr trickery needed — monitors are declared in xorg.conf at startup.
RUN apk add --no-cache xorg-server xf86-video-dummy xrandr

# Locate the guacd binary (installed to /opt/guacamole/sbin on Alpine)
# and symlink it so start.sh can simply exec guacd.
RUN GUACD=$(find /opt /usr -name guacd -type f 2>/dev/null | head -1) \
    && echo "guacd binary: $GUACD" \
    && ln -sf "$GUACD" /usr/local/bin/guacd

COPY start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/start.sh"]
