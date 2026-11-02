#!/bin/sh
# Test payload: installs a tiny program and a marker file. Uninstalled by the package's remove command.
set -e
install -m 0755 "$MUSTRA_PACKAGE_DIR/mustra-hello.sh.payload" /usr/local/bin/mustra-hello 2>/dev/null || {
  printf '#!/bin/sh\necho "hello from mustra test payload v1.0"\n' > /usr/local/bin/mustra-hello; chmod 755 /usr/local/bin/mustra-hello; }
mkdir -p /etc/mustra-hello && echo "1.0" > /etc/mustra-hello/version
echo "installed mustra-hello 1.0"
