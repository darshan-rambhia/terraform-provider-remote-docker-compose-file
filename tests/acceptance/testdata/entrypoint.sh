#!/bin/bash
set -e

# Setup authorized_keys from environment variable
if [ -n "$PUBLIC_KEY" ]; then
    echo "$PUBLIC_KEY" > /home/testuser/.ssh/authorized_keys
    chmod 600 /home/testuser/.ssh/authorized_keys
    chown testuser:testuser /home/testuser/.ssh/authorized_keys
    echo "Public key configured for testuser"
fi

# Verify SSH configuration
echo "Checking SSH configuration..."
/usr/sbin/sshd -T > /dev/null 2>&1 || {
    echo "SSH config validation failed!"
    /usr/sbin/sshd -T
    exit 1
}

# Start SSH daemon in foreground
echo "Starting SSH daemon..."
/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config 2>&1 &
SSHD_PID=$!
echo "Server listening on port 22"

# Keep container running
wait $SSHD_PID
