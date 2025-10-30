#!/bin/bash

echo "########################################"
echo "## Manual SSH Key Setup for Krithi    ##"
echo "## (Run these commands on krithi)     ##"
echo "########################################"

echo ""
echo "Run these commands directly on krithi (not remotely):"
echo ""

echo "# 1. Generate SSH key on krithi"
echo "ssh-keygen -t ed25519 -C 'sanjay@krithi'"
echo ""

echo "# 2. Copy public key to tower"
echo "ssh-copy-id sanjay@192.168.1.150"
echo "# When prompted, enter the password for sanjay on tower"
echo ""

echo "# 3. Copy public key to nano"
echo "ssh-copy-id sanjay@192.168.1.181"
echo "# When prompted, enter the password for sanjay on nano"
echo ""

echo "# 4. Copy public key to agx"
echo "ssh-copy-id sanjay@192.168.1.244"
echo "# When prompted, enter the password for sanjay on agx"
echo ""

echo "# 5. Copy public key to spark1"
echo "ssh-copy-id sanjay@192.168.1.201"
echo "# When prompted, enter the password for sanjay on spark1"
echo ""

echo "# 6. Copy public key to spark2"
echo "ssh-copy-id sanjay@192.168.1.202"
echo "# When prompted, enter the password for sanjay on spark2"
echo ""

echo "# 7. Test the connections"
echo "ssh sanjay@192.168.1.150 'echo \"SSH to tower: OK\"'"
echo "ssh sanjay@192.168.1.181 'echo \"SSH to nano: OK\"'"
echo "ssh sanjay@192.168.1.244 'echo \"SSH to agx: OK\"'"
echo "ssh sanjay@192.168.1.201 'echo \"SSH to spark1: OK\"'"
echo "ssh sanjay@192.168.1.202 'echo \"SSH to spark2: OK\"'"
echo ""

echo "After completing these steps, krithi will be able to SSH"
echo "to all other cluster nodes without passwords."