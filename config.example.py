# Example configuration for GridWatch remote capture.
# This file is for documentation purposes only. Do not import this file, and
# do not commit actual production credentials or real IPs here.
# Copy these keys into your local/committed config.py under the remote-capture section.

JUMP_USER = "jump_user"                      # SSH username for the jump host (Laptop A)
LAPTOP_A_IP = "192.168.1.10"                 # IP address of the jump host (Laptop A)
VM_USER = "vm_user"                          # SSH username for the VM hosting the Docker containers
VM_IP = "192.168.1.20"                       # IP address of the VM hosting the Docker containers
ICS_INTERFACE = "eth0"                       # Network interface on the VM host for ICS traffic
CAPTURE_CONTAINER = "plc"                    # Name or ID of the docker container to run capture inside of
CONTAINER_CAPTURE_INTERFACE = "eth1"         # Network interface inside the capture container namespace to sniff on
