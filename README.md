# SSH-Key-Inventory

## A python script for auditing ssh keys

general usage: ssh-key-inventory -u {username} [-s]

this will ssh to each host specified in the 'targets' textfile and enumerate
the non-system users and their ssh pubkeys on the system.  The output will be
stored as a json file that can be imported to Elasticsearch or similar tools
for inventory management.


Requirements:
- python dependencies - reference requirements.txt
- this script assumes the use of an administrator user specified with -u
- this administrator will connect to each host using ssh-agent keys on the
  system
- The administrator can specify a global sudo password for all hosts [-s] or
  enter the sudo password for each host when it connects.
- Assumes standard locations for keys (~/.ssh/authorized_keys) and standard
  sshd options (port 22)


Future plans:
- Add sshd configuration auditing, output to a json file
- Add record for the last time each key was used for a user (comb auth logs)
- More flexibility in ssh configuration, support for dropbear, non standard
