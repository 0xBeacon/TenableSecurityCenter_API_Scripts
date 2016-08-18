Tenable SecurityCenter API Interaction Scripts

scan_launch.py

To get this to work, you need to do a few things...
-SecurityCenter URL must be updated
-username/password strings must be updated
-Asset group ID needs to pre-created and updated in script
-Scan ID must be pre-created and updated in script

Usage -

[*] Usage: -s <ip>
[*] Examples: 
python scan_launch.py -s 10.10.10.10
python scan_launch.py -s '10.10.10.10,11.11.11.11,12.12.12.12'
python scan_launch.py -s 10.10.10.0/24


