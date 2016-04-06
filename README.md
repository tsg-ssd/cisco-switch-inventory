# cisco-switch-inventory
Python script to create CSV file with Cisco switches inventory (Collect Hostname, Management IP, Model Name, IOS version, etc.)

1. Prompts for RADIUS credentials, LOCAL credentials, simple password and enable password
2. Reads ip addresses list from file (trylist.txt)
3. Checks whether SSH and Telnet are open for each IP
4. Tries to authenticate to IP addresses read from the file via RADIUS, Local username and passwordn and simple password
5. Tries to gain access to priv mode
6. Sends commands to switch and extracts data from the outpup
 
For now the commands are sent via Telnet
SSH part is to be developed 
