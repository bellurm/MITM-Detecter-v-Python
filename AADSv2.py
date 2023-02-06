# blog-cyberworm.com

import os
import re
from tkinter import messagebox

result = os.popen("arp -a").read()

gatewayMAC = re.findall(r"(\w\w-\w\w-\w\w-\w\w-\w\w-\w\w)", result)[0]

counter = result.count(gatewayMAC)

if counter > 1:
    messagebox.showwarning("[!] MITM WARNING", f"WARNING: You are under 'Man in the Middle' attack.\nYour modem's MAC address ({gatewayMAC}) has been found {counter} times in the ARP table.")

