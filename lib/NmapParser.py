#!/usr/bin/env python

import re
import os

if not os.path.exists('ports/'):
	os.makedirs('ports/')

ports_file = open('nmap/ports.gnmap').read().split('\n')

for line in ports_file:
	ip_address = line[line.find(":")+2:line.find("(")-1]
	pattern = '([0-9]+)' + "/open/tcp"
	find_pattern = re.findall(pattern, line)
	if find_pattern:
		for i in find_pattern:
			ports_file = open('ports/%s' % i,'a')
			ports_file.write("%s\n" % ip_address)
			ports_file.close()
