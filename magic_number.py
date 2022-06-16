from optparse import OptionParser
import os
from termcolor import colored, cprint
import sys

parser = OptionParser()

parser.add_option("-f", "--file", dest="filename",
                  help="Specify file path", metavar="FILE")

(options, args) = parser.parse_args()

print()

if os.path.isfile(options.filename):
	file = options.filename
else:
	print(colored('Invalid file path', 'red'))
	sys.exit(1)

magic_numbers = {
	'png': bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0A, 0x1A, 0x0A]),
	'gif': bytes([0x47, 0x49, 0x46, 0x38]),
	'jpg/jpeg': bytes([0xFF, 0xD8, 0xFF, 0xE0]),
	'zip': bytes([0x50, 0x4b, 0x03, 0x04]),
	# 'tar': bytes([0x75, 0x73, 0x74, 0x61, 0x72]),
	'elf': bytes([0x7f, 0x45, 0x4c, 0x46]),
	'xml': bytes([0x3c, 0x3f, 0x78, 0x6d, 0x6c]),
	# 'html': bytes([0x3C, 0x68, 0x74, 0x6D, 0x6c]),
	# 'HTML': bytes([0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6d, 0x6c]),
	'pdf': bytes([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e])
}

with open(file, 'rb') as f:
	buffer = max(len(m) for m in magic_numbers.values())
	f_head = f.read(buffer)
	f_type =  [key.upper() for key, value in magic_numbers.items() if f_head.startswith(value)]
	
	if f_type:
		print(colored(*f_type, 'green'))
	else:
		print(colored('Unrecognized magic number', 'yellow'))

