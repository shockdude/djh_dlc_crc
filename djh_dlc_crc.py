# DJH DLC CRC generator
# Copyright (C) 2023 shockdude

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from forcecrc32 import modify_io_crc32
import struct
import os, sys
import argparse
import binascii
import io
from enum import Enum

class Node():
	class Types(Enum):
		content = 67
		directory = 68
		embedded = 69
		file_ref = 70
	
	FSGP_HEADER = b"FSGP\x68\xF3\x56\x3B\x38\x3D\x44\xBA\x71\xAC\xE2\x53\x00\x01\x00\x09"
	HEADER_SIZE = 16
	ZEROES = b"\x00\x00\x00\x00"

	def __init__(self, input):
		self.type = Node.Types.content
		self.name = input
		# input is a working folder
		self.child_nodes = self.get_child_nodes(input)
		
	def get_child_nodes(self, input):
		os.chdir(input)
		child_nodes = []
		for f in os.listdir():
			if os.path.isfile(f):
				filename, ext = os.path.splitext(f)
				if ext.lower() == ".txt":
					child_nodes.append(EmbeddedFileNode(f))
				else:
					child_nodes.append(FileRefNode(f))
			elif os.path.isdir(f):
				child_nodes.append(DirectoryNode(f))
		os.chdir("..")
		return child_nodes
		
	def len_name_bin(self):
		# length of string, plus null terminator
		str_len = len(self.name) + 1
		# round up to multiple of 4
		while str_len % 4 != 0:
			str_len += 1
		return str_len
		
	def get_binary(self):
		# print(self.name)
		body_offset = Node.HEADER_SIZE + 4
		
		body = b""
		os.chdir(self.name)
		for c in self.child_nodes:
			body += c.get_binary()
		os.chdir("..")
		body += Node.ZEROES
		
		crc = binascii.crc32(body)
		# additional 4 to length for reverse crc
		node_len = body_offset + len(body) + 4
		node_bytes = struct.pack(">IIIII", node_len, self.type.value, crc, body_offset, 0) + body + Node.ZEROES
		
		# compute reverse CRC
		node_io = io.BytesIO(node_bytes)
		modify_io_crc32(node_io, len(node_bytes) - 4, 0)
		node_io.seek(0)
		node_bytes = node_io.read()
		
		return Node.FSGP_HEADER + node_bytes + Node.ZEROES
			
	def print_tree(self, prefix = ""):
		print(prefix + self.name)
		for c in self.child_nodes:
			c.print_tree(prefix + "  ")
	
class DirectoryNode(Node):
	def __init__(self, input):
		self.type = Node.Types.directory
		self.name = input
		# input is a working folder
		self.child_nodes = self.get_child_nodes(input)
		
	def get_binary(self):
		# print(self.name)
		str_len = self.len_name_bin()
		body_offset = Node.HEADER_SIZE + str_len
		
		body = b""
		os.chdir(self.name)
		for c in self.child_nodes:
			body += c.get_binary()
		os.chdir("..")
		body += Node.ZEROES
		
		crc = binascii.crc32(body)
		node_len = body_offset + len(body)
		
		return struct.pack(">IIII{}s".format(str_len), node_len, self.type.value, crc, body_offset, self.name.encode("utf-8")) + body
	
class EmbeddedFileNode(Node):
	def __init__(self, input):
		self.type = Node.Types.embedded
		self.name = input
		
	def print_tree(self, prefix = ""):
		print(prefix + self.name)
		
	def get_binary(self):
		# print(self.name)
		str_len = self.len_name_bin()
		body_offset = Node.HEADER_SIZE + str_len
		
		with open(self.name, "rb") as f:
			body = f.read()
		body_len = len(body)
		
		# padding to align node to dword
		body_padding = (4 - (body_len % 4)) % 4
		for i in range(body_padding):
			body += b"\x00"
			
		body = struct.pack(">I", body_len) + body
		node_len = body_offset + len(body)
		crc = binascii.crc32(body)
		
		return struct.pack(">IIII{}s".format(str_len), node_len, self.type.value, crc, body_offset, self.name.encode("utf-8")) + body
	
class FileRefNode(Node):
	def __init__(self, input):
		self.type = Node.Types.file_ref
		self.name = input
		
	def get_binary(self):
		# print(self.name)
		str_len = self.len_name_bin()
		node_len = Node.HEADER_SIZE + str_len
		
		with open(self.name, "rb") as f:
			crc = binascii.crc32(f.read())
		
		return struct.pack(">IIII{}s".format(str_len), node_len, self.type.value, crc, 0, self.name.encode("utf-8"))
		
	def print_tree(self, prefix = ""):
		print(prefix + self.name)

def main():
	parser = argparse.ArgumentParser(description="Convert the contents of a folder into a DJ Hero DLC CRC (FSGP) file")
	parser.add_argument("input_folder")
	
	args = parser.parse_args()
	
	root = Node(args.input_folder)
	# root.print_tree()
	
	with open("DLC-" + args.input_folder, "wb") as f:
		f.write(root.get_binary())
	
if __name__ == "__main__":
	main()
