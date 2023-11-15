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

	def __init__(self, input, type):
		self.type = type
		self.name = input
		self.str_len = self.len_name_bin()
		self.node_len = 0
		self.crc = 0
		self.body_offset = 0
		self.body = b""
		
	def len_name_bin(self):
		# length of string, plus null terminator
		str_len = len(self.name) + 1
		# round up to multiple of 4
		while str_len % 4 != 0:
			str_len += 1
		return str_len

	def get_binary(self):
		return struct.pack(">IIII{}s".format(self.str_len), self.node_len, self.type.value, self.crc, self.body_offset, self.name.encode("utf-8")) + self.body
			
	def print_tree(self, prefix = ""):
		print(prefix + self.name)
	
class FileRefNode(Node):
	def __init__(self, input):
		super().__init__(input, Node.Types.file_ref)
		
		self.node_len = Node.HEADER_SIZE + self.str_len
		with open(self.name, "rb") as f:
			self.crc = binascii.crc32(f.read())

class EmbeddedFileNode(Node):
	def __init__(self, input):
		super().__init__(input, Node.Types.embedded)
		
		with open(self.name, "rb") as f:
			self.body = f.read()
		self.body_len = len(self.body)

		# padding to align body to dword
		body_padding = (4 - (self.body_len % 4)) % 4
		for i in range(body_padding):
			self.body += b"\x00"
		self.body = struct.pack(">I", self.body_len) + self.body
		self.crc = binascii.crc32(self.body)
		self.body_offset = Node.HEADER_SIZE + self.str_len
		self.node_len = self.body_offset + len(self.body)
	
class DirectoryNode(Node):
	def __init__(self, input, get_children = False):
		super().__init__(input, Node.Types.directory)
		self.body_offset = Node.HEADER_SIZE + self.str_len
		
		# input is a working folder
		self.child_nodes = self.get_child_nodes(input)
		if get_children:
			self.child_nodes = self.get_child_nodes(input)
		else:
			self.child_nodes = []
		
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
				child_nodes.append(DirectoryNode(f, True))
		os.chdir("..")
		return child_nodes
		
	def add_child_node(self, node):
		self.child_nodes.append(node)

	def get_binary(self):
		self.body = b""
		for c in self.child_nodes:
			self.body += c.get_binary()
		self.body += Node.ZEROES
		
		self.crc = binascii.crc32(self.body)
		self.node_len = self.body_offset + len(self.body)
		
		return super().get_binary()
		
	def print_tree(self, prefix = ""):
		super().print_tree(prefix)
		for c in self.child_nodes:
			c.print_tree(prefix + "  ")
		
class ContentNode(DirectoryNode):
	def __init__(self, input, get_children = False):
		super().__init__(input, get_children)
		self.type = Node.Types.content
		self.body_offset = Node.HEADER_SIZE + 4
		
	def get_binary(self):
		self.body = b""
		for c in self.child_nodes:
			self.body += c.get_binary()
		self.body += Node.ZEROES
		
		self.crc = binascii.crc32(self.body)
		# additional 4 to length for reverse crc
		self.node_len = self.body_offset + len(self.body) + 4
		node_bytes = struct.pack(">IIIII", self.node_len, self.type.value, self.crc, self.body_offset, 0) + self.body + Node.ZEROES
		
		# compute reverse CRC
		node_io = io.BytesIO(node_bytes)
		modify_io_crc32(node_io, len(node_bytes) - 4, 0)
		node_io.seek(0)
		node_bytes = node_io.read()
		
		return Node.FSGP_HEADER + node_bytes + Node.ZEROES

def main():
	parser = argparse.ArgumentParser(description="Convert the contents of a folder into a DJ Hero DLC CRC (FSGP) file")
	parser.add_argument("input_folder")
	
	args = parser.parse_args()
	
	root = ContentNode(args.input_folder, True)
	# root.print_tree()
	
	with open("DLC-" + os.path.basename(args.input_folder), "wb") as f:
		f.write(root.get_binary())
	
if __name__ == "__main__":
	main()
