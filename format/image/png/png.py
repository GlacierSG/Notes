from chunk import get_chunks
import logging

class IHDR:
	def __init__(self, data):
		i = 0
		self.width = int.from_bytes(data[i:(i:=i+4)],"big")
		self.height = int.from_bytes(data[i:(i:=i+4)],"big")
		self.bit_depth = data[i:(i:=i+1)][0] # 1,2,4,8,16
		self.color_type = data[i:(i:=i+1)][0] # 0,2,3,4,6
		self.compression_method = data[i:(i:=i+1)][0] # 0
		self.filter_method = data[i:(i:=i+1)][0] # 0
		self.interlace_method = data[i:(i:=i+1)] # 0, 1

if __name__ == '__main__':
	normal = open('normal.png', 'rb').read()
	chunks = get_chunks(normal)
	print(chunks)
	ihdr = IHDR(chunks[0].data)
	print(ihdr.width,ihdr.height)
