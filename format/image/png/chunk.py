import zlib
import logging
PNG_HEADER = b'\x89PNG\r\n\x1a\n'

class Chunk:
	def __init__(self, data: bytes, i: int):
		self.size = int.from_bytes(data[i:(i:=i+4)],"big")
		self.type = data[i:(i:=i+4)].decode()
		self.data = data[i:(i:=i+self.size)]
		self.crc = data[i:(i:=i+4)]
	
	def total_size(self):
		return len(self.type) + len(self.data) \
			 + len(self.crc) + 4
	def calc_crc(self):
		return zlib.crc32(self.type.encode() + self.data)
	def check_crc(self):
		return self.calc_crc() == int.from_bytes(self.crc,'big')
	def __str__(self):
		return f'Chunk(type: {self.type}, size: {self.size})'

def get_chunks(file):
	header = file[:len(PNG_HEADER)]
	if header != PNG_HEADER:
		logging.warning(f'Incorrect png header, {PNG_HEADER} != {header}')
	i = len(PNG_HEADER)
	chunks = [Chunk(file, i)]
	i += chunks[0].total_size()
	while True:
		if i >= len(file): 
			logging.error('Unexpected end of file')
			break
		chunks.append(Chunk(file, i))
		if not chunks[-1].check_crc(): 
			logging.warning(f'Wrong crc in chunk {chunks[-1]}, chunk nr: {len(chunks)}')
		i += chunks[-1].total_size()
		if chunks[-1].type == 'IEND': break
	return chunks



if __name__ == '__main__':
	normal = open('normal.png', 'rb').read()
	chunks = get_chunks(normal)
	for chunk in chunks:
		print(chunk)
