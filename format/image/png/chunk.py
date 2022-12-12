import zlib
import logging
PNG_HEADER = b'\x89PNG\r\n\x1a\n'

class Chunk:
	def __init__(self, file: bytes, i: int):
		size = int.from_bytes(file[i:][:4],"big")
		i += 4
		self.type = file[i:][:4].decode()
		i += 4
		self.data = file[i:][:size]
		i += size
		self.crc = file[i:][:4]

	def size(self):
		return len(self.type) + len(self.data) + len(self.crc) + 4
	def check_crc(self):
		return zlib.crc32(self.type.encode() + self.data).to_bytes(4,'big') == self.crc
	def __str__(self):
		return f'Chunk(type: {self.type}, size: {self.size()})'

def get_chunks(file):
	header = file[:len(PNG_HEADER)]
	if header != PNG_HEADER:
		logging.warning(f'Incorrect png header, {PNG_HEADER} != {header}')
	i = len(PNG_HEADER)
	chunks = [Chunk(file, i)]
	i += chunks[0].size()
	while True:
		if i >= len(file): 
			logging.warning('Unexpected end of file')
			break
		chunks.append(Chunk(file, i))
		if not chunks[-1].check_crc(): 
			logging.warning(f'Wrong crc in chunk {chunks[-1]}, chunk nr: {len(chunks)}')
		i += chunks[-1].size()
		if chunks[-1].type == 'IEND': break
	return chunks



if __name__ == '__main__':
	normal = open('normal.png', 'rb').read()
	chunks = get_chunks(normal)
	for chunk in chunks:
		print(chunk)
