from chunk import get_chunks
import logging

def ihdr(data, full=False):
	i = 0
	width = int.from_bytes(data[i:][:4],"big")
	i += 4
	height = int.from_bytes(data[i:][:4],"big")
	i += 4
	bit_depth = data[i] # 1,2,4,8,16
	i += 1
	color_type = data[i] # 0,2,3,4,6
	i += 1
	compression_method = data[i] # 0
	i += 1
	filter_method = data[i] # 0
	i += 1
	interlace_method = data[i] # 0, 1
	
	if full: 
		return width, height, \
			bit_depth, color_type, \
			compression_method, \
			filter_method, \
			interlace_method
	else:	
		return width, height

if __name__ == '__main__':
	normal = open('normal.png', 'rb').read()
	chunks = get_chunks(normal)
	print(chunks)
	width,height = ihdr(chunks[0].data)
	print(width,height)
