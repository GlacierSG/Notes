import logging

MAGIC = b'\x7fELF'


class Header:
	def __init__(self, data: bytes):
		i = 0
		# e_ident[EI_MAG0] through e_ident[EI_MAG3]
		self.magic_number = data[i:][:4]
		i+=4
		# e_ident[EI_CLASS]
		self.capacity = data[i:][0] 
		i+=1
		# e_ident[EI_DATA]
		self.endianness = data[i:][0] 
		i+=1
		# e_ident[EI_VERSION]
		self.version1 = data[i:][0] 
		i += 1
		# e_ident[EI_OSABI]
		self.target_os = data[i:][0] 
		i+=1
		# e_ident[EI_ABIVERSION]
		self.abi_version = data[i:][0]
		i+=1	
		# e_ident[EI_PAD]
		self.padding_bytes = data[i:][:7] 
		i+=7

		endian = self.endian()
		
		# e_type
		self.type = int.from_bytes(data[i:][:2], endian)
		i+=2
		# e_machine
		self.machine = int.from_bytes(data[i:][:2], endian)
		i+=2
		#  	e_version
		self.version2 = int.from_bytes(data[i:][:4], endian)
		i+=4

		size = 8 if self.is64bit() else 4
		
		# e_entry
		self.entry= int.from_bytes(data[i:][:size], endian) # 0 if no entry point
		i+=size
		# e_phoff
		self.phoff = int.from_bytes(data[i:][:size], endian)
		i+=size
		# e_shoff
		self.shoff= int.from_bytes(data[i:][:size], endian)
		i+=size
		
		# e_flags
		self.flags = int.from_bytes(data[i:][:4], endian)
		i+=4
		# e_ehsize
		self.ehsize= int.from_bytes(data[i:][:2], endian)
		i+=2	
		# e_phentsize
		self.phentsize= int.from_bytes(data[i:][:2], endian)
		i+=2
		# e_phnum
		self.phnum= int.from_bytes(data[i:][:2], endian)
		i+=2
		# e_shentsize
		self.shentsize=int.from_bytes(data[i:][:2], endian)
		i+=2
		# e_shnum
		self.shnum =int.from_bytes(data[i:][:2], endian)
		i+=2
		# e_shstrndx
		self.shstrndx = int.from_bytes(data[i:][:2], endian)
		i+=2

		self.size = i	

	def is64bit(self):
		return (self.capacity == 2)

	def endian(self):
		return header_endianness(self.endianness)

class ProgramHeaderEntry:
	def __init__(self, data: bytes, header: Header, entry_i: int):
		size = header.phentsize
		endian = header.endian()

		i = header.phoff + size*entry_i

		self.type = int.from_bytes(data[i:][:4], endian)
		i += 4
		# ...


def get_program_header_entries(data, header):
	entries = []
	for entry_i in range(header.phnum):
		entries.append(ProgramHeaderEntry(data, header, entry_i))
	return entries


			
		
### BEGINNING OF HEADER FUNCTIONS ###
def header_capacity(val:int):
	match val:
		case 1: return '32-bit'
		case 2: return '64-bit'
		case _: return None

def header_endianness(val:int):
	match val:
		case 1: return 'little'
		case 2: return 'big'
		case _: return None

def header_target_os(val:int):
	match val: 
		case 0x00: return 'System V'
		case 0x01: return 'HP-UX'
		case 0x02: return 'NetBSD'
		case 0x03: return 'Linux'
		case 0x04: return 'GNU Hurd'
		case 0x06: return 'Solaris'
		case 0x07: return 'AIX (Monterey)'
		case 0x08: return 'IRIX'
		case 0x09: return 'FreeBSD'
		case 0x0A: return 'Tru64'
		case 0x0B: return 'Novell Modesto'
		case 0x0C: return 'OpenBSD'
		case 0x0D: return 'OpenVMS'
		case 0x0E: return 'NonStop Kernel'
		case 0x0F: return 'AROS'
		case 0x10: return 'FenixOS'
		case 0x11: return 'Nuxi CloudABI'
		case 0x12: return 'Stratus Technologies OpenVOS'
		case _: return None

def header_object_file_type(val: int):
	match val:
		case 0x00: return 'ET_NONE' # Unknown
		case 0x01: return 'ET_REL' # Relocatable file
		case 0x02: return 'ET_EXEC' # Executable file
		case 0x03: return 'ET_DYN' # Shared object
		case 0x04: return 'ET_CORE' # Core file
		case 0xff00: return 'ET_LOOS' # os specific
		case 0xfeff: return 'ET_HIOS' # os specific
		case 0xff00: return 'ET_LOPROC' # Processor specific
		case 0xffff: return 'ET_HIPROC' # Processor specific
		case _: return None # Err
		
def header_instruction_set(val: int):
	match val:
		case 0x00: return 'No specific instruction set'
		case 0x01: return 'AT&T WE 32100'
		case 0x02: return 'SPARC'
		case 0x03: return 'x86'
		case 0x04: return 'Motorola 68000 (M68k)'
		case 0x05: return 'Motorola 88000 (M88k)'
		case 0x06: return 'Intel MCU'
		case 0x07: return 'Intel 80860'
		case 0x08: return 'MIPS'
		case 0x09: return 'IBM System/370'
		case 0x0A: return 'MIPS RS3000 Little-endian'
		case (0x0B|0x0C|0x0D): return 'Reserved for future use'
		case 0x0E: return 'Hewlett-Packard PA-RISC'
		case 0x0F: return 'Reserved for future use'
		case 0x13: return 'Intel 80960'
		case 0x14: return 'PowerPC'
		case 0x15: return 'PowerPC (64-bit)'
		case 0x16: return 'S390, including S390x'
		case 0x17: return 'IBM SPU/SPC'
		case (0x18|0x19|0x1a|0x1b|0x1c|0x1d|0x1e|0x1f|0x20|0x21|0x22|0x23): 
			return 'Reserved for future use'
		case 0x24: return 'NEC V800'
		case 0x25: return 'Fujitsu FR20'
		case 0x26: return 'TRW RH-32'
		case 0x27: return 'Motorola RCE'
		case 0x28: return 'Arm (up to Armv7/AArch32)'
		case 0x29: return 'Digital Alpha'
		case 0x2A: return 'SuperH'
		case 0x2B: return 'SPARC Version 9'
		case 0x2C: return 'Siemens TriCore embedded processor'
		case 0x2D: return 'Argonaut RISC Core'
		case 0x2E: return 'Hitachi H8/300'
		case 0x2F: return 'Hitachi H8/300H'
		case 0x30: return 'Hitachi H8S'
		case 0x31: return 'Hitachi H8/500'
		case 0x32: return 'IA-64'
		case 0x33: return 'Stanford MIPS-X'
		case 0x34: return 'Motorola ColdFire'
		case 0x35: return 'Motorola M68HC12'
		case 0x36: return 'Fujitsu MMA Multimedia Accelerator'
		case 0x37: return 'Siemens PCP'
		case 0x38: return 'Sony nCPU embedded RISC processor'
		case 0x39: return 'Denso NDR1 microprocessor'
		case 0x3A: return 'Motorola Star*Core processor'
		case 0x3B: return 'Toyota ME16 processor'
		case 0x3C: return 'STMicroelectronics ST100 processor'
		case 0x3D: return 'Advanced Logic Corp. TinyJ embedded processor family'
		case 0x3E: return 'AMD x86-64'
		case 0x3F: return 'Sony DSP Processor'
		case 0x40: return 'Digital Equipment Corp. PDP-10'
		case 0x41: return 'Digital Equipment Corp. PDP-11'
		case 0x42: return 'Siemens FX66 microcontroller'
		case 0x43: return 'STMicroelectronics ST9+ 8/16 bit microcontroller'
		case 0x44: return 'STMicroelectronics ST7 8-bit microcontroller'
		case 0x45: return 'Motorola MC68HC16 Microcontroller'
		case 0x46: return 'Motorola MC68HC11 Microcontroller'
		case 0x47: return 'Motorola MC68HC08 Microcontroller'
		case 0x48: return 'Motorola MC68HC05 Microcontroller'
		case 0x49: return 'Silicon Graphics SVx'
		case 0x4A: return 'STMicroelectronics ST19 8-bit microcontroller'
		case 0x4B: return 'Digital VAX'
		case 0x4C: return 'Axis Communications 32-bit embedded processor'
		case 0x4D: return 'Infineon Technologies 32-bit embedded processor'
		case 0x4E: return 'Element 14 64-bit DSP Processor'
		case 0x4F: return 'LSI Logic 16-bit DSP Processor'
		case 0x8C: return 'TMS320C6000 Family'
		case 0xAF: return 'MCST Elbrus e2k'
		case 0xB7: return 'Arm 64-bits (Armv8/AArch64)'
		case 0xDC: return 'Zilog Z80'
		case 0xF3: return 'RISC-V'
		case 0xF7: return 'Berkeley Packet Filter'
		case 0x101: return 'WDC 65C816'
		case _: None

def header_version(val):
	match val:
		case 1: return 1 # Set to 1 for the original and current version of ELF. 
		case _: return None

		
		
def check_header(header):
	if header.magic_number != MAGIC: 
		logging.warning('magic was incorrect')
	if header_capacity(header.capacity) is None:
		logging.warning('only 32-bit and 64-bit supported')
	if header_endianness(header.endianness) is None:
		logging.warning('Only big and short endiannesses supported')
	if header_version(header.version1) is None:
		logging.warning('unrecognized version1')
	if header_target_os(header.target_os) is None:
		logging.warning('unknown target os')

	if header.padding_bytes != b'\x00'*7:
		logging.warning('padding bytes not filled with zeros')
	if header_object_file_type(header.type) is None:
		logging.warning('unknown object file type')
	if header_instruction_set(header.machine) is None:
		logging.warning('unknown instruction set architecture')
	if header_version(header.version2) is None:
		logging.warning('unrecognized version2')

### END OF HEADER FUNCTION ###



if __name__ == '__main__':
	file = open('normal','rb').read()
	header = Header(file)
	check_header(header)
	
