# Executable and Linkable Format (ELF)

## Links
 * [Wikipedia: Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)

## Basic implementation

### Check if the header is as expected
```python
from header import Header, check_header

file = open('normal','rb').read()
header = Header(file)
check_header(header)
```