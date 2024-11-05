import pydasm

buffer = "\x90\x31\xc9\x31\xca\x31\xcb"

offset = 0
while offset < len(buffer):
    i = pydasm.get_instruction(buffer[offset:], pydasm.MODE_32)
    print("i:", i)
#    print(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0))
#    if not i:
#      break
#    offset += i.length
    break
