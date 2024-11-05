import pefile
import pydasm
import os

pe = pefile.PE('A.exe')

print("pe.OPTIONAL_HEADER.AddressOfEntryPoint", pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print("pe.OPTIONAL_HEADER.ImageBase", pe.OPTIONAL_HEADER.ImageBase)
print("pe.FILE_HEADER.NumberOfSections", pe.FILE_HEADER.NumberOfSections)

pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0xdeadbeef
pe.write(filename='file_to_write.exe')

for section in pe.sections:
  print (section.Name, hex(section.VirtualAddress),
    hex(section.Misc_VirtualSize), section.SizeOfRawData )


# If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:

pe.parse_data_directories()

for entry in pe.DIRECTORY_ENTRY_IMPORT:
  print("entry.dll:", entry.dll)
  for imp in entry.imports:
    print('\t', "imp.address:", hex(imp.address), "imp.name:", imp.name)

pe2 = pefile.PE('file_to_write.exe')
print("pe2.OPTIONAL_HEADER.AddressOfEntryPoint", pe2.OPTIONAL_HEADER.AddressOfEntryPoint)


pe_dll = pefile.PE('pr.dll')

for exp in pe_dll.DIRECTORY_ENTRY_EXPORT.symbols:
  print(hex(pe_dll.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)

# print(pe.dump_info())

ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()[ep:ep+100]
offset = 0
while offset < len(data):
  print('\tentered')
  i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
  print(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset))
  offset += i.length


pe = pefile.PE(os.sys.argv[1], fast_load=True)
pe.parse_data_directories( directories=[
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'] ] )