from lief import PE

print(PE.PE_TYPE)

binary32 = PE.Binary(PE.PE_TYPE.PE32_PLUS)


title   = "LIEF is awesome\0"
message = "Hello World\0"

data =  list(map(ord, title))
data += list(map(ord, message))

'''
push 0x00                 ; uType
push 0x140020000          ; Title
push 0x140020010          ; Message
push 0                    ; hWnd
call 0x14000105c          ; MessageBoxA
push 0                    ; uExitCode
call 0x14000106c          ; ExitProcess
'''




code = list(map(ord, "push 0x00"))
code = list(map(ord, "push 0x140020000"))
code = list(map(ord, "push 0x140020010"))
code = list(map(ord, "push 0"))
code = list(map(ord, "call 0x14000105c"))
code = list(map(ord, "push 0"))
code = list(map(ord, "call 0x14000106c"))



section_text                 = PE.Section(".text")
section_text.content         = code
section_text.virtual_address = 0x10000

section_data                 = PE.Section(".data")
section_data.content         = data
section_data.virtual_address = 0x20000


user32 = binary32.add_library("user32.dll")
user32.add_entry("MessageBoxA")

kernel32 = binary32.add_library("kernel32.dll")
kernel32.add_entry("ExitProcess")


print("OptionalHeader.imagebase: ", binary32.imagebase)
ExitProcess_addr = binary32.predict_function_rva("kernel32.dll", "ExitProcess")
MessageBoxA_addr = binary32.predict_function_rva("user32.dll", "MessageBoxA")

imagebase_va = binary32.imagebase
ExitProcess_addr_va = imagebase_va + ExitProcess_addr
MessageBoxA_addr_va = imagebase_va + MessageBoxA_addr


print("Address of imagebase_va: 0x{:06x} ".format(imagebase_va))

print("Address of 'ExitProcess': 0x{:06x} ".format(ExitProcess_addr))
print("Address of 'MessageBoxA': 0x{:06x} ".format(MessageBoxA_addr))


print("Address of 'ExitProcess_va': 0x{:06x} ".format(ExitProcess_addr_va))
print("Address of 'MessageBoxA_va': 0x{:06x} ".format(MessageBoxA_addr_va))


builder = PE.Builder(binary32)
builder.build_imports(True)
builder.build()
builder.write("pe_from_scratch.exe")