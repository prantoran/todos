import lief


pe = lief.parse("./A.exe")

print(pe.dos_header)
print(pe.header)
print(pe.optional_header)


# Using the abstract layer
for func in pe.imported_functions:
  print(func)


# Using the PE definition
for func in pe.imports:
  print(func)



for imported_library in pe.imports:
  print("Library name: " + imported_library.name)
  for func in imported_library.entries:
    if not func.is_ordinal:
      print(func.name, end= " ")
    print(func.iat_address)
