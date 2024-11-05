import peutils
import pefile


signature_filepath = './peid/UserDB.TXT'

with open(signature_filepath, 'rt', encoding='latin-1') as f:
    sig_data = f.read()

signatures = peutils.SignatureDatabase(data=sig_data)



def matchSig(pe):
    matches = signatures.match(pe, ep_only = True)
    print(matches)
    matches = signatures.match_all(pe, ep_only = True)
    print(matches)


matchSig(pefile.PE('A.exe'))


matchSig(pefile.PE('B.exe'))

matchSig(pefile.PE('BB.exe'))

def generateSig(pe):
    sig_length = 0
    offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print("ep offset:", offset)
    print("pe.__data__:", pe.__data__)
    print("pe.__data__[offset:offset+sig_length]:", pe.__data__[offset:offset+sig_length])
    ep_sig = signatures.generate_ep_signature(pe, 'Custom', sig_length)

    # secs_sig = signatures.generate_section_signatures(pe, 'Custom', sig_length)
    print("ep_sig:", ep_sig)
    # print("secs_sig:", secs_sig)


generateSig(pefile.PE('A.exe'))