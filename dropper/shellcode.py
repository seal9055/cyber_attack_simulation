import argparse
import os

def build_hex_list(lst):
    long_bytes = [lst[i:i+8] for i in range(0, len(lst), 8)]

    out = []
    for lst in long_bytes:
        lst.reverse()
        s = ''
        for b in lst:
            c = format(b, 'x')
            if len(c) == 1:
                c = '0' + c
            s += c

        out.append(s)

    return out

def build_shellcode(asm_bytes):
    out_str = '['
    long_bytes = [asm_bytes[i:i+8] for i in range(0, len(asm_bytes), 8)]
    for lst in long_bytes:
        lst.reverse()
        s = '0x'
        for b in lst:
            c = format(b, 'x')
            if len(c) == 1:
                c = '0' + c
            s += c
        s += 'n, '

        out_str += s

    out_str = out_str[:-2] + ']'
    return out_str

def main(bin_path):
    if os.path.exists(bin_path):
        with open(bin_path, 'rb') as f:
            asm_bytes = list(f.read())
        
        shellcode = build_shellcode(asm_bytes)
        print(shellcode)
    else:
        bin_path = bin_path.replace('\\r', '\r').replace('\\n', '\n')
        print(f"{bin_path} doesn't exist on disk, assuming it is a string")

        hex_lst = build_hex_list([ord(c) for c in bin_path])
        hex_lst.reverse()

        print(f"Length: {len(bin_path)}\n")
        for long_val in hex_lst:
            print(f"mov $0x{long_val}, %rsi")
            print(f"push %rsi")
        

        

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("bin")
    args = parser.parse_args()

    main(args.bin)