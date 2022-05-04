import argparse

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
    with open(bin_path, 'rb') as f:
        asm_bytes = list(f.read())
    
    shellcode = build_shellcode(asm_bytes)
    print(shellcode)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("bin")
    args = parser.parse_args()

    main(args.bin)