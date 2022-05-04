
## Malware Dropper

Shellcode will send a GET request to 127.0.0.1:8000/malware.bin. HTTP server respond by streaming a binary to the dropper/shellcode. The dropper will save this to /tmp/malware.bin and execve it.

## Dropper Files

- dropper.c: original dropper that I based the shellcode off of
- dropper.S: Assembly code that is converted to shellcode and run in RCE web exploit
- Makefile: make, assembles the dropper code and generates a binary with the text section
- exploit.js: RCE exploit that is run in d8 
- server.py: Example HTTP server that I used to host from localhost and serve the binary that the RCE uses
- shellcode.py: Converts the binary generated from the makefile into the shellcode bytes that the RCE js exploit uses
- hello_world: very simple hello world binary for experiments

