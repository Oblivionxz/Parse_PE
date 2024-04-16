MAKEFLAGS += -s

GCC 	   = x86_64-w64-mingw32-gcc.exe

parser:
	$(GCC) src/main.c -s -w -o bin/pe_parser.exe