#include <Windows.h>
#include <stdio.h>

int main(int argc,char *argv[]) {
	if (argc == 1) {
		printf("Usage: %s <PE>\n", argv[0]);
		return -1;
	}

	LPCSTR PEName = argv[1];
	PBYTE pBufferPE;
	SIZE_T szPE;

	printf("\t#####################[ LOADING FILE ]#####################\n");

	if(!ReadPEFromDisk(PEName, &pBufferPE, &szPE)) {
		return -1;
	}

	if (!ParsePE(pBufferPE)) {
		return -1;
	}

	return 0;
}

ReadPEFromDisk(LPCSTR lpFileName, PBYTE* pPe, SIZE_T* sPe) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pBuff = NULL;
	DWORD	dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;

	printf("[i] Reading \"%s\...\n", lpFileName);

	hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	printf("[*] CreateFile Successfully\n");

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == NULL) {
		printf("[!] GetFileSize Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	printf("[*] Allocated buffer of PE at: 0x%p\n", pBuff);

	printf("[i] File size of %s is %d\n", lpFileName, dwFileSize);

	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Read : %d of : %d \n", dwNumberOfBytesRead, dwFileSize);
		goto _EndOfFunction;
	}

	printf("[+] DONE \n");


_EndOfFunction:
	*pPe = (PBYTE)pBuff;
	*sPe = (SIZE_T)dwFileSize;
	if (hFile)
		CloseHandle(hFile);
	if (*pPe == NULL || *sPe == NULL)
		return FALSE;
	return TRUE;
}

BOOL ParsePE(PBYTE pPE) {

	printf("\n\t#####################[ STARTING PE PARSE ]#####################\n");

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	if (pImgDosHdr->e_magic != 0x5A4D){
		printf("[!] e_magic is not 0x5D4A(MZ), Invalid PE sign File.\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	if (pImgNtHdr->Signature != 0x4550) {
		printf("[!] Image NT Headers Signature is not 0x4550, Invalid NT Headers sign.\n");
	}

	printf("[i] Magic Number is 0x%04X, evaluated at MZ\n", pImgDosHdr->e_magic);
	printf("[i] NT Headers Signature is 0x%08X, equivalent at PE00\n", pImgNtHdr->Signature);
	
	printf("\n\t#####################[ IMAGE FILE HEADER ]#####################\n");

	IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdr->FileHeader;

	if (ImgFileHdr.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {

		printf("[i] Executable File Detected As: ");

		//0x2000 = DLL | 1 = SYS | 0X0002 = EXE
		if (ImgFileHdr.Characteristics & 0x2000)
			printf("DLL\n");
		else if (ImgFileHdr.Characteristics & 1)
			printf("SYS\n");
		else
			printf("EXE\n");
	}

	printf("[i] PE Arch: %s\n", ImgFileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? "x32":"x64");
	printf("[i] Number of Section in PE or Object File: %d\n", ImgFileHdr.NumberOfSections);

	printf("\n\t#####################[ OPTIONAL HEADER ]#####################\n\n");

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdr->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		printf("[!] Invalid Magic of Optional Header\n");
		return - 1;
	}

	printf("[i] File Arch (Second way) : %s \n", ImgOptHdr.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "x32" : "x64");

	printf("[+] Size Of Code Section : %d \n", ImgOptHdr.SizeOfCode);
	printf("[+] Address Of Code Section : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPE + ImgOptHdr.BaseOfCode), ImgOptHdr.BaseOfCode);
	printf("[+] Size Of Initialized Data : %d \n", ImgOptHdr.SizeOfInitializedData);
	printf("[+] Size Of Unitialized Data : %d \n", ImgOptHdr.SizeOfUninitializedData);
	printf("[+] Preferable Mapping Address : 0x%p \n", (PVOID)ImgOptHdr.ImageBase);
	printf("[+] Required Version : %d.%d \n", ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
	printf("[+] Address Of The Entry Point : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPE + ImgOptHdr.AddressOfEntryPoint), ImgOptHdr.AddressOfEntryPoint);
	printf("[+] Size Of The Image : %d \n", ImgOptHdr.SizeOfImage);
	printf("[+] File CheckSum : 0x%0.8X \n", ImgOptHdr.CheckSum);
	printf("[+] Number of entries in the DataDirectory array : %d \n", ImgOptHdr.NumberOfRvaAndSizes); // this is the same as `IMAGE_NUMBEROF_DIRECTORY_ENTRIES` - `16`

	printf("\n\t#####################[ DIRECTORIES ]#####################\n\n");

	printf("[*] Export Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	printf("[*] Import Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	printf("[*] Resource Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

	printf("[*] Exception Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	printf("[*] Base Relocation Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("[*] TLS Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("[*] Import Address Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);

	printf("\n\t#####################[ SECTIONS ]#####################\n\n");

	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdr) + sizeof(IMAGE_NT_HEADERS));
	for (size_t i = 0; i < pImgNtHdr->FileHeader.NumberOfSections; i++) {
		printf("[#] %s \n", (CHAR*)pImgSectionHdr->Name);
		printf("\tSize : %d \n", pImgSectionHdr->SizeOfRawData);
		printf("\tRVA : 0x%0.8X \n", pImgSectionHdr->VirtualAddress);
		printf("\tAddress : 0x%p \n", (PVOID)(pPE + pImgSectionHdr->VirtualAddress));
		printf("\tRelocations : %d \n", pImgSectionHdr->NumberOfRelocations);
		printf("\tPermissions : ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READWRITE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("PAGE_EXECUTE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_EXECUTE_READWRITE");
		printf("\n\n");

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}

	return TRUE;
	
}
