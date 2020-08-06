// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"



typedef struct __IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	CHAR   Name[1];
} _IMAGE_IMPORT_BY_NAME_, * _PIMAGE_IMPORT_BY_NAME;

typedef struct __IMAGE_THUNK_DATA {
	union {
		DWORD ForwarderString;      // PBYTE 
		DWORD Function;             // PDWORD
		DWORD Ordinal;
		DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} _IMAGE_THUNK_DATA_;
typedef _IMAGE_THUNK_DATA_* _PIMAGE_THUNK_DATA;

typedef struct __IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} _IMAGE_DATA_DIRECTORY_, * _PIMAGE_DATA_DIRECTORY;

typedef struct __IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} _IMAGE_DOS_HEADER_, * _PIMAGE_DOS_HEADER;

typedef struct __IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} _IMAGE_FILE_HEADER_, * _PIMAGE_FILE_HEADER;



typedef struct __IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	_IMAGE_DATA_DIRECTORY_ DataDirectory[16];
} _IMAGE_OPTIONAL_HEADER_, * _PIMAGE_OPTIONAL_HEADER;

typedef struct __IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} _IMAGE_NT_HEADERS_, * _PIMAGE_NT_HEADERS;

typedef struct __IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;                  // 0 if not bound,
											// -1 if bound, and real date\time stamp
											//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
											// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} _IMAGE_IMPORT_DESCRIPTOR_;
typedef _IMAGE_IMPORT_DESCRIPTOR_ UNALIGNED* _PIMAGE_IMPORT_DESCRIPTOR;


BOOL APIENTRY MDllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//第一次将一个DLL映射到进程的地址空间中，之后再Loaibrary不再调用这个入口函数
		MDllMain( hModule,   ul_reason_for_call,  lpReserved);
		break;
	case DLL_THREAD_ATTACH:
		break;
		//进程创建一个线程时，DLL执行与线程相关的初始化
	case DLL_THREAD_DETACH:
		//ExitThread让线程终止
		break;
	case DLL_PROCESS_DETACH:
		//将一个DLL从进程的地址空间中撤销时调用。(即最后一次FreeLibrary或FreeLibraryAndExitThread)
		//调用的是FreeLibrary时，在DllMain处理完DLL_PROCESS_DETACH通知之前，线程不会从该调用中返回。
		//DLL可能会阻碍进程的终止。
		break;
	}
	return TRUE;
}


BOOL APIENTRY MDllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	//LoadLibraryExA()
	//

	//bool isno = SetDllDirectoryA("D:\\tencent\\wechat\\");

	//if (isno == true)
	//{
	//	MessageBoxA(NULL, "TRUE", "提示", MB_OK);
	//}
	//else if (isno == false)
	//{
	//	MessageBoxA(NULL, "FALSE", "提示", MB_OK);
	//}
	//SetCurrentDirectoryA("D:\\tencent\\wechat\\");
	char c_buf[0x60] = {0};
	GetCurrentDirectoryA(0x60, c_buf);
	OutputDebugStringA("---------");
	OutputDebugStringA(c_buf);
	OutputDebugStringA("---------");
	//在进程中loadlibrary
	////打开剪切板
	if (!OpenClipboard(NULL))
	{
		return -1;
	}
	//判断是否时CF_TEXT
	if (!IsClipboardFormatAvailable(CF_TEXT))
	{
		return -1;
	}

	//获取剪切板内容
	HANDLE hClip = GetClipboardData(CF_TEXT);
	char* pbuf = (char*)GlobalLock(hClip);
	GlobalUnlock(hClip);
	//MessageBoxA(NULL, pbuf, "提示", MB_OK);
	//清空剪切板
	if (!EmptyClipboard())
	{
		return -1;
	}

	//将字符串转换成int
	//int addre = atol(pbuf);
	int value, str_len, value_temp = 0;
	str_len = strlen(pbuf);

	for (int i = 0; i < str_len; i++)
	{
		value_temp = value_temp * 10 + (*(pbuf + i) - '0');
	}

	//cout << value_temp;


	//MessageBoxW(NULL, L"OKOKOKOKOK\0", L"提示", MB_OK);
	CloseClipboard();

	//修复IAT表
	char* lpBaseAddress = (char*)value_temp;
	_PIMAGE_DOS_HEADER pDosHeader = (_PIMAGE_DOS_HEADER)(char*)lpBaseAddress;
	//MessageBoxA(NULL, "_PIMAGE_DOS_HEADER", "LoadLibraryA", MB_OK);
	_PIMAGE_NT_HEADERS pNtHeaders = (_PIMAGE_NT_HEADERS)((char*)lpBaseAddress + pDosHeader->e_lfanew);
	//MessageBoxA(NULL, "_PIMAGE_NT_HEADERS", "LoadLibraryA", MB_OK);
	_PIMAGE_IMPORT_DESCRIPTOR pImportTable = (_PIMAGE_IMPORT_DESCRIPTOR)((char*)lpBaseAddress +
	pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	//MessageBoxA(NULL, "_PIMAGE_IMPORT_DESCRIPTOR", "LoadLibraryA", MB_OK);

	char test1[20] = { pNtHeaders->OptionalHeader.ImageBase };

	//MessageBoxA(NULL, (char*)value_temp, "提示", MB_OK);


	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址
	char* lpDllName = NULL;
	HMODULE hDll = NULL;
	_PIMAGE_THUNK_DATA lpImportNameArray = NULL;
	_PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
	_PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
	FARPROC lpFuncAddress = NULL;
	DWORD i = 0;

	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		// 获取导入表中DLL的名称并加载DLL
		lpDllName = (char*)lpBaseAddress + pImportTable->Name;
		//OutputDebugStringA(lpDllName);
		//MessageBoxA(NULL, lpDllName, "LoadLibraryA", MB_OK);
		hDll = ::LoadLibraryA(lpDllName);
		
		if (NULL == hDll)
		{
			//MessageBoxA(NULL, "NULL", "LoadLibraryA", MB_OK);
			pImportTable++;
			continue;
		}

		i = 0;
		// 获取OriginalFirstThunk以及对应的导入函数名称表首地址
		lpImportNameArray = (_PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->OriginalFirstThunk);
		// 获取FirstThunk以及对应的导入函数地址表首地址
		lpImportFuncAddrArray = (_PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			// 获取IMAGE_IMPORT_BY_NAME结构
			lpImportByName = (_PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			// 判断导出函数是序号导出还是函数名称导出
			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				// 序号导出
				// 当IMAGE_THUNK_DATA值的最高位为1时，表示函数以序号方式输入，这时，低位被看做是一个函数序号
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				// 名称导出
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
			}
			//OutputDebugStringA((LPCSTR)lpImportByName->Name);
			//char c_buf[0x10] = {0};
			//sprintf_s(c_buf, "%X", (DWORD)lpFuncAddress);
			//OutputDebugStringA(c_buf);

			lpImportFuncAddrArray[i].u1.Function = (DWORD)lpFuncAddress;
			i++;
		}

		pImportTable++;
	}
    return TRUE;
}

