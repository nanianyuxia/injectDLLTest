#include <iostream>
#include <Windows.h>
#include <fstream>
#include <cstring>


using namespace std;

bool DLLText(LPVOID lpBaseAddress, HANDLE hProc)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(char*)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((char*)lpBaseAddress + pDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((char*)lpBaseAddress +
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址
	//char* lpDllName = new char[256];
	char* lpDllName = NULL;
	HANDLE hThread = NULL;
	DWORD i = 0;
	LPVOID AddressText = NULL;
	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		//memset(lpDllName, 0, 256);
		// 获取导入表中DLL的名称并加载DLL
		lpDllName = (char*)lpBaseAddress + pImportTable->Name;
		
		cout << "dll:" << lpDllName << endl;
		
		int DllLen = strlen(lpDllName) + 1;
		AddressText = NULL;
		if (!(AddressText = VirtualAllocEx(hProc, NULL, DllLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		{
			cout << "VirtualAllocEx err:" << GetLastError() << endl;
			return false;
		}

		if (!WriteProcessMemory(hProc, AddressText, lpDllName, DllLen, 0))
		{
			cout << "WriteProcessMemory err:" << GetLastError() << endl;
			return false;
		}
		
		HMODULE hMod = LoadLibraryA("kernel32.dll");
		LPTHREAD_START_ROUTINE pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
		hThread = NULL;
		hThread = CreateRemoteThread(hProc, NULL, 0, pThreadProc, AddressText, NULL, 0);
		if (hThread == NULL)
		{
			int err = GetLastError();
			cout << "CreateRemoteThread err：" << err << endl;

			return false;
		}

		WaitForSingleObject(hThread, INFINITE);
		//VirtualFreeEx(hProc, AddressText, NULL, 0);
		//CloseHandle(hThread);

		pImportTable++;
		
	}

	return TRUE;
}



bool DoRelocationTable(LPVOID lpBaseAddress, LPVOID testAddress)
{	// 参数1：已拉伸的PE   参数2：VirtualAllocEx 的返回地址


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(char*)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((char*)lpBaseAddress + pDosHeader->e_lfanew);
	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((char*)lpBaseAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	// 判断是否有 重定位表
	if ((PVOID)pLoc == (PVOID)pDosHeader)
	{
		// 重定位表 为空

		return TRUE;
	}

	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
	{
		WORD* pLocData = (WORD*)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
		//计算本节需要修正的重定位项（地址）的数目
		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (int i = 0; i < nNumberOfReloc; i++)
		{
			if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
			{
				DWORD* pAddress_A = (DWORD*)((DWORD)lpBaseAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
				*pAddress_A = (*pAddress_A) - pNtHeaders->OptionalHeader.ImageBase + (DWORD)testAddress;

			}
		}

		//转移到下一个节进行处理
		pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
	}

	return TRUE;
}


bool DoImportTable(LPVOID lpBaseAddress, HANDLE hProc)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(char*)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((char*)lpBaseAddress + pDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((char*)lpBaseAddress +
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址
	char* lpDllName = NULL;
	HMODULE hDll = NULL;
	PIMAGE_THUNK_DATA lpImportNameArray = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
	PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
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
		hDll = ::GetModuleHandle((LPCWSTR)lpDllName);
		if (NULL == hDll)
		{
			hDll = ::LoadLibrary((LPCWSTR)lpDllName);
			if (NULL == hDll)
			{
				pImportTable++;
				continue;
			}
		}

		i = 0;
		// 获取OriginalFirstThunk以及对应的导入函数名称表首地址
		lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->OriginalFirstThunk);
		// 获取FirstThunk以及对应的导入函数地址表首地址
		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			// 获取IMAGE_IMPORT_BY_NAME结构
			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

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
			WriteProcessMemory(hProc, (LPVOID)lpImportFuncAddrArray[i].u1.Function, lpFuncAddress, sizeof(DWORD), NULL);
			i++;
		}

		pImportTable++;
	}

	return TRUE;
}


bool inJectProc(HANDLE hProc)
{

	//HANDLE hDll = LoadLibrary(L"E:\\code\\injectDLLTest\\Release\\Dll_inject.dll");

	char nameDll[256] = "E:\\code\\injectDLLTest\\Release\\Dll_inject.dll";
	UINT UISize = strlen(nameDll) + 1;
	LPDWORD pThread = NULL;
	HANDLE hThread;



	LPVOID ProcAddr = NULL;
	if (!(ProcAddr = VirtualAllocEx(hProc, NULL, UISize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
	{
		cout << "VirtualAllocEx err" << endl;
		return false;
	}

	if (!WriteProcessMemory(hProc, ProcAddr, nameDll, UISize, NULL))
	{
		cout << "WriteProcessMemory err" << endl;
		return false;
	}


	HMODULE hMod = LoadLibraryA("kernel32.dll");
	LPTHREAD_START_ROUTINE pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");

	hThread = CreateRemoteThread(hProc, NULL, 0, pThreadProc, ProcAddr, NULL, pThread);
	if (hThread == NULL)
	{
		int err = GetLastError();
		cout << "CreateRemoteThread err：" << err << endl;

		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	//GetExitCodeThread(hThread, exitCode);
	//VirtualFreeEx(hProc, ProcAddr, NULL, 0);
	//CloseHandle(hThread);


	return true;
}



int main()
{
	BOOL bo_buf = SetCurrentDirectory(L"D:\\tencent\\wechat\\");

	string file_name("WeChat.exe");//"D:\\tencent\\wechat\\WeChat.exe";
	struct stat ta;
	if (stat(file_name.c_str(), &ta) != 0)
	{
		cout << "非法文件" << endl;
		return false;
	}
	ifstream read_file(file_name, ios::binary | ios::in);

	read_file.seekg(0, ios::end);
	size_t fsize = read_file.tellg();
	read_file.seekg(0, ios::beg);

	char* fBuf = new char[fsize];
	memset(fBuf, 0, fsize);
	read_file.read(fBuf, fsize);

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)fBuf;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(fBuf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = &(nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER optional_header = &(nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE && nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "非法PE文件" << endl;
		return -1;	//非法pe文件返回 -1
	}

	size_t test_size = 0;


	cout << "Nt ImageBase:" << hex << nt_header->OptionalHeader.ImageBase << endl;




	size_t v_size = optional_header->SizeOfImage;
	char* VBuf = new char[v_size];
	memset(VBuf, 0, v_size);


	memcpy(VBuf, fBuf, optional_header->SizeOfHeaders);

	for (int i = 0; i < file_header->NumberOfSections; i++, section_header++)
	{
		test_size = section_header->SizeOfRawData;
		memcpy(VBuf + section_header->VirtualAddress, fBuf + section_header->PointerToRawData, test_size);

	}

	PIMAGE_DOS_HEADER m_dos_header = (PIMAGE_DOS_HEADER)VBuf;
	PIMAGE_NT_HEADERS m_nt_header = (PIMAGE_NT_HEADERS)(VBuf + m_dos_header->e_lfanew);
	DWORD ImageBase = m_nt_header->OptionalHeader.ImageBase;

	cout << "mNt ImageBase:" << hex << (DWORD)VBuf << endl;

	if (m_dos_header->e_magic != IMAGE_DOS_SIGNATURE && m_nt_header->Signature != IMAGE_NT_SIGNATURE)	//检查是否是pe文件
	{
		cout << "非法PE文件" << endl;
		return -1;
	}


	if (m_nt_header->OptionalHeader.DataDirectory[1].VirtualAddress == 0)	//检查导入表是否存在导入表
	{
		cout << "导入表为空" << endl;
		return -3;
	}


	if (fBuf != nullptr)
	{
		delete[] fBuf;
		fBuf = nullptr;
	}



	m_dos_header = (PIMAGE_DOS_HEADER)VBuf;
	m_nt_header = (PIMAGE_NT_HEADERS)(VBuf + m_dos_header->e_lfanew);




	size_t Image_size = m_nt_header->OptionalHeader.SizeOfImage;
	size_t ImageBase_size = m_nt_header->OptionalHeader.ImageBase;



	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = { 0 };

	CONTEXT conText = { 0 };

	//E:\\工具包\\PETool.exe
	//D:\\tencent\\wechat\\PETool.exe


	wchar_t wc_buf[] = { L"E:\\PETool.exe" };
	if (CreateProcess(NULL,(LPWSTR)wc_buf, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL,NULL, &si, &pi))
	{
		
		

		conText.ContextFlags = CONTEXT_FULL;
		
		GetThreadContext(pi.hThread, &conText);
		
		typedef NTSTATUS(WINAPI* ZwUnmapViewOfSection)(HANDLE, LPVOID);//定义函数
		ZwUnmapViewOfSection UnmapViewOfSection = (ZwUnmapViewOfSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwUnmapViewOfSection");//获取函数基址
		DWORD base;
		ReadProcessMemory(pi.hProcess, (LPVOID)(conText.Ebx + 8), &base, sizeof(DWORD), NULL);
		UnmapViewOfSection(pi.hProcess, (LPVOID)base);
		

		LPVOID lpBaseAddress = VirtualAllocEx(pi.hProcess, NULL, Image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (lpBaseAddress == NULL)
		{
			DWORD err1 = GetLastError();
			cout << "err1 " << err1 << endl;
			return false;
		}

		WriteProcessMemory(pi.hProcess, lpBaseAddress, VBuf, Image_size, NULL);



		//将lpBaseAddress地址粘贴板
		int* Addre = static_cast<int*>(lpBaseAddress);
		cout << &(*Addre) << endl;
		int b = (int)(&(*Addre));
		cout << b << endl;
		char cAddr[32] = { 0 };

		sprintf_s(cAddr, "%d", b);

		HGLOBAL hMemory;
		LPTSTR lpMemory;


		int size = strlen(cAddr) + 1;

		if (!OpenClipboard(NULL))
		{
			cout << "OpenClipboard err" << endl;
			return -1;
		}

		if (!EmptyClipboard())
		{
			cout << "EmptyClipboard err" << endl;
			return -1;
		}

		if (!(hMemory = (GlobalAlloc(GMEM_MOVEABLE, size))))
		{
			cout << "GlobalAlloc err" << endl;
			return -1;
		}

		if (!(lpMemory = (LPTSTR)GlobalLock(hMemory)))
		{
			cout << "GlobalLock err" << endl;
			return -1;
		}

		memcpy_s(lpMemory, size, cAddr, size);
		GlobalUnlock(hMemory);

		if (!SetClipboardData(CF_TEXT, hMemory))
		{
			cout << "SetClipboardData err" << endl;
			return -1;
		}

		CloseClipboard();


		char* file_V = new char[Image_size];
		ZeroMemory(file_V, Image_size);

		ReadProcessMemory(pi.hProcess, lpBaseAddress, file_V, Image_size, 0);
		DoRelocationTable(VBuf, lpBaseAddress);
		
		DLLText(file_V, pi.hProcess);
		inJectProc(pi.hProcess);

		//DoImportTable(file_V, pi.hProcess);

		
		

		WriteProcessMemory(pi.hProcess, (LPVOID)((size_t)conText.Ebx + 8), &lpBaseAddress, 4, NULL);
		conText.Eax = (DWORD)lpBaseAddress + m_nt_header->OptionalHeader.AddressOfEntryPoint;

		SetThreadContext(pi.hThread, &conText);


		ResumeThread(pi.hThread);
	}
	else
	{
		cout << "err:" << GetLastError() << endl;
		return false;
	}

}




