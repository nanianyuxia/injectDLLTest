//#include <iostream>
//#include <Windows.h>
//#include <fstream>
//using namespace std;
//
//int main()
//{
//		
//	string file_name = "D:\\tencent\\wechat\\WeChat.exe";
//	struct stat ta;
//	if (stat(file_name.c_str(), &ta) != 0)
//	{
//		cout << "非法文件" << endl;
//		return false;
//	}
//	ifstream read_file(file_name, ios::binary | ios::in);
//
//	read_file.seekg(0, ios::end);
//	size_t fsize = read_file.tellg();
//	read_file.seekg(0, ios::beg);
//
//	char* fBuf = new char[fsize];
//	memset(fBuf, 0, fsize);
//	read_file.read(fBuf, fsize);
//
//
//	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)fBuf;
//	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(fBuf + dos_header->e_lfanew);
//	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_header);
//
//
//	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE && nt_header->Signature != IMAGE_NT_SIGNATURE)
//	{
//		cout << "非法PE文件" << endl;
//		return -1;	//非法pe文件返回 -1
//	}
//
//	size_t test_size = 0;
//
//
//	cout << "Nt ImageBase:" << hex << nt_header->OptionalHeader.ImageBase << endl;
//
//
//
//
//	size_t v_size = nt_header->OptionalHeader.SizeOfImage;
//	char* VBuf = new char[v_size];
//	memset(VBuf, 0, v_size);
//
//
//	memcpy(VBuf, fBuf, nt_header->OptionalHeader.SizeOfHeaders);
//
//	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_header++)
//	{
//		test_size = section_header->SizeOfRawData;
//		memcpy(VBuf + section_header->VirtualAddress, fBuf + section_header->PointerToRawData, test_size);
//	}
//
//
//
//
//
//
//
//	return 0;
//}
//
//
