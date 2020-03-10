#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<string>
#include<Windows.h>
#include<vector>


std::vector<std::pair<int, std::pair<int, int > > > vctParseRelocation;
typedef struct Section
{
	char Name[8];
	int VirtualSize;
	int RVA;
	int SizeOfRawData;
	int PoitnerToRawData;
	int POinterToRelocations;
	int PointerToLineNumber;
	WORD NumberOfRelocations;
	WORD NumberOfLineNumbers;
	int Characteristics;
	int TempOffset;
}Section;

int FindMemoryBaseAddress(std::wstring src)
{
	int BaseAddress = 0;
	void* orgPtr = nullptr;
	void* curPtr = nullptr;
	wchar_t* strTemp = new wchar_t[src.size()];
	for(int i = 0; i < src.size(); i++)
	{
		*(strTemp + i) = src[i];
		*(strTemp + i + 1) = '\x00';
	}

	__asm
	{
		mov eax, fs: [0x18]        // TIB
		mov eax, [eax + 0x30]    // TIB->PEB
		mov eax, [eax + 0x0C]     // PEB->Ldr
		lea ebx, [eax + 0x0C]    // Ldr->InLoadOrderLinks
		mov orgPtr, ebx
		loadOrderLoop :
		mov edx, [ebx]            // InLoadOrderLinks->Flink
			mov curPtr, edx
			mov edi, [edx + 0x30]   // LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer
			mov ecx, [edx + 0x18]
			test edi, edi
			je loadOrderFailed
			push strTemp
			push edi
			call strcmp
			add esp, 8
			mov esi, 0
			cmp eax, esi
			je DllFind
			loadOrderFailed :
		mov ebx, curPtr
			mov ebx, [ebx]
			mov edx, orgPtr
			cmp ebx, edx
			jne loadOrderLoop
			DllFind :
		mov ecx, [edx + 0x18]
			mov BaseAddress, ecx
	}

	return BaseAddress;
}
/*
void Decrypt(int Raw, int VA, int PointerToRawData, int Size)
{
	int* BaseAddress = FindMemoryBaseAddress(L"TestFunctionFixed.exe");

	int Start = Raw + VA - PointerToRawData;
	int From = Start + Size;

	for(int i = Start; i < From; i++)
	{
		BaseAddress[i] ^= 7;
	}
}
*/
int main()
{
	FILE* fp = fopen("DllEntryPointToFLFunctionBOriginal.dll", "rb");

	if(fp)
	{
		fseek(fp, 0, SEEK_END);
		size_t stSize = ftell(fp);

		char* buf = new char[stSize + 0x3000];
		char* Temp = new char[stSize];
		fseek(fp, 0, SEEK_SET);
		fread(buf, stSize, 1, fp);

		fclose(fp);
		fp = fopen(R"(DllEntryPointToFLFunctionB.dll)", "wb");
		fseek(fp, 0, SEEK_SET);

		PIMAGE_DOS_HEADER pDosH;
		PIMAGE_NT_HEADERS pNtH;
		PIMAGE_SECTION_HEADER pSecH;

		pDosH = (PIMAGE_DOS_HEADER)buf;
		pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)buf + pDosH->e_lfanew);

		int i32FileBaseAddress = pNtH->OptionalHeader.ImageBase;
		int i32EntryPoint = pNtH->OptionalHeader.AddressOfEntryPoint;
		int i32PointerToRawData = 0;
		int i32RVA = 0;
		int i32SizeOfRawData = 0;
		int i32SizeOfCode = pNtH->OptionalHeader.SizeOfCode;
		int i32SizeOfImage = pNtH->OptionalHeader.SizeOfImage;
		int i32TextSizeOfCode = 0;
		int i32FileEntryPointAddress = 0;

		int i32RelocRVA = 0;
		int i32RelocPointerToRawData = 0;
		int i32RelocSizeofRawData = 0;
		int i32FileTextRva = 0;

		std::vector< Section> vctSection;

		int* pModifiedTextCharacteristics = (int*)0xe0000060;
		int i32FLStart = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS);
		i32FileEntryPointAddress = pDosH->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 0x10;
		for(int i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
		{
			pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buf + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			Section Temp;

			Temp.PoitnerToRawData = pSecH->PointerToRawData;
			Temp.RVA = pSecH->VirtualAddress;
			Temp.SizeOfRawData = pSecH->SizeOfRawData;
			strcpy(Temp.Name, (const char*)pSecH->Name);
			vctSection.push_back(Temp);

			memcpy((void*)&pSecH->Characteristics, (void*)&pModifiedTextCharacteristics, 4);
			i32FLStart += sizeof(IMAGE_SECTION_HEADER);

			if(!strcmp((const char*)pSecH->Name, ".text"))
			{
				i32PointerToRawData = pSecH->PointerToRawData;
				i32RVA = pSecH->VirtualAddress;
				i32SizeOfRawData = pSecH->SizeOfRawData;
				i32FileTextRva = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER));
				i32FileTextRva += 0xc;
				//i32TextSizeOfCode=
			}
			else if(!strcmp((const char*)pSecH->Name, ".reloc"))
			{
				i32RelocRVA = pSecH->VirtualAddress;
				i32RelocPointerToRawData = pSecH->PointerToRawData;
				i32RelocSizeofRawData = pSecH->SizeOfRawData;
			}
		}

		for(int i = i32PointerToRawData; i < i32SizeOfCode; i++)
		{
			buf[i] = ~buf[i];
		}



		int* ModifiedSizeOfImage = (int*)(pNtH->OptionalHeader.SizeOfImage + 0x3000);
		int* ModifiedEntryPoint = (int*)pNtH->OptionalHeader.SizeOfImage;
		WORD* NumberOfSection = (WORD*)(pNtH->FileHeader.NumberOfSections + 0x1);

		memcpy((void*)&pNtH->OptionalHeader.SizeOfImage, (void*)&ModifiedSizeOfImage, 4);
		memcpy((void*)&pNtH->OptionalHeader.AddressOfEntryPoint, (void*)&ModifiedEntryPoint, 4);
		memcpy((void*)&pNtH->FileHeader.NumberOfSections, (void*)&NumberOfSection, 2);
		/*memcpy((void*)&buf[0x130], (void*)&ModifiedSizeOfImage, 4);
		memcpy((void*)&buf[0x108], (void*)&ModifiedEntryPoint, 4);
		memcpy((void*)&buf[0x224], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x24c], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x274], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x29c], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x2c4], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x2ec], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x314], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x33c], (void*)&pModifiedTextCharacteristics, 4);
		*/
		//buf[0xe6] = '\xa';
		Section FLSection;
		FLSection.Name[0] = '.';
		FLSection.Name[1] = 'F';
		FLSection.Name[2] = 'L';
		FLSection.Name[3] = '\x00';

		FLSection.VirtualSize = 0x3000;
		FLSection.RVA = i32SizeOfImage;
		FLSection.SizeOfRawData = 0x3000;
		FLSection.PoitnerToRawData = stSize;
		FLSection.POinterToRelocations = 0;
		FLSection.PointerToLineNumber = 0;
		FLSection.NumberOfRelocations = 0;
		FLSection.NumberOfLineNumbers = 0;
		FLSection.Characteristics = 0xe0000020;//

		memcpy((void*)&buf[i32FLStart], (void*)&FLSection, sizeof(FLSection));
		i32FLStart += sizeof(IMAGE_SECTION_HEADER);
		std::vector<std::pair<int, int> > vctRelocationVector;

		int RvaOfBlock = 0;
		int SizeOfBlock = 0;

		int i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

		memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
		memcpy((void*)&SizeOfBlock, (void*)&i32RelocPointerToRawDataToRelocSizeOfBlock, 4);


		vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
		while(1)
		{
			int TempRelocPointerToRawData = 0;
			memcpy((void*)&TempRelocPointerToRawData, (void*)&buf[SizeOfBlock], 4);
			i32RelocPointerToRawData += TempRelocPointerToRawData;

			i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;
			if(buf[SizeOfBlock] == '\x0')
				break;
			memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
			memcpy((void*)&SizeOfBlock, (void*)(&i32RelocPointerToRawDataToRelocSizeOfBlock), 4);
			vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
		}

		char cFileTextRva[2] = { 0, };
		memcpy((void*)&cFileTextRva, (void*)(&i32FileTextRva), 2);


		int i32stSizeCnt = 0;

		buf[stSize + i32stSizeCnt++] = '\x60';

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xc2';
	//	buf[stSize + i32stSizeCnt++] = '\x18';

		char cChangeEntryPoint[4] = { 0, };
		int i32CheckChangeEntryPoint = FLSection.RVA + 0xf0;

		memcpy((void*)&cChangeEntryPoint, (void*)&i32CheckChangeEntryPoint, 4);

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xf0';

		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc6';

		buf[stSize + i32stSizeCnt++] = cChangeEntryPoint[0];
		buf[stSize + i32stSizeCnt++] = cChangeEntryPoint[1];
		buf[stSize + i32stSizeCnt++] = cChangeEntryPoint[2];
		buf[stSize + i32stSizeCnt++] = cChangeEntryPoint[3];


		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xfe';

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x36';

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xfe';
		buf[stSize + i32stSizeCnt++] = '\x01';

		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x07';
		buf[stSize + i32stSizeCnt++] = '\x01';

		WORD dwMoveToDecode = 0x100 - i32stSizeCnt;//
		WORD dwChangeMoveToDecode = dwMoveToDecode - 6;// -3;

		char cChangeMoveToDecode[2] = { 0 };

		memcpy((void*)&cChangeMoveToDecode, (void*)&dwChangeMoveToDecode, 2);

		buf[stSize + i32stSizeCnt++] = '\x0f';
		buf[stSize + i32stSizeCnt++] = '\x85';

		buf[stSize + i32stSizeCnt++] = cChangeMoveToDecode[0];
		buf[stSize + i32stSizeCnt++] = cChangeMoveToDecode[1];
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x61';

		int i32FLFuncionStart = i32stSizeCnt + FLSection.RVA;//
		int i32ChangeEntryPointToOriginal = i32EntryPoint - i32FLFuncionStart - 5;// -3;

		char cOriginalEntryPoint[4] = { 0, };

		memcpy((void*)&cOriginalEntryPoint, (void*)&i32ChangeEntryPointToOriginal, 4);

		buf[stSize + i32stSizeCnt++] = '\xe9';

		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[0];
		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[1];
		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[2];
		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[3];



		/*
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x0c';

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xec';

		buf[stSize + i32stSizeCnt++] = '\x5d';
		*/
		std::string strFileName = "DllEntryPointToFLFunction.dll";
		for(int i = 0; i < strFileName.size(); i += 1)
		{
			buf[i32FLStart + 2 * i] = strFileName[i];
			buf[i32FLStart + 2 * i + 1] = '\x00';
		}

		int i32OffsetCnt = 0x100;

		for(int i = stSize + i32stSizeCnt; i < stSize + i32OffsetCnt; i++)
		{
			buf[i] = '\x00';
		}


		/*
		buf[stSize + i32OffsetCnt++] = '\x64';
		buf[stSize + i32OffsetCnt++] = '\xa1';
		buf[stSize + i32OffsetCnt++] = '\x18';
		buf[stSize + i32OffsetCnt++] = '\x0';

		buf[stSize + i32OffsetCnt++] = '\x0';
		buf[stSize + i32OffsetCnt++] = '\x0';
		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\x40';

		buf[stSize + i32OffsetCnt++] = '\x30';
		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\x40';
		buf[stSize + i32OffsetCnt++] = '\x0c';

		buf[stSize + i32OffsetCnt++] = '\x8d';
		buf[stSize + i32OffsetCnt++] = '\x58';
		buf[stSize + i32OffsetCnt++] = '\x0c';
		buf[stSize + i32OffsetCnt++] = '\x8b';

		buf[stSize + i32OffsetCnt++] = '\x13';
		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\x42';
		buf[stSize + i32OffsetCnt++] = '\x18';
		*/
		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\xd8';
		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\xd0';

		buf[stSize + i32OffsetCnt++] = '\x81';
		buf[stSize + i32OffsetCnt++] = '\xc2';
		buf[stSize + i32OffsetCnt++] = cFileTextRva[0];
		buf[stSize + i32OffsetCnt++] = cFileTextRva[1];

		buf[stSize + i32OffsetCnt++] = '\x00';
		buf[stSize + i32OffsetCnt++] = '\x00';
		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\x1a';

		buf[stSize + i32OffsetCnt++] = '\x83';
		buf[stSize + i32OffsetCnt++] = '\xc2';
		buf[stSize + i32OffsetCnt++] = '\x04';

		buf[stSize + i32OffsetCnt++] = '\x8b';

		buf[stSize + i32OffsetCnt++] = '\x0a';
		buf[stSize + i32OffsetCnt++] = '\x83';
		buf[stSize + i32OffsetCnt++] = '\xc2';
		buf[stSize + i32OffsetCnt++] = '\x04';


		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\x32';
		buf[stSize + i32OffsetCnt++] = '\x2b';
		buf[stSize + i32OffsetCnt++] = '\xce';

		buf[stSize + i32OffsetCnt++] = '\x03';
		buf[stSize + i32OffsetCnt++] = '\xd8';
		buf[stSize + i32OffsetCnt++] = '\x83';
		buf[stSize + i32OffsetCnt++] = '\xc2';
		buf[stSize + i32OffsetCnt++] = '\x10';
		buf[stSize + i32OffsetCnt++] = '\xf6';
		buf[stSize + i32OffsetCnt++] = '\x13';
		buf[stSize + i32OffsetCnt++] = '\x83';
		buf[stSize + i32OffsetCnt++] = '\xc3';
		buf[stSize + i32OffsetCnt++] = '\x01';
		buf[stSize + i32OffsetCnt++] = '\x83';
		buf[stSize + i32OffsetCnt++] = '\xe9';
		buf[stSize + i32OffsetCnt++] = '\x01';
		buf[stSize + i32OffsetCnt++] = '\x83';
		buf[stSize + i32OffsetCnt++] = '\xf9';
		buf[stSize + i32OffsetCnt++] = '\x00';
		buf[stSize + i32OffsetCnt++] = '\x75';
		buf[stSize + i32OffsetCnt++] = '\xf3';
//		buf[stSize + i32OffsetCnt++] = '\x00';
//		buf[stSize + i32OffsetCnt++] = '\x00';

		/*
		buf[stSize + 0x5e] = '\xe9';

		buf[stSize + 0x5f] = '\xd1';
		buf[stSize + 0x60] = '\x12';
		buf[stSize + 0x61] = '\xff';
		buf[stSize + 0x62] = '\xff';
		*///Jump To Original Entry Point

		for(int i = 0; i < vctRelocationVector.size(); i++)
		{
			int RvaOfBlock = vctRelocationVector[i].first;
			int DeicdeToRvaOfBlock = 0;
			memcpy((void*)&DeicdeToRvaOfBlock, (void*)&buf[RvaOfBlock], 4);
			int Section = 0;
			for(int j = 0; j < vctSection.size() - 1; j++)
			{
				int FromRvaOfBlock = vctSection[j].RVA;
				int ToRvaOfBlock = vctSection[j + 1].RVA;

				if(FromRvaOfBlock <= DeicdeToRvaOfBlock && DeicdeToRvaOfBlock < ToRvaOfBlock)
				{
					Section = j;
					break;
				}
			}

			int Size = 0;
			memcpy((void*)&Size, (void*)&buf[vctRelocationVector[i].second], 4);

			int Start = vctRelocationVector[i].second + 4;

			for(int j = 2; j < Size - 6; j += 2)
			{
				WORD Data = 0;
				int i32RvaOfBlock = 0;

				memcpy((void*)&i32RvaOfBlock, (void*)&buf[RvaOfBlock], 4);
				memcpy((void*)&Data, (void*)&buf[Start], 2);
				if(Data == 0)
					continue;
				Data &= 0x0fff;

				int RelocData = i32RvaOfBlock + Data;

	//			RelocData -= vctSection[Section].RVA;
//				RelocData += vctSection[Section].PoitnerToRawData;
				RelocData += 2;

				vctParseRelocation.push_back({ Section,{RelocData,DeicdeToRvaOfBlock} });

				Start += 2;
			}
		}

		int BaseAddress = FindMemoryBaseAddress(L"DllEntryPointToFLFunction.dll");
		BaseAddress = BaseAddress & 0xffff0000;
		int cnt = i32OffsetCnt;
		for(int i = 0; i < vctParseRelocation.size(); i++)
		{
			int Section = vctParseRelocation[i].first;
			int RelocData = vctParseRelocation[i].second.first;
			int DeicdeToRvaOfBlock = vctParseRelocation[i].second.second;
			//int RVA = vctSection[Section].RVA;
			//int PointerToRawData = vctSection[Section].PoitnerToRawData;

			int InputData = RelocData;// +DeicdeToRvaOfBlock;
			//InputData += BaseAddress;

			char cInputData[4] = { 0, };

			memcpy((void*)&cInputData, (void*)&InputData, 4);

			char HighBaseAddress[2] = { 0, };

			WORD WDHighBaseAddress = (BaseAddress & 0xffff0000) >> 16;

			memcpy((void*)&HighBaseAddress, (void*)&(WDHighBaseAddress), 2);

			buf[stSize + cnt] = '\x8b';
			buf[stSize + cnt + 1] = '\xd8';
			buf[stSize + cnt + 2] = '\x81';
			buf[stSize + cnt + 3] = '\xc3';
			buf[stSize + cnt + 4] = cInputData[0];
			buf[stSize + cnt + 5] = cInputData[1];
			buf[stSize + cnt + 6] = cInputData[2];
			buf[stSize + cnt + 7] = cInputData[3];

			buf[stSize + cnt + 8] = '\x8b';
			buf[stSize + cnt + 9] = '\xf3';
			buf[stSize + cnt + 10] = '\xc1';
			buf[stSize + cnt + 11] = '\xee';
			buf[stSize + cnt + 12] = '\x10';

			buf[stSize + cnt + 13] = '\x3e';
			buf[stSize + cnt + 14] = '\x66';
			buf[stSize + cnt + 15] = '\x89';
			buf[stSize + cnt + 16] = '\x33';

			cnt += 17;

		}




		/*buf[stSize + cnt++] = '\x8b';// EntryPoint를 바꾸는 부분인데 Write속성이 없어서 작동이 안하는 것 같음
		buf[stSize + cnt++] = '\xc8';

		buf[stSize + cnt++] = '\x81';
		buf[stSize + cnt++] = '\xc1';
		buf[stSize + cnt++] = cChangeEntryPoint[0];
		buf[stSize + cnt++] = cChangeEntryPoint[1];
		buf[stSize + cnt++] = cChangeEntryPoint[2];
		buf[stSize + cnt++] = cChangeEntryPoint[3];

		buf[stSize + cnt++] = '\x33';
		buf[stSize + cnt++] = '\xdb';

		buf[stSize + cnt++] = '\x81';
		buf[stSize + cnt++] = '\xc3';

		buf[stSize + cnt++] = cEntryPoint[0];
		buf[stSize + cnt++] = cEntryPoint[1];
		buf[stSize + cnt++] = cEntryPoint[2];
		buf[stSize + cnt++] = cEntryPoint[3];

		buf[stSize + cnt++] = '\x89';
		buf[stSize + cnt++] = '\x19';

		buf[stSize + cnt++] = '\x61';*/


		buf[stSize + cnt++] = '\x61';
		int i32FLLast = cnt + FLSection.RVA;
		int i32FLfunctionToEntryPoint = i32EntryPoint - i32FLLast - 5;// -3;

		char cFLfunctionToEntryPoint[4] = { 0, };

		memcpy((void*)&cFLfunctionToEntryPoint, (void*)&i32FLfunctionToEntryPoint, 4);

		/* dll만 로딩할때
		buf[stSize + cnt++] = '\x83';
		buf[stSize + cnt++] = '\xec';
		buf[stSize + cnt++] = '\x08';
		*/
		buf[stSize + cnt++] = '\xe9';

		buf[stSize + cnt++] = cFLfunctionToEntryPoint[0];
		buf[stSize + cnt++] = cFLfunctionToEntryPoint[1];
		buf[stSize + cnt++] = cFLfunctionToEntryPoint[2];
		buf[stSize + cnt++] = cFLfunctionToEntryPoint[3];
		buf[stSize + cnt++] = '\x00';
		buf[stSize + cnt++] = '\x00';
		buf[stSize + cnt++] = '\x00';
		buf[stSize + cnt++] = '\x00';
		buf[stSize + cnt++] = '\x01';
		fwrite(buf, sizeof(char), stSize + 0x3000, fp);
		fclose(fp);
	}

}