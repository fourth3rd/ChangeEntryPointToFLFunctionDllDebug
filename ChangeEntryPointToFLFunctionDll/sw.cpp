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
	FILE* fp = fopen("/*Original*/.dll", "rb");

	if(fp)
	{
		fseek(fp, 0, SEEK_END);
		size_t stSize = ftell(fp);

		int i32FLSize = 0x6000000;

		char* buf = new char[stSize + i32FLSize];

		fseek(fp, 0, SEEK_SET);
		fread(buf, stSize, 1, fp);

		fclose(fp);
		fp = fopen(R"(/*Fixed*/.dll)", "wb");
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

		int i32cfgRVA = 0;
		int i32cfgPointerToRawData = 0;
		int i32cfgSizeofRawData = 0;

		int i32RelocRVA = 0;
		int i32RelocPointerToRawData = 0;
		int i32RelocSizeofRawData = 0;
		int i32FileTextRva = 0;

		std::vector< Section> vctSection;

		int* pModifiedTextCharacteristics = (int*)0xe0000060;
		int i32FLStart = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS);
		i32FileEntryPointAddress = pDosH->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 0x10;

		int i32Start = 0;
		int OriginalImageOfSize = i32SizeOfImage;

		for(int i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
		{
			pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buf + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			Section Temp;
			int i32SectionParse = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER));

			int i32OrigialSize = 0;

			memcpy((void*)&i32OrigialSize, (void*)&buf[i32SectionParse + 0x10], 4);

			if(i == pNtH->FileHeader.NumberOfSections - 1)
			{
				i32Start = pSecH->SizeOfRawData + pSecH->PointerToRawData;
				//i32Start /= 4;

				i32OrigialSize += i32FLSize;
				memcpy((void*)&buf[i32SectionParse + 0x10], (void*)&i32OrigialSize, 4);

				i32OrigialSize = 0x1000000;
				memcpy((void*)&buf[i32SectionParse + 0x8], (void*)&i32OrigialSize, 4);


			}

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
			else if(!strcmp((const char*)pSecH->Name, ".00cfg"))
			{
				i32cfgRVA = pSecH->VirtualAddress;
				i32cfgPointerToRawData = pSecH->PointerToRawData;
				i32cfgSizeofRawData = pSecH->SizeOfRawData;
			}
		}

		int i32RollBackEntryPoint = i32RelocRVA + i32Start - i32RelocPointerToRawData;

		int* ModifiedSizeOfImage = (int*)(pNtH->OptionalHeader.SizeOfImage + i32FLSize);
		int* ModifiedEntryPoint = (int*)(i32RelocRVA + i32Start - i32RelocPointerToRawData);
		WORD* NumberOfSection = (WORD*)(pNtH->FileHeader.NumberOfSections);

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
		/*Section FLSection;
		FLSection.Name[0] = '.';
		FLSection.Name[1] = 'F';
		FLSection.Name[2] = 'L';
		FLSection.Name[3] = '\x00';

		FLSection.VirtualSize = i32FLSize;
		FLSection.RVA = i32SizeOfImage;
		FLSection.SizeOfRawData = i32FLSize;
		FLSection.PoitnerToRawData = stSize;
		FLSection.POinterToRelocations = 0;
		FLSection.PointerToLineNumber = 0;
		FLSection.NumberOfRelocations = 0;
		FLSection.NumberOfLineNumbers = 0;
		FLSection.Characteristics = 0xe0000020;//

		memcpy((void*)&buf[i32FLStart], (void*)&FLSection, sizeof(FLSection));
		i32FLStart += sizeof(IMAGE_SECTION_HEADER);
		*/
		std::vector<std::pair<int, int> > vctRelocationVector;

		int RvaOfBlock = 0;
		int SizeOfBlock = 0;

		int i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

		memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
		memcpy((void*)&SizeOfBlock, (void*)&i32RelocPointerToRawDataToRelocSizeOfBlock, 4);

		if(i32RelocRVA != 0)
		{
			vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
			while(1)
			{
				int TempRelocPointerToRawData = 0;
				memcpy((void*)&TempRelocPointerToRawData, (void*)&buf[SizeOfBlock], 4);
				i32RelocPointerToRawData += TempRelocPointerToRawData;

				i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

				int i32TempSizeOfBlock = 0;
				memcpy((void*)&i32TempSizeOfBlock, (void*)&buf[SizeOfBlock], 4);
				if(i32TempSizeOfBlock == 0)
					break;
				memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
				memcpy((void*)&SizeOfBlock, (void*)(&i32RelocPointerToRawDataToRelocSizeOfBlock), 4);
				vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
			}
		}
		char cFileTextRva[2] = { 0, };
		memcpy((void*)&cFileTextRva, (void*)(&i32FileTextRva), 2);

		bool bCheckIsDllorExe = false;

		if((pNtH->FileHeader.Characteristics & 0xf000) == 0x2000)
		{
			bCheckIsDllorExe = true;
		}
		int i32stSizeCnt = 0;

		buf[stSize + i32stSizeCnt++] = '\x60';

		if(bCheckIsDllorExe == true)
		{
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\xc2';
		}
		else
		{
			buf[stSize + i32stSizeCnt++] = '\x64';
			buf[stSize + i32stSizeCnt++] = '\xa1';
			buf[stSize + i32stSizeCnt++] = '\x18';
			buf[stSize + i32stSizeCnt++] = '\x0';

			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x40';

			buf[stSize + i32stSizeCnt++] = '\x30';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x40';
			buf[stSize + i32stSizeCnt++] = '\x0c';

			buf[stSize + i32stSizeCnt++] = '\x8d';
			buf[stSize + i32stSizeCnt++] = '\x58';
			buf[stSize + i32stSizeCnt++] = '\x0c';
			buf[stSize + i32stSizeCnt++] = '\x8b';

			buf[stSize + i32stSizeCnt++] = '\x13';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x42';
			buf[stSize + i32stSizeCnt++] = '\x18';
		}
		//	buf[stSize + i32stSizeCnt++] = '\x18';

		char cChangeEntryPoint[4] = { 0, };
		int i32CheckChangeEntryPoint = i32RollBackEntryPoint + 0xf0;

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

		buf[stSize + i32stSizeCnt++] = '\xc6';// 여기가 dll 사용
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

		int i32FLFuncionStart = i32stSizeCnt + i32RollBackEntryPoint;
		int i32ChangeEntryPointToOriginal = i32EntryPoint - i32FLFuncionStart - 5;// -3;

		char cOriginalEntryPoint[4] = { 0, };

		memcpy((void*)&cOriginalEntryPoint, (void*)&i32ChangeEntryPointToOriginal, 4);

		buf[stSize + i32stSizeCnt++] = '\xe9';

		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[0];
		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[1];
		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[2];
		buf[stSize + i32stSizeCnt++] = cOriginalEntryPoint[3];

		int i32OffsetCnt = 0x100;

		for(int i = stSize + i32stSizeCnt; i < stSize + i32OffsetCnt; i++)
		{
			buf[i] = '\x0';
		}

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
							//RelocData += 2;

				int i32FileRelocOffset = Data + i32RvaOfBlock - vctSection[Section].RVA + vctSection[Section].PoitnerToRawData;// +2;


				vctParseRelocation.push_back({ Section,{RelocData,i32FileRelocOffset} });

				Start += 2;
			}
		}

		char cFileImageBase[4] = { 0 };
		memcpy((void*)&cFileImageBase, (void*)&i32FileBaseAddress, 4);



		buf[stSize + i32OffsetCnt++] = '\xbb';//relocation 과정 준비
		buf[stSize + i32OffsetCnt++] = cFileImageBase[0];
		buf[stSize + i32OffsetCnt++] = cFileImageBase[1];
		buf[stSize + i32OffsetCnt++] = cFileImageBase[2];
		buf[stSize + i32OffsetCnt++] = cFileImageBase[3];

		//buf[stSize + i32OffsetCnt++] = '\x3b';
		//buf[stSize + i32OffsetCnt++] = '\xc3';
		//buf[stSize + i32OffsetCnt++] = '\x7e';
		//buf[stSize + i32OffsetCnt++] = '\x06';

		buf[stSize + i32OffsetCnt++] = '\x8b';
		buf[stSize + i32OffsetCnt++] = '\xc8';
		buf[stSize + i32OffsetCnt++] = '\x2b';
		buf[stSize + i32OffsetCnt++] = '\xcb';
		//buf[stSize + i32OffsetCnt++] = '\xeb';
		//buf[stSize + i32OffsetCnt++] = '\x04';//offset

		//buf[stSize + i32OffsetCnt++] = '\x8b';
		//buf[stSize + i32OffsetCnt++] = '\xcb';
		//buf[stSize + i32OffsetCnt++] = '\x2b';
		//buf[stSize + i32OffsetCnt++] = '\xc8';

		int cnt = i32OffsetCnt;
		for(int i = 0; i < vctParseRelocation.size(); i++)
		{

			int SSection = vctParseRelocation[i].first;
			int RelocData = vctParseRelocation[i].second.first;

			int InputData = RelocData;// +DeicdeToRvaOfBlock;
			//InputData += BaseAddress;

			char cInputData[4] = { 0, };

			memcpy((void*)&cInputData, (void*)&InputData, 4);
			int i32FileRelocOffset = vctParseRelocation[i].second.second;
			char cType[4] = { 0 };

			for(int j = 0; j < 4; j++)
			{
				cType[j] = buf[i32FileRelocOffset + j];
			}

			buf[stSize + cnt++] = '\x8b';
			buf[stSize + cnt++] = '\xd8';
			buf[stSize + cnt++] = '\x81';
			buf[stSize + cnt++] = '\xc3';
			buf[stSize + cnt++] = cInputData[0];
			buf[stSize + cnt++] = cInputData[1];
			buf[stSize + cnt++] = cInputData[2];
			buf[stSize + cnt++] = cInputData[3];

			buf[stSize + cnt++] = '\xbe';
			buf[stSize + cnt++] = cType[0];
			buf[stSize + cnt++] = cType[1];
			buf[stSize + cnt++] = cType[2];
			buf[stSize + cnt++] = cType[3];

			buf[stSize + cnt++] = '\x03';
			buf[stSize + cnt++] = '\xf1';

			buf[stSize + cnt++] = '\x89';
			buf[stSize + cnt++] = '\x33';

		}


		buf[stSize + cnt++] = '\x61';

		int i32FLLast = cnt + i32RollBackEntryPoint;
		int i32FLfunctionToEntryPoint = i32EntryPoint - i32FLLast - 5;// -3;

		char cFLfunctionToEntryPoint[4] = { 0, };

		memcpy((void*)&cFLfunctionToEntryPoint, (void*)&i32FLfunctionToEntryPoint, 4);



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



		for(int i = i32PointerToRawData; i < i32SizeOfCode; i++)
		{
			buf[i] = ~buf[i];
		}

		char* Temp = new char[stSize];

		fwrite(buf, sizeof(char), stSize + i32FLSize, fp);
		fclose(fp);
	}

}