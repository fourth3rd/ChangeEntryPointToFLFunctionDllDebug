#pragma once

#include "../BaseDLL/Base.h"

extern "C" FLEXPORT bool TestBaseFuncEx(const char* pszText);

class FLEXPORT CBaseEx : public CBase
{
public:
	CBaseEx();
	virtual ~CBaseEx();

	virtual bool Print(const char* pszText);
};

class FLEXPORT CBasePVFTestEx : public CBasePVFTest
{
public:
	CBasePVFTestEx();
	virtual ~CBasePVFTestEx();

	virtual bool Print(const char* pszText);
};

class FLEXPORT CBaseExEx : public CBase
{
public:
	CBaseExEx();
	virtual ~CBaseExEx();

	static CBaseEx* GetNewBaseEx();

private:
	int a;
};


/*
class CImageReader
{
public:
	virtual bool Read(char* pFileName) = 0;

	virtual char* GetBuffer();

	char* pBuffer = nullptr;
};


class CImageReaderForJPG : public CImageReader
{
public:
	virtual bool Read(char* pFileName)
	{
		// JPG 리딩 구현
		return true;
	}
};

class CImageReaderForGIF : public CImageReader
{
public:
	virtual bool Read(char* pFileName)
	{
		// GIF 리딩 구현
		return true;
	}
};


CImageReaderFactory
{
	static CImageReader* Decode(char* pFileName)
    {
		CImageReader* pReturn = nullptr;

		if(파일 뒷자리가.jpg면)
		{
			pReturn = new CImageReaderJPG;
			pReturn->Read(pFileName);
			return pReturn;
		}
		else if(파일 두시자더ㅣ거미ㅏㅈㅅ.gif면)
			return new CImageReaderGIF;
		else
			return nullptr;
	}
}

CImageReader* pReader = CImageReaderFactor::Decoding(pFileName);

if(pReader)
{
	pReader->GetBuffer();
		pReader->GetBuffer();

	pRead
	*/