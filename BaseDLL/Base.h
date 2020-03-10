#pragma once

#include <cstdio>

extern "C" FLEXPORT bool TestBaseFunc(const char* pszText);

class FLEXPORT CBase
{
public:
	CBase();
	virtual ~CBase();

	virtual bool Print(const char* pszText);
};

class FLEXPORT CBasePVFTest
{
public:
	CBasePVFTest()
	{
		printf("BasePVFTest Constructor\n");
	}
	virtual ~CBasePVFTest()
	{
		printf("BasePVFTest Destructor\n");
	}

	virtual bool Print(const char* pszText) = 0;
};

