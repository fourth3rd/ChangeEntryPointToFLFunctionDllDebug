#include "pch.h"
#include "Base.h"

#include <cstdio>

extern "C" FLEXPORT bool TestBaseFunc(const char* pszText)
{
	printf("->TestBaseFunc : ");

	if(pszText)
		printf("%s", pszText);

	printf("\n");

	return pszText ? true : false;
}

CBase::CBase()
{
	printf("Base Constructor\n");
}

CBase::~CBase()
{
	printf("Base Destructor\n");
}

bool CBase::Print(const char* pszText)
{
	printf("->Base : ");

	if(pszText)
		printf("%s", pszText);

	printf("\n");
	
	return pszText ? true : false;
}
