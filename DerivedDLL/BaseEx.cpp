#include "pch.h"
#include "BaseEx.h"

#include <cstdio>

extern "C" FLEXPORT bool TestBaseFuncEx(const char* pszText)
{
	printf("->TestBaseFuncEx : ");

	if(pszText)
		printf("%s", pszText);

	return TestBaseFunc(pszText);
}

CBaseEx::CBaseEx()
{
	printf("BaseEx Constructor\n");
}

CBaseEx::~CBaseEx()
{
	printf("BaseEx Destructor\n");
}

bool CBaseEx::Print(const char* pszText)
{
	printf("->BaseEx");
	if(pszText)
		printf("%s", pszText);
	printf("\n");

	return __super::Print(pszText);
}

CBasePVFTestEx::CBasePVFTestEx()
{
	printf("BasePVFTestEx Constructor\n");
}

CBasePVFTestEx::~CBasePVFTestEx()
{
	printf("BasePVFTestEx Destructor\n");
}

bool CBasePVFTestEx::Print(const char* pszText)
{
	printf("->CBasePVFTestEx");
	if(pszText)
		printf("%s", pszText);
	printf("\n");

	CBase* p = new CBase;
	bool b = p->Print(pszText);
	delete p;
	return b;
}

CBaseExEx::CBaseExEx()
{
}

CBaseExEx::~CBaseExEx()
{
}

CBaseEx* CBaseExEx::GetNewBaseEx()
{
	CBaseEx* pBaseEx = new CBaseEx;
	pBaseEx->Print("pBaseExMan");
	CBaseEx cBaseEx;
	cBaseEx.Print("cBaseExMan");

	return pBaseEx;
}
