#include "pch.h"
#include "BaseUsing.h"

#include <cstdio>

CBaseUsing::CBaseUsing()
{
	printf("BaseUsing Constructor\n");
}

CBaseUsing::~CBaseUsing()
{
	printf("BaseUsing Destructor\n");
}

bool CBaseUsing::Print(const char* pszText)
{
	printf("-> BaseUsing : ");
	return m_base.Print(pszText);
}
