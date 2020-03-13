#include<cstdio>

#include "Def.h"
#include "../DerivedMFCDll/CFLDialogTest.h"
#include "../DerivedMFCDll/resource.h"
#include "../DerivedDLL/BaseUsing.h"
#include "../DerivedDLL/BaseEx.h"
#include "stdafx.h"

int main()
{
	CBaseUsing bu;

	bool b = false;
	
	printf("=================================\n");
	printf("Normal Func Test\n");
	b = TestBaseFuncEx("HELLO LAND!");
	
	printf("=================================\n");
	printf("TEST NORMAL CLASS(Has a relation)\n");
	b &= bu.Print("HELLO WORLD!");
	printf("=================================\n");

	CBaseEx bex;
	printf("TEST DERIVED CLASS with VF\n");
	b &= bex.Print("HELLO NEW WORLD!");
	printf("=================================\n");


	CBaseEx* pUtEunGer = CBaseExEx::GetNewBaseEx();

	
	CBasePVFTestEx* pbpvf = new CBasePVFTestEx;
	printf("TEST DERIVED CLASS with PVF\n");
	b &= pbpvf->Print("HELLO FINAL NEW WORLD!");
	printf("=================================\n");

	printf("B is %d\n", b);
	

	if(!AfxWinInit(::GetModuleHandle(NULL), NULL, ::GetCommandLine(), 0))
	{
		printf("MFC DLL failed\n");
	}
	else
	{
		//AFX_MANAGE_STATE(AfxGetStaticModuleState());
		CFLDialogTest A;
		A.DoModal();
	}


	return 0;
}