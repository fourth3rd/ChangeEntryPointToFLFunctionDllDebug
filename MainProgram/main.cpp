#include<cstdio>

#include "Def.h"
#include "../DerivedDLL/BaseUsing.h"
#include "../DerivedDLL/BaseEx.h"


int main()
{
	CBaseUsing bu;

	bool b = false;
	/*
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
	*/
	///*


	CBaseEx* pUtEunGer = CBaseExEx::GetNewBaseEx();

	
	CBasePVFTestEx* pbpvf = new CBasePVFTestEx;
	printf("TEST DERIVED CLASS with PVF\n");
	b &= pbpvf->Print("HELLO FINAL NEW WORLD!");
	printf("=================================\n");

	printf("B is %d\n", b);
	
	return 0;
}