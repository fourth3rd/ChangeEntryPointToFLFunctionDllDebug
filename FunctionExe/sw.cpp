#include<stdio.h>
#include<Windows.h>
//#pragma comment(lib,"DllEntryPointToFLFunction.lib")

//extern "C" __declspec(dllimport) void PrintHelloA();

int main()
{
	HMODULE hModule = LoadLibrary(L"DllEntryPointToFLFunction");

	FARPROC fFuntion = GetProcAddress(hModule, "PrintHelloA");

	fFuntion();
}

