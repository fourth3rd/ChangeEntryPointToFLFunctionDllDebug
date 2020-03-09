#pragma once
#include<Windows.h>

extern "C" __declspec(dllexport) void PrintHelloA()
{
    MessageBoxEx(NULL, L"Print Hello A", 0, 0, 0);
}