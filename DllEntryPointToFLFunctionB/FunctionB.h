#pragma once
#include<Windows.h>

extern "C" __declspec(dllexport) void PrintHelloB()
{
    MessageBoxEx(NULL, L"Print Hello B", 0, 0, 0);
}