#pragma once
#ifdef DERIVEMFCDDLL_EXPORTS
#define FLEXPORT __declspec(dllexport)
#else
#define FLEXPORT __declspec(dllimport)
#endif
