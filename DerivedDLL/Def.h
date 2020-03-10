#pragma once

#ifdef DERIVEDDLL_EXPORTS
#define FLEXPORT __declspec(dllexport)
#else
#define FLEXPORT __declspec(dllimport)
#endif

#ifdef _DEBUG
#define LIB_IMPORT_PREFIX "../Debug/"
#else
#define LIB_IMPORT_PREFIX "../Release/"
#endif
