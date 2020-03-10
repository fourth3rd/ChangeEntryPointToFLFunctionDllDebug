#pragma once

#include "../BaseDLL/Base.h"

class FLEXPORT CBaseUsing
{
public:
	CBaseUsing();
	virtual ~CBaseUsing();

	bool Print(const char* pszText);

private:
	CBase m_base;
};

