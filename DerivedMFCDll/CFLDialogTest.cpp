// CFLDialogTest.cpp: 구현 파일
//

#include "pch.h"
#include "CFLDialogTest.h"
#include "afxdialogex.h"
#include "resource.h"

// CFLDialogTest 대화 상자

IMPLEMENT_DYNAMIC(CFLDialogTest, CDialog)

CFLDialogTest::CFLDialogTest(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_DIALOG1, pParent)
{

}

CFLDialogTest::~CFLDialogTest()
{
}

void CFLDialogTest::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CFLDialogTest, CDialog)
END_MESSAGE_MAP()


// CFLDialogTest 메시지 처리기
