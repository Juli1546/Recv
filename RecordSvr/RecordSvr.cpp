// RecordSvr.cpp : �������̨Ӧ�ó������ڵ㡣
//


#include "stdafx.h"
#include "GSocket.h"


int _tmain(int argc, _TCHAR* argv[])
{
	GSocket  kk;
	kk.Init("192.168.218.112",1556);
	kk.Run();
	return 0;
}

