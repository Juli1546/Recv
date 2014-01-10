// RecordSvr.cpp : 定义控制台应用程序的入口点。
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

