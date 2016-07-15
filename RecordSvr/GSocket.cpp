#include "StdAfx.h"
#include "GSocket.h"
#define ERR_MSG_LEN 64
int gClientNUM = 0;



void Log(std::string strMsg)
{

	printf("%s",strMsg.c_str());

	OutputDebugString(strMsg.c_str());
	char str[128]= {0};
	DWORD dwWrite=0;
	SYSTEMTIME curTime;
	GetLocalTime(&curTime);

	HANDLE hFile = ::CreateFile("E:\\IOCP.log", GENERIC_WRITE|GENERIC_READ,FILE_SHARE_WRITE|FILE_SHARE_READ,
		NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		return;
	::SetFilePointer(hFile,0,0,FILE_END);

	std::string strTime;// = strMsg;

	sprintf_s(str,"[%04d%02d%02d %02d:%02d:%02d]  ",curTime.wYear,curTime.wMonth,curTime.wDay,
		curTime.wHour,curTime.wMinute,curTime.wSecond);

	strTime += str;
	strTime += strMsg;

	::WriteFile(hFile,strTime.c_str(),(DWORD)strTime.length(),&dwWrite,NULL);
	::CloseHandle(hFile);
}



GSocket::GSocket()
{
	m_CompletionPort = INVALID_HANDLE_VALUE;
	m_Socket = INVALID_SOCKET;
	SYSTEM_INFO             systeminfo;
	GetSystemInfo(&systeminfo);
}

GSocket::~GSocket(void)
{

	if(m_CompletionPort != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_CompletionPort);
	}
	if(m_Socket != INVALID_SOCKET)
	{
		closesocket(m_Socket);
	}
}
int GSocket::Init(std::string IP,int port/*,void * Pcallback,void * puser*/)
{
	m_sServiceIP = IP;
	m_nPort = port;
	//m_callbackDone =(LPDONE)Pcallback;
	//m_Puser = puser;
	return 0;
}
int GSocket::Run()
{
	int nRet = 0;
	char sErrorMsg[ERR_MSG_LEN]={0};
	WSADATA     wsaData;
	nRet = WSAStartup(0x0202, &wsaData);
	if(nRet!=0)
	{
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSAStartup Error ID = %d\r\n",nRet);
		Log(sErrorMsg);
		Sleep(1000*3);
		exit(-1) ; //WSAStartup 失败
	}
	m_CompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if(m_CompletionPort == INVALID_HANDLE_VALUE)
	{
		nRet = GetLastError();
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"CreateIoCompletionPort Error ID = %d\r\n",nRet);
		Log(sErrorMsg);
		Sleep(1000*3);
		return -1 ; //创建完成端口失败
	}

	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);

	//Log("|->");
	for(DWORD i =0; i<sysinfo.dwNumberOfProcessors*2;i++)
	{
		AddThread();
	}
	//Log("<-|\r\n");


	m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	//设置为TCP\IP协议
	if(m_Socket == INVALID_SOCKET)
	{
		nRet = GetLastError();
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"Create Socket  Error ID = %d\r\n",nRet);
		Log(sErrorMsg);
		Sleep(1000*3);
		return -2;//创建Socket失败
	}


	//取得本机IP地址
	PHOSTENT hostinfo; 
	char name[155];
	std::string sHostIP;
	if( gethostname ( name, sizeof(name)) == 0) 
	{ 
		if((hostinfo = gethostbyname(name)) != NULL) 
		{ 
			sHostIP = inet_ntoa (*(struct in_addr *)*hostinfo->h_addr_list);
		}
	}

	//默认为主机地址 双网卡时一定要传入地址 否则会取第一块地址
	if(m_sServiceIP.size() == 0)
	{
		m_sServiceIP = sHostIP;
	}

	SOCKADDR_IN            Addr;	
	Addr.sin_family = AF_INET;
	Addr.sin_addr.S_un.S_addr = inet_addr(m_sServiceIP.c_str());
	Addr.sin_port = htons(m_nPort);

	nRet = bind(m_Socket, (struct sockaddr *)&Addr, sizeof(SOCKADDR_IN));
	if(SOCKET_ERROR == nRet )
	{
		nRet = GetLastError();
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"bind Socket  Error ID = %d\r\n",nRet);
		Log(sErrorMsg);
		Sleep(1000*3);
		return -3;//bind失败
	}

	int nRecvBuf = 512*1024;
	setsockopt(m_Socket, SOL_SOCKET, SO_SNDBUF, (const char * )&nRecvBuf, sizeof(int));

	nRet = listen(m_Socket,SOMAXCONN);

#ifdef _DEBUG
	SYSTEMTIME curTime;
	GetLocalTime(&curTime);
	char str[32]={0};
	sprintf_s(str,"[%04d-%02d-%02d %02d:%02d:%02d]",curTime.wYear,curTime.wMonth,curTime.wDay,
		curTime.wHour,curTime.wMinute,curTime.wSecond);
	printf("*---------------------*\r\n");
	printf("****服务器创建成功*****\r\n");
	printf("*%s*\r\n",str);
	printf("*---------------------*\r\n");
#endif

	while(true)
	{
		SOCKADDR_IN            ClientAddr;	
		int			AddrSize = sizeof(SOCKADDR_IN);
		SOCKET Clientsocket = accept(m_Socket,(struct sockaddr *)&ClientAddr,&AddrSize);	//ACCEPT
		if(Clientsocket==INVALID_SOCKET)
		{
			if(m_Socket == INVALID_SOCKET)
			{
				Log("服务器端口关闭\r\n");
				break;
			}
			nRet = GetLastError();
			memset(sErrorMsg,0,ERR_MSG_LEN);
			sprintf_s(sErrorMsg,ERR_MSG_LEN,"Accept Socket  Error ID = %d\r\n",nRet);
			Log(sErrorMsg);
			continue;
		}
		++gClientNUM;
		printf("%dNew Client %s:%d\r\n",gClientNUM,inet_ntoa(ClientAddr.sin_addr), ntohs(ClientAddr.sin_port));

		//**//1
		SOCKET      sClient;
		SOCKADDR_IN server;
		sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		memset(&server, 0, sizeof(SOCKADDR_IN));
		server.sin_family = AF_INET;
		server.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
		server.sin_port = htons(37777);
		int  conbret =  connect(sClient, (struct sockaddr *)&server, sizeof(SOCKADDR_IN));
		if(conbret == -1)
		{
			closesocket(sClient);
			continue ; 
		}
		//**


		ClientInfo * pInfo = new ClientInfo();
		strcpy_s(pInfo->ClientIP,16,inet_ntoa(ClientAddr.sin_addr));
		pInfo->nPort = ntohs(ClientAddr.sin_port);
		pInfo->Socket = Clientsocket;

		//**//1
		strcpy_s(pInfo->DES_ClientIP,16,"15.113.222.195");
		pInfo->DES_nPort = 37777;
		pInfo->DES_Socket = sClient;
		pInfo->DESenable = false;

		if(( CreateIoCompletionPort((HANDLE)sClient, m_CompletionPort,(ULONG_PTR) pInfo, 0)==NULL)) //BIND IOCP
		{ 
			nRet = GetLastError();
			memset(sErrorMsg,0,ERR_MSG_LEN);
			sprintf_s(sErrorMsg,ERR_MSG_LEN," CreateIoCompletionPort(Bind) Error ID = %d\r\n",nRet);
			Log(sErrorMsg);
			delete pInfo;
			continue ;
		}
		//**



		if(( CreateIoCompletionPort((HANDLE)Clientsocket, m_CompletionPort,(ULONG_PTR) pInfo, 0)==NULL)) //BIND IOCP
		{ 
			nRet = GetLastError();
			memset(sErrorMsg,0,ERR_MSG_LEN);
			sprintf_s(sErrorMsg,ERR_MSG_LEN," CreateIoCompletionPort(Bind) Error ID = %d\r\n",nRet);
			Log(sErrorMsg);
			delete pInfo;
			continue ;
		}
		PPER_IO_OPERATION_DATA  IoData = (PPER_IO_OPERATION_DATA)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(PER_IO_OPERATION_DATA));//申请不可动内存
		if(!IoData)
		{
			nRet = GetLastError();
			memset(sErrorMsg,0,ERR_MSG_LEN);
			sprintf_s(sErrorMsg,ERR_MSG_LEN," New IODATA Error ID = %d\r\n",nRet);
			Log(sErrorMsg);
			HeapFree(GetProcessHeap(),0,IoData);
			delete pInfo;
			continue ;
		}

		memset(&IoData->OverLapped,0,sizeof(OVERLAPPED));
		memset(IoData->Bufdata,0,BUFFER_SIZE);
		IoData->DataBuf.buf = IoData->Bufdata;
		IoData->DataBuf.len = BUFFER_SIZE;
		IoData->NumberOfBytesRecvd = 0;
		IoData->Flags = 0;
		IoData->OperType = true; // RECV
		IoData->IOdel = false;
		IoData->soccls = false;
		IoData->Y2Z = true;

		nRet = WSARecv(Clientsocket,
			&IoData->DataBuf,
			1,
			&IoData->NumberOfBytesRecvd,
			&IoData->Flags,
			&IoData->OverLapped,
			NULL);
		if(nRet)
		{
			nRet = GetLastError();
			if(nRet == ERROR_IO_PENDING)
			{
			}
			else
			{
			if(nRet == 10054||nRet == 10053)
			{
				if(pInfo)
				{
					if(closesocket(pInfo->Socket)==SOCKET_ERROR)
					{
						Log("Close Socket Error! \r\n");
					}
					if(closesocket(pInfo->DES_Socket)==SOCKET_ERROR)
					{
						Log("Close Socket Error2! \r\n");
					}
					delete pInfo;
					pInfo = NULL;
				}
				if(IoData)
				{
					HeapFree(GetProcessHeap(),0,IoData);
					IoData = NULL;
				}
			}
			memset(sErrorMsg,0,ERR_MSG_LEN);
			sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSARecv Error ID = %d\r\n",nRet);
			Log(sErrorMsg);
			continue;
			}
		}
		//**/1
		PPER_IO_OPERATION_DATA  sIoData = (PPER_IO_OPERATION_DATA)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(PER_IO_OPERATION_DATA));//申请不可动内存
		if(!sIoData)
		{
			nRet = GetLastError();
			memset(sErrorMsg,0,ERR_MSG_LEN);
			sprintf_s(sErrorMsg,ERR_MSG_LEN," New IODATA Error ID = %d\r\n",nRet);
			Log(sErrorMsg);
			HeapFree(GetProcessHeap(),0,sIoData);
			delete pInfo;
			continue ;
		}

		memset(&sIoData->OverLapped,0,sizeof(OVERLAPPED));
		memset(sIoData->Bufdata,0,BUFFER_SIZE);
		sIoData->DataBuf.buf = sIoData->Bufdata;
		sIoData->DataBuf.len = BUFFER_SIZE;
		sIoData->NumberOfBytesRecvd = 0;
		sIoData->Flags = 0;
		sIoData->OperType = true; // RECV
		sIoData->IOdel = false;
		sIoData->soccls = false;
		sIoData->Y2Z = false;

		nRet = WSARecv(sClient,
			&sIoData->DataBuf,
			1,
			&sIoData->NumberOfBytesRecvd,
			&sIoData->Flags,
			&sIoData->OverLapped,
			NULL);
		if(nRet)
		{
			nRet = GetLastError();
			if(nRet == ERROR_IO_PENDING) continue;
			if(nRet == 10054||nRet == 10053)
			{
				if(pInfo)
				{
					if(closesocket(pInfo->Socket)==SOCKET_ERROR)
					{
						Log("Close Socket Error! \r\n");
					}
					if(closesocket(pInfo->DES_Socket)==SOCKET_ERROR)
					{
						Log("Close Socket Error2! \r\n");
					}
					delete pInfo;
					pInfo = NULL;
				}
				if(sIoData)
				{
					HeapFree(GetProcessHeap(),0,sIoData);
					sIoData = NULL;
				}
			}
			memset(sErrorMsg,0,ERR_MSG_LEN);
			sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSARecv Error ID = %d\r\n",nRet);
			Log(sErrorMsg);
			continue;
		}
		//***

	}
	return 0;
}
int GSocket::Stop()
{
	int nRet = 0;
	char sErrorMsg[ERR_MSG_LEN]={0};


	BOOL bCloseIoComp = PostQueuedCompletionStatus(m_CompletionPort,0xFFFFFFFF, 0, NULL);
	if(!bCloseIoComp)
	{
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSACleanup Error ");
		Log(sErrorMsg);
	}
	BOOL bChd = CloseHandle(m_CompletionPort);
	if(!bChd)
	{
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"Close IOCP Error ");
		Log(sErrorMsg);
	}
	m_CompletionPort = INVALID_HANDLE_VALUE;
	nRet = closesocket(m_Socket);
	if(nRet==SOCKET_ERROR)
	{
		nRet = GetLastError();
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"closesocket Error ID = %d\r\n",nRet);
		printf(sErrorMsg);
		Log(sErrorMsg);
	}
	m_Socket = INVALID_SOCKET;
	nRet = WSACleanup();
	if(nRet!=0)
	{
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSACleanup Error ID = %d\r\n",nRet);
		Log(sErrorMsg);
	}

	return 0;
}

bool GSocket::Send(SOCKET ClientSocket,char * buf,int nLen)
{ // 会降低效率，新申请了内存 并于收到完成状态后删除。


	if(nLen>BUFFER_SIZE)
	{
		Log("超过缓冲区大小，发送失败！\r\n");
	}
	int nRet = 0;
	char sErrorMsg[ERR_MSG_LEN]={0};
	PPER_IO_OPERATION_DATA  IoData = (PPER_IO_OPERATION_DATA)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(PER_IO_OPERATION_DATA));//申请不可动内存
	if(!IoData)
	{
		nRet = GetLastError();
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN," New IODATA Error ID = %d\r\n",nRet);
		Log(sErrorMsg);
		HeapFree(GetProcessHeap(),0,IoData);
		return false ; // 发送失败
	}

	memset(&IoData->OverLapped,0,sizeof(OVERLAPPED));
	memset(IoData->Bufdata,0,BUFFER_SIZE);

	memcpy(IoData->Bufdata,buf,nLen); //拷贝要发送的内容

	IoData->DataBuf.buf = IoData->Bufdata;
	IoData->DataBuf.len = nLen;
	IoData->NumberOfBytesRecvd = 0;
	IoData->Flags = 0;
	IoData->OperType = false; // RECV
	IoData->IOdel = true; //接收到时删除
	IoData->soccls = false;
	nRet = WSASend(ClientSocket,
		&IoData->DataBuf,
		1,
		&IoData->NumberOfBytesRecvd,
		IoData->Flags,
		&IoData->OverLapped,
		NULL);
	if(nRet)
	{
		nRet = GetLastError();
		if(nRet == ERROR_IO_PENDING) return true;
		if(nRet == 10054||nRet == 10053)
		{

			closesocket(ClientSocket);
			if(IoData)
			{
				HeapFree(GetProcessHeap(),0,IoData);
				IoData = NULL;
			}
		}
		memset(sErrorMsg,0,ERR_MSG_LEN);
		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSASend Error ID = %d\r\n",nRet);
		Log(sErrorMsg);
		return false;
	}
	return true;
}

DWORD WINAPI GSocket :: WorkerThread(LPVOID lParam)
{
	GSocket * pGsocket = (GSocket*)lParam;
	pGsocket->Worker();
	return 0;
}

void GSocket::AddThread()
{
	HANDLE ThreadHandle = NULL;
	ThreadHandle = CreateThread(NULL, 0, WorkerThread, this, 0, NULL);
	if(ThreadHandle)
	{
		//Log("+");
		m_nThreadHandle.push_back(ThreadHandle);
	}
	else
	{
		//Log("-");
	}
}


void GSocket::Worker()
{
	DWORD												dwBytesTransferred = 0;
	ClientInfo   *										pCInfo = NULL;//客户端信息
	PPER_IO_OPERATION_DATA			IOData = NULL;	//重叠数据
	int														nRet = 0;
	char sErrorMsg[ERR_MSG_LEN]={0};
	while(true)
	{//while


		nRet =  GetQueuedCompletionStatus(m_CompletionPort,&dwBytesTransferred,(PULONG_PTR)&pCInfo,(LPOVERLAPPED *)&IOData,INFINITE);
		if (dwBytesTransferred == 0xFFFFFFFF)
		{//收到完成端口退出消息，退出完成端口 结束线程。
			return ;
		}// if  end

		if(nRet == 0 || dwBytesTransferred == 0)
		{//收到错误信息 关闭当前连接 释放空间。

			nRet = GetLastError();

			if(pCInfo)
			{
				if(closesocket(pCInfo->Socket)==SOCKET_ERROR)
				{
					memset(sErrorMsg,0,ERR_MSG_LEN);
					sprintf_s(sErrorMsg,ERR_MSG_LEN,"ThreadClose Socket Error! ID = %d\r\n",nRet);
					Log(sErrorMsg);
					continue ;

				}
				if(closesocket(pCInfo->DES_Socket)==SOCKET_ERROR)
				{
					memset(sErrorMsg,0,ERR_MSG_LEN);
					sprintf_s(sErrorMsg,ERR_MSG_LEN,"ThreadClose Socket Error! ID = %d\r\n",nRet);
					Log(sErrorMsg);
					continue;
				}
				delete pCInfo;
				pCInfo = NULL;
			}
			if(IOData)
			{
				HeapFree(GetProcessHeap(),0,IOData);
				IOData = NULL;
			}

			continue;
		} // if  end

		if(dwBytesTransferred>=BUFFER_SIZE)
		{
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!-%d\r\n",dwBytesTransferred);
		}

		//**
		if(IOData->OperType)
		{// if 1 
			////接收完成 ，处理接收到的数据 
			//int ret =  m_callbackDone(pCInfo->Socket,pCInfo->ClientIP,pCInfo->nPort,m_Puser,IOData->Bufdata,(u_long *)(&IOData->DataBuf.len));	 // 回调给上层函数处理
			//if(IOData->DataBuf.len>BUFFER_SIZE)
			//{
			//	Log("警告：线程中 超过缓冲区大小，发送失败！\r\n");
			//	ret = 2; // 内容超过缓冲区大小，不发送，并置为接收状态。
			//}
			//if(ret == 1)
			//{ //if 2
			//	//返回为1，将缓冲数据发给客户端
			//	IOData->OperType = false; //将IO结构设置为 SEND
			//	nRet = WSASend(pCInfo->Socket,
			//		&IOData->DataBuf,
			//		1,
			//		&IOData->NumberOfBytesRecvd,
			//		IOData->Flags,
			//		&IOData->OverLapped,
			//		NULL);
			//	if(nRet==SOCKET_ERROR)
			//	{
			//		nRet = GetLastError();
			//		if(nRet == ERROR_IO_PENDING) continue;
			//		if(nRet == 10054||nRet == 10053)
			//		{
			//			if(pCInfo)
			//			{
			//				if(closesocket(pCInfo->Socket)==SOCKET_ERROR)
			//				{
			//					Log("ThreadClose Socket Error! \r\n");
			//				}
			//				delete pCInfo;
			//				pCInfo = NULL;
			//			}
			//			if(IOData)
			//			{
			//				HeapFree(GetProcessHeap(),0,IOData);
			//				IOData = NULL;
			//			}
			//		}
			//		memset(sErrorMsg,0,ERR_MSG_LEN);
			//		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSARecv Error ID = %d\r\n",nRet);
			//		printf(sErrorMsg);
			//		Log(sErrorMsg);
			//		continue;
			//	}
			//}//if 2 end
			//else if(ret == 2)
			//{//else 2
			//	//返回为2，重新设置IOCP为接收状态 
			//	memset(&IOData->OverLapped,0,sizeof(OVERLAPPED));
			//	memset(IOData->Bufdata,0,BUFFER_SIZE);
			//	IOData->DataBuf.buf = IOData->Bufdata;
			//	IOData->DataBuf.len = BUFFER_SIZE;
			//	IOData->NumberOfBytesRecvd = 0;
			//	IOData->Flags = 0;
			//	IOData->OperType = true; // RECV
			//	IOData->IOdel = false;
			//	IOData->soccls = false;
			//	DWORD Flags = 0;
			//	DWORD RecvBytes = 0;
			//	nRet = WSARecv(pCInfo->Socket,
			//		&IOData->DataBuf,
			//		1,
			//		&IOData->NumberOfBytesRecvd,
			//		&IOData->Flags,
			//		&IOData->OverLapped,
			//		NULL);
			//	if(nRet==SOCKET_ERROR)
			//	{
			//		nRet = GetLastError();
			//		if(nRet == ERROR_IO_PENDING) continue;
			//		if(nRet == 10054||nRet == 10053)
			//		{
			//			if(pCInfo)
			//			{
			//				if(closesocket(pCInfo->Socket)==SOCKET_ERROR)
			//				{
			//					Log("ThreadClose Socket Error! \r\n");
			//				}
			//				delete pCInfo;
			//				pCInfo = NULL;
			//			}
			//			if(IOData)
			//			{
			//				HeapFree(GetProcessHeap(),0,IOData);
			//				IOData = NULL;
			//			}
			//		}
			//		memset(sErrorMsg,0,ERR_MSG_LEN);
			//		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSARecv Error ID = %d\r\n",nRet);
			//		printf(sErrorMsg);
			//		Log(sErrorMsg);
			//		continue;
			//	}
			//}//else 2 end
			//else if(ret == 3)
			//{//else 3
			//	IOData->OperType = false; //将IO结构设置为 SEND
			//	IOData->IOdel = true; //将发送标志 设置为完成
			//	IOData->soccls = true;//将socket关闭
			//	nRet = WSASend(pCInfo->Socket,
			//		&IOData->DataBuf,
			//		1,
			//		&IOData->NumberOfBytesRecvd,
			//		IOData->Flags,
			//		&IOData->OverLapped,
			//		NULL);
			//	if(nRet==SOCKET_ERROR)
			//	{
			//		nRet = GetLastError();
			//		if(nRet == ERROR_IO_PENDING) continue;
			//		if(nRet == 10054||nRet == 10053)
			//		{
			//			if(pCInfo)
			//			{
			//				if(closesocket(pCInfo->Socket)==SOCKET_ERROR)
			//				{
			//					Log("ThreadClose Socket Error! \r\n");
			//				}
			//				delete pCInfo;
			//				pCInfo = NULL;
			//			}
			//			if(IOData)
			//			{
			//				HeapFree(GetProcessHeap(),0,IOData);
			//				IOData = NULL;
			//			}
			//		}
			//		memset(sErrorMsg,0,ERR_MSG_LEN);
			//		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSARecv Error ID = %d\r\n",nRet);
			//		printf(sErrorMsg);
			//		Log(sErrorMsg);
			//		continue;
			//	}
			//}//else 3 end
			//else if(ret == 4)
			//{//else 4
			//	//收到4 关闭 socket 清理IO结构
			//	if(pCInfo)
			//	{
			//		if(closesocket(pCInfo->Socket)==SOCKET_ERROR)
			//		{
			//			Log("ThreadClose Socket Error! \r\n");
			//		}
			//		delete pCInfo;
			//		pCInfo = NULL;
			//	}
			//	if(IOData)
			//	{
			//		HeapFree(GetProcessHeap(),0,IOData);
			//		IOData = NULL;
			//	}

			//	continue;
			//}//else 4 end
			//else
			//{
			//	Log("回调函数返回非法值 ! \r\n");
			//}
			if(IOData->Y2Z)
			{//Y2Z = true  源端发往转发端
				IOData->OperType = false; //SEND
				IOData->DataBuf.len = dwBytesTransferred;
				nRet = WSASend(pCInfo->DES_Socket,
					&IOData->DataBuf,
					1,
					&IOData->NumberOfBytesRecvd,
					IOData->Flags,
					&IOData->OverLapped,
					NULL);
				printf("Send Y2Z %d\r\n",IOData->NumberOfBytesRecvd);
				if(nRet)
				{
					nRet = GetLastError();
					if(nRet == ERROR_IO_PENDING) continue;
					if(nRet == 10054||nRet == 10053)
					{

						closesocket(pCInfo->Socket);
						closesocket(pCInfo->DES_Socket);
						if(IOData)
						{
							HeapFree(GetProcessHeap(),0,IOData);
							IOData = NULL;
						}
					}
					memset(sErrorMsg,0,ERR_MSG_LEN);
					sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSASend Error ID = %d\r\n",nRet);
					Log(sErrorMsg);
					continue;
				}
				//////////////////////
				//if(!pCInfo->DESenable)
				//{
				//	//**/1
				//	PPER_IO_OPERATION_DATA  sIoData = (PPER_IO_OPERATION_DATA)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(PER_IO_OPERATION_DATA));//申请不可动内存
				//	if(!sIoData)
				//	{
				//		nRet = GetLastError();
				//		memset(sErrorMsg,0,ERR_MSG_LEN);
				//		sprintf_s(sErrorMsg,ERR_MSG_LEN," New IODATA Error ID = %d\r\n",nRet);
				//		Log(sErrorMsg);
				//		HeapFree(GetProcessHeap(),0,sIoData);
				//		continue ;
				//	}

				//	memset(&sIoData->OverLapped,0,sizeof(OVERLAPPED));
				//	memset(sIoData->Bufdata,0,BUFFER_SIZE);
				//	sIoData->DataBuf.buf = sIoData->Bufdata;
				//	sIoData->DataBuf.len = BUFFER_SIZE;
				//	sIoData->NumberOfBytesRecvd = 0;
				//	sIoData->Flags = 0;
				//	sIoData->OperType = true; // RECV
				//	sIoData->IOdel = false;
				//	sIoData->soccls = false;
				//	sIoData->Y2Z = false;

				//	nRet = WSARecv(pCInfo->DES_Socket,
				//		&sIoData->DataBuf,
				//		1,
				//		&sIoData->NumberOfBytesRecvd,
				//		&sIoData->Flags,
				//		&sIoData->OverLapped,
				//		NULL);
				//	if(nRet)
				//	{
				//		nRet = GetLastError();
				//		if(nRet == ERROR_IO_PENDING) continue;
				//		if(nRet == 10054||nRet == 10053)
				//		{
				//			if(pCInfo)
				//			{
				//				if(closesocket(pCInfo->DES_Socket)==SOCKET_ERROR)
				//				{
				//					Log("Close Socket Error! \r\n");
				//				}
				//				if(closesocket(pCInfo->Socket)==SOCKET_ERROR)
				//				{
				//					Log("Close Socket Error2! \r\n");
				//				}
				//				delete pCInfo;
				//				pCInfo = NULL;
				//			}
				//			if(sIoData)
				//			{
				//				HeapFree(GetProcessHeap(),0,sIoData);
				//				sIoData = NULL;
				//			}
				//		}
				//		memset(sErrorMsg,0,ERR_MSG_LEN);
				//		sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSARecv Error ID = %d\r\n",nRet);
				//		Log(sErrorMsg);
				//		continue;
				//	}
				//	//***
				//	pCInfo->DESenable = true;

				//}
				//////////////////////////

			}
			else
			{//Y2Z = flase  转发端发往源端
				IOData->OperType = false; //SEND
				IOData->DataBuf.len = dwBytesTransferred;
				nRet = WSASend(pCInfo->Socket,
					&IOData->DataBuf,
					1,
					&IOData->NumberOfBytesRecvd,
					IOData->Flags,
					&IOData->OverLapped,
					NULL);
				printf("Send Z2Y %d\r\n",IOData->NumberOfBytesRecvd);
				if(nRet)
				{
					nRet = GetLastError();
					if(nRet == ERROR_IO_PENDING) continue;
					if(nRet == 10054||nRet == 10053)
					{

						closesocket(pCInfo->Socket);
						closesocket(pCInfo->DES_Socket);
						if(IOData)
						{
							HeapFree(GetProcessHeap(),0,IOData);
							IOData = NULL;
						}
					}
					memset(sErrorMsg,0,ERR_MSG_LEN);
					sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSASend Error ID = %d\r\n",nRet);
					Log(sErrorMsg);
					continue;
				}
			}

		}// if 1 end
		else
		{//else 1
			//发送完成 ， 重新设置IOCP为接收状态 
			if(IOData->IOdel)
			{//接收到完成状态，删除该重叠结构

				if(IOData->soccls)
				{//socket关闭指示为真，关闭该SOCKET
					closesocket(pCInfo->Socket);
					delete pCInfo;
					pCInfo = NULL;

					printf("close Soket!\r\n");
				}

				HeapFree(GetProcessHeap(),0,IOData);
				IOData = NULL;
				continue;
			}


			memset(&IOData->OverLapped,0,sizeof(OVERLAPPED));
			memset(IOData->Bufdata,0,BUFFER_SIZE);
			IOData->DataBuf.buf = IOData->Bufdata;
			IOData->DataBuf.len = BUFFER_SIZE;
			IOData->NumberOfBytesRecvd = 0;
			IOData->Flags = 0;
			IOData->OperType = true; // RECV
			IOData->IOdel = false;
			IOData->soccls = false;

			DWORD Flags = 0;
			DWORD RecvBytes = 0;

			if(IOData->Y2Z)
			{
				nRet = WSARecv(pCInfo->Socket,
					&IOData->DataBuf,
					1,
					&IOData->NumberOfBytesRecvd,
					&IOData->Flags,
					&IOData->OverLapped,
					NULL);
			}
			else
			{
				nRet = WSARecv(pCInfo->DES_Socket,
					&IOData->DataBuf,
					1,
					&IOData->NumberOfBytesRecvd,
					&IOData->Flags,
					&IOData->OverLapped,
					NULL);
			}


			if(nRet)
			{
				nRet = GetLastError();
				if(nRet == ERROR_IO_PENDING) continue;
				if(nRet == 10054||nRet == 10053)
				{
					if(pCInfo)
					{
						if(closesocket(pCInfo->Socket)==SOCKET_ERROR)
						{
							Log("ThreadClose Socket Error! \r\n");
						}
						if(closesocket(pCInfo->DES_Socket)==SOCKET_ERROR)
						{
							Log("ThreadClose Socket Error! \r\n");
						}
						delete pCInfo;
						pCInfo = NULL;
					}
					if(IOData)
					{
						HeapFree(GetProcessHeap(),0,IOData);
						IOData = NULL;
					}
				}
				memset(sErrorMsg,0,ERR_MSG_LEN);
				sprintf_s(sErrorMsg,ERR_MSG_LEN,"WSARecv Error ID = %d\r\n",nRet);
				printf(sErrorMsg);
				Log(sErrorMsg);
				continue;
			}
		}//else 1 end
		//**
	}//while end
}
