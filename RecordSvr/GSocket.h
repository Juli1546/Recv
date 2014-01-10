#pragma once
#include <string>
#include <vector>
#include "winsock2.h"
#pragma comment(lib,"ws2_32.lib")

//缓冲区大小
#define BUFFER_SIZE			4096

/* 底层处理回调函数
*sok		客户端SOCKET
* IP			客户端IP
* nport	客户端端口
* pUser	客户端传入的上下文指针
* Buf		数据缓冲区
* BufLen 数据缓冲区长度

* 返回 1	底层将会将Buf中的数据发送到客户端，并将IOCP置为接收状态。//注意 : Buf中缓冲的数据不得超过 BufLen大小  //发出，不关闭
* 返回 2	底层将会将Buf置0，并将IOCP置为接收状态。																												//不发出，不关闭
* 返回 3	底层将Buf中的数据发送到客户端，并关闭客户端SOCKET 清理 IO重叠结构																	//发出，关闭
* 返回 4	底层直接关闭客户端socket并清理IO重叠结构																												//不发出，关闭	
*/
typedef  int (CALLBACK* LPDONE)( SOCKET sok, char * IP, int nPort, void * pUser ,  char FAR * Buf,u_long * BufLen); 



//IO重叠结构
typedef struct _PER_IO_OPERATION_DATA
{
	//重叠结构
	OVERLAPPED	OverLapped;
	//数据缓冲区
	WSABUF				DataBuf;
	char						Bufdata[BUFFER_SIZE];
	DWORD				NumberOfBytesRecvd;
	DWORD				 Flags;
	//操作类型表示
	bool					OperType;  //true:RECV    false:SEND
	bool					IOdel;	//操作标记，标记操作完成。在收到完成命令后 删除IO结构。
	bool					soccls;//操作标记就，标记通讯完成，在收到后关闭该路socket；
	bool					Y2Z;//转发标记	true： 把数据由源数据发给转发端，false：转发端发给源端
}PER_IO_OPERATION_DATA,*PPER_IO_OPERATION_DATA;


//客户端信息
struct ClientInfo 
{
    SOCKET  Socket;						//源SOCKET
    CHAR		ClientIP[16];              //源 IP 
    int			nPort;							//源端口


	SOCKET  DES_Socket;						//转发SOCKET
    CHAR		DES_ClientIP[16];              //转发 IP 
    int			DES_nPort;							//转发端口

	bool		DESenable;						//目标服务是否准备好
};

class GSocket
{
private:
	std::string					m_sServiceIP;			//本机IP  从配置文件取得本机IP，防止多个网卡造成IP选择冲突
	u_short						m_nPort;					//监听端口
	SOCKET						m_Socket;					//服务端SOCKET
	HANDLE						m_CompletionPort;//完成端口
	
	
	LPDONE						m_callbackDone;     //数据处理回调函数
	void *							m_Puser;					//传送给回调函数的上下文指针


	std::vector<HANDLE>	m_nThreadHandle;
public:
	int								Init(std::string IP,int port/*,void * Pcallback,void * puser*/);
	int								Run();
	int								Stop();
	bool								Send(SOCKET ClientSocket,char * buf,int nLen);

	void							AddThread();
	static DWORD  WINAPI	WorkerThread(LPVOID lParam);//线程函数
	void							Worker();//工作函数，由线程函数启动


public:
	GSocket();
	~GSocket(void);
};
