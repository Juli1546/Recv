#pragma once
#include <string>
#include <vector>
#include "winsock2.h"
#pragma comment(lib,"ws2_32.lib")

//��������С
#define BUFFER_SIZE			4096

/* �ײ㴦��ص�����
*sok		�ͻ���SOCKET
* IP			�ͻ���IP
* nport	�ͻ��˶˿�
* pUser	�ͻ��˴����������ָ��
* Buf		���ݻ�����
* BufLen ���ݻ���������

* ���� 1	�ײ㽫�ὫBuf�е����ݷ��͵��ͻ��ˣ�����IOCP��Ϊ����״̬��//ע�� : Buf�л�������ݲ��ó��� BufLen��С  //���������ر�
* ���� 2	�ײ㽫�ὫBuf��0������IOCP��Ϊ����״̬��																												//�����������ر�
* ���� 3	�ײ㽫Buf�е����ݷ��͵��ͻ��ˣ����رտͻ���SOCKET ���� IO�ص��ṹ																	//�������ر�
* ���� 4	�ײ�ֱ�ӹرտͻ���socket������IO�ص��ṹ																												//���������ر�	
*/
typedef  int (CALLBACK* LPDONE)( SOCKET sok, char * IP, int nPort, void * pUser ,  char FAR * Buf,u_long * BufLen); 



//IO�ص��ṹ
typedef struct _PER_IO_OPERATION_DATA
{
	//�ص��ṹ
	OVERLAPPED	OverLapped;
	//���ݻ�����
	WSABUF				DataBuf;
	char						Bufdata[BUFFER_SIZE];
	DWORD				NumberOfBytesRecvd;
	DWORD				 Flags;
	//�������ͱ�ʾ
	bool					OperType;  //true:RECV    false:SEND
	bool					IOdel;	//������ǣ���ǲ�����ɡ����յ��������� ɾ��IO�ṹ��
	bool					soccls;//������Ǿͣ����ͨѶ��ɣ����յ���رո�·socket��
	bool					Y2Z;//ת�����	true�� ��������Դ���ݷ���ת���ˣ�false��ת���˷���Դ��
}PER_IO_OPERATION_DATA,*PPER_IO_OPERATION_DATA;


//�ͻ�����Ϣ
struct ClientInfo 
{
    SOCKET  Socket;						//ԴSOCKET
    CHAR		ClientIP[16];              //Դ IP 
    int			nPort;							//Դ�˿�


	SOCKET  DES_Socket;						//ת��SOCKET
    CHAR		DES_ClientIP[16];              //ת�� IP 
    int			DES_nPort;							//ת���˿�

	bool		DESenable;						//Ŀ������Ƿ�׼����
};

class GSocket
{
private:
	std::string					m_sServiceIP;			//����IP  �������ļ�ȡ�ñ���IP����ֹ����������IPѡ���ͻ
	u_short						m_nPort;					//�����˿�
	SOCKET						m_Socket;					//�����SOCKET
	HANDLE						m_CompletionPort;//��ɶ˿�
	
	
	LPDONE						m_callbackDone;     //���ݴ���ص�����
	void *							m_Puser;					//���͸��ص�������������ָ��


	std::vector<HANDLE>	m_nThreadHandle;
public:
	int								Init(std::string IP,int port/*,void * Pcallback,void * puser*/);
	int								Run();
	int								Stop();
	bool								Send(SOCKET ClientSocket,char * buf,int nLen);

	void							AddThread();
	static DWORD  WINAPI	WorkerThread(LPVOID lParam);//�̺߳���
	void							Worker();//�������������̺߳�������


public:
	GSocket();
	~GSocket(void);
};
