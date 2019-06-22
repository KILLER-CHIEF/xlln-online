// xlln-online.cpp : Defines the exported functions for the DLL application.
//
#include <Winsock2.h>
#include "dllMain.h"
#include "xlln-online.h"
#include <thread>
#include <condition_variable>
#include <atomic>

// #41140
tXLLNLogin XLLNLogin;

// #41141
tXLLNLogout XLLNLogout;

// #41142
tXLLNModifyProperty XLLNModifyProperty;

// #41143
tXLLNDebugLog XLLNDebugLog;
BOOL xllnOnline_Initialised = FALSE;

bool XLLN_Online_Mode = true;
ULONG XLLN_Online_Mode_hIpv4 = INADDR_NONE;
ULONG XLLNOnline_Relay_hIpv4 = INADDR_NONE;
WORD XLLNOnline_Relay_hPort_Base = 2000;

// #24
typedef INT(WINAPI *tXSocketSendTo)(SOCKET s, const char *buf, int len, int flags, sockaddr *to, int tolen);
DWORD Import_XSocketSendTo = 0;
tXSocketSendTo XSocketSendTo = NULL;
static INT WINAPI XSocketSendToHook(SOCKET s, const char *buf, int len, int flags, sockaddr *to, int tolen)
{
	INT result = SOCKET_ERROR;

	WORD nPort = ((struct sockaddr_in*)to)->sin_port;
	WORD hPort = ntohs(nPort);
	ULONG nIpv4 = ((struct sockaddr_in*)to)->sin_addr.s_addr;
	ULONG hIpv4 = ntohl(nIpv4);
	WORD port_base = (hPort / 1000) * 1000;
	WORD port_offset = hPort % 1000;

	if ((hIpv4 == INADDR_BROADCAST || hIpv4 == INADDR_ANY) && XLLN_Online_Mode) {
		XLLNDebugLog(0, "XLLNOnline: XSocketSendTo() - Wrapped Broadcast.");

		const int cpHeaderLen = sizeof(XLLN_CUSTOM_PACKET_SENTINEL) + sizeof(XLLNCustomPacketType::Type);
		const int altBufLen = len + cpHeaderLen + sizeof(XNADDR);
		// Check overflow condition.
		if (altBufLen < 0) {
			WSASetLastError(WSAEMSGSIZE);
			return SOCKET_ERROR;
		}

		char *altBuf = (char*)malloc(sizeof(char) * altBufLen);

		altBuf[0] = XLLN_CUSTOM_PACKET_SENTINEL;
		altBuf[sizeof(XLLN_CUSTOM_PACKET_SENTINEL)] = XLLNCustomPacketType::STOCK_PACKET_FORWARDED;
		XNADDR &xnAddr = *(XNADDR*)&altBuf[sizeof(XLLN_CUSTOM_PACKET_SENTINEL) + sizeof(XLLNCustomPacketType::Type)];
		xnAddr.inaOnline.s_addr = 0x100;//FIXME
		memcpy_s(&altBuf[cpHeaderLen + sizeof(XNADDR)], altBufLen - cpHeaderLen - sizeof(XNADDR), buf, len);
		((struct sockaddr_in*)to)->sin_addr.s_addr = htonl(XLLNOnline_Relay_hIpv4);
		((struct sockaddr_in*)to)->sin_port = htons(XLLNOnline_Relay_hPort_Base + port_offset);
		result = sendto(s, altBuf, altBufLen, 0, to, tolen);

		free(altBuf);
	}
	else {
		result = XSocketSendTo(s, buf, len, flags, to, tolen);
	}
	return result;
}

static SOCKET XLLNOnline_socket_udp_rand = INVALID_SOCKET;

static CRITICAL_SECTION XLLNOnline_lock_customsocketlisten_thread;
static std::thread XLLNOnline_thread_customsocketlisten;
static BOOL XLLNOnline_customsocketlisten_running = FALSE;
static std::condition_variable XLLNOnline_cond_customsocketlisten;
static std::atomic<bool> XLLNOnline_customsocketlisten_exit = TRUE;
static std::atomic<bool> XLLNOnline_customsocketlisten_break_sleep = FALSE;

static VOID CustomSocketListen()
{
	std::mutex mutexPause;
	char buff[1024];
	sockaddr SenderAddr;
	int SenderAddrSize = sizeof(SenderAddr);

	char packetHeadToClient[4] = { XLLN_CUSTOM_PACKET_SENTINEL, XLLNCustomPacketType::CUSTOM_OTHER, 'X', 'O' };

	while (1) {
		//EnterCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);

		int result = 0;
		do {
			result = recvfrom(XLLNOnline_socket_udp_rand, buff, sizeof(buff), 0, &SenderAddr, &SenderAddrSize);
			if (result > 0) {
				if (result > sizeof(packetHeadToClient) && *(unsigned int*)buff == *(unsigned int*)&packetHeadToClient) {
					switch (buff[sizeof(packetHeadToClient)]) {
					case XLLNOnlineCustomPacketType::REQ_IPv4_REPLY: {
						XLLN_Online_Mode_hIpv4 = *(ULONG*)&buff[sizeof(packetHeadToClient) + 1];
						XLLNDebugLog(0, "XLLNOnline: Received XLLNOnline 02 response.");
						break;
					}
					default: {
						XLLNDebugLog(0, "XLLNOnline: Received UNKNOWN XLLNOnline packet.");
						continue;
					}
					}
				}
				else {
					XLLNDebugLog(0, "XLLNOnline: Received UNKNOWN Custom UDP 0 packet.");
				}
			}
		} while (result > 0);

		//LeaveCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);

		std::unique_lock<std::mutex> lock(mutexPause);
		XLLNOnline_cond_customsocketlisten.wait_for(lock, std::chrono::seconds(1), []() { return XLLNOnline_customsocketlisten_exit == TRUE || XLLNOnline_customsocketlisten_break_sleep == TRUE; });
		if (XLLNOnline_customsocketlisten_exit) {
			break;
		}
		XLLNOnline_customsocketlisten_break_sleep = FALSE;
	}

	shutdown(XLLNOnline_socket_udp_rand, SD_SEND);

	unsigned int retryNumber = 0;
	const unsigned int MAX_RETRY_NUMBER = 2 * 1000 / 10; // 10ms sleep from below. Wait no longer than 2 seconds.

	while (true) {
		int result = recv(XLLNOnline_socket_udp_rand, buff, sizeof(buff), 0);

		if (result == 0) {
			break;
			//return 0; // Client gracefully closed connection.
		}
		else if (result > 0) {
			break;
			//return -1; // Received unexpected data instead of socket closure
		}
		else
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK) {
				if (retryNumber++ == MAX_RETRY_NUMBER) {
					break;
					//return -1; // Client didn't close socket within specified time
				}

				Sleep(10); // wait 10ms
			}
			else {
				break;
				//return -1; // Unexpected error occured
			}
		}
	}

	closesocket(XLLNOnline_socket_udp_rand);
	XLLNOnline_socket_udp_rand = INVALID_SOCKET;
}

static VOID CustomSocketListenStart()
{
	EnterCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);

	if (XLLNOnline_customsocketlisten_running) {
		XLLNOnline_customsocketlisten_break_sleep = TRUE;
		XLLNOnline_cond_customsocketlisten.notify_all();
	}
	else {
		XLLNOnline_customsocketlisten_running = TRUE;
		XLLNOnline_customsocketlisten_exit = FALSE;
		XLLNOnline_thread_customsocketlisten = std::thread(CustomSocketListen);
	}

	LeaveCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);
}
static VOID CustomSocketListenStop()
{
	EnterCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);

	if (XLLNOnline_customsocketlisten_running) {
		XLLNOnline_customsocketlisten_running = FALSE;
		LeaveCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);
		if (XLLNOnline_customsocketlisten_exit == FALSE) {
			XLLNOnline_customsocketlisten_exit = TRUE;
			XLLNOnline_cond_customsocketlisten.notify_all();
			XLLNOnline_thread_customsocketlisten.join();
		}
	}
	else {
		LeaveCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);
	}
}

static void SendRequestOnlineIpv4Addr()
{
	if (XLLNOnline_socket_udp_rand == INVALID_SOCKET) {
		XLLNDebugLog(0, "XLLNOnline: ERROR: XLLNOnline_socket_udp_rand not initialised.");
		return;
	}
	if (XLLNOnline_Relay_hIpv4 == INADDR_NONE) {
		XLLNDebugLog(0, "XLLNOnline: ERROR: XLLNOnline_Relay_hIpv4 not initialised.");
		return;
	}

	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(XLLNOnline_Relay_hIpv4);
	serverAddress.sin_port = htons(XLLNOnline_Relay_hPort_Base + 1);

	char msg[9] = { XLLN_CUSTOM_PACKET_SENTINEL, XLLNCustomPacketType::CUSTOM_OTHER, 'X', 'O', XLLNOnlineCustomPacketType::REQ_IPv4 };
	*(DWORD*)(&msg[5]) = htonl(1); // Version.

	for (int i = 0; i <= 5; i++) {
		if (sendto(XLLNOnline_socket_udp_rand, msg, sizeof(msg), NULL, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) <= 0) {
			//returns -1 if it wasn't successful. Note that it doesn't return -1 if the connection couldn't be established (UDP)
			XLLNDebugLog(0, "XLLNOnline: ERROR: Failed to Send Request for Online Ipv4 Addr.");
		}
		XLLNDebugLog(0, "XLLNOnline: Sent Request for Online Ipv4 Addr.");

		Sleep(2500L);

		if (XLLN_Online_Mode_hIpv4 != INADDR_NONE) {
			return;
		}
	}
	XLLNDebugLog(0, "XLLNOnline: ERROR: Failed to receive reply for Online Ipv4 Addr.");
}

VOID WINAPI LiveOverLanBroadcastHandler(LIVE_SERVER_DETAILS *session_details)
{
	if (XLLNOnline_socket_udp_rand == INVALID_SOCKET) {
		XLLNDebugLog(0, "XLLNOnline: ERROR: XLLNOnline_socket_udp_rand not initialised.");
		return;
	}

	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(XLLNOnline_Relay_hIpv4);
	serverAddress.sin_port = htons(XLLNOnline_Relay_hPort_Base + 1);

	const int length = sizeof(session_details->HEAD) + (session_details->HEAD.bCustomPacketType == XLLNCustomPacketType::LIVE_OVER_LAN_ADVERTISE ? sizeof(session_details->ADV) + session_details->ADV.propsSize : sizeof(session_details->UNADV));

	if (sendto(XLLNOnline_socket_udp_rand, (char*)session_details, length, NULL, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) <= 0) {
		//returns -1 if it wasn't successful. Note that it doesn't return -1 if the connection couldn't be established (UDP)
		XLLNDebugLog(0, "XLLNOnline: ERROR: Failed to Send LiveOverLanBroadcast.");
	}
}

static DWORD SetOnlineMode(bool onlineMode)
{
	if (onlineMode && XLLN_Online_Mode_hIpv4 != INADDR_NONE) {
		DWORD old = 0;
		bool success = XLLNModifyProperty(2, &XLLN_Online_Mode_hIpv4, &old) == ERROR_SUCCESS;

		if (success) {
			DWORD setHandler = (DWORD)LiveOverLanBroadcastHandler;
			DWORD old = 0;
			success = XLLNModifyProperty(3, &setHandler, &old) == ERROR_SUCCESS;

			if (!success) {
				XLLNModifyProperty(2, NULL, NULL);
			}
		}

		XLLN_Online_Mode = success;
	}
	else {
		XLLN_Online_Mode = false;
		XLLNModifyProperty(2, NULL, NULL);
		XLLNModifyProperty(3, NULL, NULL);
	}
	return ERROR_SUCCESS;
}

static DWORD WINAPI ThreadProc(LPVOID lpParam)
{
	srand((unsigned int)time(NULL));

	CustomSocketListenStart();

	SendRequestOnlineIpv4Addr();

	SetOnlineMode(XLLN_Online_Mode);

	xllnOnline_Initialised = TRUE;

	return TRUE;
}

static BOOL InitOther()
{
	InitializeCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);

	WSADATA wsaData;
	DWORD result = WSAStartup(2, &wsaData);
	//BOOL success = result == 0;

	if ((XLLNOnline_socket_udp_rand = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
		XLLNDebugLog(0, "XLLNOnline: ERROR: Could not create UDP 0 socket.");
	}

	char broadcast = '1';
	if (setsockopt(XLLNOnline_socket_udp_rand, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
		XLLNDebugLog(0, "XLLNOnline: ERROR: Unable to setsockopt SO_BROADCAST for UDP 0 socket.");
	}

	u_long iMode = 1;
	if (ioctlsocket(XLLNOnline_socket_udp_rand, FIONBIO, &iMode) != NO_ERROR) {
		XLLNDebugLog(0, "XLLNOnline: ERROR: Unable to ioctlsocket FIONBIO 1 for UDP 0 socket.");
	}

	CreateThread(0, NULL, ThreadProc, NULL, NULL, NULL);

	return TRUE;
}

static BOOL UninitOther()
{
	CustomSocketListenStop();

	if (XLLN_Online_Mode) {
		XLLNModifyProperty(2, NULL, NULL);
		XLLNModifyProperty(3, NULL, NULL);
	}

	WSACleanup();

	DeleteCriticalSection(&XLLNOnline_lock_customsocketlisten_thread);
	return TRUE;
}

void WriteBytes(DWORD destAddress, LPVOID bytesToWrite, int numBytes)
{
	DWORD OldProtection;
	DWORD temp;

	VirtualProtect((LPVOID)destAddress, numBytes, PAGE_EXECUTE_READWRITE, &OldProtection);
	memcpy((LPVOID)destAddress, bytesToWrite, numBytes);
	VirtualProtect((LPVOID)destAddress, numBytes, OldProtection, &temp); //quick fix for exception that happens here
}

void WritePointer(DWORD offset, void *ptr)
{
	BYTE* pbyte = (BYTE*)&ptr;
	BYTE assmNewFuncRel[0x4] = { pbyte[0], pbyte[1], pbyte[2], pbyte[3] };
	WriteBytes(offset, assmNewFuncRel, 0x4);
}

void PatchCall(DWORD call_addr, DWORD new_function_ptr)
{
	DWORD callRelative = new_function_ptr - (call_addr + 5);
	WritePointer(call_addr + 1, reinterpret_cast<void*>(callRelative));
}

static DWORD RVAToFileMap(LPVOID pMapping, DWORD ddva)
{
	return (DWORD)pMapping + ddva;
}

static DWORD PEImportHack(HMODULE hModule)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)hModule;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("ERROR: Not DOS - This file is not a DOS application.\n");
		return ERROR_BAD_EXE_FORMAT;
	}

	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((DWORD)hModule + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		printf("ERROR: Not Valid PE - This file is not a valid NT Portable Executable.\n");
		return ERROR_BAD_EXE_FORMAT;
	}

	IMAGE_DATA_DIRECTORY IDE_Import = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (IDE_Import.Size <= 0) {
		printf("WARNING: No Import Table - No import information in this PE.\n");
		return ERROR_TAG_NOT_PRESENT;
	}

	if (IDE_Import.Size % sizeof(IMAGE_IMPORT_DESCRIPTOR) != 0) {
		printf("WARNING: Import Table not expected size.\n");
		return ERROR_INVALID_DLL;
	}

	WORD import_section_id = 0;
	IMAGE_SECTION_HEADER* section_headers = (IMAGE_SECTION_HEADER*)((DWORD)&nt_headers->OptionalHeader + nt_headers->FileHeader.SizeOfOptionalHeader);

	{
		DWORD i;
		for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
			if (IDE_Import.VirtualAddress >= section_headers[i].VirtualAddress && IDE_Import.VirtualAddress < section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize) {
				import_section_id = i & 0xFF;
				break;
			}
		}
		if (i >= nt_headers->FileHeader.NumberOfSections) {
			printf("WARNING: Import Table section not found.\n");
			return ERROR_TAG_NOT_PRESENT;
		}
	}

	IMAGE_IMPORT_DESCRIPTOR* fm_import_dir = (IMAGE_IMPORT_DESCRIPTOR*)RVAToFileMap(hModule, IDE_Import.VirtualAddress);
	DWORD maxi = IDE_Import.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	for (DWORD i = 0; i < maxi; i++) {
		if (fm_import_dir[i].Name == NULL) {
			break;
		}
		char *im_name = (char*)RVAToFileMap(hModule, fm_import_dir[i].Name);
		if (_strnicmp(im_name, "xlive.dll", 10) != 0) {
			continue;
		}
		DWORD pthunk_addr = fm_import_dir[i].FirstThunk;// + section_headers[import_section_id].PointerToRawData - section_headers[import_section_id].VirtualAddress;
		DWORD pthunk_ordinal = fm_import_dir[i].OriginalFirstThunk;// + section_headers[import_section_id].PointerToRawData - section_headers[import_section_id].VirtualAddress;
		IMAGE_THUNK_DATA* thunk_addrs = (IMAGE_THUNK_DATA*)((DWORD)hModule + pthunk_addr);
		IMAGE_THUNK_DATA* thunk_hints = (IMAGE_THUNK_DATA*)((DWORD)hModule + pthunk_ordinal);
		for (DWORD j = 0; thunk_hints[j].u1.AddressOfData != 0; j++) {
			WORD ordinal = thunk_hints[j].u1.Ordinal & 0xFF;
			char *ordinal_name = 0;
			DWORD ordinal_addr = (DWORD)&thunk_addrs[j].u1.AddressOfData;
			if (!(thunk_hints[j].u1.AddressOfData & 0x80000000)) {
				DWORD thunk_hints_i = thunk_hints[j].u1.AddressOfData;// + section_headers[import_section_id].PointerToRawData - section_headers[import_section_id].VirtualAddress;
				ordinal = *(WORD*)((DWORD)hModule + (thunk_hints_i));
				ordinal_name = (char*)((DWORD)hModule + (thunk_hints_i + sizeof(WORD)));
			}
			if (ordinal == 0x18) {
				Import_XSocketSendTo = (DWORD)ordinal_addr;
				XSocketSendTo = (tXSocketSendTo)*(DWORD*)(ordinal_addr);
				WritePointer(ordinal_addr, &XSocketSendToHook);
			}
		}
		break;
	}

	if (!Import_XSocketSendTo) {
		return ERROR_NO_MATCH;
		return ERROR_NOT_FOUND;
	}

	return ERROR_SUCCESS;
	return ERROR_FUNCTION_FAILED;
}

/*
// #73
typedef DWORD(WINAPI *tXNetGetTitleXnAddr)(XNADDR *pAddr);
tXNetGetTitleXnAddr XNetGetTitleXnAddr = NULL;
#define XNET_GET_XNADDR_PENDING             0x00000000 // Address acquisition is not yet complete
static DWORD WINAPI XNetGetTitleXnAddrHook(XNADDR *pAddr)
{
	DWORD result = XNetGetTitleXnAddr(pAddr);
	if (result != XNET_GET_XNADDR_PENDING && true) {
		pAddr->ina.s_addr = inet_addr("60.241.213.195"); //TODO Online Address.
	}
	return result;
}
static DWORD XNetGetTitleXnAddrHookHelper = (DWORD)XNetGetTitleXnAddrHook;*/



BOOL InitXLive()
{
	// Get XLLN exports.
	HMODULE hDllXlive = GetModuleHandle(L"xlive.dll");
	if (!hDllXlive) {
		return FALSE;
	}
	XLLNLogin = (tXLLNLogin)GetProcAddress(hDllXlive, (PCSTR)41140);
	if (!XLLNLogin) {
		return FALSE;
	}
	XLLNLogout = (tXLLNLogout)GetProcAddress(hDllXlive, (PCSTR)41141);
	if (!XLLNLogout) {
		return FALSE;
	}
	XLLNModifyProperty = (tXLLNModifyProperty)GetProcAddress(hDllXlive, (PCSTR)41142);
	if (!XLLNModifyProperty) {
		return FALSE;
	}
	XLLNDebugLog = (tXLLNDebugLog)GetProcAddress(hDllXlive, (PCSTR)41143);
	if (!XLLNDebugLog) {
		return FALSE;
	}

	if (PEImportHack(hTitleModule)) {
		return FALSE;
	}

	WSADATA wsaData;
	DWORD result = WSAStartup(2, &wsaData);

	struct hostent *he;
	struct in_addr **addr_list;
	if ((he = gethostbyname("glitchyscripts.com")) != NULL) {
		addr_list = (struct in_addr **) he->h_addr_list;

		for (int i = 0; addr_list[i] != NULL; i++) {
			//Return the first one;
			XLLNOnline_Relay_hIpv4 = ntohl((*addr_list[i]).s_addr);
			XLLNOnline_Relay_hPort_Base = 6000;
			break;
		}
	}
	else {
		int err = WSAGetLastError();
	}


	InitOther();

	return TRUE;
}

BOOL UninitXLive()
{
	UninitOther();

	WSACleanup();

	if (Import_XSocketSendTo) {
		WritePointer((DWORD)Import_XSocketSendTo, &XSocketSendTo);
		XSocketSendTo = 0;
		Import_XSocketSendTo = 0;
	}

	return TRUE;
}

// #1
DWORD WINAPI XLLNOnlineSetMode(DWORD *onlineMode)
{
	if (!xllnOnline_Initialised) {
		XLLN_Online_Mode = *onlineMode != 0;
		return ERROR_NOT_READY;
	}
	DWORD result = SetOnlineMode(*onlineMode != 0);
	*onlineMode = XLLN_Online_Mode ? 1 : 0;
	return result;
}
