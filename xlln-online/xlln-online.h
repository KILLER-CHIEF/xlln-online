#pragma once

typedef struct XLIVE_INPUT_INFO {
	UINT cbSize;
	HWND hWnd;
	UINT uMSG;
	WPARAM wParam;
	LPARAM lParam;
	BOOL fHandled;
	LRESULT lRet;
} XLIVE_INPUT_INFO;

typedef struct
{
	IN_ADDR     ina;                            // IP address (zero if not static/DHCP)
	IN_ADDR     inaOnline;                      // Online IP address (zero if not online)
	WORD        wPortOnline;                    // Online port
	BYTE        abEnet[6];                      // Ethernet MAC address
	BYTE        abOnline[20];                   // Online identification
} XNADDR;

typedef ULONGLONG XUID;

typedef struct
{
	BYTE        ab[8];                          // xbox to xbox key identifier
} XNKID;

typedef struct
{
	BYTE        ab[16];                         // xbox to xbox key exchange key
} XNKEY;

typedef enum _XUSER_SIGNIN_STATE
{
	eXUserSigninState_NotSignedIn,
	eXUserSigninState_SignedInLocally,
	eXUserSigninState_SignedInToLive
} XUSER_SIGNIN_STATE;

#define XUSER_NAME_SIZE                 16
#define XUSER_MAX_NAME_LENGTH           (XUSER_NAME_SIZE - 1)

// #5262
XUSER_SIGNIN_STATE WINAPI XUserGetSigninState(DWORD dwUserIndex);
// #5263
DWORD WINAPI XUserGetName(DWORD dwUserIndex, LPSTR szUserName, DWORD cchUserName);

#pragma pack(push, 1) // Save then set byte alignment setting.
typedef struct {
	struct {
		BYTE bSentinel;
		BYTE bCustomPacketType;
	} HEAD;
	union {
		struct {
			XUID xuid;
			XNADDR xnAddr;
			DWORD dwServerType;
			XNKID xnkid;
			XNKEY xnkey;
			DWORD dwMaxPublicSlots;
			DWORD dwMaxPrivateSlots;
			DWORD dwFilledPublicSlots;
			DWORD dwFilledPrivateSlots;
			DWORD cProperties;
			union {
				DWORD pProperties;
				DWORD propsSize;
			};
		} ADV;
		struct {
			XUID xuid;
		} UNADV;
	};
} LIVE_SERVER_DETAILS;
#pragma pack(pop) // Return to original alignment setting.

#define XLLN_CUSTOM_PACKET_SENTINEL (BYTE)0x00
namespace XLLNCustomPacketType {
	enum Type : BYTE {
		UNKNOWN = 0x00,
		STOCK_PACKET,
		STOCK_PACKET_FORWARDED,
		CUSTOM_OTHER,
		UNKNOWN_USER_ASK,
		UNKNOWN_USER_REPLY,
		LIVE_OVER_LAN_ADVERTISE,
		LIVE_OVER_LAN_UNADVERTISE,
	};
}

namespace XLLNOnlineCustomPacketType {
	enum Type : BYTE {
		UNKNOWN = 0x00,
		REQ_IPv4,
		REQ_IPv4_REPLY,
	};
}

typedef DWORD(WINAPI *tXLLNLogin)(DWORD dwUserIndex, BOOL bLiveEnabled, DWORD dwUserId, const CHAR *szUsername);
extern tXLLNLogin XLLNLogin;
typedef DWORD(WINAPI *tXLLNLogout)(DWORD dwUserIndex);
extern tXLLNLogout XLLNLogout;
typedef DWORD(WINAPI *tXLLNModifyProperty)(DWORD propertyId, DWORD *newValue, DWORD *oldValue);
extern tXLLNModifyProperty XLLNModifyProperty;
typedef DWORD(WINAPI *tXLLNDebugLog)(DWORD logLevel, const char *message);
extern tXLLNDebugLog XLLNDebugLog;

extern bool XLLN_Online_Mode;
extern ULONG XLLN_Online_Mode_hIpv4;

BOOL InitXLive();
BOOL UninitXLive();
