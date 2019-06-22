// dllMain.cpp : Defines the entry point for the DLL application.
#include "dllMain.h"
#include "xlln-online.h"

HMODULE hTitleModule = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		hTitleModule = GetModuleHandle(NULL);
		if (!hTitleModule) {
			return FALSE;
		}
		if (!InitXLive()) {
			return FALSE;
		}
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		UninitXLive();
	}
	else if (ul_reason_for_call == DLL_THREAD_ATTACH) {

	}
	else if (ul_reason_for_call == DLL_THREAD_DETACH) {

	}
	return TRUE;
}
