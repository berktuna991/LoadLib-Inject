bool InjectDll(DWORD processId, std::string dllPath)
{
    HANDLE hThread, hProcess;
    void*  pLibRemote = 0;
	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	char DllFullPathName[_MAX_PATH];
    GetFullPathNameA(dllPath.c_str(), _MAX_PATH, DllFullPathName, NULL);
	// Process handle aldır (processid)
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	// dll konumunu chara aktar
    char szLibPath[_MAX_PATH];
    strcpy_s(szLibPath, DllFullPathName);
	// 1. Uygulama içine dll yi alloc(modül olarak ekleme) ediyor
    pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL)
    {
        printf("Hafıza alınamadı, lütfen tekrar yönetici olarak başlatınız\n");//Sadece Konsol için > printf
        return false;
    }
	// 2. Kopyalanan hafızaya dll yi yazdır
    WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath, sizeof(szLibPath), NULL);
	// 3. Hafızayı thread olarak aktar.
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);
	if (hThread == NULL)
    {
        printf("Injectleme Başarısız oldu");//Sadece Konsol için > printf
        return false;
    }
	printf("Dll Başarıyla Injectlendi\n");//Sadece Konsol için > printf
	return true;
}
