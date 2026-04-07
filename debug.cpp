#include "debug.h"

#define READ_CODE_SIZE 1024
#define BP_TOTAL_COUNT 100
#define DLL_TOTAL_COUNT 100
#define MAX_SCP_COUNT 1000
#define MAX_SCP_LEN 64
//断点类型
#define BP_TYPE_SYS 0x1 //一次性断点
#define BP_TYPE_NORMAL 0x2
#define BP_TYPE_MEM_READ 0x4
#define BP_TYPE_MEM_WRITE 0x8
#define BP_TYPE_HD_READ 0x10
#define BP_TYPE_HD_WRITE 0x20
#define BP_TYPE_HD_EXE 0x40

DWORD g_trace_end;
FILE * fTrace;
char g_scpBuf[MAX_SCP_LEN];
DWORD g_singleStep;
DEBUG_EVENT * g_lpev = NULL;
DWORD g_isSysBp;
DWORD g_lastAsmAddress;//上次反汇编地址
BPInfo * g_bpArr;// 存储全部断点信息的数组
HardPointInfo g_bhArr[4];// 存储全部硬件断点信息的数组
int g_bpSingel;
DWORD g_lastDataAddress;
ModInfo * g_modArr;
DWORD g_mainModBase;
HANDLE g_hProcess;
DWORD g_bmSingel;
DWORD g_bhSingel;
char * g_scpData[MAX_SCP_COUNT];
int g_nScpIndex;
int g_isScpMod;
int g_traceMod;

void InitRes(){
    g_lpev = (DEBUG_EVENT*)malloc(sizeof(DEBUG_EVENT));
    g_isSysBp = TRUE;
    g_lastAsmAddress = 0;
    g_isScpMod = FALSE;
    g_traceMod = FALSE;
    g_bpArr = (BPInfo*)malloc(sizeof(BPInfo)* BP_TOTAL_COUNT);
    if (g_bpArr != NULL){
        //ZeroMemory(g_bpArr, sizeof(BPInfo)* BP_TOTAL_COUNT);
        for (int i = 0; i < BP_TOTAL_COUNT; i++){
            g_bpArr[i].bpIsUsed = FALSE;
        }
    }
    else{
        printf("断点初始化失败,断点功能失效\n");
    }
    g_bpSingel = -1;
    g_bmSingel = -1;
    g_bhSingel = -1;
    g_singleStep = FALSE;
    g_modArr = (ModInfo*)malloc(sizeof(ModInfo)* DLL_TOTAL_COUNT);
    if (g_modArr != NULL){
        for (int i = 0; i < DLL_TOTAL_COUNT; i++){
            g_modArr[i].isUse = FALSE;
        }
    }
    //初始化硬件断点信息结构
    for (int i = 0; i < 4; i++){
        g_bhArr[i].bpIsUsed = FALSE;
    }
    for (int i = 0; i < MAX_SCP_COUNT; i++){
        g_scpData[i] = (char*)malloc(MAX_SCP_LEN);
    }
    g_nScpIndex = 0;
}

void startDebug(const char* szPath, const char* szCmdLine){
    
    printf("debuging:%s\n", szPath);
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOA);

    //以调试方式创建进程
    DWORD isProcessCreated = CreateProcessA(
        szPath, 
        (char*)szCmdLine, 
        NULL, 
        NULL,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS,
        NULL, 
        NULL,
        &si, 
        &pi);

    if (isProcessCreated == 0){
        printf("创建调试进程失败\n");
        return;
    }

    //执行调试循环
    eventLoop();
}

void eventLoop(){
    //DBG_CONTINUE：已经处理异常，继续执行
    //DBG_EXCEPTION_NOT_HANDLED ： 没有处理异常，把异常还给进程
    DWORD dwContinusStatus = DBG_EXCEPTION_NOT_HANDLED;//默认将异常还给进程
    
    while (TRUE){
        WaitForDebugEvent(g_lpev, INFINITE);

        DWORD exCode = g_lpev->dwDebugEventCode;
        switch (exCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            dwContinusStatus = onException();
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            dwContinusStatus = onCreateProcess();
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            break;
        case LOAD_DLL_DEBUG_EVENT:
            dwContinusStatus = onLoadDll();
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            dwContinusStatus = onUnLoadDll();
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            break;
        default:
            break;
        }
        ContinueDebugEvent(g_lpev->dwProcessId, g_lpev->dwThreadId, dwContinusStatus);
    }
}

int main(int argc, char* argv[])
{
    if (argc <= 1){
        printf("debug.exe {xxx.exe} [cmdLine]");
    }
    else{
        char szPath[MAX_PATH] = { 0 };
        char szCmdLine[MAX_PATH] = { 0 };
        strcpy(szPath, argv[1]);
        if(argc > 2){
            for (int i = 2; i < argc; i++){
                strcat(szCmdLine, argv[i]);
            }
        }

        //初始化全局变量等资源
        InitRes();
        //启动调试器
        startDebug(szPath, szCmdLine);
    }

    system("pause");
	return 0;
}

void getRegs(CONTEXT * pctx){
    if (pctx == NULL){
        printf("获取寄存器环境失败，传入指针为空");
        return;
    }
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, g_lpev->dwThreadId);
    if (hThread == NULL){
        printf("获取寄存器环境失败\n");
        return;
    }
    pctx->ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, pctx);
    CloseHandle(hThread);
}
void setRegs(CONTEXT * pctx){
    if (pctx == NULL){
        printf("获取寄存器环境失败，传入指针为空");
        return;
    }
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, g_lpev->dwThreadId);
    if (hThread == NULL){
        printf("获取寄存器环境失败\n");
        return;
    }
    pctx->ContextFlags = CONTEXT_ALL;
    SetThreadContext(hThread, pctx);
    CloseHandle(hThread);
}

void showRegs(CONTEXT * pctx){
    char showBuf[1024] = { 0 };
    char flagsReg[64] = { 0 };
    getFlagRegStr(pctx->EFlags, flagsReg);

    char szFmt[] = 
        "eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n"
        "eip=%08x esp=%08x ebp=%08x          %s\n"
        "cs=%04x  ss=%04x  ds=%04x  es=%04x  fs=%04x  gs=%04x  efl=%08x\n";

    wsprintfA(showBuf, szFmt,
        pctx->Eax,
        pctx->Ebx,
        pctx->Ecx,
        pctx->Edx,
        pctx->Esi,
        pctx->Edi,
        pctx->Eip,
        pctx->Esp,
        pctx->Ebp,
        flagsReg,
        pctx->SegCs,
        pctx->SegSs,
        pctx->SegDs,
        pctx->SegEs,
        pctx->SegFs,
        pctx->SegGs,
        pctx->EFlags
        );

    printf(showBuf);
}

void getFlagRegStr(DWORD flags, char * output){
    if (output == NULL){
        printf("缓冲区为空\n");
        return;
    }
    char * p = output;

    if (flags & 0x800){
        p += wsprintfA(p, "OF=1 ");
    }
    else{
        p += wsprintfA(p, "OF=0 ");
    }
    if (flags & 0x400){
        p += wsprintfA(p, "DF=1 ");
    }
    else{
        p += wsprintfA(p, "DF=0 ");
    }
    if (flags & 0x200){
        p += wsprintfA(p, "IF=1 ");
    }
    else{
        p += wsprintfA(p, "IF=0 ");
    }
    if (flags & 0x80){
        p += wsprintfA(p, "SF=1 ");
    }
    else{
        p += wsprintfA(p, "SF=0 ");
    }
    if (flags & 0x40){
        p += wsprintfA(p, "ZF=1 ");
    }
    else{
        p += wsprintfA(p, "ZF=0 ");
    }
    if (flags & 0x10){
        p += wsprintfA(p, "AF=1 ");
    }
    else{
        p += wsprintfA(p, "AF=0 ");
    }
    if (flags & 0x4){
        p += wsprintfA(p, "PF=1 ");
    }
    else{
        p += wsprintfA(p, "PF=0 ");
    }
    if (flags & 0x1){
        p += wsprintfA(p, "CF=1 ");
    }
    else{
        p += wsprintfA(p, "CF=0 ");
    }
}

DWORD ov_read(DWORD lpRemoteAddress, char * output, int size){
    if (output == NULL){
        printf("接收缓冲区为NULL");
        return -1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_lpev->dwProcessId);
    if (hProcess == NULL){
        printf("读失败，打开进程失败");
        return -1;
    }
    DWORD dwOld;
    VirtualProtectEx(hProcess, (LPVOID)(lpRemoteAddress & ~0xfff), 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
    DWORD readBytes = 0;
    ReadProcessMemory(hProcess, (LPVOID)lpRemoteAddress, output, size, &readBytes);
    VirtualProtectEx(hProcess, (LPVOID)(lpRemoteAddress & ~0xfff), 0x1000, dwOld, &dwOld);

    CloseHandle(hProcess);

    return readBytes;
}
DWORD ov_write(DWORD lpRemoteAddress, const char * input, int size){
    if (input == NULL){
        printf("写入缓冲区为NULL");
        return -1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_lpev->dwProcessId);
    if (hProcess == NULL){
        printf("写失败，打开进程失败");
        return -1;
    }
    DWORD dwOld;
    VirtualProtectEx(hProcess, (LPVOID)(lpRemoteAddress & ~0xfff), 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
    DWORD readBytes = 0;
    WriteProcessMemory(hProcess, (LPVOID)lpRemoteAddress, input, size, &readBytes);
    VirtualProtectEx(hProcess, (LPVOID)(lpRemoteAddress & ~0xfff), 0x1000, dwOld, &dwOld);

    CloseHandle(hProcess);

    return readBytes;
}

//异常分发以及处理
DWORD onException(){
    DWORD dwContinusStatusRet = DBG_EXCEPTION_NOT_HANDLED;//默认不处理

    DWORD expCode = g_lpev->u.Exception.ExceptionRecord.ExceptionCode;
    DWORD expAddress = (DWORD)g_lpev->u.Exception.ExceptionRecord.ExceptionAddress;
    DWORD expInfo0 = g_lpev->u.Exception.ExceptionRecord.ExceptionInformation[0];
    DWORD expInfo1 = g_lpev->u.Exception.ExceptionRecord.ExceptionInformation[1];

    printf("[info] expCode=%08x expAddress=%08x"
        " expInfomation[0]=%08x expInfomation[1]=%08x\n"
        , expCode, expAddress, expInfo0, expInfo1);

    switch (expCode)
    {
    case EXCEPTION_BREAKPOINT:
        dwContinusStatusRet = onBreakPoint();
        break;
    case EXCEPTION_SINGLE_STEP:
        dwContinusStatusRet = onSingleStep();
        break;
    case EXCEPTION_ACCESS_VIOLATION:
        dwContinusStatusRet = onMemBreakPoint();
        break;
    default:
        break;
    }

    return dwContinusStatusRet;
}

DWORD onCreateProcess(){
    printf("========================================\n");
    
    printf("process pid:            %d\n", g_lpev->dwProcessId);
    printf("process start address:  0x%08x\n", g_lpev->u.CreateProcessInfo.lpStartAddress);
    printf("process base  address:  0x%08x\n", g_lpev->u.CreateProcessInfo.lpBaseOfImage);
    printf("========================================\n");
    
    //g_lastDataAddress 查看内存地址初始化 为主模块第一个iat地址
    char pBase[0x1000] = { 0 };
    DWORD dwBase = (DWORD)g_lpev->u.CreateProcessInfo.lpBaseOfImage;
    g_mainModBase = dwBase;//保存主模块地址

    ov_read(dwBase, pBase, 0x1000);
    IMAGE_DOS_HEADER * pDos = (IMAGE_DOS_HEADER *)pBase;
    IMAGE_NT_HEADERS * pNts = (IMAGE_NT_HEADERS *)(pBase + pDos->e_lfanew);

    IMAGE_IMPORT_DESCRIPTOR firstIid;
    ov_read(dwBase + pNts->OptionalHeader.DataDirectory[1].VirtualAddress,
        (char*)&firstIid, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    g_lastDataAddress = dwBase + firstIid.FirstThunk;

    //在程序入口下断点
    setNormalBp((DWORD)g_lpev->u.CreateProcessInfo.lpStartAddress, 1);
    /*setMemBp((DWORD)g_lpev->u.CreateProcessInfo.lpStartAddress,
        4, BP_TYPE_MEM_READ | BP_TYPE_SYS);*/
    //setHardBp((DWORD)g_lpev->u.CreateProcessInfo.lpStartAddress, 0, BP_TYPE_HD_EXE);

    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_lpev->dwProcessId);
    return DBG_EXCEPTION_NOT_HANDLED;
}

DWORD onBreakPoint(){
    DWORD dwContinusStatusRet = DBG_EXCEPTION_NOT_HANDLED;//默认不处理
    CONTEXT ctx;
    getRegs(&ctx);

    //判断是否系统断点
    if (g_isSysBp){
        g_isSysBp = FALSE;
        showRegs(&ctx);
        ov_dasm(ctx.Eip, 1); 
        dwContinusStatusRet = onCmd();// 命令接口
    }
    //不是系统断点
    else{
        //判断是不是我们自己的断点
        PVOID expAddress = g_lpev->u.Exception.ExceptionRecord.ExceptionAddress;
        int nIndex = -1;
        for (int i = 0; i < BP_TOTAL_COUNT; i++){
            if (g_bpArr[i].bpAddress == (DWORD)expAddress &&
                g_bpArr[i].bpType & BP_TYPE_NORMAL &&
                g_bpArr[i].bpIsUsed == TRUE
                ){
                nIndex = i;
                break;
            }
        }
        if (nIndex == -1){
            //不是我们的断点，放给进程
            dwContinusStatusRet = DBG_EXCEPTION_NOT_HANDLED;
        }
        else{
            //是我们自己打的断点
            ov_write(g_bpArr[nIndex].bpAddress, &g_bpArr[nIndex].bpData, 1);//写回1字节代码
            ctx.Eip--;
            setRegs(&ctx);
            showRegs(&ctx);
            ov_dasm(ctx.Eip, 1);
            if (g_bpArr[nIndex].bpType&BP_TYPE_SYS){
                g_bpArr[nIndex].bpIsUsed = FALSE;
                //处理trace模式
                if (g_traceMod == TRUE){
                    return ov_cmd_t();
                }
            }
            else{
                //重复断点，断步配合
                g_bpSingel = nIndex;
                ctx.EFlags |= 0x100;
                setRegs(&ctx);
            }
            dwContinusStatusRet = onCmd();//断步配合和单步会冲突,稍后解决
        }
    }

    return dwContinusStatusRet;
}

DWORD onSingleStep(){
    CONTEXT ctx;
    getRegs(&ctx);
    DWORD dwContinusStatusRet = DBG_EXCEPTION_NOT_HANDLED;//默认我们不处理
    
    //trace
    if (g_traceMod == TRUE){
        if (ctx.Eip == g_trace_end){
            g_traceMod = FALSE;
            g_singleStep = TRUE;
            if (fTrace){
                char code[16];
                ov_read(ctx.Eip, code, 16);
                char asmbuf[64];
                char buf[MAX_PATH];
                int asmSize;
                Decode2Asm((DWORD)code, (DWORD)asmbuf, (DWORD)&asmSize, ctx.Eip);
                char szLocalBak[MAX_PATH];
                strcpy(szLocalBak, asmbuf);
                char * szIsCallJmp = strtok(szLocalBak, " ");
                if (strcmp(szIsCallJmp, "jmp") == 0 ||
                    strcmp(szIsCallJmp, "call") == 0){
                    char szLookApiName[MAX_PATH];
                    int ret = lookupApiName(ctx.Eip, szLookApiName);
                    if (ret >= 0){
                        char * pFix = strchr(asmbuf, ' ') + 1;
                        strcpy(pFix, szLookApiName);
                    }
                }
                sprintf(buf, "%08x      %s \n", ctx.Eip, asmbuf);
                fwrite(buf, strlen(buf), 1, fTrace);
                fclose(fTrace);
                fTrace = NULL;
            }
        }
        if (fTrace != NULL){
            char code[16];
            ov_read(ctx.Eip, code, 16);
            char asmbuf[64];
            char buf[MAX_PATH];
            int asmSize;
            Decode2Asm((DWORD)code, (DWORD)asmbuf, (DWORD)&asmSize, ctx.Eip);
            char szLocalBak[MAX_PATH];
            strcpy(szLocalBak, asmbuf);
            char * szIsCallJmp = strtok(szLocalBak, " ");
            if (strcmp(szIsCallJmp, "jmp") == 0 ||
                strcmp(szIsCallJmp, "call") == 0){
                char szLookApiName[MAX_PATH];
                int ret = lookupApiName(ctx.Eip, szLookApiName);
                if (ret >= 0){
                    char * pFix = strchr(asmbuf, ' ') + 1;
                    strcpy(pFix, szLookApiName);
                }
            }
            sprintf(buf, "%08x      %s \n", ctx.Eip, asmbuf);
            fwrite(buf, strlen(buf), 1, fTrace);
            if ((unsigned char)code[0] == 0xe8){
                return ov_cmd_g(ctx.Eip + 5);
            }
        }
        return ov_cmd_t();
    }

    //硬件断点
    dr6 * d6 = (dr6*)&ctx.Dr6;
    dr7 * d7 = (dr7*)&ctx.Dr7;
    if (d6->B0 == 1 || d6->B1 == 1 || d6->B2 == 1 || d6->B3 == 1){
        //命中硬件断点
        getRegs(&ctx);
        showRegs(&ctx);
        ov_dasm((DWORD)g_lpev->u.Exception.ExceptionRecord.ExceptionAddress, 1);

        //删除硬件断点，并继续命令--依旧设置断步标志
        if (d6->B0 == 1){
            d7->L0 = 0;
            g_bhSingel = 0;
        }
        else if (d6->B1 == 1){
            d7->L1 = 0;
            g_bhSingel = 1;
        }
        else if (d6->B2 == 1){
            d7->L2 = 0;
            g_bhSingel = 2;
        }
        else if (d6->B3 == 1){
            d7->L3 = 0;
            g_bhSingel = 3;
        }
        ctx.Dr6 = 0;
        ctx.EFlags |= 0x100;
        setRegs(&ctx);
        return onCmd();
    }
    //断步配合
    if (g_bhSingel >= 0){
        //把所有有效的都设回去
        if (g_bhArr[0].bpIsUsed == TRUE){
            d7->L0 = 1;
        }
        if (g_bhArr[1].bpIsUsed == TRUE){
            d7->L1 = 1;
        }
        if (g_bhArr[2].bpIsUsed == TRUE){
            d7->L2 = 1;
        }
        if (g_bhArr[3].bpIsUsed == TRUE){
            d7->L3 = 1;
        }
        setRegs(&ctx);
        g_bhSingel = -1;
        dwContinusStatusRet = DBG_CONTINUE;
    }
    if (g_bpSingel >= 0){
        char byte = 0xcc;
        //一定要检测一下这个断点是否还有效
        if (g_bpArr[g_bpSingel].bpIsUsed == TRUE){
            ov_write(g_bpArr[g_bpSingel].bpAddress, &byte, 1);
        }
        g_bpSingel = -1;
        dwContinusStatusRet = DBG_CONTINUE;
    }
    if (g_bmSingel >= 0){
        if (g_bpArr[g_bmSingel].bpIsUsed == TRUE){
            DWORD dwOld;
            VirtualProtectEx(g_hProcess, (LPVOID)g_bpArr[g_bmSingel].bpMemPage, 0x1000,
                PAGE_NOACCESS, &dwOld);
        }
        g_bmSingel = -1;
        dwContinusStatusRet = DBG_CONTINUE;
    }
    //单步执行
    if (g_singleStep == TRUE){
        g_singleStep = FALSE;
        getRegs(&ctx);
        showRegs(&ctx);
        ov_dasm((DWORD)g_lpev->u.Exception.ExceptionRecord.ExceptionAddress, 1);
        return onCmd();
    }
    return dwContinusStatusRet;
}

DWORD onMemBreakPoint(){
    CONTEXT ctx;
    getRegs(&ctx);
    DWORD dwContinusStatusRet = DBG_EXCEPTION_NOT_HANDLED;//默认我们不处理
    printf("[info]处理内存断点\n");

    /*首先判断内存访问无效的地址是否命中我们的断点*/
    DWORD expCode = g_lpev->u.Exception.ExceptionRecord.ExceptionCode;
    DWORD expAddress = (DWORD)g_lpev->u.Exception.ExceptionRecord.ExceptionAddress;
    //expRorW = 0:读   1：写   8：执行,执行本质上是读
    DWORD expRorW = g_lpev->u.Exception.ExceptionRecord.ExceptionInformation[0];
    DWORD expAccessAddress = g_lpev->u.Exception.ExceptionRecord.ExceptionInformation[1];
    
    //遍历断点信息,比对异常信息。
    int nIndex = -1;
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == FALSE){
            continue;
        }
        else{
            if (g_bpArr[i].bpAddress <= expAccessAddress &&
                expAccessAddress < g_bpArr[i].bpAddress + g_bpArr[i].bpMemLen)
            {
                if (expRorW == 8 || expRorW == 0){
                    if (g_bpArr[i].bpType & BP_TYPE_MEM_READ){
                        nIndex = i;
                        break;
                    }
                }
                else if (expRorW == 1){
                    if (g_bpArr[i].bpType & BP_TYPE_MEM_WRITE){
                        nIndex = i;
                        break;
                    }
                }
            }
        }
    }

    if (nIndex == -1){
        //没找到，不是我们的断点位置，但是需要判断是否落在我们改掉的内存页，如果是，告诉它没事，继续运行
        //否则不管我们事，交给程序运行
        int nIndex0 = -1;
        for (int i = 0; i < BP_TOTAL_COUNT; i++){
            if (g_bpArr[i].bpIsUsed == FALSE){
                continue;
            }
            else{
                if (g_bpArr[i].bpMemPage <= expAccessAddress &&
                    expAccessAddress < g_bpArr[i].bpMemPage + 0x1000){
                    nIndex0 = i;
                }
            }
        }

        if (nIndex0 == -1){
            dwContinusStatusRet = DBG_EXCEPTION_NOT_HANDLED;
        }
        else{
            //误杀，我们恢复一下现场，然后断步再改回属性 nIndex0.page = 我们破坏的页;
            DWORD dwOld;
            VirtualProtectEx(g_hProcess, (LPVOID)g_bpArr[nIndex0].bpMemPage, 0x1000,
                g_bpArr[nIndex0].bpMemOld, &dwOld);
            //断步配合
            ctx.EFlags |= 0x100;
            setRegs(&ctx);
            g_bmSingel = nIndex0;
            dwContinusStatusRet = DBG_CONTINUE;
        }
    }
    else{
        //命中断点。nIndex
        showRegs(&ctx);
        ov_dasm(ctx.Eip, 1);
        //先不管一次性的
        DWORD dwOld;
        VirtualProtectEx(g_hProcess, (LPVOID)g_bpArr[nIndex].bpMemPage, 0x1000, 
            g_bpArr[nIndex].bpMemOld, &dwOld);
        ctx.EFlags |= 0x100;
        setRegs(&ctx);
        g_bmSingel = nIndex;
        dwContinusStatusRet = onCmd();
    }

    return dwContinusStatusRet;
}

DWORD ov_dasm(DWORD lpAddress, int nLine){
    CONTEXT ctx;
    char bCodeBuf[READ_CODE_SIZE];
    char szAsm[MAX_PATH];
    DWORD nDisasmedSize;
    DWORD nCurCode = 0;

    if (lpAddress == 0){
        if (g_lastAsmAddress == 0){
            getRegs(&ctx);
            lpAddress = ctx.Eip;
        }
        else{
            lpAddress = g_lastAsmAddress;
        }
    }
    
    //从被调试进程读取二进制到缓冲区
    DWORD readBytes = ov_read(lpAddress, bCodeBuf, READ_CODE_SIZE);
    if (readBytes < READ_CODE_SIZE){
        printf("从进程读取机器码失败或不完整\n");
        return -1;
    }

    //反汇编nLine条指令
    for (int i = 0; i < nLine; i++){
        Decode2Asm((DWORD)(bCodeBuf + nCurCode), (DWORD)szAsm, (DWORD)&nDisasmedSize, lpAddress);
        
        //给指令上色
        char szLocalBak0[MAX_PATH];
        strcpy(szLocalBak0, szAsm);
        char * szOpcode = strtok(szLocalBak0, " ");

        WORD color = 7; // 默认白色

        if (szOpcode != NULL) {
            if (strcmp(szOpcode, "call") == 0) {
                color = 10; //亮绿色
            }
            else if (strcmp(szOpcode, "jmp") == 0) {
                color = 12; //亮红色
            }
            else if (szOpcode[0] == 'j') {
                color = 14; //黄
            }
            else if (strcmp(szOpcode, "push") == 0 || strcmp(szOpcode, "pop") == 0){
                color = 13; //紫色 - 妹妹说紫色很有韵味
            }
            else if (strcmp(szOpcode, "ret") == 0){
                color = 11; //灰色
            }
        }

        //反查
        char szLocalBak[MAX_PATH];
        strcpy(szLocalBak, szAsm);
        char * szIsCallJmp = strtok(szLocalBak, " ");
        if (strcmp(szIsCallJmp, "jmp") == 0 ||
            strcmp(szIsCallJmp, "call") == 0){
            char szLookApiName[MAX_PATH];
            int ret = lookupApiName(lpAddress, szLookApiName);
            if (ret>=0){
                char * pFix = strchr(szAsm, ' ') + 1;
                strcpy(pFix, szLookApiName);
            }
        }
        

        //输出 反汇编信息
        printf("%08x  ", lpAddress);
        for (int j = 0; j<nDisasmedSize; j++){
            printf("%02x ", (unsigned char)bCodeBuf[j + nCurCode]);
        }
        for (int k = 0;k < (int)(11 - nDisasmedSize); k++){
            printf("   ");
        }
        SetConsoleColor(color);
        printf(szAsm);
        printf("\n");
        SetConsoleColor(7);//只给指令上色，恢复默认的白色

        nCurCode += nDisasmedSize;
        lpAddress += nDisasmedSize;
    }

    g_lastAsmAddress = lpAddress;
}

DWORD onCmd(){
    DWORD dwContinusStatusRet = DBG_EXCEPTION_NOT_HANDLED;//默认不处理
    char cmdBuf[MAX_PATH] = { 0 };

    //获取，并解析命令
_reInput:
    if (g_isScpMod == FALSE){
        printf("cmd >>");
    }
    gets(cmdBuf);
    if (g_isScpMod == TRUE){
        printf("<执行脚本> <%s>\n", cmdBuf);
    }
    //解析命令和参数
    char * cmd = strtok(cmdBuf, " ");
    if (cmd == NULL){
        goto _InvalidCmd;
    }
    //处理脚本结束命令
    if (strcmp(cmd, "scp_end") == 0){
        printf("脚本命令执行完毕: %s\n", cmdBuf);
        freopen("CONIN$", "r", stdin);
        g_isScpMod = FALSE;
        return onCmd();
    }
    //处理u命令
    if (strcmp(cmd, "u") == 0){
        DWORD lpAddress = NULL;
        char* param1 = strtok(NULL, " ");
        if (param1 != NULL){
            lpAddress = strtoul(param1, NULL, 16);
        }
        dwContinusStatusRet = ov_cmd_u(lpAddress);
    }
    //处理bp命令
    else if (strcmp(cmd, "bp") == 0){
        DWORD bpAddress = NULL;
        int isbpSys = FALSE;
        char* param1 = strtok(NULL, " ");
        if (param1 != NULL){
            bpAddress = strtoul(param1, NULL, 16);
            char * param2 = strtok(NULL, " ");
            if (param2 != NULL){
                if (strcmp(param2, "sys") == 0){
                    isbpSys = TRUE;
                }
            }
        }
        else{
            goto _InvalidCmd;
        }
        dwContinusStatusRet = ov_cmd_bp(bpAddress, isbpSys);
    }
    //g命令
    else if (strcmp(cmd, "g") == 0){
        DWORD gAddress = NULL;
        char* param1 = strtok(NULL, " ");
        if (param1 != NULL){
            gAddress = strtoul(param1, NULL, 16);
        }
        dwContinusStatusRet = ov_cmd_g(gAddress);
    }
    //步入t命令
    else if (strcmp(cmd, "t") == 0){
        dwContinusStatusRet = ov_cmd_t();
    }
    //步过命令
    else if (strcmp(cmd, "p") == 0){
        dwContinusStatusRet = ov_cmd_p();
    }
    //trace
    else if (strcmp(cmd, "trace") == 0){
        char* param1 = strtok(NULL, " ");
        if (param1 == NULL){
            printf("指令错误，正确格式：bm {起始地址} {结束地址} [模块名]");
            goto _InvalidCmd;
        }
        else{
            DWORD startAddress = strtoul(param1, NULL, 16);
            char* param2 = strtok(NULL, " ");
            if (param2 == NULL){
                printf("指令错误，正确格式：bm {起始地址} {结束地址} [模块名]");
                goto _InvalidCmd;
            }
            else{
                DWORD endAddress = strtoul(param2, NULL, 16);
                char* param3 = strtok(NULL, " ");
                dwContinusStatusRet = ov_cmd_trace(startAddress, endAddress,param3);
            }
        }
    }
    //r命令
    else if (strcmp(cmd, "r") == 0){
        dwContinusStatusRet = ov_cmd_r();
    }
    //dd命令 
    else if (strcmp(cmd, "dd") == 0){
        DWORD dataAddress = NULL;
        char* param1 = strtok(NULL, " ");
        if (param1 != NULL){
            dataAddress = strtoul(param1, NULL, 16);
        }
        else{
            dataAddress = g_lastDataAddress;
        }
        dwContinusStatusRet = ov_cmd_dd(dataAddress);
    }
    //e命令
    else if (strcmp(cmd, "e") == 0){
        DWORD dataAddress = NULL;
        char* param1 = strtok(NULL, " ");
        if (param1 != NULL){
            dataAddress = strtoul(param1, NULL, 16);
        }
        else{
            dataAddress = g_lastDataAddress;
        }
        dwContinusStatusRet = ov_cmd_e(dataAddress);
    }
    else if (strcmp(cmd, "quit") == 0){
        dwContinusStatusRet = ov_cmd_q();
    }
    else if (strcmp(cmd, "ml")==0){
        dwContinusStatusRet = ov_cmd_ml();
    }
    else if (strcmp(cmd, "dump") == 0){
        char* param1 = strtok(NULL, " ");
        if (param1 == NULL){
            printf("请输入dump后的文件名:{dump xxx.exe}");
            goto _InvalidCmd;
        }
        else{
            dwContinusStatusRet = ov_cmd_dump(param1);
        }
    }
    else if (strcmp(cmd, "bm") == 0){
        char* param1 = strtok(NULL, " ");
        if (param1 == NULL){
            printf("指令错误，正确格式：bm {地址} {长度[1/2/4]} {r/w}");
            goto _InvalidCmd;
        }
        else{
            DWORD bmAddress = strtoul(param1, NULL, 16);
            char* param2 = strtok(NULL, " ");
            if (param2 == NULL){
                printf("指令错误，正确格式：bm {地址} {长度[1/2/4]} {r/w}");
                goto _InvalidCmd;
            }
            else{
                DWORD bmLen = strtoul(param2, NULL, 16);
                if (bmLen != 1 && bmLen != 2 && bmLen != 4){
                    printf("指令错误，正确格式：bm {地址} {长度[1/2/4]} {r/w}");
                    goto _InvalidCmd;
                }
                char* param3 = strtok(NULL, " ");
                if (param3 == NULL){
                    printf("指令错误，正确格式：bm {地址} {长度[1/2/4]} {r/w}");
                    goto _InvalidCmd;
                }
                else{
                    int bmType;
                    if (strcmp(param3, "r") == 0){
                        bmType = BP_TYPE_MEM_READ;
                    }
                    else if (strcmp(param3, "w") == 0){
                        bmType = BP_TYPE_MEM_WRITE;
                    }
                    else{
                        printf("指令错误，正确格式：bm {地址} {长度[1/2/4]} {r/w}");
                        goto _InvalidCmd;
                    }
                    dwContinusStatusRet = ov_cmd_bm(bmAddress, bmLen, bmType);
                }
            }
        }
    }
    else if (strcmp(cmd, "bpl") == 0){
        dwContinusStatusRet = ov_cmd_bpl();
    }
    else if (strcmp(cmd, "bml") == 0){
        dwContinusStatusRet = ov_cmd_bml();
    }
    else if (strcmp(cmd, "bhl") == 0){
        dwContinusStatusRet = ov_cmd_bhl();
    }
    else if (strcmp(cmd, "ls") == 0){
        dwContinusStatusRet = ov_cmd_ls();
    }
    else if (strcmp(cmd, "es") == 0){
        dwContinusStatusRet = ov_cmd_es();
    }
    else if (strcmp(cmd, "bpc") == 0){
        char* param1 = strtok(NULL, " ");
        if (param1 == NULL){
            printf("请输入要删除的断点序号\n");
            goto _InvalidCmd;
        }
        else{
            DWORD ord = strtoul(param1, NULL, 16);
            dwContinusStatusRet = ov_cmd_bpc(ord);
        }
    }
    else if (strcmp(cmd, "bmc") == 0){
        char* param1 = strtok(NULL, " ");
        if (param1 == NULL){
            printf("请输入要删除的断点序号\n");
            goto _InvalidCmd;
        }
        else{
            DWORD ord = strtoul(param1, NULL, 16);
            dwContinusStatusRet = ov_cmd_bmc(ord);
        }
    }
    else if (strcmp(cmd, "bhc") == 0){
        char* param1 = strtok(NULL, " ");
        if (param1 == NULL){
            printf("请输入要删除的断点序号\n");
            goto _InvalidCmd;
        }
        else{
            DWORD ord = strtoul(param1, NULL, 16);
            dwContinusStatusRet = ov_cmd_bhc(ord);
        }
    }
    else if (strcmp(cmd, "bh") == 0){
        char* param1 = strtok(NULL, " ");
        if (param1 == NULL){
            printf("指令错误，正确格式：bh {地址} {类型 r/w/e} {长度1/2/4}");
            goto _InvalidCmd;
        }
        else{
            DWORD bhAddress = strtoul(param1, NULL, 16);
            char* param2 = strtok(NULL, " ");
            if (param2 == NULL){
                printf("指令错误，正确格式：bh {地址} {类型 r/w/e} {长度1/2/4}");
                goto _InvalidCmd;
            }
            else{
                DWORD bhType;
                if (strcmp(param2, "r") == 0){
                    bhType = BP_TYPE_HD_READ;
                }
                else if (strcmp(param2, "w") == 0){
                    bhType = BP_TYPE_HD_WRITE;
                }
                else if (strcmp(param2, "e") == 0){
                    bhType = BP_TYPE_HD_EXE;
                }
                else{
                    printf("指令错误，正确格式：bh {地址} {类型 r/w/e} {长度1/2/4}");
                    goto _InvalidCmd;
                }
                char* param3 = strtok(NULL, " ");
                if (param3 == NULL){
                    printf("指令错误，正确格式：bh {地址} {类型 r/w/e} {长度1/2/4}");
                    goto _InvalidCmd;
                }
                else{
                    DWORD bhLen;
                    if (bhType == BP_TYPE_HD_EXE){
                        bhLen = 0;
                        dwContinusStatusRet = ov_cmd_bh(bhAddress, bhLen, bhType);
                    }
                    else{
                        bhLen = strtoul(param3, NULL, 16);
                        if (bhLen != 1 && bhLen != 2 && bhLen != 4){
                            printf("指令错误，正确格式：bh {地址} {类型 r/w/e} {长度1/2/4}");
                            goto _InvalidCmd;
                        }
                        else{
                            dwContinusStatusRet = ov_cmd_bh(bhAddress,bhLen,bhType);
                        }
                    }
                }
            }
        }
    }
    //无效命令
    else{
_InvalidCmd:
        printf("无效命令,输入?查看帮助\n");
        rewind(stdin);
        goto _reInput;
    }
    return dwContinusStatusRet;
}
//001e45c0
DWORD ov_cmd_u(DWORD lpAddress){
    sprintf(g_scpBuf, "u %08x \n", lpAddress);
    addScp(g_scpBuf);//添加到脚本

    ov_dasm(lpAddress, 8);
    return onCmd();
}

//设置一般断点
DWORD ov_cmd_bp(DWORD bpAddress, int isbpSys){

    if (bpAddress < 0x10000 || bpAddress > 0x7fffffff){
        printf("断点地址非法\n");
        return onCmd();
    }
    if (isbpSys){
        sprintf(g_scpBuf, "bp %08x sys\n", bpAddress);
    }
    else{
        sprintf(g_scpBuf, "bp %08x\n", bpAddress);
    }
    
    addScp(g_scpBuf);//添加到脚本

    setNormalBp(bpAddress, isbpSys);
    return onCmd();
}

int setNormalBp(DWORD bpAddress, int isbpSys){
    //先看有没有重复断点,有就直接返回
    for (int i = 0; i < 4; i++){
        if (g_bhArr[i].bpIsUsed == TRUE && g_bhArr[i].bpAddress == bpAddress){
            printf("此处已存在断点，清除后再设\n");
            return -1;
        }
    }

    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpAddress == bpAddress && g_bpArr[i].bpIsUsed == TRUE){
            printf("此处已存在断点，清除后再设\n");
            return -1;
        }
    }

    //查找断点数组空闲位置
    int nIndex = 0;
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == FALSE){
            nIndex = i;
            break;
        }
    }

    //向查找到的空闲位置填充断点信息
    if (isbpSys == TRUE){
        g_bpArr[nIndex].bpType = BP_TYPE_SYS | BP_TYPE_NORMAL;
    }
    else{
        g_bpArr[nIndex].bpType = BP_TYPE_NORMAL;
    }

    g_bpArr[nIndex].bpOrdin = nIndex;
    g_bpArr[nIndex].bpIsUsed = TRUE;
    g_bpArr[nIndex].bpAddress = bpAddress;
    ov_read(bpAddress, &g_bpArr[nIndex].bpData, 1);

    //设置断点地址位置为0xcc
    char byte = 0xcc;
    ov_write(bpAddress, &byte, 1);

    printf("一般断点设置成功\n");
}

DWORD ov_cmd_g(DWORD gAddress){
    if (gAddress != NULL){
        setNormalBp(gAddress, TRUE);
    }

    sprintf(g_scpBuf, "g %08x\n", gAddress);
    addScp(g_scpBuf);//添加到脚本

    return DBG_CONTINUE;
}

DWORD ov_cmd_t(){
    CONTEXT ctx;
    getRegs(&ctx);
    ctx.EFlags |= 0x100;
    setRegs(&ctx);
    g_singleStep = TRUE;

    sprintf(g_scpBuf, "t\n");
    addScp(g_scpBuf);//添加到脚本
    
    return DBG_CONTINUE;
}

DWORD ov_cmd_p(){

    sprintf(g_scpBuf, "p\n");
    addScp(g_scpBuf);//添加到脚本

    //用eip头一个字节判断。如果是e8，在下一行下断，否则单步步入
    char byte;
    CONTEXT ctx;
    getRegs(&ctx);
    ov_read(ctx.Eip, &byte, 1);
    if ((unsigned char)byte == 0xe8){
        setNormalBp(ctx.Eip + 5, 1);
        return ov_cmd_g(NULL);
    }
    else{
        return ov_cmd_t();
    }
}

DWORD ov_cmd_trace(DWORD start, DWORD end, char * mod){
    if (mod == NULL){
        //trace所有模块
        g_traceMod = TRUE;
        fTrace = fopen("trace.scp", "w");
        g_trace_end = end;
        return ov_cmd_t();
    }
}

DWORD ov_cmd_r(){

    sprintf(g_scpBuf, "r\n");
    addScp(g_scpBuf);//添加到脚本

    CONTEXT ctx;
    getRegs(&ctx);
    showRegs(&ctx);
    return onCmd();
}

DWORD ov_cmd_dd(DWORD dataAddress){

    sprintf(g_scpBuf, "dd %08x\n", dataAddress);
    addScp(g_scpBuf);//添加到脚本

    char bData[128];
    ov_read(dataAddress, bData, 128);
    for (int i = 0; i < 8; i++){
        printf("%08X  ", dataAddress + i * 16);

        for (int j = 0; j < 16; j++){
            printf("%02X ", (unsigned char)bData[i * 16 + j]);
            if (j == 7) printf("- ");
        }

        printf("  ");
        for (int j = 0; j < 16; j++){
            unsigned char ch = (unsigned char)bData[i * 16 + j];
            printf("%c", (ch >= 32 && ch < 127) ? ch : '.');
        }
        printf("\n");
    }
    g_lastDataAddress = dataAddress+128;
    return onCmd();
}

DWORD ov_cmd_e(DWORD dataAddress){

    char byte;
    char byteInput[3] = { 0 };

    printf("编辑内存，输入十六进制值修改，按q退出\n");

    for (int i = 0;; i++){
        ov_read(dataAddress + i, &byte, 1);
        printf("%08X: %02x -> ", dataAddress + i, (unsigned char)byte);

        scanf("%2s", byteInput);

        // 检查退出命令
        if (strcmp(byteInput, "q") == 0 || strcmp(byteInput, "Q") == 0) {
            fflush(stdin);
            break;
        }

        char byteToWrite = strtoul(byteInput, NULL, 16);
        ov_write(dataAddress + i, &byteToWrite, 1);
    }

    return onCmd();
}

DWORD ov_cmd_q(){

    sprintf(g_scpBuf, "q\n");
    addScp(g_scpBuf);//添加到脚本

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_lpev->dwProcessId);
    TerminateProcess(h, 0);
    CloseHandle(h);
    printf("程序退出\n");
    system("pause");
    ExitProcess(0);
}

DWORD ov_cmd_ml(){

    sprintf(g_scpBuf, "ml\n");
    addScp(g_scpBuf);//添加到脚本

    printf("======================================================\n");
    printf("lpBase          lpName\n");
    for (int i = 0; i < DLL_TOTAL_COUNT; i++){
        if (g_modArr[i].isUse == TRUE){
            if (g_modArr[i].fUnicode == 0){
                printf("0x%08x      %s\n", g_modArr[i].pDllBase, g_modArr[i].szDllName);
            }
            else{
                wprintf(L"0x%08x      %s\n", g_modArr[i].pDllBase, g_modArr[i].szDllName);
            }
        }
    }
    printf("======================================================\n");
    return onCmd();
}

DWORD onLoadDll() {
    
    int nIndex = -1;
    for (int i = 0; i < DLL_TOTAL_COUNT; i++){
        if (g_modArr[i].isUse == FALSE){
            nIndex = i;
            break;
        }
    }
    if (nIndex != -1){
        g_modArr[nIndex].isUse = TRUE;
        g_modArr[nIndex].fUnicode = g_lpev->u.LoadDll.fUnicode;
        g_modArr[nIndex].pDllBase = (DWORD)g_lpev->u.LoadDll.lpBaseOfDll;
        //g_lpev->u.LoadDll.lpImageName;
        DWORD pName = NULL;
        ov_read((DWORD)g_lpev->u.LoadDll.lpImageName, (char*)&pName, 4);
        if (pName != NULL){
            ov_read(pName,g_modArr[nIndex].szDllName, MAX_PATH * 2);
        }
        else{
            wcscpy((wchar_t*)g_modArr[nIndex].szDllName, L"--");
        }
    }
    //枚举模块-ldr
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, g_lpev->dwProcessId);
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        int moduleCount = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < moduleCount && i < 1024; i++) {
            char szModName[MAX_PATH];
            // 获取模块文件名
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                /*printf("[%4d] 基址: 0x%08p  模块: %s\n",
                    i, hMods[i], szModName);*/
                //遍历g_modArr
                int nIndex = -1;
                for (int j = 0; j < DLL_TOTAL_COUNT; j++){
                    if ((DWORD)hMods[i] == g_modArr[j].pDllBase){
                        nIndex = j;
                        break;
                    }
                }
                if (nIndex == -1){
                    for (int k = 0; k < DLL_TOTAL_COUNT; k++){
                        if (g_modArr[k].isUse == FALSE){
                            g_modArr[k].isUse = TRUE;
                            g_modArr[k].fUnicode = 0;
                            g_modArr[k].pDllBase = (DWORD)hMods[i];
                            strcpy(g_modArr[nIndex].szDllName, szModName);
                            break;
                        }
                    }
                }
                else{
                    g_modArr[nIndex].fUnicode = 0;
                    strcpy(g_modArr[nIndex].szDllName, szModName);
                }
            }
        }
    }
    CloseHandle(hProcess);

    return DBG_EXCEPTION_NOT_HANDLED;
}

DWORD onUnLoadDll() {
    int nIndex = -1;
    for (int i = 0; i < DLL_TOTAL_COUNT; i++){
        if (g_modArr[i].pDllBase == (DWORD)g_lpev->u.UnloadDll.lpBaseOfDll){
            nIndex = i;
            break;
        }
    }
    g_modArr[nIndex].isUse = FALSE;

    return DBG_EXCEPTION_NOT_HANDLED;
}

//输入当前指令，返回新的字符串szAsm
// e9 xx xx xx xx 
// ff 25 xx xx xx xx 绝对 内存[]
// e8 xx xx xx xx 
// eb xx
DWORD __findAddr(DWORD codeAddress){
    char code[16];
    ov_read(codeAddress, code, 16);
    DWORD next_addr_rva = 0;
    DWORD next_addr_va = 0;
    if (code[0] == (char)0xe9 || code[0] == (char)0xe8){
        next_addr_rva = *(DWORD*)&code[1];
        next_addr_va = next_addr_rva + 5 + codeAddress;
    }
    else if (code[0] == (char)0xeb){
        next_addr_rva = *(unsigned char*)&code[1];
        next_addr_va = next_addr_rva + 2 + codeAddress;
    }
    else if(code[0] == (char)0xff && code[1] == (char)0x25){
        next_addr_va = *(DWORD*)&code[2];
        DWORD va;
        ov_read(next_addr_va, (char*)&va, 4);
        return va;
    }
    else{
        return NULL;
    }
    char nextCode[16];
    char nextAsm[MAX_PATH];
    int nAsmSize;
    ov_read(next_addr_va, nextCode, 16);
    Decode2Asm((DWORD)nextCode, (DWORD)nextAsm, (DWORD)&nAsmSize, next_addr_va);
    
    char* p = strtok(nextAsm, " ");
    if (p == NULL){
        return next_addr_va;
    }
    if (strcmp(p, "jmp") == 0 || strcmp(p, "call") == 0){
        return __findAddr(next_addr_va);
    }
    return next_addr_va;
}

int APIReLookup(HANDLE hProcess,DWORD pBase, DWORD pDstFunAddress, char * out){
    char szDllNameBuf[MAX_PATH] = { 0 };
    char szfuncNameBuf[MAX_PATH] = { 0 };

    //pBase = 目标函数所在dll基址
    //搞个缓冲区把pe头读进来
    char pPeBuf[0x1000] = { 0 };
    ReadProcessMemory(hProcess, (LPVOID)pBase, pPeBuf, 0x1000, NULL);

    //解析pe头，读目标的导出表
    IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER*)pPeBuf;

    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS*)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
    IMAGE_EXPORT_DIRECTORY * expTbl = new IMAGE_EXPORT_DIRECTORY;
    DWORD expTblVa = pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress + pBase;

    ReadProcessMemory(hProcess, (LPVOID)expTblVa, expTbl, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);

    int sizeOfName = expTbl->NumberOfNames;
    int sizeOfFunc = expTbl->NumberOfFunctions;

    //读3个地址表
    DWORD * pAddressOfFunc = new DWORD[sizeOfFunc];
    DWORD * pAddressOfName = new DWORD[sizeOfName];
    WORD * pAddressOfNameOdrinal = new WORD[sizeOfName];

    ReadProcessMemory(hProcess, (LPVOID)(pBase + expTbl->AddressOfFunctions), pAddressOfFunc, 4 * sizeOfFunc, NULL);
    ReadProcessMemory(hProcess, (LPVOID)(pBase + expTbl->AddressOfNames), pAddressOfName, 4 * sizeOfName, NULL);
    ReadProcessMemory(hProcess, (LPVOID)(pBase + expTbl->AddressOfNameOrdinals), pAddressOfNameOdrinal, 2 * sizeOfName, NULL);


    //比对函数地址，
    DWORD dstFuncRva = pDstFunAddress - pBase;
    WORD nIndex = -1;
    DWORD nNameIndex = -1;
    for (int i = 0; i < sizeOfFunc; i++){
        if (dstFuncRva == pAddressOfFunc[i]){
            //找到目标函数，拿到当前下标，去名称序号表里查找相应索引
            nIndex = i;
            break;
        }
    }

    if (nIndex != -1){
        for (int i = 0; i < sizeOfName; i++){
            if (pAddressOfNameOdrinal[i] == nIndex){
                //找到目标名称索引，去名称表里取函数名rva
                nNameIndex = i;
                break;
            }
        }
    }

    if (nNameIndex != -1){
        ReadProcessMemory(hProcess,
            (LPVOID)(pBase + pAddressOfName[nNameIndex]), szfuncNameBuf, MAX_PATH, NULL);
        ReadProcessMemory(hProcess, (LPVOID)(pBase + expTbl->Name), szDllNameBuf, MAX_PATH, NULL);
    }

    if (nIndex == -1 || nNameIndex == -1){
        return -1;
    }
    wsprintfA(out, "%s!%s", szDllNameBuf, szfuncNameBuf);

    if (expTbl){
        delete expTbl;
    }
    if (pAddressOfFunc){
        delete[] pAddressOfFunc;
    }
    if (pAddressOfName){
        delete[] pAddressOfName;
    }
    if (pAddressOfNameOdrinal){
        delete[] pAddressOfNameOdrinal;
    }
    return 1;
}

//返回值<0失败
int lookupApiName(DWORD codeAddress, char * szAsm){
    //第一步，获取反查的地址
    //可能的情况，有以上4种基本的跳，（不算条件跳）
    //思路，不管是哪种跳，都递归到不跳为止
    DWORD funAddr = __findAddr(codeAddress);
    if (funAddr == NULL){
        return -1;
    }
    char dstModName[MAX_PATH];
    DWORD pModBase = NULL;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, g_lpev->dwProcessId);
    MODULEINFO modInfo = { 0 };
    
    for (int i = 0; i < DLL_TOTAL_COUNT; i++){
        if (g_modArr[i].isUse == TRUE){
            //查询模块大小
            GetModuleInformation(hProcess, (HMODULE)g_modArr[i].pDllBase,
                &modInfo, sizeof(modInfo));
            //查找反查函数所在模块地址
            if (funAddr >= g_modArr[i].pDllBase && funAddr <
                modInfo.SizeOfImage + g_modArr[i].pDllBase){
                CloseHandle(hProcess);
                hProcess = NULL;
                pModBase = g_modArr[i].pDllBase;
                
                if (g_modArr[i].fUnicode == 0){
                    strcpy(dstModName, strrchr(g_modArr[i].szDllName, '\\') + 1);
                }
                else{
                    int len = wcslen((const wchar_t*)g_modArr[i].szDllName);
                    char localBuf[MAX_PATH] = { 0 };
                    for (int j = 0; j < len; j++){
                        localBuf[j] = g_modArr[i].szDllName[j * 2];
                    }
                    strcpy(dstModName, strrchr(localBuf, '\\') + 1);
                }
                break;
            }
        }
    }

    if (pModBase == NULL || g_mainModBase == pModBase){
        return -1;//反查失败
    }
    
    /*strcpy(szAsm, dstModName);
    strcat(szAsm, "!");*/

    char szfunName[MAX_PATH] = { 0 };
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_lpev->dwProcessId);
    if (APIReLookup(h, pModBase, funAddr, szfunName) < 0){
        return -1;
    }
    strcpy(szAsm, szfunName);
    if (h){
        CloseHandle(h);
    }
    if (hProcess){
        CloseHandle(hProcess);
    }
    return 1;
}

DWORD ov_cmd_dump(char * dstPath){
    printf("正在dump文件到 %s...\n", dstPath);
    //思路：先写主模块pe头，改对齐，之后写入整个主模块 -- 解析pe头的工作应该放初始化里，先这样写
    char pPeBuf[0x1000] = { 0 };
    ov_read(g_mainModBase, pPeBuf, 0x1000);
    //解析pe头，读目标的导出表
    IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER*)pPeBuf;
    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS*)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
    FILE * fp = fopen(dstPath, "wb");
    //int sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
    IMAGE_SECTION_HEADER * pSectionHeaders = 
        (IMAGE_SECTION_HEADER*)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    int numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
    //修改节的大小
    for (int i = 0; i < numberOfSections; i++){
        pSectionHeaders[i].SizeOfRawData = pSectionHeaders[i].Misc.VirtualSize;
        pSectionHeaders[i].PointerToRawData = pSectionHeaders[i].VirtualAddress;
    }
    //设置对齐
    pNtHeaders->OptionalHeader.FileAlignment = pNtHeaders->OptionalHeader.SectionAlignment;
    //把所有内存中的断点恢复
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == TRUE && g_bpArr[i].bpType&BP_TYPE_NORMAL){
            ov_write(g_bpArr[i].bpAddress, &g_bpArr[i].bpData, 1);
        }
    }
    //写pe头
    fwrite(pPeBuf, 0x1000, 1, fp);
    //写pe体
    char buf[0x1000];
    for (DWORD i = 0x1000; i < pNtHeaders->OptionalHeader.SizeOfImage; i+=0x1000){
        ov_read(i + g_mainModBase, buf, 0x1000);
        fwrite(buf, 0x1000, 1, fp);
    }
    
    if (fp){
        fclose(fp);
    }

    printf("dump完成\n", dstPath);
    //把所有内存中的断点打上
    char byte = 0xcc;
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == TRUE && g_bpArr[i].bpType&BP_TYPE_NORMAL){
            ov_write(g_bpArr[i].bpAddress, &byte, 1);
        }
    }
    return onCmd();
}

//设置内存断点
void setMemBp(DWORD bpAddress, DWORD bpLength, DWORD bpType){
    //先看有没有重复断点,有就直接返回
    for (int i = 0; i < 4; i++){
        if (g_bhArr[i].bpIsUsed == TRUE && g_bhArr[i].bpAddress == bpAddress){
            printf("此处已存在断点，清除后再设\n");
            return;
        }
    }
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpAddress == bpAddress && g_bpArr[i].bpIsUsed == TRUE){
            printf("此处已存在断点，清除后再设\n");
            return;
        }
    }

    HANDLE hProcess;
    if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_lpev->dwProcessId)) == NULL){
        printf("设置断点失败，打开进程句柄失败\n");
        return;
    }
    DWORD dwOld;
    if (VirtualProtectEx(hProcess, (LPVOID)(bpAddress & ~0xfff), 0x1000, PAGE_NOACCESS, &dwOld) == 0){
        printf("设置断点失败，设置内存属性失败\n");
        return;
    }

    /*把断点信息存储进断点结构数组*/
    //查找断点数组空闲位置
    int nIndex = 0;
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == FALSE){
            nIndex = i;
            break;
        }
    }

    //注意，如果此页原来已经有断点存在，则属性已经是NO_ACCESS,
    //我们要找到一个其他有效的内存断点，来获取原来的属性
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if ((bpAddress & ~0xfff) == g_bpArr[i].bpMemPage && g_bpArr[i].bpIsUsed==TRUE){
            dwOld = g_bpArr[i].bpMemOld;
        }
    }
    //填充断点信息结构
    g_bpArr[nIndex].bpAddress = bpAddress;
    g_bpArr[nIndex].bpIsUsed = TRUE;
    g_bpArr[nIndex].bpMemOld = dwOld;
    g_bpArr[nIndex].bpMemLen = bpLength;
    g_bpArr[nIndex].bpOrdin = nIndex;
    g_bpArr[nIndex].bpType = bpType;
    g_bpArr[nIndex].bpMemPage = bpAddress & ~0xfff;

    printf("内存断点设置成功\n");
}

DWORD ov_cmd_bm(DWORD bmAddress, DWORD bmLen, DWORD bmType){
    //先做永久断点
    sprintf(g_scpBuf, "bm %08x %08x %08x\n", bmAddress, bmLen, bmType);
    addScp(g_scpBuf);//添加到脚本

    setMemBp(bmAddress, bmLen, bmType);
    return onCmd();
}

void lsNormalBp(){
    printf("============ 一般断点列表 ============================\n");
    printf("序号       地址          代码        类型\n");
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == TRUE){
            if (g_bpArr[i].bpType & BP_TYPE_NORMAL){
                printf("%d", g_bpArr[i].bpOrdin);
                printf("          ");
                printf("0x%08x", g_bpArr[i].bpAddress);
                printf("    ");
                printf("%02x", (unsigned char)g_bpArr[i].bpData);
                printf("          ");
                if (g_bpArr[i].bpType & BP_TYPE_SYS){
                    printf("%s", "一次性");
                }
                else{
                    printf("%s", "重复");
                }
                printf("\n");
            }
        }
    }
    printf("=====================================================\n");
}
void lsMemBp(){
    printf("============ 内存断点列表 =============================\n");
    printf("序号       地址          长度        类型\n");
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == TRUE){
            if (g_bpArr[i].bpType & BP_TYPE_MEM_WRITE || 
                g_bpArr[i].bpType & BP_TYPE_MEM_READ){
                printf("%d", g_bpArr[i].bpOrdin);
                printf("          ");
                printf("0x%08x", g_bpArr[i].bpAddress);
                printf("    ");
                printf("%d", (unsigned char)g_bpArr[i].bpMemLen);
                printf("          ");
                if (g_bpArr[i].bpType & BP_TYPE_MEM_WRITE){
                    printf("%s", "写");
                }
                else{
                    printf("%s", "读或执行");
                }
                printf("\n");
            }
        }
    }
    printf("===================================================\n");
}

void delNormalBp(int ord){
    if (ord < 0 || ord >= BP_TOTAL_COUNT){
        return;
    }
    if (g_bpArr[ord].bpIsUsed == FALSE){
        return;
    }
    if (!(g_bpArr[ord].bpType & BP_TYPE_NORMAL)){
        return;
    }
    g_bpArr[ord].bpIsUsed = FALSE;
    ov_write(g_bpArr[ord].bpAddress, &g_bpArr[ord].bpData, 1);
    printf("一般断点删除成功\n");
}

void delMemBp(int ord){
    if (ord < 0 || ord >= BP_TOTAL_COUNT){
        return;
    }
    if (g_bpArr[ord].bpIsUsed == FALSE){
        return;
    }
    if (!(g_bpArr[ord].bpType & BP_TYPE_MEM_READ) && 
        !(g_bpArr[ord].bpType & BP_TYPE_MEM_WRITE)){
        return;
    }
    //遍历除ord外的所有有效断点,如果有，则不恢复内存属性
    int nIndex = -1;
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpIsUsed == TRUE &&
            g_bpArr[i].bpOrdin != ord &&
            g_bpArr[i].bpMemPage == g_bpArr[ord].bpMemPage
            ){
            nIndex = i;
            break;
        }
    }
    if (nIndex != -1){
        g_bpArr[ord].bpIsUsed = FALSE;
    }
    else{
        //ord是最后一个有效的该内存页断点，恢复属性
        g_bpArr[ord].bpIsUsed = FALSE;
        DWORD dwOld;
        VirtualProtectEx(g_hProcess, (LPVOID)g_bpArr[ord].bpMemPage,
            0x1000, g_bpArr[ord].bpMemOld, &dwOld);
        //g_bmSingel = -1;
    }
    printf("内存断点删除成功\n");
}

DWORD ov_cmd_bpl(){
    sprintf(g_scpBuf, "bpl\n");
    addScp(g_scpBuf);//添加到脚本
    lsNormalBp();
    return onCmd();
}
DWORD ov_cmd_bml(){
    sprintf(g_scpBuf, "bml\n");
    addScp(g_scpBuf);//添加到脚本
    lsMemBp();
    return onCmd();
}

DWORD ov_cmd_bpc(int ord){
    sprintf(g_scpBuf, "bpc %d\n", ord);
    addScp(g_scpBuf);//添加到脚本
    delNormalBp(ord);
    return onCmd();
}
DWORD ov_cmd_bmc(int ord){
    sprintf(g_scpBuf, "bmc %d\n", ord);
    addScp(g_scpBuf);//添加到脚本
    delMemBp(ord);
    return onCmd();
}

DWORD ov_cmd_bh(DWORD bhAddress, int bhLen, DWORD bhType){
    sprintf(g_scpBuf, "bh %08x %08x %08x\n", bhAddress, bhLen, bhType);
    addScp(g_scpBuf);//添加到脚本

    setHardBp(bhAddress, bhLen, bhType);
    return onCmd();
}

void setHardBp(DWORD bhAddress, int bhLen, DWORD bhType){
    //第0步是检查别设已经有的
    for (int i = 0; i < 4; i++){
        if (g_bhArr[i].bpIsUsed == TRUE && g_bhArr[i].bpAddress == bhAddress){
            printf("设置失败，禁止设置相同地址的硬断\n");
            return;
        }
    }
    for (int i = 0; i < BP_TOTAL_COUNT; i++){
        if (g_bpArr[i].bpAddress == bhAddress && g_bpArr[i].bpIsUsed == TRUE){
            printf("此处已存在断点，清除后再设\n");
            return;
        }
    }
    //第一步就是找到空闲的断点寄存器
    int nIndex = -1;
    for (int i = 0; i < 4; i++){
        if (g_bhArr[i].bpIsUsed == FALSE){
            nIndex = i;
            break;
        }
    }
    if (nIndex == -1){
        printf("硬件断点寄存器用完了，尝试清除断点后重设\n");
        return;
    }

    //填充硬件断点信息
    g_bhArr[nIndex].bpAddress = bhAddress;
    g_bhArr[nIndex].bpIsUsed = TRUE;
    g_bhArr[nIndex].bpType = bhType;
    g_bhArr[nIndex].bpLen = bhLen;

    //设置调试寄存器的值
    //获取相应的dr6，dr7,向dr0-3写入地址
    CONTEXT ctx;
    getRegs(&ctx);
    dr6 * d6 = (dr6*)&ctx.Dr6;
    dr7 * d7 = (dr7*)&ctx.Dr7;

    switch (nIndex){
    case 0:
        ctx.Dr0 = bhAddress;
        d7->L0 = 1;
        d7->LE0 = bhLen;
        if (bhType == BP_TYPE_HD_READ){
            d7->RW0 = 3;
        }
        else if (bhType == BP_TYPE_HD_WRITE){
            d7->RW0 = 1;
        }
        else if (bhType == BP_TYPE_HD_EXE){
            d7->RW0 = 0;
        }
        break;
    case 1:
        ctx.Dr1 = bhAddress;
        d7->L1 = 1;
        d7->LE1 = bhLen;
        if (bhType == BP_TYPE_HD_READ){
            d7->RW1 = 3;
        }
        else if (bhType == BP_TYPE_HD_WRITE){
            d7->RW1 = 1;
        }
        else if (bhType == BP_TYPE_HD_EXE){
            d7->RW1 = 0;
        }
        break;
    case 2:
        ctx.Dr2 = bhAddress;
        d7->L2 = 1;
        d7->LE2 = bhLen;
        if (bhType == BP_TYPE_HD_READ){
            d7->RW2 = 3;
        }
        else if (bhType == BP_TYPE_HD_WRITE){
            d7->RW2 = 1;
        }
        else if (bhType == BP_TYPE_HD_EXE){
            d7->RW2 = 0;
        }
        break;
    case 3:
        ctx.Dr3 = bhAddress;
        d7->L3 = 1;
        d7->LE3 = bhLen;
        if (bhType == BP_TYPE_HD_READ){
            d7->RW3 = 3;
        }
        else if (bhType == BP_TYPE_HD_WRITE){
            d7->RW3 = 1;
        }
        else if (bhType == BP_TYPE_HD_EXE){
            d7->RW3 = 0;
        }
        break;
    default:
        break;
    }
    ctx.Dr6 = 0;
    setRegs(&ctx);
    printf("硬件断点设置成功\n");
}
void lsHardBp(){
    printf("================硬件断点===============================================\n");
    printf("序号    调试寄存器     断点地址      断点类型      断点长度\n");
    for (int i = 0; i < 4; i++){
        if (g_bhArr[i].bpIsUsed == TRUE){
            printf("%d", i);
            printf("        ");
            if (i == 0){
                printf("dr0");
            }
            else if (i == 1){
                printf("dr1");
            }
            else if (i == 2){
                printf("dr2");
            }
            else if (i == 3){
                printf("dr3");
            }
            printf("             ");
            printf("0x%08x", g_bhArr[i].bpAddress);
            printf("    ");
            if (g_bhArr[i].bpType == BP_TYPE_HD_EXE){
                printf("执行");
            }
            else if (g_bhArr[i].bpType == BP_TYPE_HD_READ){
                printf("写入");
            }
            else if (g_bhArr[i].bpType == BP_TYPE_HD_WRITE){
                printf("读取");
            }
            printf("               ");
            printf("%d", g_bhArr[i].bpLen);
            printf("\n");
        }
    }
    printf("=======================================================================\n");
}

void delHardBp(int ord){
    if (ord < 0 || ord >= 4){
        printf("删除失败,序号输入错误\n");
        return;
    }
    if (g_bhArr[ord].bpIsUsed == FALSE){
        printf("不要重复删除断点\n");
        return;
    }

    //设置断点信息
    g_bhArr[ord].bpIsUsed = FALSE;

    //设调试寄存器
    CONTEXT ctx;
    getRegs(&ctx);
    dr6 * d6 = (dr6*)&ctx.Dr6;
    dr7 * d7 = (dr7*)&ctx.Dr7;
    switch (ord){
    case 0:
        d7->L0 = 0;
        break;
    case 1:
        d7->L1 = 0;
        break;
    case 2:
        d7->L2 = 0;
        break;
    case 3:
        d7->L3 = 0;
        break;
    default:
        break;
    }
    setRegs(&ctx);
}

DWORD ov_cmd_bhl(){
    sprintf(g_scpBuf, "bhl\n");
    addScp(g_scpBuf);//添加到脚本
    lsHardBp();
    return onCmd();
}

DWORD ov_cmd_bhc(int ord){
    sprintf(g_scpBuf, "bhc %d\n", ord);
    addScp(g_scpBuf);//添加到脚本

    delHardBp(ord);
    printf("删除硬件断点成功\n");
    return onCmd();
}

DWORD ov_cmd_ls(){
    return onLoadScript();
}

DWORD ov_cmd_es(){
    onExpScript();
    return onCmd();
}

DWORD onLoadScript(){
    FILE * fp = fopen("debug.scp","r");//检测有没有这个脚本
    if (fp == NULL){
        printf("加载脚本失败,脚本文件不存在\n");
        return onCmd();
    }
    //重定向标准输入
    rewind(stdin);
    fflush(stdin);
    if (freopen("debug.scp", "r", stdin) == NULL) {
        printf("无法重定向标准输入\n");
        fclose(fp);
        return onCmd();
    }
    //关闭原来的文件指针，因为freopen已经接管了
    fclose(fp);
    printf("开始执行脚本\n");
    g_isScpMod = TRUE;
    return onCmd();
}
DWORD onExpScript(){
    FILE * fp = fopen("debug.scp", "a");
    if (fp == NULL){
        printf("导出失败\n");
        return onCmd();
    }
    //小bug；未清理最后一行的scp_end标志,导致脚本有上次残留的记录

    //把有效命令写入脚本
    for (int i = 0; i < g_nScpIndex; i++){
        int nScpLen = strlen(g_scpData[i]);
        fwrite(g_scpData[i], nScpLen, 1, fp);
    }
    //写入结束标志
    fwrite("scp_end", 8, 1, fp);

    if (fp){
        fclose(fp);
    }
}

void addScp(char * scp){
    if (g_nScpIndex >= MAX_SCP_COUNT){
        return;
    }
    strcpy(g_scpData[g_nScpIndex], scp);
    g_nScpIndex++;
}