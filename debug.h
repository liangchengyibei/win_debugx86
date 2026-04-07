#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib,"dasm.lib")

__declspec(dllimport) extern "C" void __stdcall Decode2Asm(DWORD, DWORD, DWORD, DWORD);

void InitRes();
void startDebug(const char* szPath,const char* szCmdLine);
void eventLoop();
void getRegs(CONTEXT * pctx);
void showRegs(CONTEXT * pctx);
void getFlagRegStr(DWORD flags, char * output);
void addScp(char * scp);

int setNormalBp(DWORD bpAddress, int isbpSys);
void setMemBp(DWORD bpAddress, DWORD bpLength, DWORD bpType);
void setHardBp(DWORD bhAddress, int bhLen, DWORD bhType);
void lsNormalBp();
void lsMemBp();
void lsHardBp();
void delNormalBp(int ord);
void delMemBp(int ord);
void delHardBp(int ord);
int lookupApiName(DWORD codeAddress, char * szAsm);

DWORD onException();
DWORD onBreakPoint();
DWORD onSingleStep();
DWORD onMemBreakPoint();
DWORD onCreateProcess();
DWORD onLoadDll();
DWORD onUnLoadDll();
DWORD onLoadScript();
DWORD onExpScript();
DWORD onCmd();


DWORD ov_read(DWORD lpRemoteAddress, char * output, int size);
DWORD ov_write(DWORD lpRemoteAddress, const char * input, int size);
DWORD ov_dasm(DWORD lpAddress, int nLine);


DWORD ov_cmd_u(DWORD lpAddress);
DWORD ov_cmd_bp(DWORD bpAddress, int isbpSys);
DWORD ov_cmd_g(DWORD gAddress);
DWORD ov_cmd_t();
DWORD ov_cmd_trace(DWORD start,DWORD end,char * mod);
DWORD ov_cmd_p();
DWORD ov_cmd_r();
DWORD ov_cmd_dd(DWORD dataAddress);
DWORD ov_cmd_e(DWORD dataAddress);//没做脚本
DWORD ov_cmd_q();
DWORD ov_cmd_ml();
DWORD ov_cmd_dump(char * dstPath); //没做脚本
DWORD ov_cmd_bm(DWORD bmAddress, DWORD bmLen, DWORD bmType);
DWORD ov_cmd_bpl();
DWORD ov_cmd_bml();
DWORD ov_cmd_bpc(int ord);
DWORD ov_cmd_bmc(int ord);
DWORD ov_cmd_bh(DWORD bhAddress, int bhLen, DWORD bhType);
DWORD ov_cmd_bhl();
DWORD ov_cmd_bhc(int ord);
DWORD ov_cmd_ls();
DWORD ov_cmd_es();
//th
void inline SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

//断点信息结构
typedef struct BreakPointInfo{
    DWORD bpAddress;//断点地址
    char bpData;//断点数据
    DWORD bpMemOld;//内存旧的属性
    DWORD bpMemLen;//内存断点长度 1,2,4
    DWORD bpMemPage;//内存断点所在页地址
    int bpType;//断点类型
    int bpIsUsed;//断点是否有效
    int bpOrdin;//断点序号
}BPInfo;

typedef struct HardPointInfo{
    DWORD bpAddress;//断点地址
    int bpType;//断点类型
    int bpIsUsed;//断点是否有效
    int bpLen;
}HardPointInfo;

typedef struct ModInfo{
    char szDllName[MAX_PATH*2];
    DWORD pDllBase;
    int fUnicode;
    int isUse;
}ModInfo;

typedef struct dr7{
    unsigned L0 : 1;//局部线程
    unsigned G0 : 1;//所有线程，但对于intel来说不灵
    unsigned L1 : 1;
    unsigned G1 : 1;
    unsigned L2 : 1;
    unsigned G2 : 1;
    unsigned L3 : 1;
    unsigned G3 : 1;
    unsigned res : 8;
    unsigned RW0 : 2;//读、写、访问
    unsigned LE0 : 2;//断点位置的数据长度。如果是执行断点，必须设置为0
    unsigned RW1 : 2;
    unsigned LE1 : 2;
    unsigned RW2 : 2;
    unsigned LE2 : 2;
    unsigned RW3 : 2;
    unsigned LE3 : 2;
}dr7;
typedef struct dr6{
    unsigned B0 : 1;//如果命中dr0，此位为1
    unsigned B1 : 1;
    unsigned B2 : 1;
    unsigned B3 : 1;
    unsigned res : 28;
}dr6;