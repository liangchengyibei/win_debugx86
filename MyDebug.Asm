
.386
.model flat,stdcall
option casemap:none

include MyDebug.inc
include windows.inc
include kernel32.inc
include user32.inc
includelib kernel32.lib
includelib user32.lib
includelib msvcrt.lib
includelib dasm.lib

rewind proto c :dword
strtoul proto c :dword,:dword,:dword
strcmp proto c :dword,:dword
printf proto c :dword,:VARARG
wprintf proto c :dword,:VARARG
gets proto c :dword
strtok proto c :dword,:dword
scanf proto c :dword,:VARARG
system proto c :dword
memset proto c :dword,:dword,:dword
memcpy proto c :dword,:dword,:dword

malloc proto c :dword
free proto c :dword
Decode2Asm  PROTO :dword,:dword,:dword,:dword

_breakPointInfo struct 
    _bpAdress dd 0
    _isOnce dd 0
    _bpType dd 0 ;0:int3 1:mem_exc
    _isUsed dd 0
    _oldMemType dd 0
    _oldCode db 0
_breakPointInfo ends

.const 
    _of1 db "OF=1 ",0
    _of0 db "OF=0 ",0
    _df1 db "DF=1 ",0
    _df0 db "DF=0 ",0
    _if1 db "IF=1 ",0
    _if0 db "IF=0 ",0
    _sf1 db "SF=1 ",0
    _sf0 db "SF=0 ",0
    _zf1 db "ZF=1 ",0
    _zf0 db "ZF=0 ",0
    _af1 db "AF=1 ",0
    _af0 db "AF=0 ",0
    _pf1 db "PF=1 ",0
    _pf0 db "PF=0 ",0
    _cf1 db "CF=1 ",0
    _cf0 db "CF=0 ",0
    
    szSysPause db "pause",0
    szTestFmt db "test string:%s",0
    szTestMsg db "this is my debug",0
    szTestInputMsg db "%s",0
    szErrCreateProcess db "CreateProcess Err!",0
    szErrOpenProcess db "OpenProcess Err!",0
    ;szDebugedPath db "D:\CR52\myPro\project\MyDebug\hello.exe",0
    szDebugedPath db "hello.exe",0
    szLogDllLoadFmtA db "ModLoad: %08x %08x   %s",0ah,0dh,0
    szLogDllLoadFmtW dw "M","o","d","L","o","a","d",":"," ","%","0","8","x"," ","%","0","8","x"," "," "," ","%","s",0ah,0,0dh,0,0,0

    szFmtShowRegs db "eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x",0ah,0dh
                  db "eip=%08x esp=%08x ebp=%08x iopl=%d         %s",0ah,0dh
                  db "cs=%04x  ss=%04x  ds=%04x  es=%04x  fs=%04x  gs=%04x             efl=%08x",0ah,0dh,0
    
    szFmtDword db "%08x",0   
    szFmtAddress db "%p:",0
    szFmtCode db "%02X ",0
    szFmtSpace db "   ",0
    szFmtStr db "%s",0ah,0dh,0
    szFmtInputStr db "%s",0
    szFmtCmd db " ",0
    szFmtCreateProcessEvent db "entryPoint in:%p",0ah,0dh,0
    
    szCmdMsg db "[cmd]",0
    szCmdMsgHelp db "help",0
    szCmdHelp db "look code: u [0xaddress] [nLine]  :: u 00401000 10",0ah,0dh
              db "look Regs: r                      :: r            ",0ah,0dh
              db "goto code: g                      :: g            ",0ah,0dh,0
    szCmd_u db "u",0
    szCmd_g db "g",0
    szCmd_r db "r",0
    szCmd_t db "t",0
    szCmd_p db "p",0
    szCmd_bp db "bp",0
    
.data
    
    szTestInput db 1024 dup(0)
    lpEv dd 0   ;ptr DEBUG_EVENT
    szOutDllInfo db 4096 dup(0)
    lpLastCodeAddress dd 0
    
    g_isStep dd 0
    g_bpInfoArr _breakPointInfo 4096 dup(<>)
    g_bpNum dd 0
    g_isSysBp dd 0
.code

_GetFlagString proc uses ebx esi edi, flags:DWORD, output:PTR BYTE
    mov esi, output
    mov ebx, flags

    mov eax, ebx
    and eax, 800h
    .if eax
        invoke wsprintf,esi,offset _of1
    .else
        invoke wsprintf,esi,offset _of0
    .endif
    add esi, eax

    mov eax, ebx
    and eax, 400h
    .if eax
        invoke wsprintf,esi,offset _df1
    .else
        invoke wsprintf,esi,offset _df0
    .endif
    add esi, eax

    mov eax, ebx
    and eax, 200h
    .if eax
        invoke wsprintf,esi,offset _if1
    .else
        invoke wsprintf,esi,offset _if0
    .endif
    add esi, eax

    mov eax, ebx
    and eax, 80h
    .if eax
        invoke wsprintf,esi,offset _sf1
    .else
        invoke wsprintf,esi,offset _sf0
    .endif
    add esi, eax
    
    mov eax, ebx
    and eax, 40h
    .if eax
        invoke wsprintf,esi,offset _zf1
    .else
        invoke wsprintf,esi,offset _zf0
    .endif
    add esi, eax

    mov eax, ebx
    and eax, 10h
    .if eax
        invoke wsprintf,esi,offset _af1
    .else
        invoke wsprintf,esi,offset _af0
    .endif
    add esi, eax
    
    mov eax, ebx
    and eax, 4
    .if eax
        invoke wsprintf,esi,offset _pf1
    .else
        invoke wsprintf,esi,offset _pf0
    .endif
    add esi, eax
    
    mov eax, ebx
    and eax, 1
    .if eax
        invoke wsprintf,esi,offset _cf1
    .else
        invoke wsprintf,esi,offset _cf0
    .endif
    add esi, eax
    
    ret
_GetFlagString endp
;DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT);
;DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT);
;DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT);
;DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT);
;DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT);
;DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT);
;DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT);
;DWORD OnRipEvent(const LPDEBUG_EVENT);

_getRegs proc uses ebx esi edi lpContext:ptr CONTEXT
    LOCAL @h:dword
    
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT 
    invoke OpenThread,THREAD_ALL_ACCESS,FALSE,[esi].dwThreadId
    mov @h,eax
    mov edi,lpContext
    assume edi:ptr CONTEXT
    mov [edi].ContextFlags,CONTEXT_ALL
    invoke GetThreadContext,@h,lpContext
    invoke CloseHandle,@h
    ret

_getRegs endp

_setRegs proc uses ebx esi edi lpContext:ptr CONTEXT
    LOCAL @h:dword
    
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT 
    invoke OpenThread,THREAD_ALL_ACCESS,FALSE,[esi].dwThreadId
    mov @h,eax
    mov edi,lpContext
    assume edi:ptr CONTEXT
    mov [edi].ContextFlags,CONTEXT_ALL
    invoke SetThreadContext,@h,lpContext
    invoke CloseHandle,@h
    ret

_setRegs endp

_showRegs proc uses ebx esi edi lpCtx:dword
    LOCAL @buf[1024]:byte
    LOCAL @iopl:dword
    LOCAL @flagBuffer[64]:byte
     
    mov @iopl,0
    mov esi,lpCtx
    assume esi:ptr CONTEXT
    invoke _GetFlagString,[esi].regFlag,addr @flagBuffer
    
    mov eax,[esi].regFlag
    shr eax,12
    and eax,03h
    mov @iopl,eax
    push [esi].regFlag
    push [esi].regGs
    push [esi].regFs
    push [esi].regEs
    push [esi].regDs
    push [esi].regSs
    push [esi].regCs
    lea eax,@flagBuffer
    push eax
    push @iopl
    push [esi].regEbp
    push [esi].regEsp
    push [esi].regEip
    push [esi].regEdi
    push [esi].regEsi
    push [esi].regEdx
    push [esi].regEcx
    push [esi].regEbx
    push [esi].regEax
    push offset szFmtShowRegs
    lea eax,@buf
    push eax
    call wsprintf
    
    invoke printf,addr @buf
    ret

_showRegs endp

_read proc uses ebx esi edi lpDst:dword,lpOut:dword,bufSize:dword
    
    LOCAL @handle:dword
    LOCAL @ret:dword
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT
    
    invoke OpenProcess,PROCESS_ALL_ACCESS,FALSE,[esi].dwProcessId
    mov @handle,eax
    .if eax==0
        invoke printf,offset szErrOpenProcess
    .endif
    
    invoke ReadProcessMemory,@handle,lpDst,lpOut,bufSize,addr @ret
    invoke CloseHandle,@handle
    
    mov eax,@ret
    ret
_read endp

_write proc uses ebx esi edi lpDst:dword,lpIn:dword,bufSize:dword
    
    LOCAL @handle:dword
    LOCAL @ret:dword
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT
    
    invoke OpenProcess,PROCESS_ALL_ACCESS,FALSE,[esi].dwProcessId
    mov @handle,eax
    .if eax==0
        invoke printf,offset szErrOpenProcess
    .endif
    
    invoke WriteProcessMemory,@handle,lpDst,lpIn,bufSize,addr @ret
    invoke CloseHandle,@handle
    
    mov eax,@ret
    ret
_write endp

_OnLoadDllDebugEvent proc uses ebx esi edi
    LOCAL @dllInfo:ptr LOAD_DLL_DEBUG_INFO
    LOCAL @buf[1024]:byte
    LOCAL @lpNameAddress:dword
    
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT
    lea eax,[esi].u.LoadDll
    mov @dllInfo,eax
    mov esi,@dllInfo
    assume esi:ptr LOAD_DLL_DEBUG_INFO
    
    invoke _read,[esi].lpImageName,addr @lpNameAddress,4
    .if @lpNameAddress==0
        ret
    .endif
    invoke _read,@lpNameAddress,addr @buf,1024
    
    .if [esi].fUnicode == 0 ;ANSI
        
        invoke wsprintfA,offset szOutDllInfo,offset szLogDllLoadFmtA,
            [esi].lpBaseOfDll,[esi].dwDebugInfoFileOffset,addr @buf
        invoke printf,offset szOutDllInfo
        
    .else ;Unicide
        invoke wsprintfW,offset szOutDllInfo,offset szLogDllLoadFmtW,
            [esi].lpBaseOfDll,[esi].dwDebugInfoFileOffset,addr @buf
        invoke wprintf,offset szOutDllInfo
        
    .endif
    ret
_OnLoadDllDebugEvent endp

_OnCreateProcessDebugEvent proc uses ebx esi edi
    LOCAL @szBuf[1024]:dword
    LOCAL @bpInfo:_breakPointInfo
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT
    lea eax,[esi].u.CreateProcessInfo
    mov edi,eax
    assume edi:ptr CREATE_PROCESS_DEBUG_INFO 
    
    invoke wsprintf,addr @szBuf,offset szFmtCreateProcessEvent,[edi].lpStartAddress
    invoke printf,addr @szBuf
    
    ;set entrypoint breakpoint
    mov eax,[edi].lpStartAddress
    mov @bpInfo._bpAdress,eax
    mov @bpInfo._isOnce,1
    mov @bpInfo._bpType,0
    mov @bpInfo._isUsed,1
    invoke _setBp,addr @bpInfo
    ret
    
_OnCreateProcessDebugEvent endp

_testApi proc uses ebx esi edi
    
    invoke printf,offset szTestFmt,offset szTestMsg
    invoke scanf,offset szTestInputMsg,offset szTestInput
    invoke printf,offset szTestInput 
    
    ret

_testApi endp

_startDebug proc uses ebx esi edi szPath:dword,szCmdLine:dword

    LOCAL @si:STARTUPINFO
    LOCAL @pi:PROCESS_INFORMATION
    LOCAL @ret:dword
    
    invoke malloc,sizeof DEBUG_EVENT
    mov lpEv,eax
    
    invoke memset,addr @si,0,sizeof STARTUPINFO
    invoke memset,addr @pi,0,sizeof PROCESS_INFORMATION
    
    mov @si.cb,sizeof STARTUPINFO
    
    invoke CreateProcess,szPath,szCmdLine,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,
                        NULL,NULL,addr @si,addr @pi
    mov @ret,eax
    
    .if @ret==0
        invoke printf,offset szErrCreateProcess
        mov eax,-1
        ret
    .endif
    
    
    call _eventLoop
    
    ret
_startDebug endp

_endDebug proc uses ebx esi edi 
    
    .if lpEv!=0
        invoke free,lpEv
    .endif
    ret
_endDebug endp

_eventLoop proc uses ebx esi edi
    LOCAL @Info[1024]:byte
    LOCAL @dwContinueStatus:dword
    mov @dwContinueStatus,DBG_CONTINUE
    
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT
    .while TRUE
        invoke WaitForDebugEvent,lpEv,INFINITE
        
        .if [esi].dwDebugEventCode == EXCEPTION_DEBUG_EVENT
            mov eax,[esi].u.Exception.pExceptionRecord.ExceptionCode
            .if eax == EXCEPTION_BREAKPOINT ;int 3
                invoke _onBreakPoint
                mov @dwContinueStatus,eax
                
            .elseif eax == EXCEPTION_SINGLE_STEP ; step
                invoke _onSingleStep
                mov @dwContinueStatus,eax
            .else ;default
                
            .endif
        .elseif [esi].dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT
        .elseif [esi].dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT
            invoke _OnCreateProcessDebugEvent
        .elseif [esi].dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT
        .elseif [esi].dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
        .elseif [esi].dwDebugEventCode == LOAD_DLL_DEBUG_EVENT    
            invoke _OnLoadDllDebugEvent
        .elseif [esi].dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT
        .elseif [esi].dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT
        .endif
        
        invoke ContinueDebugEvent,[esi].dwProcessId,[esi].dwThreadId,@dwContinueStatus        
    .endw    
    ret
_eventLoop endp

_dasm proc uses ebx esi edi lpAddress:dword,nLine:dword
    LOCAL @ctx:CONTEXT
    LOCAL @codeBuf[4096]:byte
    LOCAL @szAsm[1024]:byte
    LOCAL @nCodeSizeOfDisAsm:dword
    LOCAL @localpAddr:dword
    LOCAL @index:dword
    LOCAL @index1:dword
    LOCAL @numofspace:dword
    
    mov @index,0
    mov @index1,0

    
    .if lpAddress==0
        .if lpLastCodeAddress==0
            invoke _getRegs,addr @ctx
            mov eax,@ctx.regEip
            mov lpAddress,eax
        .else
            mov eax,lpLastCodeAddress
            mov lpAddress,eax
        .endif
    .endif
    
    invoke _read,lpAddress,addr @codeBuf,sizeof @codeBuf
    .if eax<0
        ret
    .endif
    
    lea esi,@codeBuf
    lea edi,@szAsm
    mov eax,lpAddress
    mov @localpAddr,eax

    .while TRUE
        mov @numofspace,08h
        mov eax,nLine
        
        .break.if @index1>=eax
        
        invoke Decode2Asm,esi,edi,addr @nCodeSizeOfDisAsm,@localpAddr
        mov eax,@nCodeSizeOfDisAsm
        sub @numofspace,eax
        
        invoke printf,offset szFmtAddress,@localpAddr ;address
        
        mov @index,0
        .while TRUE
            mov eax,@nCodeSizeOfDisAsm
            .break.if @index>=eax
            lea eax,@index
            mov eax,[eax]
            lea edx,[esi + eax]
            xor eax,eax
            mov al,byte ptr [edx]
            push eax
            push offset szFmtCode
            call printf
            inc @index
        .endw
        
        mov @index,0
        .while TRUE
            mov eax,@numofspace
            .break.if @index>=eax
            invoke printf,offset szFmtSpace
            inc @index
        .endw

        invoke printf,offset szFmtStr,edi
        
        add esi,@nCodeSizeOfDisAsm
        mov eax,@nCodeSizeOfDisAsm
        add @localpAddr,eax
        inc @index1
    .endw
    mov eax,@localpAddr
    mov lpLastCodeAddress,eax
    
    xor eax,eax
    ret

_dasm endp

_onBreakPoint proc uses ebx esi edi 

    LOCAL @oldCode:byte
    LOCAL @index:dword
    LOCAL @ctx:CONTEXT
    LOCAL @h:dword
    LOCAL @szTestBuf[16]:byte
    
    ;invoke MessageBeep,0FFFFFFFFh
    mov edi,offset g_bpInfoArr
    assume edi:ptr _breakPointInfo
    mov esi,lpEv
    assume esi:ptr DEBUG_EVENT
    
    .if g_isSysBp!=1
        mov g_isSysBp,1
        invoke _getRegs,addr @ctx
        invoke _showRegs,addr @ctx
        invoke _dasm,@ctx.regEip,1
        invoke _ExcCmd
        ret
    
    .else
        mov @index,0
        .while TRUE
            mov eax,@index
            .break.if eax>=g_bpNum
            mov eax,[esi].u.Exception.pExceptionRecord.ExceptionAddress
            .if eax == [edi]._bpAdress && [edi]._isUsed==1
                .break
            .endif
            
            add edi,sizeof _breakPointInfo
            inc @index
        .endw
    
        
        mov eax,g_bpNum
        .if eax==@index
            ;not find
            mov eax,DBG_EXCEPTION_NOT_HANDLED
            ret
        .else
            ;find
            ;invoke MessageBox,0,0,0,0
            lea eax,[edi]._oldCode
            mov dl,byte ptr [eax]
            mov @oldCode,dl
            movzx eax, @oldCode
            invoke _write,[edi]._bpAdress,addr @oldCode,1
            invoke OpenProcess,PROCESS_ALL_ACCESS,FALSE,[esi].dwProcessId
            mov @h,eax
            invoke FlushInstructionCache ,@h,[edi]._bpAdress,10
            invoke _getRegs,addr @ctx
            sub @ctx.regEip,1
            invoke _setRegs,addr @ctx
            invoke _showRegs,addr @ctx
            invoke _dasm,@ctx.regEip,1
            .if [edi]._isOnce==1
                mov [edi]._isUsed,0
                sub g_bpNum,1
            .endif
            invoke _ExcCmd            
            ret
        .endif
    .endif

    ret
_onBreakPoint endp

_ExcCmd proc uses ebx esi edi
    LOCAL @cmdInputBuf[1024]:byte
    LOCAL @cmd:dword
    LOCAL @param1:dword
    LOCAL @param2:dword

    invoke printf,offset szCmdMsg
    invoke gets,addr @cmdInputBuf
    
    
    ;parse cmd------------------------------------------------------------------   
    invoke strtok,addr @cmdInputBuf,offset szFmtCmd
    mov @cmd,eax
    .if @cmd==0
        mov eax,DBG_CONTINUE
        invoke _ExcCmd
        ret
    .endif
    
    .if @cmd!=0
        invoke strtok,NULL,offset szFmtCmd
        mov @param1,eax
        .if @param2!=0
            invoke strtok,NULL,offset szFmtCmd
            mov @param2,eax
        .endif
    .endif
    
    ;help------------------------------------------------------------------
    invoke strcmp,offset szCmdMsgHelp,@cmd
    .if eax==0
        invoke printf,offset szCmdHelp
        invoke _ExcCmd
        ret
    .endif
    
    ;u------------------------------------------------------------------
    invoke strcmp,offset szCmd_u,@cmd
    .if eax==0
        invoke _cmd_u,@param1,@param2
        invoke _ExcCmd
        ret
    .endif
    
    ;r------------------------------------------------------------------
    invoke strcmp,offset szCmd_r,@cmd
    .if eax==0
        invoke _cmd_regs,@param1,@param2
        invoke _ExcCmd
        ret
    .endif
    
    ;g-------------------------------------------------------------------
    invoke strcmp,offset szCmd_g,@cmd
    .if eax==0
        mov eax,DBG_CONTINUE
        ret
    .endif

    ;t-------------------------------------------------------------------
    invoke strcmp,offset szCmd_t,@cmd
    .if eax==0
        call _cmd_t
        ret
    .endif
    
    ;bp-------------------------------------------------------------------
    invoke strcmp,offset szCmd_bp,@cmd
    .if eax==0
        invoke _cmd_bp,@param1,@param2
        invoke _ExcCmd
        ret
    .endif

    invoke GetStdHandle,STD_INPUT_HANDLE
    invoke FlushConsoleInputBuffer,eax
    
    invoke _ExcCmd
    
    
    ret
_ExcCmd endp

_cmd_bp proc uses ebx esi edi param1:dword,param2:dword

    LOCAL @pAddressParam:dword
    LOCAL @nLineParam:dword
    LOCAL @bpInfo:_breakPointInfo
    LOCAL @ctx:CONTEXT
    
    invoke _getRegs,addr @ctx
    mov eax,@ctx.regEip
    
    mov @pAddressParam,eax
    mov @nLineParam,0
    
    .if param1!=0
        invoke strtoul,param1,NULL,16
        mov @pAddressParam,eax
    .endif
    .if param2!=0
        invoke strtoul,param2,NULL,10
        mov @nLineParam,eax
    .endif
    
    mov eax,@pAddressParam
    mov @bpInfo._bpAdress,eax
    mov eax,@nLineParam
    mov @bpInfo._isOnce,eax
    mov @bpInfo._bpType,0
    mov @bpInfo._isUsed,1
    
    invoke _setBp,addr @bpInfo
    
    ret
_cmd_bp endp

_cmd_u proc uses ebx esi edi param1:dword,param2:dword
    
    LOCAL @pAddressParam:dword
    LOCAL @nLineParam:dword
    
    mov @pAddressParam,0
    mov @nLineParam,8
    .if param1!=0
        invoke strtoul,param1,NULL,16
        mov @pAddressParam,eax
    .endif
    .if param2!=0
        invoke strtoul,param2,NULL,10
        mov @nLineParam,eax
    .endif
        
    invoke _dasm,@pAddressParam,@nLineParam
    ret
_cmd_u endp

_cmd_regs proc uses ebx esi edi param1:dword,param2:dword
    LOCAL @ctx:CONTEXT
    .if param1==0
        invoke _getRegs,addr @ctx
        invoke _showRegs,addr @ctx
        
    .elseif param1!=0 && param2!=0
        ;set regs
    .endif    
    ret
_cmd_regs endp

_cmd_t proc uses ebx esi edi
    LOCAL @ctx:CONTEXT
    invoke _getRegs,addr @ctx
    or @ctx.regFlag,0100h
    invoke _setRegs,addr @ctx
    mov g_isStep,1
    mov eax,DBG_CONTINUE
    ret
_cmd_t endp

_setBp proc uses ebx esi edi bpInfo:ptr _breakPointInfo
    ;g_bpInfoArr
    LOCAL @poldCode:dword
    LOCAL @int3:byte
    LOCAL @poldMemType:dword
    LOCAL @h:dword
    LOCAL @pbpMemAddress:dword
    
    mov @int3,0cch
    
    mov edi,offset g_bpInfoArr
    assume edi:ptr _breakPointInfo
    
    .while TRUE
        .break.if [edi]._isUsed==0
        add edi,sizeof _breakPointInfo
    .endw

    invoke memcpy,edi,bpInfo,sizeof _breakPointInfo
    
    lea eax,[edi]._oldCode
    mov @poldCode,eax
    lea eax,[edi]._oldMemType
    mov @poldMemType,eax
    
    mov esi,bpInfo
    assume esi:ptr _breakPointInfo
    mov eax,[esi]._bpType
    .if eax==0 ;int 3
        invoke _read,[esi]._bpAdress,@poldCode,1
        invoke _write,[esi]._bpAdress,addr @int3,1
    .elseif eax==1 ;mem_exc
        mov edi,lpEv
        assume edi:ptr DEBUG_EVENT
        invoke OpenProcess,PROCESS_ALL_ACCESS,FALSE,[edi].dwProcessId
        mov @h,eax
        mov eax,[esi]._bpAdress
        and eax,0fffff000h
        mov @pbpMemAddress,eax
        invoke VirtualProtectEx,@h,@pbpMemAddress,01000h,PAGE_NOACCESS,@poldMemType
    .endif
    
    invoke CloseHandle,@h
    add g_bpNum,1
    ret

_setBp endp

_onSingleStep proc uses ebx esi edi
    LOCAL @ctx:CONTEXT
    LOCAL @ret:dword

    mov @ret,DBG_EXCEPTION_NOT_HANDLED
    .if g_isStep==1
        mov g_isStep,0 
        invoke _getRegs,addr @ctx
        invoke _showRegs,addr @ctx
        invoke _dasm,@ctx.regEip,1
        invoke _ExcCmd
        mov @ret,eax
    .else

    .endif
    
    mov eax,@ret
    ret

_onSingleStep endp

_main proc uses ebx esi edi
    invoke _startDebug,offset szDebugedPath,NULL
    ;call _testApi
    invoke _endDebug
    invoke system,offset szSysPause
    ret
_main endp

    start:
    call _main
    invoke ExitProcess,0
    end start