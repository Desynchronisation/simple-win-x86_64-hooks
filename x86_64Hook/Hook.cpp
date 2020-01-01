#include <iostream>
#include "Hook.h"

#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine/BeaEngine.h"


Hook::Hook(void* originalFuncPtr, void* hookFuncPtr, size_t length)
	:
#ifdef _WIN64
    m_jmpBytes{ 0x50,                                               //push rax
                0x48, 0xB8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //mov  rax, [QWORD]
                0xFF, 0xE0,                                         //jmp  rax
                0x58 },                                             //pop  rax
#else
    m_jmpBytes{ 0xE9, 0x0, 0x0, 0x0, 0x0 },                         //jmp  [DWORD]
#endif
	m_originalBytes(nullptr),
	m_length(length),
	m_originalFuncPtr(originalFuncPtr),
	m_hookFuncPtr(hookFuncPtr),
	m_protection(PAGE_EXECUTE_READWRITE),
	m_trampoline(m_originalBytes), 
	m_isHoked(false)
{
	if (m_originalFuncPtr)
	{
		calculateLength();

		m_originalBytes = (BYTE*)VirtualAlloc(0, m_length + 14, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		changeProtection();
#ifdef _WIN64
		m_originalBytes[0] = 0x58; //pop rax
		memcpy(m_originalBytes + 1, m_originalFuncPtr, m_length);
		calculateJump((BYTE*)m_originalFuncPtr + 13); //jump to pop rax
		memcpy(m_originalBytes + m_length + 1, m_jmpBytes, 13); //mov and jmp with push rax
#else
		memcpy(m_originalBytes, m_originalFuncPtr, m_length);
		calculateJump((BYTE*)m_originalFuncPtr + m_length, m_originalBytes + m_length);
		memcpy(m_originalBytes + m_length, m_jmpBytes, 5);
#endif
		changeProtection();
	}
}

Hook::~Hook()
{
	restore();
	if (m_originalBytes) {
		VirtualFree(m_originalBytes, m_length + 14, MEM_RELEASE);
	}
}

void Hook::calculateLength()
{
	if (m_length != 0) {
		return;
	}

#ifdef _WIN64
	size_t minLength = 14;
#else
	size_t minLength = 5;
#endif

	DISASM disasm = { 0 };
	disasm.EIP = (size_t)m_originalFuncPtr;

	while (m_length < minLength)
	{
		int currentLength = Disasm(&disasm);
		m_length += currentLength;
		disasm.EIP += currentLength;
	}
}

void Hook::NOP()
{
	if (!m_originalBytes) {
		return;
	}

	m_protection = PAGE_EXECUTE_READWRITE;
	changeProtection();
	memset(m_originalBytes, 0x90, m_length);
	changeProtection();
	m_isHoked = true;
}

bool Hook::restore()
{
	if (!m_isHoked) {
		return false;
	}

	m_protection = PAGE_EXECUTE_READWRITE;
	changeProtection();
#ifdef _WIN64
	memcpy(m_originalFuncPtr, m_originalBytes + 1, m_length);
#else
	memcpy(m_originalFuncPtr, m_originalBytes, m_length);
#endif
	changeProtection();
	m_isHoked = false;
	
	return true;
}

void Hook::calculateJump(void* to, void* from)
{
#ifdef _WIN64
	*(QWORD*)(m_jmpBytes + 3) = (QWORD)to;
#else
	*(DWORD*)(m_jmpBytes + 1) = ((DWORD)to - (DWORD)from) - 5;
#endif
}

void Hook::changeProtection()
{
	VirtualProtect(m_originalFuncPtr, m_length, m_protection, &m_protection);
}

void Hook::baseHook()
{
	m_protection = PAGE_EXECUTE_READWRITE;
	changeProtection();
	memset(m_originalFuncPtr, 0x90, m_length);

	calculateJump((BYTE*)m_hookFuncPtr, m_originalFuncPtr);

#ifdef _WIN64
	memcpy(m_originalFuncPtr, m_jmpBytes, 14);//mov and jmp with push,pop rax
#else
	memcpy(m_originalFuncPtr, m_jmpBytes, 5);
#endif

	changeProtection();
	m_isHoked = true;
}

BYTE*& Hook::hook()
{

#ifdef _WIN64
	m_trampoline = (BYTE*)m_originalFuncPtr + 13;//jump to pop rax
#else
	m_trampoline = (BYTE*)m_originalFuncPtr + m_length;
#endif

	if (!m_originalFuncPtr || !m_hookFuncPtr || m_isHoked) {
		return m_trampoline;
	}

	baseHook();
	return m_trampoline;
}

BYTE*& Hook::hookWithTrampoline()
{	
	if (!m_originalFuncPtr || !m_hookFuncPtr || m_isHoked) {
		return m_trampoline;
	}

	baseHook();
	m_trampoline = m_originalBytes;
	return m_trampoline;
}