#pragma once

#ifndef HOOK_H_
#define HOOK_H_
#include <Windows.h>

typedef DWORD64 QWORD;

class Hook
{
private:
	BYTE	m_jmpBytes[14];
	BYTE*	m_originalBytes;
	size_t	m_length;
	void*	m_originalFuncPtr;
	void*	m_hookFuncPtr;
	DWORD	m_protection;
	BYTE*	m_trampoline;
	bool	m_isHoked;

	//Hook(const Hook& h) = delete;
	//Hook&operator=(const Hook& h) = delete;

	void calculateLength();
	void calculateJump(void* to, void* from = 0);
	void changeProtection();
	void baseHook();

public:
	Hook(void* originalFuncPtr, void* hookFuncPtr, size_t length = 0);
	~Hook();

	bool	isHooked() { return m_isHoked; }
	void	NOP();
	bool	restore();
	BYTE*&	hook();
	BYTE*&	hookWithTrampoline();
};

#endif // !HOOK_H_