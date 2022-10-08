#pragma once

#include <stdexcept>
#include <string>
#include <sstream>
#include <Windows.h>
#include <accctrl.h>

namespace tokenDumper{

	HANDLE GetProcessHandle(DWORD pid);
	std::string ConvertSidToString(const PSID pSid);
	std::string ConvertPrivilegeToString(const LUID * pLuid);
	std::string ConvertLuidToString(const LUID * pLuid);
	std::string LookupAccount(const PSID pSid);
	std::string TrusteeToString(const PTRUSTEE_A pTrustee);

	class win32_exception : public std::runtime_error {
	public:
		win32_exception(DWORD lastError, const std::string& msg) : m_lastError(lastError), runtime_error(makeMessage(lastError, msg)) {
		}

		DWORD GetLastError() const { return m_lastError; }
	private:
		std::string makeMessage(DWORD lastError, const std::string & what_arg)
		{
			std::stringstream ss;
			//https://docs.microsoft.com/en-us/windows/win32/debug/retrieving-the-last-error-code
			LPVOID lpMsgBuf(nullptr);

			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				lastError,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPSTR)&lpMsgBuf,
				0,
				NULL);

			ss << what_arg << " : (" << lastError << ")" << static_cast<LPCSTR>(lpMsgBuf);
			LocalFree(lpMsgBuf);
			return ss.str();
		}
	private:
		DWORD m_lastError;
	};

	template <typename T>
	class ArrayDeleter 
	{
	public:
		explicit ArrayDeleter(T* obj) : m_pObj(obj) {}
		~ArrayDeleter() {
			delete[] m_pObj;
		}

		//non copyable
		ArrayDeleter(const ArrayDeleter&)				= delete;
		ArrayDeleter& operator=(const ArrayDeleter&)	= delete;

		const T* Get() const { return m_pObj; }
		T* Get() { return m_pObj; }

	private:
		T* m_pObj;
	};
};

