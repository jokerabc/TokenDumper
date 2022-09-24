#include "stdafx.h"
#include <vector>
#include <exception>
#include <string>
#include <sstream>
#include <iomanip>
#include <sddl.h>
#include "Auxiliary.h"

namespace tokenDumper {

	HANDLE GetProcessHandle(DWORD pid) {

		return OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	}

	std::string ConvertSidToString(const PSID pSid) {

		LPSTR outStr = nullptr;
		if (!ConvertSidToStringSidA(pSid, &outStr))
			throw win32_exception(GetLastError(), "Failed ConvertSidToStringSidW in ConvertSidToString");

		std::string retval(outStr);
		LocalFree(outStr);

		return retval;
	}

	std::string ConvertPrivilegeToString(const LUID * pLuid) {

		// const PLUID is LUID * const
		// API argument is non const PLUID, but I guess API might not modify this parameter.
		PLUID argPluid = const_cast<PLUID>(pLuid);

		std::vector<char> buf(3);
		DWORD cchName = static_cast<DWORD>(buf.size());
		if (!LookupPrivilegeNameA(NULL, argPluid, &buf[0], &cchName)) {

			DWORD err = GetLastError();
			if (ERROR_INSUFFICIENT_BUFFER == err) {
				buf.resize(cchName + static_cast<DWORD>(1));
				cchName = static_cast<DWORD>(buf.size());
				if (LookupPrivilegeNameA(NULL, argPluid, &buf[0], &cchName)) {
					return &buf[0];
				}
				else {
					err = GetLastError();
				}
			}

			throw win32_exception(err, "Failed to convert LUID to string.");

		}
		else {
			return &buf[0];
		}
	}

	std::string ConvertLuidToString(const LUID* pLuid) {

		std::stringstream ss;
		ss << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << pLuid->HighPart
			<< "-" << std::setw(8) << pLuid->LowPart;

		return ss.str();
	}
	std::string LookupAccount(const PSID pSid) {

		size_t initSize = 10;
		std::vector<char> bufName(initSize), bufDomainName(initSize);

		DWORD bufNameSize = static_cast<DWORD>(bufName.size());
		DWORD bufDomainNameSize = static_cast<DWORD>(bufDomainName.size());

		SID_NAME_USE nameUse;
		if (!LookupAccountSidA(NULL, pSid, &bufName[0], &bufNameSize, &bufDomainName[0], &bufDomainNameSize, &nameUse)) {

			DWORD err = GetLastError();
			BOOL success{ FALSE };

			if (ERROR_INSUFFICIENT_BUFFER == err) {
				DWORD newSize = (bufNameSize > bufDomainNameSize) ? bufNameSize : bufDomainNameSize;
				bufName.resize(newSize);
				bufDomainName.resize(newSize);

				bufNameSize = bufDomainNameSize = newSize;

				if (!LookupAccountSidA(NULL, pSid, &bufName[0], &bufNameSize, &bufDomainName[0], &bufDomainNameSize, &nameUse)) {
					err = GetLastError();
					success = FALSE;
				}
				else {
					success = TRUE;
				}

			}

			if (!success) {
				throw win32_exception(err, "Failed to call LookupAccountSidA in LookupAccount");
			}


		}

		std::string accountName;
		if ('\0' == bufDomainName[0]) {	//empty
			accountName = &bufName[0];
		}
		else {
			accountName = &bufDomainName[0];
			accountName += '\\';
			accountName += &bufName[0];

		}

		return accountName;
	}

	std::string TrusteeToString(const PTRUSTEE_A pTrustee) {

		if (TRUSTEE_BAD_FORM == pTrustee->TrusteeForm) {

			throw std::invalid_argument("Trustee is bad form in TrusteeToString");
		}

		if (TRUSTEE_IS_NAME == pTrustee->TrusteeForm) {
			return pTrustee->ptstrName;
		}
		else if (TRUSTEE_IS_SID == pTrustee->TrusteeForm) {

			return LookupAccount( reinterpret_cast<PSID>(pTrustee->ptstrName));
		}
		else if (TRUSTEE_IS_OBJECTS_AND_SID == pTrustee->TrusteeForm) {

			return LookupAccount( reinterpret_cast<POBJECTS_AND_SID>(pTrustee->ptstrName)->pSid);
		}
		else if (TRUSTEE_IS_OBJECTS_AND_NAME == pTrustee->TrusteeForm) {

			return reinterpret_cast<POBJECTS_AND_NAME_A>(pTrustee->ptstrName)->ptstrName;
		}
		else
		{
			std::stringstream ss;
			ss << "Invalid trustee form(" << static_cast<int>(pTrustee->TrusteeForm) << ") in TrusteeToString";
			throw std::invalid_argument(ss.str());
		}

	}
};
