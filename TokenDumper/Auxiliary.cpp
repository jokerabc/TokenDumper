#include "stdafx.h"
#include <vector>
#include <sddl.h>
#include "Auxiliary.h"

namespace tokenDumper {

	HANDLE GetProcessHandle(DWORD pid) {

		return OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	}

	std::string ConvertSidToString(PSID pSid) {

		LPSTR outStr = nullptr;
		if (!ConvertSidToStringSidA(pSid, &outStr))
			throw win32_exception(GetLastError(), "Failed ConvertSidToStringSidW in ConvertSidToString");

		std::string retval(outStr);
		LocalFree(outStr);

		return retval;
	}

	std::string ConvertLuidToString(PLUID pLuid) {

		std::vector<char> buf(3);
		DWORD cchName = static_cast<DWORD>(buf.size());
		if (!LookupPrivilegeNameA(NULL, pLuid, &buf[0], &cchName)) {

			DWORD err = GetLastError();
			if (ERROR_INSUFFICIENT_BUFFER == err) {
				buf.resize(cchName + static_cast<DWORD>(1));
				cchName = static_cast<DWORD>(buf.size());
				if (LookupPrivilegeNameA(NULL, pLuid, &buf[0], &cchName)) {
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

	std::string LookupAccount(PSID pSid) {

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
};
