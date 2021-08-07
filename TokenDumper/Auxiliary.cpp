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

};
