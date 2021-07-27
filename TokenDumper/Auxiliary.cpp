#include "stdafx.h"
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
};
