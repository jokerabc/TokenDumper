#include "TokenDumper.h"

namespace tokenDumper {

	std::string TokenInformationClassToString(TOKEN_INFORMATION_CLASS infoClass) {

		switch (infoClass) {
		case TokenUser:
			return "TokenUser";
		case TokenIntegrityLevel:
			return "TokenIntegrityLevel";
		default: {
			std::stringstream ss;
			ss << "(" << static_cast<int>(infoClass) << ")";
			return ss.str();
		}
		}
	}
}