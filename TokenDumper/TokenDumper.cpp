#include "TokenDumper.h"

namespace tokenDumper {

	std::string TokenInformationClassToString(TOKEN_INFORMATION_CLASS infoClass) {

		switch (infoClass) {
		case TokenUser:
			return "TokenUser";
		case TokenGroups:
			return "TokenGroups";
		case TokenIntegrityLevel:
			return "TokenIntegrityLevel";
		default: {
			std::stringstream ss;
			ss << "(" << static_cast<int>(infoClass) << ")";
			return ss.str();
		}
		}
	}

	std::vector<std::string> GroupAttributesToString(DWORD attributes) {

		std::vector<std::string> retval;
		if (SE_GROUP_MANDATORY & attributes)
			retval.emplace_back("Mandatory");
		if (SE_GROUP_ENABLED_BY_DEFAULT & attributes)
			retval.emplace_back("EnabledByDefault");
		if (SE_GROUP_ENABLED & attributes)
			retval.emplace_back("Enabled");
		if (SE_GROUP_OWNER & attributes)
			retval.emplace_back("Owner");
		if (SE_GROUP_USE_FOR_DENY_ONLY & attributes)
			retval.emplace_back("Deny");
		if (SE_GROUP_INTEGRITY & attributes)
			retval.emplace_back("Integrity");
		if (SE_GROUP_INTEGRITY_ENABLED & attributes)
			retval.emplace_back("IntegrityEnabled");
		if (SE_GROUP_LOGON_ID & attributes)
			retval.emplace_back("LogonID");
		if (SE_GROUP_RESOURCE & attributes)
			retval.emplace_back("Resource");

		return retval;
	}
	std::string FirstRidToString(DWORD rid) {
		switch (rid) {
		case SECURITY_DIALUP_RID:
			return "DIALUP";
		case SECURITY_NETWORK_RID:
			return "NETWORK";
		case SECURITY_BATCH_RID:
			return "BATCH";
		case SECURITY_INTERACTIVE_RID:
			return "INTERACTIVE";
		case SECURITY_LOGON_IDS_RID:
			return "LOGIN_IDS";
		case SECURITY_SERVICE_RID:
			return "SERIVCE";
		case SECURITY_ANONYMOUS_LOGON_RID:
			return "ANONYMOUS LOGON";
		case SECURITY_PROXY_RID:
			return "PROXY";
		case SECURITY_ENTERPRISE_CONTROLLERS_RID:
			return "ENTERPRISE_CONTROLLERS";
		case SECURITY_PRINCIPAL_SELF_RID:
			return "PRINCIPAL_SELF";
		case SECURITY_AUTHENTICATED_USER_RID:
			return "AUTHENTICATED_USER";
		case SECURITY_RESTRICTED_CODE_RID:
			return "RESTRICTED_CODE";
		case SECURITY_TERMINAL_SERVER_RID:
			return "TERMINAL_SERVER";
		case SECURITY_LOCAL_SYSTEM_RID:
			return "LOCAL_SYSTEM";
		case SECURITY_NT_NON_UNIQUE:
			return "NT_NON_UNIQUE";
		case SECURITY_BUILTIN_DOMAIN_RID:
			return "BUILTIN_DOMAIN";
		case SECURITY_WRITE_RESTRICTED_CODE_RID:
			return "RESTRICTED_CODE";
		default: {
			std::stringstream ss;
			ss << "Unknown(" << rid << ")";
			return ss.str();
		}
		}
	}

	std::string RidForGroupsToString(DWORD rid) {

		switch (rid) {
			//Aliases
		case DOMAIN_ALIAS_RID_ADMINS:
			return "Administrators";
		case DOMAIN_ALIAS_RID_USERS:
			return "Users";
		case DOMAIN_ALIAS_RID_GUESTS:
			return "Guests";
		case DOMAIN_ALIAS_RID_POWER_USERS:
			return "PowerUsers";

		default: {
			std::stringstream ss;
			ss << "Unknown(" << rid << ")";
			return ss.str();
		}
		}
	}

}