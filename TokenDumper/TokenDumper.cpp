#include "TokenDumper.h"

namespace tokenDumper {

	std::string TokenInformationClassToString(TOKEN_INFORMATION_CLASS infoClass) {

		switch (infoClass) {
		case TokenUser:
			return "TokenUser";
		case TokenGroups:
			return "TokenGroups";
		case TokenPrivileges:
			return "TokenPrivilges";
		case TokenOwner:
			return "TokenOwner";
		case TokenPrimaryGroup:
			return "TokenPrimaryGroup";
		case TokenDefaultDacl:
			return "TokenDefaultDacl";
		case TokenSource:
			return "TokenSource";
		case TokenType:
			return "TokenType";
		case TokenImpersonationLevel:
			return "TokenImpersonationLevel";
		case TokenIntegrityLevel:
			return "TokenIntegrityLevel";
		case TokenStatistics:
			return "TokenStatistics";
		case TokenRestrictedSids:
			return "TokenRestrictedSids";
		case TokenSessionId:
			return "TokenSessionId";
		case TokenGroupsAndPrivileges:
			return "TokenGroupsAndPrivileges";
		default: {
			std::stringstream ss;
			ss << "(" << static_cast<int>(infoClass) << ")";
			return ss.str();
		}
		}
	}

	std::string TrusteeTypeToString(TRUSTEE_TYPE type) {

		switch (type) {
		case TRUSTEE_IS_UNKNOWN:
			return "Unknown";
		case TRUSTEE_IS_USER:
			return "User";
		case TRUSTEE_IS_GROUP:
			return "Group";
		case TRUSTEE_IS_DOMAIN:
			return "Domain";
		case TRUSTEE_IS_ALIAS:
			return "Alias";
		case TRUSTEE_IS_WELL_KNOWN_GROUP:
			return "WellKnownGroup";
		case TRUSTEE_IS_DELETED:
			return "Deleted";
		case TRUSTEE_IS_INVALID:
			return "Invalid";
		case TRUSTEE_IS_COMPUTER:
			return "Computer";
		default: {
			std::stringstream ss;
			ss << "(" << static_cast<int>(type) << ")";
			return ss.str();
		}
		}
	}

	std::vector<std::string> AccessMaskToStringVec(ACCESS_MASK mask) {

		std::vector<std::string> retval;
		// Generic rights
		if (mask & GENERIC_READ)
			retval.emplace_back("GENERIC_READ");
		if (mask & GENERIC_WRITE)
			retval.emplace_back("GENERIC_WRITE");
		if (mask & GENERIC_EXECUTE)
			retval.emplace_back("GENERIC_EXECUTE");
		if (mask & GENERIC_ALL)
			retval.emplace_back("GENERIC_ALL");

		// Standard rights
		if( mask & STANDARD_RIGHTS_ALL)
			retval.emplace_back("STANDARD_RIGHTS_ALL");
		else if( mask & STANDARD_RIGHTS_REQUIRED)
			retval.emplace_back("STANDARD_RIGHTS_REQUIRED");
		else {

			if (mask & DELETE)
				retval.emplace_back("DELETE");
			if (mask & READ_CONTROL)
				retval.emplace_back("READ_CONTROL");
			if (mask & WRITE_DAC)
				retval.emplace_back("WRITE_DAC");
			if (mask & WRITE_OWNER)
				retval.emplace_back("WRITE_OWNER");
			if (mask & SYNCHRONIZE)
				retval.emplace_back("SYNCHRONIZE");
		}


		// Specific rights

		if( mask & SPECIFIC_RIGHTS_ALL)
			retval.emplace_back("SPECIFIC_RIGHTS_ALL");
		else {

			if( mask & PROCESS_TERMINATE)
				retval.emplace_back("PROCESS_TERMINATE");
			if( mask & PROCESS_CREATE_THREAD)
				retval.emplace_back("PROCESS_CREATE_THREAD");
			if( mask & PROCESS_SET_SESSIONID)
				retval.emplace_back("PROCESS_SET_SESSIONID");
			if( mask & PROCESS_VM_OPERATION)
				retval.emplace_back("PROCESS_VM_OPERATION");
			if( mask & PROCESS_VM_READ)
				retval.emplace_back("PROCESS_VM_READ");
			if( mask & PROCESS_VM_WRITE)
				retval.emplace_back("PROCESS_VM_WRITE");
			if( mask & PROCESS_DUP_HANDLE)
				retval.emplace_back("PROCESS_DUP_HANDLE");
			if( mask & PROCESS_CREATE_PROCESS)
				retval.emplace_back("PROCESS_CREATE_PROCESS");
			if( mask & PROCESS_SET_QUOTA)
				retval.emplace_back("PROCESS_SET_QUOTA");
			if( mask & PROCESS_SET_INFORMATION)
				retval.emplace_back("PROCESS_SET_INFORMATION");
			if( mask & PROCESS_QUERY_INFORMATION)
				retval.emplace_back("PROCESS_QUERY_INFORMATION");
			if( mask & PROCESS_SUSPEND_RESUME)
				retval.emplace_back("PROCESS_SUSPEND_RESUME");
			if( mask & PROCESS_QUERY_LIMITED_INFORMATION)
				retval.emplace_back("PROCESS_QUERY_LIMITED_INFORMATION");
			if( mask & PROCESS_SET_LIMITED_INFORMATION)
				retval.emplace_back("PROCESS_SET_LIMITED_INFORMATION");

			//0x4000, 0x8000 may be Change Permissions and Change Owner
			if (mask & 0x4000)
				retval.emplace_back("Change Permissions(0x4000)");
			if (mask & 0x8000)
				retval.emplace_back("Change Owner(0x8000)");
		}

		return retval;
	}

	std::vector<std::string> AcesssInheritanceToStringVec(DWORD inheritance) {

		std::vector<std::string> retval;

		if (inheritance == NO_INHERITANCE)
			retval.emplace_back("NO_INHERITANCE");

		//TODO: Handle other possible values
		//https://docs.microsoft.com/en-us/windows/win32/api/accctrl/ns-accctrl-explicit_access_a
		// Currently, I don't understand about 'grfInheritance'

		return retval;
	}



	std::string AccessModeToString(ACCESS_MODE mode) {

		switch (mode) {
		case NOT_USED_ACCESS:
			return "NOT_USED";
		case GRANT_ACCESS:
			return "GRANT";
		case SET_ACCESS:
			return "SET";
		case DENY_ACCESS:
			return "DENY";
		case REVOKE_ACCESS:
			return "REVOKE";
		case SET_AUDIT_SUCCESS:
			return "SET_AUDIT_SUCCESS";
		case SET_AUDIT_FAILURE:
			return "SET_AUDIT_FAILURE";
		default: {
			std::stringstream ss;
			ss << "Unknown(" << static_cast<int>(mode) << ")";
			return ss.str();
		}

		}
	}
	std::string AttributesToString(DWORD attributes, BOOL bHex, const std::vector<std::string>& strAttributes) {

		std::stringstream ssAttrs;
		if (bHex)
			ssAttrs << "0x" << std::hex;
		ssAttrs << attributes;
		if (!strAttributes.empty()) {

			std::vector<std::string>::const_iterator it = strAttributes.begin();
			std::vector<std::string>::const_iterator end_it = strAttributes.end();

			ssAttrs << '(';
			while (true) {
				ssAttrs << *it;
				++it;
				if (end_it == it) {
					ssAttrs << ")";
					break;
				}
				else {
					ssAttrs << " | ";
				}
			}
		}

		return ssAttrs.str();
	}
	std::vector<std::string> GroupAttributesToStringVec(DWORD attributes) {

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

	std::vector<std::string> PrivilegeAttributesToStringVec(DWORD attributes) {

		std::vector<std::string> retval;
		if (SE_PRIVILEGE_ENABLED_BY_DEFAULT & attributes)
			retval.emplace_back("EnabledByDefault");
		if (SE_PRIVILEGE_ENABLED & attributes)
			retval.emplace_back("Enabled");
		if (SE_PRIVILEGE_REMOVED & attributes)
			retval.emplace_back("Removed");
		if (SE_PRIVILEGE_USED_FOR_ACCESS & attributes)
			retval.emplace_back("UsedForAccess");

		if (retval.empty())
			retval.emplace_back("Disabled");
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

	std::string TokenTypeToString(TOKEN_TYPE type) {

		switch (type){
		case TokenPrimary:
			return "TokenPrimary";
		case TokenImpersonation:
			return "TokenImpersonation";
		default: {
			std::stringstream ss;
			ss << "Unknown(" << static_cast<int>(type) << ")";
			return ss.str();
		}
		}
	}

	std::string ImpersonationLevelToString(SECURITY_IMPERSONATION_LEVEL level) {

		switch (level) {
		case SecurityAnonymous:
			return "SecurityAnonymous";
		case SecurityIdentification:
			return "SecurityIdentification";
		case SecurityImpersonation:
			return "SecurityImpersonation";
		case SecurityDelegation:
			return "SecurityDelegation";
		default: {
			std::stringstream ss;
			ss << "Unknown(" << static_cast<int>(level) << ")";
			return ss.str();
		}
		}
	}

}