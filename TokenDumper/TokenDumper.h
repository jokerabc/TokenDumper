#pragma once
#include <ostream>
#include <vector>
#include <string>
#include <Windows.h>

namespace tokenDumper {


	template<typename PresentTrait>
	class TokenDumper{
	public:
		explicit TokenDumper() {
		}

		typename PresentTrait::InfoType Dump(const BYTE* data, TOKEN_INFORMATION_CLASS infoClass);


	private:
		// Dump each class
		typename PresentTrait::InfoType DumpTokenUser(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenGroups(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenPrivileges(const BYTE* data);
		//TokenOwner,
		//TokenPrimaryGroup,
		//TokenDefaultDacl,
		//TokenSource,
		//TokenType,
		//TokenImpersonationLevel,
		//TokenStatistics,
		//TokenRestrictedSids,
		//TokenSessionId,
		//TokenGroupsAndPrivileges,
		//TokenSessionReference,
		//TokenSandBoxInert,
		//TokenAuditPolicy,
		//TokenOrigin,
		//TokenElevationType,
		//TokenLinkedToken,
		//TokenElevation,
		//TokenHasRestrictions,
		//TokenAccessInformation,
		//TokenVirtualizationAllowed,
		//TokenVirtualizationEnabled,
		typename PresentTrait::InfoType DumpTokenIntegrityLevel(const BYTE* data);
		//TokenUIAccess,
		//TokenMandatoryPolicy,
		//TokenLogonSid,
		//TokenIsAppContainer,
		//TokenCapabilities,
		//TokenAppContainerSid,
		//TokenAppContainerNumber,
		//TokenUserClaimAttributes,
		//TokenDeviceClaimAttributes,
		//TokenRestrictedUserClaimAttributes,
		//TokenRestrictedDeviceClaimAttributes,
		//TokenDeviceGroups,
		//TokenRestrictedDeviceGroups,
		//TokenSecurityAttributes,
		//TokenIsRestricted,
		//TokenProcessTrustLevel,
		//TokenPrivateNameSpace,
		//TokenSingletonAttributes,
		//TokenBnoIsolation,
		//TokenChildProcessFlags,
		//TokenIsLessPrivilegedAppContainer,
		//TokenIsSandboxed,
		//TokenOriginatingProcessTrustLevel,
		//MaxTokenInfoClass  
	private:
	public:
	};

	// Helper Functions
	std::string TokenInformationClassToString(TOKEN_INFORMATION_CLASS infoClass);

	std::string AttributesToString(DWORD attributes, const std::vector<std::string>& strAttributes);
	std::vector<std::string> GroupAttributesToString(DWORD attributes);
	std::vector<std::string> PrivilegeAttributesToString(DWORD attributes);
	std::string FirstRidToString(DWORD rid);
	std::string RidForGroupsToString(DWORD rid);
};

#include "TokenDumper.hpp"
