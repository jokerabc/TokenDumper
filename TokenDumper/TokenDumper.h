#pragma once
#include <ostream>
#include <vector>
#include <string>
#include <Windows.h>
#include <accctrl.h>

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
		typename PresentTrait::InfoType DumpTokenOwner(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenPrimaryGroup(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenDefaultDacl(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenSource(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenType(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenImpersonationLevel(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenStatistics(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenRestrictedSids(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenSessionId(const BYTE* data);
		typename PresentTrait::InfoType DumpTokenGroupsAndPrivileges(const BYTE* data);
		//TokenSessionReference,	//Reserved
		typename PresentTrait::InfoType DumpTokenSandBoxInert(const BYTE* data);
		//TokenAuditPolicy,			//Reserved
		typename PresentTrait::InfoType DumpTokenOrigin(const BYTE* data);
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
	// Dump the specific structure
	void DumpSidAndAttributes(const SID_AND_ATTRIBUTES & sidAndAttributes, PresentTrait & trait);
	void DumpLuidAndAttributes(const LUID_AND_ATTRIBUTES& luid, PresentTrait& trait);

	public:
	};


	// Helper Functions
	std::string TokenInformationClassToString(TOKEN_INFORMATION_CLASS infoClass);
	std::string TrusteeTypeToString(TRUSTEE_TYPE type);
	std::vector<std::string> AccessMaskToStringVec(ACCESS_MASK mask);
	std::vector<std::string> AcesssInheritanceToStringVec(DWORD inheritance);
	std::string AccessModeToString(ACCESS_MODE mode);
	std::string AttributesToString(DWORD attributes, BOOL bHex, const std::vector<std::string>& strAttributes);
	std::vector<std::string> GroupAttributesToStringVec(DWORD attributes);
	std::vector<std::string> PrivilegeAttributesToStringVec(DWORD attributes);
	std::string FirstRidToString(DWORD rid);
	std::string RidForGroupsToString(DWORD rid);
	std::string TokenTypeToString(TOKEN_TYPE type);
	std::string ImpersonationLevelToString(SECURITY_IMPERSONATION_LEVEL level);
};

#include "TokenDumper.hpp"
