
#include <string>
#include <vector>
#include <rapidjson/prettywriter.h>

#include "Auxiliary.h"
namespace tokenDumper {

	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::Dump(const BYTE* data, TOKEN_INFORMATION_CLASS infoClass) {


		switch (infoClass) {
		case TokenUser: {
			return DumpTokenUser(data);
		}
		case TokenGroups: {
			return DumpTokenGroups(data);
		}
		case TokenIntegrityLevel: {
			return DumpTokenIntegrityLevel(data);
		}
		case TokenPrivileges: {
			return DumpTokenPrivileges(data);
		}
			default:{

				std::stringstream ss;
				ss << TokenInformationClassToString(infoClass) << " is not supported.";
				throw std::runtime_error(ss.str());
			}
		
		}


	}

	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::DumpTokenUser(const BYTE* data) {

		const TOKEN_USER * user = reinterpret_cast<const TOKEN_USER*>(data);

		PresentTrait trait;
		trait.Start("User");

		// Get a SID
		std::string strSid = ConvertSidToString(user->User.Sid);
		trait.AddItem("Sid", strSid.c_str(), FALSE, FALSE);

		// Get an attribute
		trait.AddItem("Attributes", std::to_string(user->User.Attributes).c_str(), TRUE, FALSE);

		return trait.End();

	}

	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::DumpTokenGroups(const BYTE* data) {

		const TOKEN_GROUPS* groups = reinterpret_cast<const TOKEN_GROUPS*>(data);

		PresentTrait trait;
		trait.Start("Groups");

		DWORD groupCount = groups->GroupCount;
		size_t initSize = 3;
		std::vector<char> bufName(initSize), bufDomainName(initSize);

		for (DWORD index = 0; index < groupCount; ++index) {

			SID_AND_ATTRIBUTES groupSidAndAttributes = groups->Groups[index];

			DWORD bufNameSize = static_cast<DWORD>(bufName.size());
			DWORD bufDomainNameSize = static_cast<DWORD>(bufDomainName.size());

			SID_NAME_USE nameUse;
			if (!LookupAccountSidA(NULL, groupSidAndAttributes.Sid, &bufName[0], &bufNameSize, &bufDomainName[0], &bufDomainNameSize, &nameUse)){

				DWORD err = GetLastError();
				if (ERROR_INSUFFICIENT_BUFFER == err) {
					DWORD newSize = (bufNameSize > bufDomainNameSize) ? bufNameSize : bufDomainNameSize;
					bufName.resize(newSize);
					bufDomainName.resize(newSize);

					bufNameSize = bufDomainNameSize = newSize;

					if (!LookupAccountSidA(NULL, groupSidAndAttributes.Sid, &bufName[0], &bufNameSize, &bufDomainName[0], &bufDomainNameSize, &nameUse)) {
					}

				}
			}

			std::string groupName;
			if ('\0' ==  bufDomainName[0]) {	//empty
				groupName = &bufName[0];
			}
			else {
				groupName = &bufDomainName[0];
				groupName += '\\';
				groupName += &bufName[0];

			}

			trait.OpenGroup(groupName.c_str());

			// Get a SID
			std::string strSid = ConvertSidToString(groupSidAndAttributes.Sid);
			trait.AddItem("Sid", strSid.c_str(), FALSE, TRUE);

			// Get an attribute
			std::vector<std::string> strAttributes = GroupAttributesToString(groupSidAndAttributes.Attributes);
			std::string strDetailedAttributes = AttributesToString( groupSidAndAttributes.Attributes, strAttributes);

			trait.AddItem("Attributes", strDetailedAttributes.c_str(), FALSE, FALSE);
			trait.CloseGroup();

		}

		return trait.End();
	}

	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::DumpTokenPrivileges(const BYTE* data) {

		const TOKEN_PRIVILEGES* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(data);

		PresentTrait trait;
		trait.Start("Privilegs");

		for (DWORD index = 0; index < privileges->PrivilegeCount; ++index) {

			LUID_AND_ATTRIBUTES privilegeAndAttributes = privileges->Privileges[index];

			//Convert privilege to string
			std::string strPrivilege = ConvertLuidToString(&(privilegeAndAttributes.Luid));
			trait.OpenGroup(strPrivilege.c_str());

			// Get an attribute
			std::vector<std::string> strAttributes = PrivilegeAttributesToString(privilegeAndAttributes.Attributes);
			std::string strDetailedAttributes= AttributesToString(privilegeAndAttributes.Attributes, strAttributes);

			trait.AddItem("Attributes", strDetailedAttributes.c_str() , FALSE, FALSE);
			trait.CloseGroup();
		}


		return trait.End();


	}

	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::DumpTokenIntegrityLevel(const BYTE* data) {

		const TOKEN_MANDATORY_LABEL* mandatoryLevel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(data);

		PresentTrait trait;
		trait.Start("IntegrityLevel");

		// S-1-16-x stands for the mandatory level
		// The last number(x) is an actual level.
		// 
		// Get a SID
		std::string strSid = ConvertSidToString(mandatoryLevel->Label.Sid);
		DWORD level = *GetSidSubAuthority(mandatoryLevel->Label.Sid,(DWORD)(UCHAR)(*GetSidSubAuthorityCount(mandatoryLevel->Label.Sid) - 1));
		
		if (SECURITY_MANDATORY_UNTRUSTED_RID == level)
			strSid += " (SECURITY_MANDATORY_UNTRUSTED_RID)";
		else if(SECURITY_MANDATORY_LOW_RID == level)
			strSid += " (SECURITY_MANDATORY_LOW_RID)";
		else if(SECURITY_MANDATORY_MEDIUM_RID)
			strSid += " (SECURITY_MANDATORY_MEDIUM_RID)";
		else if(SECURITY_MANDATORY_MEDIUM_PLUS_RID)
			strSid += " (SECURITY_MANDATORY_MEDIUM_PLUS_RID)";
		else if(SECURITY_MANDATORY_HIGH_RID)
			strSid += " (SECURITY_MANDATORY_HIGH_RID)";
		else if(SECURITY_MANDATORY_SYSTEM_RID)
			strSid += " (SECURITY_MANDATORY_SYSTEM_RID)";
		else if(SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
			strSid += " (SECURITY_MANDATORY_PROTECTED_PROCESS_RID)";

		trait.AddItem("Sid", strSid.c_str(), FALSE, FALSE);

		// Get an attribute
		trait.AddItem("Attributes", std::to_string(mandatoryLevel->Label.Attributes).c_str(), TRUE, FALSE);

		return trait.End();
	}


};
