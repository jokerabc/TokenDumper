
#include <string>
#include <rapidjson/prettywriter.h>

#include "Auxiliary.h"
namespace tokenDumper {

	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::Dump(const BYTE* data, TOKEN_INFORMATION_CLASS infoClass) {
	

		switch (infoClass) {
		case TokenIntegrityLevel: {
			//			trait.AddOtherTrait("IntegrityLevel", DumpTokenIntegrityLevel(data));
			return DumpTokenIntegrityLevel(data);
		}
			default:{

				std::stringstream ss;
				ss << TokenInformationClassToString(infoClass) << " is not supported.";
				throw std::runtime_error(ss.str());
			}
		
		}


	}

	
	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::DumpTokenIntegrityLevel(const BYTE* data) {

		//PresentTrait trait(m_os);void 
		const TOKEN_MANDATORY_LABEL* mandatoryLevel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(data);
		//m_trait.OpenGroup("IntegrityLevel");
	
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

		//trait.CloseGroup();
		
		return trait.End();
	}


};
