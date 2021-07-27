
#include <rapidjson/prettywriter.h>

namespace tokenDumper {

	template<typename PresentTrait>
	void TokenDumper<PresentTrait>::Dump(const BYTE* data, TOKEN_INFORMATION_CLASS infoClass, std::ostream & os) {
	
		PresentTrait trait;
		trait.Start("Result");

		switch (infoClass) {
		case TokenIntegrityLevel: {
			trait.AddOtherTrait("IntegrityLevel", DumpTokenIntegrityLevel(data));
			break;
		}
		}

		trait.Print(os);

	}

	
	template<typename PresentTrait>
	typename PresentTrait::InfoType TokenDumper<PresentTrait>::DumpTokenIntegrityLevel(const BYTE* data) {

		//PresentTrait trait(m_os);void 
		const TOKEN_MANDATORY_LABEL* mandatoryLevel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(data);
		//m_trait.OpenGroup("IntegrityLevel");
	
		PresentTrait trait;

		trait.Start("IntegrityLevel");

		// Get a SID
		std::string strSid = ConvertSidToString(mandatoryLevel->Label.Sid);
		trait.AddItem("Sid", strSid.c_str(), FALSE, FALSE);

		// Get an attribute
		trait.AddItem("Attributes", std::to_string(mandatoryLevel->Label.Attributes).c_str(), TRUE, FALSE);

		//trait.CloseGroup();
		
		return trait.End();
	}
};
