#pragma once
#include <ostream>
#include <rapidjson/document.h>
#include <pugixml.hpp>

namespace tokenDumper {


	// PresentTrait classes must have below funtions.
	/*
	*  1. void OpenGroup(const char * name );
	*  2. void CloseGroup();
	*  3. void AddItem(const char * name, const char * value, bool bIsNumber, bool bIsAttr);
	*/
	class JsonTrait {
	public:
		using InfoType = rapidjson::Document;
	public:
		JsonTrait();
		JsonTrait(const JsonTrait&) = delete;
		JsonTrait& operator = (const JsonTrait&) = delete;
		void Start(const char * title );
		InfoType End();
		void OpenGroup(const char* name);
		void CloseGroup();
		void AddItem(const char* name, const char* value, bool bIsNumber, bool bIsAttr);
		void AddOtherTrait(const char * name,  const InfoType& info);
		// TODO: will implement operator <<
		void Print(std::ostream& os);
	private:
		InfoType			 m_obj;
	};

	class XMLTrait {
	public:
		using InfoType = pugi::xml_document;
	public:
		XMLTrait();
		XMLTrait(const XMLTrait&) = delete;
		XMLTrait& operator = (const XMLTrait&) = delete;
		void Start(const char * title );
		InfoType End();
		void OpenGroup(const char* name);
		void CloseGroup();
		void AddItem(const char* name, const char* value, bool IsNumber, bool bIsAttr);
		void AddOtherTrait(const char * name,  const InfoType& info);
		void Print(std::ostream& os);
	private:
		InfoType			 m_obj;
		pugi::xml_node		 m_curNode;
	};
};


