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
		JsonTrait() noexcept;

		// This class is non-copyable
		JsonTrait(const JsonTrait&) = delete;
		JsonTrait& operator = (const JsonTrait&) = delete;

		// This class is movable
		JsonTrait(JsonTrait&& rhs) noexcept;
		JsonTrait& operator=(JsonTrait&& rhs) noexcept;

		void Start(const char * title );
		InfoType End();
		void OpenGroup(const char* name);
		void CloseGroup();
		void AddItem(const char* name, const char* value, bool bIsNumber, bool bIsAttr);
		void AddSubTrait(const char * name,  const InfoType& info);
		// TODO: will implement operator <<
		void Print(std::ostream& os);
	private:
		InfoType			 m_obj;
	};

	class XMLTrait {
	public:
		using InfoType = pugi::xml_document;
	public:
		XMLTrait() noexcept;
		
		// This class is non-copyable
		XMLTrait(const XMLTrait&) = delete;
		XMLTrait& operator = (const XMLTrait&) = delete;

		// This class is movable
		XMLTrait(XMLTrait&& rhs) noexcept;
		XMLTrait& operator=(XMLTrait&& rhs) noexcept;

		void Start(const char * title );
		InfoType End();
		void OpenGroup(const char* name);
		void CloseGroup();
		void AddItem(const char* name, const char* value, bool IsNumber, bool bIsAttr);
		void AddSubTrait(const char * name,  const InfoType& info);
		void Print(std::ostream& os);
	private:
		InfoType			 m_obj;
		pugi::xml_node		 m_curNode;
	};
};


