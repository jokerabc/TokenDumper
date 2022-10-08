#pragma once
#include <ostream>
#include <stack>
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
	private:
		// OpenGroup function uses this structure to save name and rapidjson::Value.
		struct JSON_OBJECT {
			JSON_OBJECT() = delete;
			JSON_OBJECT(const JSON_OBJECT&) = delete;
			JSON_OBJECT& operator = (const JSON_OBJECT&) = delete;
			JSON_OBJECT(std::string&& name, rapidjson::Value&& obj) : m_name(std::move(name)), m_obj(std::move(obj)){}
			JSON_OBJECT(JSON_OBJECT&& obj) noexcept : m_name(std::move(obj.m_name)), m_obj(std::move(obj.m_obj)) {}
			JSON_OBJECT& operator = (JSON_OBJECT&& obj) noexcept {
				m_name = std::move(obj.m_name);
				m_obj = std::move(obj.m_obj);
			}
			std::string			m_name;
			rapidjson::Value	m_obj;
		};
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
		void Print(std::ostream& os) const;
	private:
		InfoType						m_obj;
		std::stack<JSON_OBJECT>			m_objects;
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
		void Print(std::ostream& os) const;
	private:
		InfoType			 m_obj;
		pugi::xml_node		 m_curNode;
	};
};

/*template<typename T, typename std::enable_if_t<
	std::disjunction_v<
	std::is_same_v<T, tokenDumper::JsonTrait>,
	std::is_same_v<T, tokenDumper::XMLTrait> >>>*/

// Only for JsonTrait and XMLTrait
template <class T,
	typename std::enable_if_t<std::is_same_v<T, tokenDumper::JsonTrait> || std::is_same_v<T, tokenDumper::XMLTrait> >* = nullptr>
	std::ostream& operator << (std::ostream& os, const T& obj) {

	obj.Print(os);
	return os;
}

