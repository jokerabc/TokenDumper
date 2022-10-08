#include "stdafx.h"
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include "PresentTrait.h"


namespace tokenDumper {

	//////////////////////// Class JsonTrait

	JsonTrait::JsonTrait() noexcept { 
		m_obj.SetObject();
	}


	JsonTrait::JsonTrait(JsonTrait&& rhs) noexcept : m_obj(std::move(rhs.m_obj)) {

	}
	JsonTrait& JsonTrait::operator=(JsonTrait&& rhs) noexcept {
		m_obj = std::move(rhs.m_obj);
		return *this;
	}

	void JsonTrait::Start(const char * title) {
	}

	JsonTrait::InfoType JsonTrait::End() {

		return std::move(m_obj);
	}

	void JsonTrait::OpenGroup(const char* name) {
	//////////////////////// Class JsonTrait

		// It it hard to get child Value after calling AddMember function.
		// So, just save them to the m_objects, and then, call AddMember in the CloseGroup
		rapidjson::Value o(rapidjson::kObjectType);
		m_objects.emplace(std::string(name), std::move(o));

	}

	void JsonTrait::CloseGroup() {

		if (!m_objects.empty()) {

			JSON_OBJECT obj = std::move(m_objects.top());
			m_objects.pop();
			rapidjson::Value vName;
			vName.SetString(obj.m_name.c_str(), m_obj.GetAllocator());	// deep-copy

			if (m_objects.empty()) {
				m_obj.AddMember(vName, obj.m_obj, m_obj.GetAllocator());
			}
			else {
				m_objects.top().m_obj.AddMember(vName, obj.m_obj, m_obj.GetAllocator());
			}

		}
		else {
			throw std::runtime_error("There is no object in JsonTrait::CloseGroup");
		}
	}

	void JsonTrait::AddItem(const char* name, const char* value, bool bIsNumber, bool bIsAttr) {
		
		rapidjson::Value val, vName;

		if (bIsNumber) {
			val.SetInt(std::atoi(value));
		}
		else{
			val.SetString(value, m_obj.GetAllocator());
		}

		vName.SetString(name, m_obj.GetAllocator());	// deep-copy

		if (m_objects.empty()) {
			// To the document
			m_obj.AddMember(vName, val, m_obj.GetAllocator());
		}
		else {
			m_objects.top().m_obj.AddMember(vName, val, m_obj.GetAllocator());

		}
	}

	void JsonTrait::AddSubTrait(const char * name, const InfoType& info) {
		
		rapidjson::Value vName;
		vName.SetString(name, m_obj.GetAllocator());	// deep-copy
		rapidjson::Value subObj = rapidjson::Value(info, m_obj.GetAllocator());
		m_obj.AddMember(vName, subObj, m_obj.GetAllocator());

	}

	void JsonTrait::Print(std::ostream& os) const {

		rapidjson::StringBuffer buffer;
		rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
		m_obj.Accept(writer);
		os << buffer.GetString();
	}

	//////////////////////// Class XMLTrait
	XMLTrait::XMLTrait() noexcept {

	} 

	XMLTrait::XMLTrait(XMLTrait&& rhs) noexcept : m_obj(std::move(rhs.m_obj)), m_curNode(std::move(rhs.m_curNode)) {

	}

	XMLTrait& XMLTrait::operator=(XMLTrait&& rhs) noexcept {
		m_obj = std::move(rhs.m_obj);
		m_curNode = std::move(rhs.m_curNode);

		return *this;

	}

	void XMLTrait::Start(const char* title) {

		m_curNode = m_obj.append_child(title);
	}

	XMLTrait::InfoType XMLTrait::End() {

		return std::move(m_obj);
	}

	void XMLTrait::OpenGroup(const char* name) {

		m_curNode = m_curNode.append_child(name);
	}

	void XMLTrait::CloseGroup() {

		m_curNode = m_curNode.parent();
	}

	void XMLTrait::AddItem(const char* name, const char* value, bool IsNumber, bool bIsAttr) {

		if (bIsAttr) {
			pugi::xml_attribute attr = m_curNode.append_attribute(name);
			attr.set_value(value);
		}
		else {
			pugi::xml_node node = m_curNode.append_child(name);
			node.text().set(value);
		}
	}

	void XMLTrait::AddSubTrait(const char* name, const InfoType& info) {

		m_obj.first_child().append_copy(info.first_child());
	}

	void XMLTrait::Print(std::ostream& os) const {

		m_obj.print(os);
	}
}

