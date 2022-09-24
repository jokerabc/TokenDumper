// TokenDumper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "stdafx.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <Windows.h>

#include "Auxiliary.h"
#include "TokenDumper.h"
#include "PresentTrait.h"


enum class RESULT_FORMAT {
	JSON,
	XML
};

using BYTE_ARRAY = tokenDumper::ArrayDeleter<BYTE>;

std::shared_ptr<BYTE_ARRAY> GetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS tokenInfoClass);

// from https://gist.github.com/plasticbox/3708a6cdfbece8cd224487f9ca9794cd
// simple.exe -ip="127.0.0.1" -port=1000
// std::string ip = getCmdOption(argc, argv, "-ip=");
// std::string port = getCmdOption(argc, argv, "-port=");
std::string getCmdOption(int argc, char* argv[], const std::string& option)
{
	std::string cmd;
	for (int i = 0; i < argc; ++i)
	{
		std::string arg = argv[i];
		if (0 == arg.find(option))
		{
			std::size_t found = arg.find_first_of("=");
			cmd = arg.substr(found + 1);
			return cmd;
		}
	}
	return cmd;
}

void ShowUsage(const std::string & errStr) {

	if (!errStr.empty()) {
		std::cerr << errStr << "\n";
	}

	std::cout << "Usage: ";
}

template<typename PresentTrait>
PresentTrait Dump(HANDLE hToken, const std::vector< TOKEN_INFORMATION_CLASS>& categories) {

	PresentTrait retval;
	retval.Start("TokenDumper");

	for (auto category : categories) {

		std::shared_ptr<BYTE_ARRAY> tokenInfo = GetTokenInfo(hToken, category);
		tokenDumper::TokenDumper<PresentTrait> tokenDumper;
		retval.AddSubTrait(tokenDumper::TokenInformationClassToString(category).c_str(), tokenDumper.Dump(tokenInfo->Get(), category));
	}

	return std::move(retval);

}

int main(int argc, char** argv)
{
	try
	{
		DWORD pid{ 0 };
		RESULT_FORMAT format{ RESULT_FORMAT::JSON };	// Default is JSON
		// Get a process id from parameters
		std::string strPid = getCmdOption(argc, argv, "-pid=");
		if (strPid.empty()) {
			ShowUsage("-pid argument is mandatory.");
			return 0;
		}
		else {
			pid = static_cast<DWORD>(std::atoi(strPid.c_str()));
		}

		std::string strFormat = getCmdOption(argc, argv, "-format=");
		if (!strFormat.empty()) {
			if (0 == _stricmp(strFormat.c_str(), "json")) {
				format = RESULT_FORMAT::JSON;
			}
			else if (0 == _stricmp(strFormat.c_str(), "xml")) {
				format = RESULT_FORMAT::XML;
			}
			else {
				std::stringstream ss;
				ss << "Invalid format: " << strFormat;
				ShowUsage(ss.str());
				return 0;
			}
		}


		HANDLE hToken = nullptr;
		if (!::OpenProcessToken(tokenDumper::GetProcessHandle(pid), TOKEN_QUERY, &hToken)) {
			std::stringstream ss;
			ss << "Failed to open token pid: " << pid;
			throw tokenDumper::win32_exception(GetLastError(), ss.str());
		}

		// TokenImpersonationLevel: If the access token is not an impersonation token, the function fails.
		// This program inspects the main token of programs, so calling GetTokenInformation with TokenImpersonationLevel always returns 'ERROR_INVALID_PARAMETER'
		std::vector<TOKEN_INFORMATION_CLASS> tokenInfoClasses = { TokenUser, TokenGroups, TokenPrivileges, TokenOwner, 
			TokenPrimaryGroup, TokenIntegrityLevel, TokenDefaultDacl, /*TokenSource*/
			TokenType, /*TokenImpersonationLevel*/
			TokenStatistics,
			TokenRestrictedSids};

		if (RESULT_FORMAT::JSON == format) {
			tokenDumper::JsonTrait result = Dump<tokenDumper::JsonTrait>(hToken, tokenInfoClasses);
			std::cout << result;
		}
		else if (RESULT_FORMAT::XML == format) {
			tokenDumper::XMLTrait result = Dump<tokenDumper::XMLTrait>(hToken, tokenInfoClasses);
			std::cout << result;
		}

		return 1;
	}
	catch (const std::exception& ex) {

		std::cerr << "exception: " << ex.what();
	}
	catch (...) {

		std::cerr << "unknown exception";
	}

	return 0;
}

std::shared_ptr<BYTE_ARRAY> GetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS tokenInfoClass) {

	DWORD tokenInfoLength{ 0 };
	if (GetTokenInformation(token, tokenInfoClass, nullptr, 0, &tokenInfoLength)) {
		// Something wrong, this function must return FALSE
		std::stringstream ss;
		ss << "GetTokenInformation succeeded even though there is no buffer. class: " << tokenDumper::TokenInformationClassToString(tokenInfoClass);
		throw std::runtime_error(ss.str());
	}
	else if( ERROR_INSUFFICIENT_BUFFER != GetLastError() ){
		DWORD err = GetLastError();
		std::stringstream ss;
		ss << "Failed to call GetTokenInformation in GetTokenInfo. class: " << tokenDumper::TokenInformationClassToString(tokenInfoClass);
		throw tokenDumper::win32_exception(err, ss.str());
	}
	else {
		std::shared_ptr<BYTE_ARRAY> retval(new BYTE_ARRAY(new BYTE[tokenInfoLength])); 
		if (!GetTokenInformation(token, tokenInfoClass, retval->Get(), tokenInfoLength, &tokenInfoLength)) {
			std::stringstream ss;
			ss << "Failed to call(second) GetTokenInformation in GetTokenInfo. class: " << tokenDumper::TokenInformationClassToString(tokenInfoClass);
			throw tokenDumper::win32_exception(GetLastError(), ss.str());
		}
		else {
			return retval;
		}
	}


}
