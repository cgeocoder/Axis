#pragma once

#ifndef __AXIS_RESPONSE_H__
#define __AXIS_RESPONSE_H__

#include "http.h"

#include <map>
#include <string>

namespace axis {

	class Response {
		friend class AxisServer;

	private:
		Response();

		void fill_std_response();
		std::string make_src() const;

	public:
		std::string protocol_version;
		enum Status status;
		std::string data;
		std::map<std::string, std::string> headers;

		Response(const char* _Text);

		Response(const std::string& _Text);
		Response(const std::string& _Text, Status _Status);
	};
}

#endif // !__AXIS_RESPONSE_H__