#pragma once

#ifndef __AXIS_REQUEST_H__
#define __AXIS_REQUEST_H__

#include "http.h"

namespace axis {

	class Request {
	public:
		Request(const std::string& _RawText);

		Method method;
		std::string protocol_version;
		std::string path;
		std::map<std::string, std::string> headers;

		std::string raw_text, data;
	};
}

#endif // !__AXIS_REQUEST_H__