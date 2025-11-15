#pragma once

#ifndef __AXIS_HTTP_H__
#define __AXIS_HTTP_H__

#include "response.h"

#include <string>
#include <fstream>
#include <vector>
#include <map>

namespace axis {
	enum Method {
		INVALID_METHOD,
		GET,
		HEAD,
		POST,
		PUT,
		DELETE,
		CONNECT,
		OPTIONS,
		TRACE,
		PATCH
	};

	enum Status {
		InvalidStatus,
		Continue = 100,
		SwitchingProtocols = 101,
		Processing = 102,
		EarlyHints = 103,

		OK = 200,
		Created = 201,
		Accepted = 202,
		Non_AuthoritativeInformation = 203,
		NoContent = 204,
		ResetContent = 205,
		PartialContent = 206,
		Multi_Status = 207,
		AlreadyReported = 208,
		IMUsed = 226,

		MultipleChoices = 300,
		MovedPermanently = 301,
		Found = 302,
		SeeOther = 303,
		NotModified = 304,
		UseProxy = 305,
		TemporaryRedirect = 307,
		PermanentRedirect = 308,

		BadRequest = 400,
		Unauthorized = 401,
		PaymentRequired = 402,
		Forbidden = 403,
		NotFound = 404,
		MethodNotAllowed = 405,
		NotAcceptable = 406,
		ProxyAuthenticationRequired = 407,
		RequestTimeout = 408,
		Conflict = 409,
		Gone = 410,
		LengthRequired = 411,
		PreconditionFailed = 412,
		PayloadTooLarge = 413,
		URITooLong = 414,
		UnsupportedMediaType = 415,
		RangeNotSatisfiable = 416,
		ExpectationFailed = 417,
		Imateapot = 418,
		AuthenticationTimeout = 419,
		MisdirectedRequest = 421,
		UnprocessableEntity = 422,
		Locked = 423,
		FailedDependency = 424,
		TooEarly = 425,
		UpgradeRequired = 426,
		PreconditionRequired = 428,
		TooManyRequests = 429,
		RequestHeaderFieldsTooLarge = 431,
		RetryWith = 449,
		UnavailableForLegalReasons = 451,
		ClientClosedRequest = 499,

		InternalServerError = 500,
		NotImplemented = 501,
		BadGateway = 502,
		ServiceUnavailable = 503,
		GatewayTimeout = 504,
		HTTPVersionNotSupported = 505,
		VariantAlsoNegotiates = 506,
		InsufficientStorage = 507,
		LoopDetected = 508,
		BandwidthLimitExceeded = 509,
		NotExtended = 510,
		NetworkAuthenticationRequired = 511,
		UnknownError = 520,
		WebServerIsDown = 521,
		ConnectionTimedOut = 522,
		OriginIsUnreachable = 523,
		ATimeoutOccurred = 524,
		SSLHandshakeFailed = 525,
		InvalidSSLCertificate = 526
	};

	class HTTP {
	public:
		static std::map<Status, std::string> StatusMap;
		static std::map<std::string, std::string> URLEncodingMap;
		static std::string str_status(Status _Status);
	};

	using key_val = std::pair<std::string, std::string>;

	Response redirect_to(const std::string& _To);
	Response send_file(const std::string& _FileName);
	Response send_file(const std::string& _FileName, Status _StatusCode);
	Response render_template(const std::string& _FileName, std::map<std::string, std::string>& _Data);
	Response render_template(const std::string& _FileName, std::map<std::string, std::string>& _Data, Status _StatusCode);
	std::vector<key_val> parse_key_value_data(const std::string& _RawData);
	std::vector<std::string> div_by(const std::string& path, char separator);
	std::vector<std::string> div_by_sections(const std::string& path);
	bool is_mask_of(const std::string& mask, const std::string& path);
	void decode_string(std::string& str);

	class Section {
	public:
		enum SectionType {
			non_template_section,
			template_non_empty_section,
			template_variants_section,
			template_any_section
		};

		inline Section(const std::string& _Section) : section{ _Section } {
			if (_Section.find('<') == std::string::npos) {
				type = SectionType::non_template_section;
			}
			else if (_Section == "<...>") {
				type = SectionType::template_non_empty_section;
			}
			else if (_Section == "<?>") {
				type = SectionType::template_any_section;
			}
			else {
				type = SectionType::template_variants_section;
			}
		}

		inline bool one_of_variants(const std::string& _Section) const {
			for (std::string& var : div_by(section.substr(0, section.length() - 1), '|')) {
				if (_Section == var)
					return true;
			}

			return false;
		}

		SectionType type;
		std::string section;
	};
}

#endif // !__AXIS_HTTP_H__