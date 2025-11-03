#pragma once

#ifndef __HTTP_H__
#define __HTTP_H__

#include <iostream>
#include <string>
#include <fstream>
#include <map>

namespace axis {
	static enum Method {
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

	static enum Status {
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
		static std::string str_status(Status _Status);
	};

}

#endif // !__HTTP_H__