#define GLOBAL_LOGGER

#include <array>
#include <fstream>

#include "axis_server.h"
#include "logger/log.h"

#undef DELETE

HttpServer::HttpServer(const std::string& _IP, unsigned short _Port) 
	: m_Run { true },
	m_IP{ _IP },
	m_Port{ _Port } {
	clog::Log& l = clog::l();

	if (!init_server(_IP, _Port)) {
		l.err(__FUNCTION__ "(): init_server() failed: " + m_CriticalError);
		m_Run = false;

		return;
	}
}

Response default_not_fount_callback(Request& r, const std::vector<std::string>& p) {
	return { "Not Found", HTTP::Status::NotFound };
}

Response default_method_not_allowed_callback(Request& r) {
	return { "Method not allowed", HTTP::Status::MethodNotAllowed };
}

bool HttpServer::init_server(const std::string& _IP, unsigned short _Port) {
	WSAData wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		m_CriticalError = "WSAStartup() failed: error for downloading lib";
		return false;
	}

	int sizeofaddr = sizeof(m_SockAddrIn);
	m_SockAddrIn.sin_addr.s_addr = inet_addr(_IP.c_str());
	m_SockAddrIn.sin_port = htons(_Port);
	m_SockAddrIn.sin_family = AF_INET;

	if ((m_ServerSocket = socket(AF_INET, SOCK_STREAM, NULL)) < 0) {
		m_CriticalError = "socket() failed: unable to create socket";
		return false;
	}

	if (bind(m_ServerSocket, (SOCKADDR*)&m_SockAddrIn, sizeof(m_SockAddrIn)) < 0) {
		m_CriticalError = "bind() failed: unable to bind socket";
		return false;
	}

	if (listen(m_ServerSocket, 2) < 0) {
		m_CriticalError = "listen() failed";
		return false;
	}
	
	m_NotFoundCallback = ::default_not_fount_callback;
	m_MethodNotAllowedCallback = ::default_method_not_allowed_callback;

	m_AllowMethods = {
		HTTP::Method::GET,
		HTTP::Method::HEAD,
		HTTP::Method::POST,
		HTTP::Method::PUT,
		HTTP::Method::DELETE,
		HTTP::Method::CONNECT,
		HTTP::Method::OPTIONS,
		HTTP::Method::TRACE,
		HTTP::Method::PATCH
	};
	
	return true;
}

bool HttpServer::set_allow_methods(const std::initializer_list<HTTP::Method>& _MehodList) {
	for (auto& method : _MehodList) {
		if (method < HTTP::Method::GET || method > HTTP::Method::PATCH)
			return false;
	}

	m_AllowMethods.clear();
	m_AllowMethods = _MehodList;

	return true;
}

void HttpServer::operator ()(const std::string& _Path, const RefCallback& _Callback) {
	if (m_PathMap.find(_Path) != m_PathMap.end()) {
		std::cout << "Warning: redefinition when accessing '" << _Path << "'\n";
	}

	m_PathMap[_Path] = _Callback;
}

void HttpServer::operator ()(const std::string& _Path, const RefCallbackAdv& _Callback) {
	if (m_PathMapAdv.find(_Path) != m_PathMapAdv.end()) {
		std::cout << "Warning: redefinition when accessing '" << _Path << "'\n";
	}

	m_PathMapAdv[_Path] = _Callback;
}

void HttpServer::set_not_found_callback(RefCallbackAdv& _Callback) {
	m_NotFoundCallback = _Callback;
}

void HttpServer::set_method_not_allowed_callback(RefCallback& _Callback) {
	m_MethodNotAllowedCallback = _Callback;
}

void HttpServer::accept() {
	clog::Log& l = clog::l();

	int sizeofaddr = sizeof(m_SockAddrIn);
	SOCKET* new_client = new SOCKET{ ::accept(m_ServerSocket, (SOCKADDR*)&m_SockAddrIn, &sizeofaddr) };

	if (*new_client == 0) {
		l.err(__FUNCTION__ "(): accept() failed: client could not connect to the server");
	}
	else {
		l.info(__FUNCTION__ "(): [s: %llu] accept(): client connected", *new_client);

		auto create_client_thread = [&]() -> ClientInfo* {
			return new ClientInfo{
				new std::thread{ std::thread(&HttpServer::dispatcher, this, new_client) },
				new_client
			};
		};

		for (size_t i = 0; i < m_ClientCounter; ++i) {
			if (*m_Clients[i]->socket == 0) {
				m_Clients[i]->thread->detach();

				delete m_Clients[i]->thread;
				delete m_Clients[i]->socket;
				delete m_Clients[i];

				m_Clients[i] = create_client_thread();
				return;
			}
		}

		if (m_ClientCounter == m_MaxClients) {
			Response response = Response("<h1>The server cannot process your request because the maximum number of connections has been exceeded</h1>");
			make_response(*new_client, response);
			closesocket(*new_client);
		}
		else {
			m_Clients[m_ClientCounter++] = create_client_thread();
		}
	}
}

void HttpServer::dispatcher(SOCKET* _ClientSocket) {
	clog::Log& l = clog::l();

	l.info(__FUNCTION__ "(): [s: %llu] start", *_ClientSocket);

	bool client_run = true;

	while (client_run) {
		Request req = receive(*_ClientSocket);

		__debugbreak();

		if (m_AllowMethods.find(req.method) == m_AllowMethods.end()) {
			m_DataMutex.lock();

			Response response = m_MethodNotAllowedCallback(req);

			__debugbreak();

			if (!make_response(*_ClientSocket, response)) {
				l.err(__FUNCTION__ "(): [s: %llu] make_response() failed", *_ClientSocket);
			}

			m_DataMutex.unlock();
		}
		else {
			auto& req_headers = req.headers;

			if ((req_headers.find("Connection") != req_headers.end()) && (req_headers["Connection"] == "Closed")) {
				client_run = false;
			}

			l.info(__FUNCTION__ "(): [s: %llu] required '%s'", *_ClientSocket, req.path.c_str());

			m_DataMutex.lock();

			Response response;

			if (m_PathMap.find(req.path) != m_PathMap.end()) {
				response = m_PathMap[req.path](req);
			}
			else {
				response = Response("Not found");
			}

			auto& resp_headers = response.headers;

			if ((resp_headers.find("Connection") != resp_headers.end()) && (resp_headers["Connection"] == "Closed")) {
				client_run = false;
			}

			if (!make_response(*_ClientSocket, response)) {
				l.err(__FUNCTION__ "(): [s: %llu] make_response() failed", *_ClientSocket);
			}

			m_DataMutex.unlock();
		}
	}

	l.info(__FUNCTION__ "(): [s: %llu] end. Client disconnected", *_ClientSocket);

	::closesocket(*_ClientSocket);
	*_ClientSocket = 0;
}

bool HttpServer::make_response(SOCKET _ClientSocket, Response& _Response) {
	std::string src_response = _Response.make_src();

	return !(send(
		_ClientSocket,
		src_response.c_str(),
		src_response.length(), 0) < 0);
}

Request HttpServer::receive(SOCKET _ClientSocket) {
	clog::Log& l = clog::l();

	std::vector<std::string> src_lines;
	std::string raw_text, src_line;

	int res = 0;
	char ch = 0;

	while (!((res = recv(_ClientSocket, (char*)&ch, sizeof(char), 0)) < 0)) {
		src_line += ch;
		raw_text += ch;

		if (src_line == "\r\n") {
			break;
		}

		if (src_line.find("\r\n") != std::string::npos) {
			src_lines.push_back(src_line);
			src_line.clear();
		}
	}

	if (res < 0) {
		l.err(__FUNCTION__"(): recv() failed. Close socket (%llu)", _ClientSocket);
		return Request("");
	}

	Request _Result(raw_text);

	std::string line = src_lines.at(0);

	// first line
	size_t spaces[2] = {
		line.find_first_of(' '),
		line.find_last_of(' '),
	};

	if ((spaces[0] == std::string::npos) || (spaces[1] == std::string::npos)) {
		l.err(__FUNCTION__"(): [s: %llu] invalid HTTP first line. Close socket", _ClientSocket);
		return Request("");
	}

	std::string str_method = line.substr(0, spaces[0]);

	const char* methods[9] = { "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH" };

	for (size_t i = 0; i < 9; ++i) {
		if (str_method == methods[i]) {
			_Result.method = (HTTP::Method)(i + 1);
		}
	}

	if (_Result.method == HTTP::Method::INVALID) {
		l.err(__FUNCTION__"(): [s: %llu] invalid HTTP method. Close socket", _ClientSocket);
		return Request("");
	}

	_Result.path = line.substr(spaces[0] + 1, spaces[1] - spaces[0] - 1);
	_Result.protocol_version = line.substr(spaces[1] + 1, line.length() - spaces[1] - 3);

	for (size_t i = 1; i < src_lines.size(); ++i) {
		line = src_lines.at(i);

		size_t div_seq = line.find(": ");

		if (div_seq == std::string::npos) {
			l.err(__FUNCTION__"(): [s: %llu] invalid (%llu) header. Close socket", _ClientSocket, i);
			return Request("");
		}

		_Result.headers[line.substr(0, div_seq)] = line.substr(div_seq + 2, line.length() - div_seq - 4);
	}

	if (_Result.headers.find("Content-Length") != _Result.headers.end()) {
		size_t content_length = std::stoull(_Result.headers["Content-Length"]);

		char* _data = new char[content_length + 1];

		if (recv(_ClientSocket, _data, content_length * sizeof(char), 0) < 0) {
			l.err(__FUNCTION__"(): recv() failed. Close socket (%llu)", _ClientSocket);
			return Request("");
		}

		_data[content_length] = 0;
		_Result.data = _data;
		_Result.raw_text.append(_Result.data);

		delete[] _data;
	}

	return _Result;
}

int HttpServer::run() {
	clog::Log& l = clog::l();
	l.info(__FUNCTION__ "(): server start at %s:%d", m_IP.c_str(), (int)m_Port);

	while (m_Run) {
		accept();
	}

	return 0;
}

std::string HttpServer::file(std::string _FileName) {
	std::string file_text, line;

	std::ifstream file{ _FileName };

	if (!file.is_open()) {
		clog::l().warn(__FUNCTION__"() could not open the file '%s'", _FileName.c_str());
	}
	else {
		while (std::getline(file, line)) {
			file_text.append(line);
		}
	}

	return file_text;
}

// Request class

Request::Request(const std::string& _RawText) 
	: raw_text{ _RawText },
	method{ HTTP::Method::INVALID } {}

// Response class

Response::Response() {
	fill_std_response();
}

Response::Response(const char* _Text) {
	fill_std_response();

	headers["Content-Length"] = std::to_string(strlen(_Text));
	data = _Text;
}

Response::Response(const std::string& _Text) {
	fill_std_response();

	headers["Content-Length"] = std::to_string(_Text.length());
	data = _Text;
}

Response::Response(const std::string& _Text, HTTP::Status _Status) {
	fill_std_response();

	status = _Status;
	headers["Content-Length"] = std::to_string(_Text.length());
	data = _Text;
}

void Response::fill_std_response() {
	status = HTTP::Status::OK;
	protocol_version = "HTTP/1.1";

	headers["Server"] = "Asix";
	headers["Content-Type"] = "text/html";
	headers["Connection"] = "Closed";
}

std::string Response::make_src() {
	std::string _Src;

	std::string newline = "\r\n";
	constexpr const char* space = " ";

	_Src.append(protocol_version + space)
		.append(HTTP::str_status(status) + newline);

	for (auto& header : headers) {
		_Src.append(header.first + ": " + header.second + newline);
	}

	return _Src.append(newline + data + newline + newline);
}

std::string HTTP::str_status(HTTP::Status _Status) {
	auto& status_map = HTTP::StatusMap;

	if (status_map.find(_Status) == status_map.end()) {
		return status_map[HTTP::Status::Imateapot];
	}
	else {
		return status_map[_Status];
	}
}

std::map<HTTP::Status, std::string> HTTP::StatusMap = std::map<HTTP::Status, std::string>({
	{ HTTP::Status::Continue, "100 Continue" },
	{ HTTP::Status::SwitchingProtocols, "101 Switching Protocols" },
	{ HTTP::Status::Processing, "102 Processing" },
	{ HTTP::Status::EarlyHints, "103 Early Hints" },
	{ HTTP::Status::OK, "200 OK" },
	{ HTTP::Status::Created, "201 Created" },
	{ HTTP::Status::Accepted, "202 Accepted" },
	{ HTTP::Status::Non_AuthoritativeInformation, "203 Non-Authoritative Information" },
	{ HTTP::Status::NoContent, "204 No Content" },
	{ HTTP::Status::ResetContent, "205 Reset Content" },
	{ HTTP::Status::PartialContent, "206 Partial Content" },
	{ HTTP::Status::Multi_Status, "207 Multi-Status" },
	{ HTTP::Status::AlreadyReported, "208 Already Reported" },
	{ HTTP::Status::IMUsed, "226 IM Used" },
	{ HTTP::Status::MultipleChoices, "300 Multiple Choices" },
	{ HTTP::Status::MovedPermanently, "301 Moved Permanently" },
	{ HTTP::Status::Found, "302 Found" },
	{ HTTP::Status::SeeOther, "303 See Other" },
	{ HTTP::Status::NotModified, "304 Not Modified" },
	{ HTTP::Status::UseProxy, "305 Use Proxy" },
	{ HTTP::Status::TemporaryRedirect, "307 Temporary Redirect" },
	{ HTTP::Status::PermanentRedirect, "308 Permanent Redirect" },
	{ HTTP::Status::BadRequest, "400 Bad Request" },
	{ HTTP::Status::Unauthorized, "401 Unauthorized" },
	{ HTTP::Status::PaymentRequired, "402 Payment Required" },
	{ HTTP::Status::Forbidden, "403 Forbidden" },
	{ HTTP::Status::NotFound, "404 Not Found" },
	{ HTTP::Status::MethodNotAllowed, "405 Method Not Allowed" },
	{ HTTP::Status::NotAcceptable, "406 Not Acceptable" },
	{ HTTP::Status::ProxyAuthenticationRequired, "407 Proxy Authentication Required" },
	{ HTTP::Status::RequestTimeout, "408 Request Timeout" },
	{ HTTP::Status::Conflict, "409 Conflict" },
	{ HTTP::Status::Gone, "410 Gone" },
	{ HTTP::Status::LengthRequired, "411 Length Required" },
	{ HTTP::Status::PreconditionFailed, "412 Precondition Failed" },
	{ HTTP::Status::PayloadTooLarge, "413 Payload Too Large" },
	{ HTTP::Status::URITooLong, "414 URI Too Long" },
	{ HTTP::Status::UnsupportedMediaType, "415 Unsupported Media Type" },
	{ HTTP::Status::RangeNotSatisfiable, "416 Range Not Satisfiable" },
	{ HTTP::Status::ExpectationFailed, "417 Expectation Failed" },
	{ HTTP::Status::Imateapot, "418 I'm a teapot" },
	{ HTTP::Status::AuthenticationTimeout, "419 Authentication Timeout" },
	{ HTTP::Status::MisdirectedRequest, "421 Misdirected Request" },
	{ HTTP::Status::UnprocessableEntity, "422 Unprocessable Entity" },
	{ HTTP::Status::Locked, "423 Locked" },
	{ HTTP::Status::FailedDependency, "424 Failed Dependency" },
	{ HTTP::Status::TooEarly, "425 Too Early" },
	{ HTTP::Status::UpgradeRequired, "426 Upgrade Required" },
	{ HTTP::Status::PreconditionRequired, "428 Precondition Required" },
	{ HTTP::Status::TooManyRequests, "429 Too Many Requests" },
	{ HTTP::Status::RequestHeaderFieldsTooLarge, "431 Request Header Fields Too Large" },
	{ HTTP::Status::RetryWith, "449 Retry With" },
	{ HTTP::Status::UnavailableForLegalReasons, "451 Unavailable For Legal Reasons" },
	{ HTTP::Status::ClientClosedRequest, "499 Client Closed Request" },
	{ HTTP::Status::InternalServerError, "500 Internal Server Error" },
	{ HTTP::Status::NotImplemented, "501 Not Implemented" },
	{ HTTP::Status::BadGateway, "502 Bad Gateway" },
	{ HTTP::Status::ServiceUnavailable, "503 Service Unavailable" },
	{ HTTP::Status::GatewayTimeout, "504 Gateway Timeout" },
	{ HTTP::Status::HTTPVersionNotSupported, "505 HTTP Version Not Supported" },
	{ HTTP::Status::VariantAlsoNegotiates, "506 Variant Also Negotiates" },
	{ HTTP::Status::InsufficientStorage, "507 Insufficient Storage" },
	{ HTTP::Status::LoopDetected, "508 Loop Detected" },
	{ HTTP::Status::BandwidthLimitExceeded, "509 Bandwidth Limit Exceeded" },
	{ HTTP::Status::NotExtended, "510 Not Extended" },
	{ HTTP::Status::NetworkAuthenticationRequired, "511 Network Authentication Required" },
	{ HTTP::Status::UnknownError, "520 Unknown Error" },
	{ HTTP::Status::WebServerIsDown, "521 Web Server Is Down" },
	{ HTTP::Status::ConnectionTimedOut, "522 Connection Timed Out" },
	{ HTTP::Status::OriginIsUnreachable, "523 Origin Is Unreachable" },
	{ HTTP::Status::ATimeoutOccurred, "524 A Timeout Occurred" },
	{ HTTP::Status::SSLHandshakeFailed, "525 SSL Handshake Failed" },
	{ HTTP::Status::InvalidSSLCertificate, "526 Invalid SSL Certificate" }
});

#define DELETE (0x00010000L)
