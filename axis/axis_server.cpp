#define GLOBAL_LOGGER

#include <array>
#include <fstream>

#include "request.h"
#include "axis_server.h"
#include "logger/log.h"

#undef DELETE

namespace axis {
	AxisServer::AxisServer(const std::string& _IP, unsigned short _Port)
		: m_Run{ true },
		m_IP{ _IP },
		m_Port{ _Port } {
		clog::Log& l = clog::l();

		if (!init_server(_IP, _Port)) {
			l.err(__FUNCTION__ "(): init_server() failed: %s", m_CriticalError.c_str());
			m_Run = false;

			return;
		}
	}

	static Response default_not_fount_callback(Request& r) {
		return { "Not Found", NotFound };
	}

	static Response default_method_not_allowed_callback(Request& r) {
		return { "Method not allowed", MethodNotAllowed };
	}

	bool AxisServer::init_server(const std::string& _IP, unsigned short _Port) {
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

		m_NotFoundCallback = default_not_fount_callback;
		m_MethodNotAllowedCallback = default_method_not_allowed_callback;

		return true;
	}

	static bool is_template_path(const std::string& _Path) {
		if (_Path.find("/<") == std::string::npos) {
			return false;
		}

		size_t path_length = _Path.length();
		int br_count = 0;

		for (size_t i = 0; i < path_length - 1; ++i) {
			if (_Path.substr(i, 2) == "/<") {
				if (br_count != 0)
					return false;

				br_count += 1;
			}
			else if (_Path.substr(i, 2) == ">/") {
				if (br_count != 1)
					return false;

				br_count -= 1;
			}
		}

		if ((br_count == 1) && (_Path[path_length - 1] != '>'))
			return false;

		return true;
	}

	void AxisServer::operator ()(const std::string& _Path, const RefCallback& _Callback) {
		(void)(*this)(_Path, m_AllMethods, _Callback);
	}

	void AxisServer::operator ()(const std::string& _Path, const std::initializer_list<Method>& _Methods, const RefCallback& _Callback) {
		clog::Log& l = clog::l();

		if (_Callback == nullptr) {
			l.err(" callback function for '%s' is nullptr", _Path.c_str());
			return;
		}

		if (m_PathMap.find(_Path) != m_PathMap.end()) {
			l.warn("redefinition when accessing: path='%s'", _Path.c_str());
		}

		if (_Methods.size() == 0) {
			l.warn("allowed method list for '%s' is empty. Set default (all allow) list", _Path.c_str());
		}

		for (Method method : _Methods) {
			if (method < GET || method > PATCH) {
				l.warn("using unknoun method (not from <enum axis::Method>): method=%d", (int)method);
			}
		}

		// template
		bool a = is_template_path(_Path);

		__debugbreak();

		if (is_template_path(_Path)) {
			if (m_PathMapTemplates.find(_Path) != m_PathMapTemplates.end()) {
				l.warn("redefinition for template path when accessing: path='%s'", _Path.c_str());
			}

			std::vector<std::string> path_temp_sections = div_by_sections(_Path);
			std::vector<Section> sections;

			for (size_t i = 0; i < path_temp_sections.size(); ++i) {
				std::string& section = path_temp_sections.at(i);

				if (section.find('<') != std::string::npos) {
					if (section == "<?>") {
						if (i != path_temp_sections.size() - 1) {
							l.warn("the next sections of the path after <?> will be ignored: path='%s'", _Path.c_str());
							break;
						}
					}
					else if (section.find("<|") != std::string::npos || section.find("|>") != std::string::npos || section.find('/') != std::string::npos) {
						l.err("the path template is incorrect: section='%s', path='%s'", section.c_str(), _Path.c_str());
						return;
					}
				}
			}

			m_PathMapTemplates[_Path] = {
				_Callback, _Methods
			}; 
		}
		else {
			m_PathMap[_Path] = {
				_Callback, _Methods
			};
		}
	}

	std::vector<std::string> div_by(const std::string& path, char separator) {
		std::vector<std::string> sections;
		size_t div = 0, next_div = 0;

		while ((next_div = path.find(separator, next_div + 1)) != std::string::npos) {
			sections.push_back(path.substr(div + 1, next_div - div - 1));

			div = next_div;
		}
		sections.push_back(path.substr(div + 1, next_div - div - 1));

		return sections;
	};

	std::vector<std::string> div_by_sections(const std::string& path) {
		return div_by(path, '/');
	}

	bool is_mask_of(const std::string& mask, const std::string& path) {
		std::vector<Section> mask_sections, path_sections;

		for (auto& section : div_by_sections(path))
			path_sections.push_back(Section(section));

		for (auto& section : div_by_sections(mask))
			mask_sections.push_back(Section(section));

		size_t m_sec_size = mask_sections.size(),
			p_sec_size = path_sections.size();

		if (m_sec_size > p_sec_size)
			return false;

		const size_t min_sections_count = min(m_sec_size, p_sec_size);

		for (size_t i = 0; i < min_sections_count; ++i) {
			Section& m_sec = mask_sections.at(i),
				&p_sec = path_sections.at(i);

			if (m_sec.type == Section::non_template_section) {
				if (m_sec.section != p_sec.section)
					return false;
			}
			else if (m_sec.type == Section::template_variants_section) {
				if (!m_sec.one_of_variants(p_sec.section))
					return false;
			}
			else if (m_sec.type == Section::template_any_section) {
				return true;
			}
		}

		return true;
	}

	void decode_string(std::string& str) {
		for (auto& p : HTTP::URLEncodingMap) {
			size_t pos;

			while ((pos = str.find(p.first)) != std::string::npos) {
				__debugbreak();

				str = str.substr(0, pos)
					+ p.second 
					+ str.substr(pos + p.first.length());

				__debugbreak();
			}
		}
	}

	/*
	* /section1/<...>	means one non-empty section
	*
	* /section1/<a|b>	means /section1/a or /section1/b
	*
	* /section1/<?>		means any number of sections
	*
	*/

	void AxisServer::set_not_found_callback(RefCallback&& _Callback) {
		m_NotFoundCallback = _Callback;
	}

	void AxisServer::set_method_not_allowed_callback(RefCallback&& _Callback) {
		m_MethodNotAllowedCallback = _Callback;
	}

	void AxisServer::accept() {
		clog::Log& l = clog::l();

		int sizeofaddr = sizeof(m_SockAddrIn);
		SOCKET* new_client = new SOCKET{ ::accept(m_ServerSocket, (SOCKADDR*)&m_SockAddrIn, &sizeofaddr) };

		if (*new_client == 0) {
			l.err(__FUNCTION__ "(): accept() failed: client could not connect to the server");
		}
		else {
			l.info(__FUNCTION__ "(): [s: %llu] accept(): client connected", *new_client);

			auto create_client_thread = [&]() -> ClientData* {
				return new ClientData{
					new std::thread{ std::thread(&AxisServer::dispatcher, this, new_client) },
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
				make_response(*new_client,
					Response("<h1>The server cannot process your request because the maximum number of connections has been exceeded</h1>")
				);
				closesocket(*new_client);
				delete new_client;
			}
			else {
				m_Clients[m_ClientCounter++] = create_client_thread();
			}
		}
	}

	void AxisServer::dispatcher(SOCKET* _ClientSocket) {
		clog::Log& l = clog::l();

		bool client_run = true;

		auto send_method_not_allowed = [&](Request& r) -> void {
			if (!make_response(*_ClientSocket, m_MethodNotAllowedCallback(r))) {
				l.err(__FUNCTION__ "(): [s: %llu] make_response() failed", *_ClientSocket);
			}
		};

		while (client_run) {
			Request req = receive(*_ClientSocket);
			decode_string(req.path);

			std::map<std::string, std::string>& req_headers = req.headers;

			if ((req_headers.find("Connection") != req_headers.end()) && (req_headers["Connection"] == "Closed")) {
				client_run = false;
			}

			l.info(__FUNCTION__ "(): [s: %llu] required '%s'", *_ClientSocket, req.path.c_str());

			m_DataMutex.lock();

			Response response;
			Callback callback = find_callback(req.path);

			if (callback.f == nullptr) {
				response = m_NotFoundCallback(req);
			}
			else {
				if ((!callback.methods.empty()) && (callback.methods.find(req.method) == callback.methods.end())) {
					send_method_not_allowed(req);
				}
				else {
					response = callback.f(req);
				}
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

		::closesocket(*_ClientSocket);
		*_ClientSocket = 0;
	}

	static int axis_send_string(SOCKET _ClientSocket, const std::string& _Str) {
		int send_result = 0;
		size_t str_len = _Str.length();

		constexpr unsigned int max_message_len = MAXDWORD32;
		size_t sections = str_len / (size_t)max_message_len + 1;

		for (size_t i = 0; i < sections; ++i) {
			std::string section_message = _Str.substr(
				i * max_message_len,
				max_message_len
			);

			send_result = send(
				_ClientSocket,
				section_message.c_str(),
				(int)section_message.length(), 0);

			if (send_result < 0) {
				return send_result;
			}
		}

		return send_result;
	}

	bool AxisServer::make_response(SOCKET _ClientSocket, const Response& _Response) {
		return !(axis_send_string(_ClientSocket, _Response.make_src()) < 0);
	}

	Callback AxisServer::find_callback(std::string& _Path) {
		for (auto& path_temp : m_PathMapTemplates) {
			if (is_mask_of(path_temp.first, _Path))
				return path_temp.second;
		}

		if (m_PathMap.find(_Path) != m_PathMap.end()) {
			return m_PathMap[_Path];
		}

		return Callback{ nullptr };
	}

	Request AxisServer::receive(SOCKET _ClientSocket) {
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
				_Result.method = (Method)(i + 1);
			}
		}

		if (_Result.method == INVALID_METHOD) {
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

			if (recv(_ClientSocket, _data, (int)content_length * sizeof(char), 0) < 0) {
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

	int AxisServer::run() {
		if (!m_Run)
			return -1;

		clog::Log& l = clog::l();
		l.info(__FUNCTION__ "(): server start at %s:%d", m_IP.c_str(), (int)m_Port);

		while (m_Run) {
			accept();
		}

		return 0;
	}

	Response send_file(const std::string& _FileName) {
		return send_file(_FileName, OK);
	}

	Response send_file(const std::string& _FileName, Status _StatusCode) {
		std::string file_text, line;

		std::ifstream file{ _FileName };

		if (!file.is_open()) {
			clog::l().warn(__FUNCTION__"() could not open the file '%s'", _FileName.c_str());
		}
		else {
			while (std::getline(file, line))
				file_text.append(line);

			file.close();
		}

		return Response(file_text, _StatusCode);
	}

	Response render_template(const std::string& _FileName, std::map<std::string, std::string>& _Data) {
		return render_template(_FileName, _Data, OK);
	}

	Response render_template(const std::string& _FileName, std::map<std::string, std::string>& _Data, Status _StatusCode) {
		std::string file_text, line;

		std::ifstream file{ _FileName };

		if (!file.is_open()) {
			clog::l().warn(__FUNCTION__"() could not open the file '%s'", _FileName.c_str());
		}
		else {
			while (std::getline(file, line)) {
				for (auto& pair : _Data) {
					size_t param_index = line.find('%' + pair.first + '%');

					if (param_index != std::string::npos) {
						line =
							line.substr(0, param_index) +
							pair.second +
							line.substr(param_index + 2 + pair.first.length());
					}
				}

				file_text.append(line);
			}
		}

		return Response(file_text, _StatusCode);
	}

	Response redirect_to(const std::string& _To) {
		Response response("");
		response.status = MovedPermanently;
		response.protocol_version = "HTTP/1.1";
		response.headers["Location"] = _To;

		return response;
	}

	std::vector<std::pair<std::string, std::string>> parse_key_value_data(const std::string& _RawData) {
		std::vector<std::pair<std::string, std::string>> result;

		size_t last_ampersand = -1,
			ampersand = -1;

		while ((ampersand = _RawData.find('&', ampersand + 1)) != std::string::npos) {
			std::string param = _RawData.substr(last_ampersand + 1, ampersand - last_ampersand - 1);

			size_t assign = param.find('=');

			result.push_back({
				param.substr(0, assign),
				param.substr(assign + 1)
			});

			last_ampersand = ampersand;
		}

		std::string param = _RawData.substr(_RawData.find_last_of('&') + 1);
		size_t assign = param.find('=');

		result.push_back({
			param.substr(0, assign),
			param.substr(assign + 1)
		});

		return result;
	}

	// Request class

	Request::Request(const std::string& _RawText)
		: raw_text{ _RawText },
		method{ Method::INVALID_METHOD } {}

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

	Response::Response(const std::string& _Text, Status _Status) {
		fill_std_response();

		status = _Status;
		headers["Content-Length"] = std::to_string(_Text.length());
		data = _Text;
	}

	void Response::fill_std_response() {
		status = OK;
		protocol_version = "HTTP/1.1";

		headers["Server"] = "Asix";
		headers["Content-Type"] = "text/html";
		headers["Connection"] = "Closed";
	}

	std::string Response::make_src() const {
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

	std::string HTTP::str_status(Status _Status) {
		auto& status_map = HTTP::StatusMap;

		if (status_map.find(_Status) == status_map.end()) {
			return status_map[Imateapot];
		}
		else {
			return status_map[_Status];
		}
	}

	std::initializer_list<Method> AxisServer::m_AllMethods = { GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH };

	std::map<Status, std::string> HTTP::StatusMap = std::map<Status, std::string>({
		{ Continue, "100 Continue" },
		{ SwitchingProtocols, "101 Switching Protocols" },
		{ Processing, "102 Processing" },
		{ EarlyHints, "103 Early Hints" },
		{ OK, "200 OK" },
		{ Created, "201 Created" },
		{ Accepted, "202 Accepted" },
		{ Non_AuthoritativeInformation, "203 Non-Authoritative Information" },
		{ NoContent, "204 No Content" },
		{ ResetContent, "205 Reset Content" },
		{ PartialContent, "206 Partial Content" },
		{ Multi_Status, "207 Multi-Status" },
		{ AlreadyReported, "208 Already Reported" },
		{ IMUsed, "226 IM Used" },
		{ MultipleChoices, "300 Multiple Choices" },
		{ MovedPermanently, "301 Moved Permanently" },
		{ Found, "302 Found" },
		{ SeeOther, "303 See Other" },
		{ NotModified, "304 Not Modified" },
		{ UseProxy, "305 Use Proxy" },
		{ TemporaryRedirect, "307 Temporary Redirect" },
		{ PermanentRedirect, "308 Permanent Redirect" },
		{ BadRequest, "400 Bad Request" },
		{ Unauthorized, "401 Unauthorized" },
		{ PaymentRequired, "402 Payment Required" },
		{ Forbidden, "403 Forbidden" },
		{ NotFound, "404 Not Found" },
		{ MethodNotAllowed, "405 Method Not Allowed" },
		{ NotAcceptable, "406 Not Acceptable" },
		{ ProxyAuthenticationRequired, "407 Proxy Authentication Required" },
		{ RequestTimeout, "408 Request Timeout" },
		{ Conflict, "409 Conflict" },
		{ Gone, "410 Gone" },
		{ LengthRequired, "411 Length Required" },
		{ PreconditionFailed, "412 Precondition Failed" },
		{ PayloadTooLarge, "413 Payload Too Large" },
		{ URITooLong, "414 URI Too Long" },
		{ UnsupportedMediaType, "415 Unsupported Media Type" },
		{ RangeNotSatisfiable, "416 Range Not Satisfiable" },
		{ ExpectationFailed, "417 Expectation Failed" },
		{ Imateapot, "418 I'm a teapot" },
		{ AuthenticationTimeout, "419 Authentication Timeout" },
		{ MisdirectedRequest, "421 Misdirected Request" },
		{ UnprocessableEntity, "422 Unprocessable Entity" },
		{ Locked, "423 Locked" },
		{ FailedDependency, "424 Failed Dependency" },
		{ TooEarly, "425 Too Early" },
		{ UpgradeRequired, "426 Upgrade Required" },
		{ PreconditionRequired, "428 Precondition Required" },
		{ TooManyRequests, "429 Too Many Requests" },
		{ RequestHeaderFieldsTooLarge, "431 Request Header Fields Too Large" },
		{ RetryWith, "449 Retry With" },
		{ UnavailableForLegalReasons, "451 Unavailable For Legal Reasons" },
		{ ClientClosedRequest, "499 Client Closed Request" },
		{ InternalServerError, "500 Internal Server Error" },
		{ NotImplemented, "501 Not Implemented" },
		{ BadGateway, "502 Bad Gateway" },
		{ ServiceUnavailable, "503 Service Unavailable" },
		{ GatewayTimeout, "504 Gateway Timeout" },
		{ HTTPVersionNotSupported, "505 HTTP Version Not Supported" },
		{ VariantAlsoNegotiates, "506 Variant Also Negotiates" },
		{ InsufficientStorage, "507 Insufficient Storage" },
		{ LoopDetected, "508 Loop Detected" },
		{ BandwidthLimitExceeded, "509 Bandwidth Limit Exceeded" },
		{ NotExtended, "510 Not Extended" },
		{ NetworkAuthenticationRequired, "511 Network Authentication Required" },
		{ UnknownError, "520 Unknown Error" },
		{ WebServerIsDown, "521 Web Server Is Down" },
		{ ConnectionTimedOut, "522 Connection Timed Out" },
		{ OriginIsUnreachable, "523 Origin Is Unreachable" },
		{ ATimeoutOccurred, "524 A Timeout Occurred" },
		{ SSLHandshakeFailed, "525 SSL Handshake Failed" },
		{ InvalidSSLCertificate, "526 Invalid SSL Certificate" }
	});

	std::map<std::string, std::string> HTTP::URLEncodingMap = std::map<std::string, std::string>({
		{"%7E", "~"},
		{"60%", "`"},
		{"27%", "'"},
		{"22%", "\""},
		{"40%", "@"},
		{"%3F", "?"},
		{"21%", "!"},
		{"23%", "#"},
		{"%B9", "¹"},
		{"24%", "$"},
		{"25%", "%"},
		{"%5E", "^"},
		{"26%", "&"},
		{"%2B", "+"},
		{"%2A", "*"},
		{"%3A", ":"},
		{"%2C", ","},
		{"28%", "("},
		{"29%", ")"},
		{"%7B", "{"},
		{"%7D", "}"},
		{"%5B", "["},
		{"%5D", "]"},
		{"%3C", "<"},
		{"%3E", ">"},
		{"%2F", "/"},
		{"%5C", " "},
		{"%C0", "À"},
		{"%E0", "à"},
		{"%C1", "Á"},
		{"%E1", "á"},
		{"%C2", "Â"},
		{"%E2", "â"},
		{"%C3", "Ã"},
		{"%E3", "ã"},
		{"%C4", "Ä"},
		{"%E4", "ä"},
		{"%C5", "Å"},
		{"%E5", "å"},
		{"%A8", "¨"},
		{"%B8", "¸"},
		{"%C6", "Æ"},
		{"%E6", "æ"},
		{"%C7", "Ç"},
		{"%E7", "ç"},
		{"%C8", "È"},
		{"%E8", "è"},
		{"%C9", "É"},
		{"%E9", "é"},
		{"%CA", "Ê"},
		{"%EA", "ê"},
		{"%CB", "Ë"},
		{"%EB", "ë"},
		{"%CC", "Ì"},
		{"%EC", "ì"},
		{"%CD", "Í"},
		{"%ED", "í"},
		{"%CE", "Î"},
		{"%EE", "î"},
		{"%CF", "Ï"},
		{"%EF", "ï"},
		{"%D0", "Ð"},
		{"%F0", "ð"},
		{"%D1", "Ñ"},
		{"%F1", "ñ"},
		{"%D2", "Ò"},
		{"%F2", "ò"},
		{"%D3", "Ó"},
		{"%F3", "ó"},
		{"%D4", "Ô"},
		{"%F4", "ô"},
		{"%D5", "Õ"},
		{"%F5", "õ"},
		{"%D6", "Ö"},
		{"%F6", "ö"},
		{"%D7", "×"},
		{"%F7", "÷"},
		{"%D8", "Ø"},
		{"%F8", "ø"},
		{"%D9", "Ù"},
		{"%F9", "ù"},
		{"%DA", "Ú"},
		{"%FA", "ú"},
		{"%DB", "Û"},
		{"%FB", "û"},
		{"%DC", "Ü"},
		{"%FC", "ü"},
		{"%DD", "Ý"},
		{"%FD", "ý"},
		{"%DE", "Þ"},
		{"%FE", "þ"},
		{"%DF", "ß"},
		{"%FF", "ÿ"}
	});
}

#define DELETE (0x00010000L)
