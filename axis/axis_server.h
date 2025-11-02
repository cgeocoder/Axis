#pragma once

#ifndef __AXIS_SERVER_H__
#define __AXIS_SERVER_H__

#include "http/http.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)
#pragma warning(disable: 4091)

#include <WinSock2.h>
#include <winsock.h>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <initializer_list>
#include <set>

namespace axis {

	class AxisServer;

	class Request {
	public:
		Request(const std::string& _RawText);

		HTTP::Method method;
		std::string protocol_version;
		std::string path;
		std::map<std::string, std::string> headers;

		std::string raw_text, data;
	};

	class Response {
		friend class AxisServer;

	private:
		Response();

		void fill_std_response();
		std::string make_src() const;

	public:
		std::string protocol_version;
		HTTP::Status status;
		std::string data;
		std::map<std::string, std::string> headers;

		Response(const char* _Text);

		Response(const std::string& _Text);
		Response(const std::string& _Text, HTTP::Status _Status);
	};

	typedef Response(*RefCallback)(Request&);
	typedef Response(*RefCallbackAdv)(Request&, const std::vector<std::string>&);

	class ClientInfo {
	public:
		std::thread* thread;
		SOCKET* socket;
	};

	class PathMask {
	public:
		static inline bool mask(const std::string& _Path) { return true; }
	};

	class AxisServer {
	private:
		std::string m_IP;
		unsigned short m_Port;

		SOCKET m_ServerSocket;
		SOCKADDR_IN m_SockAddrIn;

		std::mutex m_DataMutex;
		std::map<std::string, RefCallback> m_PathMap;
		std::map<std::string, RefCallbackAdv> m_PathMapAdv;
		RefCallbackAdv m_NotFoundCallback;
		RefCallback m_MethodNotAllowedCallback;

		std::string m_CriticalError;
		bool m_Run;

		size_t m_MaxClients = 10, m_ClientCounter = 0;
		ClientInfo* m_Clients[10];

		std::set<HTTP::Method> m_AllowMethods;

	public:
		AxisServer(const std::string& _IP, unsigned short _Port);

		void operator ()(const std::string& _Path, const RefCallback& _Callback);

		void operator ()(const std::string& _Path, const RefCallbackAdv& _Callback);

		void set_not_found_callback(RefCallbackAdv& _Callback);
		void set_method_not_allowed_callback(RefCallback& _Callback);

		bool set_allow_methods(const std::initializer_list<HTTP::Method>& _MehodList);

		// static std::vector<std::pair<std::string, std::string>> parse_user_data();

		int run();

	private:
		void accept();
		void dispatcher(SOCKET* _ClientSocket);

		Request receive(SOCKET _ClientSocket);
		bool make_response(SOCKET _ClientSocket, const Response& _Response);

		bool init_server(const std::string& _IP, unsigned short _Port);
	};

	Response redirect_to(const std::string& _To);
	Response send_file(const std::string& _FileName);
	std::vector<std::pair<std::string, std::string>> parse_parameter(const std::string& _ParametersRaw);

}

#endif // !__AXIS_SERVER_H__