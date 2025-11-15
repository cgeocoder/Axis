#pragma once

#ifndef __AXIS_SERVER_H__
#define __AXIS_SERVER_H__

#include "http.h"
#include "callback.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)
#pragma warning(disable: 4091)

#include <WinSock2.h>
#include <winsock.h>
#include <map>
#include <thread>
#include <mutex>
#include <initializer_list>

namespace axis {
	class AxisServer;
	class Request;
	class Response;

	class ClientData {
	public:
		std::thread* thread;
		SOCKET* socket;
	};

	class AxisServer {
	private:
		std::string m_IP;
		unsigned short m_Port;

		SOCKET m_ServerSocket;
		SOCKADDR_IN m_SockAddrIn;

		std::mutex m_DataMutex;
		std::map<std::string, Callback> m_PathMap;
		std::map<std::string, Callback> m_PathMapTemplates;
		RefCallback m_NotFoundCallback;
		RefCallback m_MethodNotAllowedCallback;

		std::string m_CriticalError;
		bool m_Run;

		size_t m_MaxClients = 10, m_ClientCounter = 0;
		ClientData* m_Clients[10];

		static std::initializer_list<Method> m_AllMethods;

	public:
		AxisServer(const std::string& _IP, unsigned short _Port);

		void operator ()(
			const std::string& _Path, 
			const RefCallback& _Callback
		);

		void operator ()(
			const std::string& _Path, 
			const std::initializer_list<Method>& _Methods,
			const RefCallback& _Callback
		);

		void set_not_found_callback(RefCallback&& _Callback);
		void set_method_not_allowed_callback(RefCallback&& _Callback);

		int run();

	private:
		void accept();
		void dispatcher(SOCKET* _ClientSocket);

		Request receive(SOCKET _ClientSocket);
		bool make_response(SOCKET _ClientSocket, const Response& _Response);
		Callback find_callback(std::string& _Path);

		bool init_server(const std::string& _IP, unsigned short _Port);
	};
}

#endif // !__AXIS_SERVER_H__