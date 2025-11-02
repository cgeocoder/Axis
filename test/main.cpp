#include "../axis/axis_server.h"
#include <iostream>

int main() {
	HttpServer app("192.168.1.45", 80);

	app.set_allow_methods({ HTTP::Method::GET, HTTP::Method::POST });

	app("/", [](Request& r) -> Response {
		if (r.method != HTTP::Method::GET) {
			return { "<h1>Method not allowed</h1>", HTTP::Status::MethodNotAllowed };
		}

		return "<a href='/login'>Login page</a>";
	});

	app("/login", [](Request& r) -> Response {
		if (r.method == HTTP::Method::GET) {
			return HttpServer::file("src\\test\\page_login.html");
		}
		else {
			return r.data;
		}
	});

	return app.run();
}