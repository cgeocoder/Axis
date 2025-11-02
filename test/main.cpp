#include "../axis/axis_server.h"
#include <iostream>

int main() {
	HttpServer app("192.168.1.45", 80);

	app("/", [](Request& r) -> Response {
		return "<h1>Hello from root page</h1>";
	});

	app("/login", [](Request& r) -> Response {

		return "<h1>Hello from login page</h1>";
	});

	return app.run();
}