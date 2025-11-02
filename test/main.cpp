#include "../axis/axis_server.h"
#include <iostream>

int main() {
	using namespace axis;

	AxisServer app("192.168.1.45", 80);

	app.set_allow_methods({ HTTP::Method::GET, HTTP::Method::POST });

	app("/", [](Request& r) -> Response {
		if (r.method != HTTP::Method::GET) {
			return { "<h1>Method not allowed</h1>", HTTP::Status::MethodNotAllowed };
		}

		return "<a href='/login'>Login page</a>";
	});

	app("/login", [](Request& r) -> Response {
		if (r.method == HTTP::Method::GET) {
			return send_file("src\\test\\page_login.html");
		}
		else {
			auto p = parse_parameter(r.data);

			__debugbreak();

			return redirect_to("/account");
		}
	});

	return app.run();
}