#include "../axis/axis_server.h"
#include <iostream>

int main() {
	using namespace axis;

	AxisServer app("192.168.1.33", 80);

	app.set_allow_methods({ GET, POST });

	app("/", { GET }, [](Request& r) -> Response {
		
		return "<a href='/login'>Login page</a>";
	});

	app("/login", { GET, POST }, [](Request& r) -> Response {
		if (r.method == GET) {
			return send_file("src\\test\\page_login.html");
		}
		else {
			return redirect_to("/account");
		}
	});

	return app.run();
}