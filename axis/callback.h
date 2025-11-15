#pragma once

#ifndef __AXIS_CALLBACK_H__
#define __AXIS_CALLBACK_H__

#include "request.h"
#include "response.h"

#include <set>
#include <vector>

namespace axis {

	typedef Response(*RefCallback)(Request&);

	struct Callback {
		RefCallback f = nullptr;
		std::set<Method> methods;
	};
}

#endif // !__AXIS_CALLBACK_H__