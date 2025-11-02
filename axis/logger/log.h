#pragma once

#ifndef __LOGS_H__
#define __LOGS_H__

#define _CRT_SECURE_NO_WARNINGS

#include <string>

namespace clog {

	// Logging
	class Log final {
	private:
		// gets current data in [dd.mm.yy - hh.mm.ss]
		static std::string get_current_date();

		/*void color_cstring_print(
			const char* start_color,
			const char* format_string,
			const std::string& str,
			va_list arg_list
		) {
			const char* color_start = start_color;
			const char* color_end = "\033[0m";

			if (this->out_file_std != stdout)
				color_start = color_end = "";

			char log_title[127] = { 0 };

			sprintf(log_title, format_string,
				this->get_current_date().c_str(),
				color_start, color_end,
				str.c_str());

			vfprintf(this->out_file_std, log_title, arg_list);
		}

		void color_wcstring_print() {

		}*/

	public:
		Log();
		Log(FILE* common_out_file);
		Log(FILE* out_file_std, FILE* out_file_err);

		// just printf
		void p(const std::string& str, ...) const;

		// just wprintf
		void p(const std::wstring& str, ...) const;

		// print one character
		void p(char chr) const;

		// print with error tag
		void err(const std::string& str, ...) const;
		void err(const std::wstring& str, ...) const;

		// print with info tag
		void info(const std::string& str, ...) const;
		void info(const std::wstring& str, ...) const;

		// print with warn tag
		void warn(const std::string& str, ...) const;
		void warn(const std::wstring& str, ...) const;

		inline void set_err_out(FILE* out_file_err) { this->out_file_err = out_file_err; }
		inline void set_std_out(FILE* out_file_std) { this->out_file_std = out_file_std; }

	private:
		FILE* out_file_std = NULL;
		FILE* out_file_err = NULL;
	};

#ifdef GLOBAL_LOGGER
	Log& l();
#endif // !GLOBAL_LOGGER
}

#endif // __LOGS_H__