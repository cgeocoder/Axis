#define _CRT_NON_CONFORMING_SWPRINTFS

#include "log.h"

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <locale.h>

namespace clog {

    Log::Log() {
        setlocale(LC_ALL, ".utf8");

        this->out_file_std = stdout;
        this->out_file_err = stderr;
    }

    Log::Log(FILE* common_out_file) {
        setlocale(LC_ALL, ".utf8");

        _ASSERT(common_out_file == nullptr);

        this->out_file_std = common_out_file;
        this->out_file_err = common_out_file;
    }

    Log::Log(FILE* out_file_std, FILE* out_file_err) {
        setlocale(LC_ALL, ".utf8");

        _ASSERT(out_file_std == nullptr || out_file_err == nullptr);

        this->out_file_std = out_file_std;
        this->out_file_err = out_file_err;
    }

    std::string Log::get_current_date() {
        time_t now = time(0);

        char buf[32];
        strftime(buf, sizeof(buf), "[%d.%m.%y - %X]", &(*localtime(&now)));

        return std::string(buf);
    }

    void Log::p(const std::string& str, ...) const {
        va_list args;
        va_start(args, str.c_str());

        vfprintf(this->out_file_err, str.c_str(), args);

        va_end(args);
    }

    void Log::p(const std::wstring& str, ...) const {
        va_list args;
        va_start(args, str.c_str());

        vfwprintf(this->out_file_err, str.c_str(), args);

        va_end(args);
    }

    void Log::p(char chr) const {
        fputc(chr, this->out_file_std);
    }

#define BEGIN_COLOR_RED "\x1B[31m"
#define BEGIN_COLOR_GREEN "\x1B[32m"
#define BEGIN_COLOR_YELLOW "\x1B[93m"
#define END_COLOR "\033[0m"

    void Log::err(const std::string& str, ...) const {
        const char* err_color_start = BEGIN_COLOR_RED;
        const char* err_color_end = END_COLOR;

        if (this->out_file_err != stderr && this->out_file_err != stdout)
            err_color_start = err_color_end = "";

        va_list args;
        va_start(args, str.c_str());

        char log_title[127] = { 0 };

        sprintf(log_title,
            "%s %sERROR%s: %s\n",
            this->get_current_date().c_str(),
            err_color_start, err_color_end,
            str.c_str());

        vfprintf(this->out_file_err, log_title, args);

        va_end(args);
    }

    void Log::err(const std::wstring& str, ...) const {
        const char* err_color_start = BEGIN_COLOR_RED;
        const char* err_color_end = END_COLOR;

        if (this->out_file_err != stderr && this->out_file_err != stdout)
            err_color_start = err_color_end = "";


        va_list args;
        va_start(args, str.c_str());

        wchar_t log_title[127] = { 0 };

        swprintf(log_title,
            L"%S %SERROR%S: %ws\n",
            this->get_current_date().c_str(),
            err_color_start, err_color_end,
            str.c_str());

        vfwprintf(this->out_file_err, log_title, args);

        va_end(args);
    }

    void Log::info(const std::string& str, ...) const {
        const char* info_color_start = BEGIN_COLOR_GREEN;
        const char* info_color_end = END_COLOR;

        if (this->out_file_std != stdout)
            info_color_start = info_color_end = "";

        va_list args;
        va_start(args, str.c_str());

        char log_title[127] = { 0 };

        sprintf(log_title,
            "%s %sINFO%s: %s\n",
            this->get_current_date().c_str(),
            info_color_start, info_color_end,
            str.c_str());

        vfprintf(this->out_file_std, log_title, args);

        va_end(args);
    }

    void Log::info(const std::wstring& str, ...) const {
        const char* info_color_start = BEGIN_COLOR_GREEN;
        const char* info_color_end = END_COLOR;

        if (this->out_file_std != stdout)
            info_color_start = info_color_end = "";

        va_list args;
        va_start(args, str.c_str());

        wchar_t log_title[127] = { 0 };

        swprintf(log_title,
            L"%S %SINFO%S: %ws\n",
            this->get_current_date().c_str(),
            info_color_start, info_color_end,
            str.c_str());

        vfwprintf(this->out_file_std, log_title, args);

        va_end(args);
    }

    void Log::warn(const std::string& str, ...) const {
        const char* warn_color_start = BEGIN_COLOR_YELLOW;
        const char* warn_color_end = END_COLOR;

        if (this->out_file_std != stdout)
            warn_color_start = warn_color_end = "";

        va_list args;
        va_start(args, str.c_str());

        char log_title[127] = { 0 };

        sprintf(log_title,
            "%s %sWARN%s: %s\n",
            this->get_current_date().c_str(),
            warn_color_start, warn_color_end,
            str.c_str());

        vfprintf(this->out_file_std, log_title, args);

        va_end(args);
    }

    void Log::warn(const std::wstring& str, ...) const {
        const char* warn_color_start = BEGIN_COLOR_YELLOW;
        const char* warn_color_end = END_COLOR;

        if (this->out_file_std != stdout)
            warn_color_start = warn_color_end = "";

        va_list args;
        va_start(args, str.c_str());

        wchar_t log_title[127] = { 0 };

        swprintf(log_title,
            L"%S %SWARN%S: %ws\n",
            this->get_current_date().c_str(),
            warn_color_start, warn_color_end,
            str.c_str());

        vfwprintf(this->out_file_std, log_title, args);

        va_end(args);
    }

#undef BEGIN_COLOR_RED
#undef BEGIN_COLOR_GREEN
#undef BEGIN_COLOR_YELLOW
#undef END_COLOR

    Log _logger;

    // Global Logger
    Log& l() { return _logger; }
}