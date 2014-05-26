/*
    This file is part of AcceSSL.

    Copyright 2011-2014 Marcin Gozdalik <gozdal@gmail.com>

    AcceSSL is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    AcceSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with AcceSSL; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _ACCESSL_LOG_H
#define _ACCESSL_LOG_H

#include <log4c.h>

int log_init(void);
void log_destroy(void);
const char *log_hex(int len, const unsigned char *data);

#define LOG_MODULE_DEFINE \
    static log4c_category_t *__logging_cat

#define LOG_MODULE_INIT(module) \
    __logging_cat = log4c_category_get(module)

#define LOG_MODULE_DESTROY(...) \
    log4c_category_delete(__logging_cat)

#ifdef _DEBUG

#define LOG_TRACE(...) \
    log4c_category_log(__logging_cat, LOG4C_PRIORITY_TRACE, __VA_ARGS__)

#define LOG_DEBUG(...) \
    log4c_category_log(__logging_cat, LOG4C_PRIORITY_DEBUG, __VA_ARGS__)
#else

#define LOG_TRACE(...) \
    do {} while(0)

#define LOG_DEBUG(...) \
    do {} while(0)

#endif

#define LOG_INFO(...) \
    log4c_category_log(__logging_cat, LOG4C_PRIORITY_INFO, __VA_ARGS__)

#define LOG_WARN(...) \
    log4c_category_log(__logging_cat, LOG4C_PRIORITY_WARN, __VA_ARGS__)

#define LOG_ERROR(...) \
    log4c_category_log(__logging_cat, LOG4C_PRIORITY_ERROR, __VA_ARGS__)

#define LOG_FATAL(...) \
    log4c_category_log(__logging_cat, LOG4C_PRIORITY_FATAL, __VA_ARGS__)

#endif // _ACCESSL_LOG_H
