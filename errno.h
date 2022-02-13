/**
 * Simple HTTP server application
 *
 * Author: Pavel Kratochvil (xkrato61)
 *
 * @file errno.h
 *
 * @brief defines error codes
 */
#ifndef HTTPSERVER_ERRNO_H
#define HTTPSERVER_ERRNO_H

#define ERROR -1        // generic error
#define ERROR_SOCK -2   // unable to create socket
#define ERROR_BIND -3   // binding failed
#define ERROR_LIS -4    // listening failed
#define ERROR_ACC -5    // accepting failed
#define ERROR_RD -6     // reading failed
#define ERROR_PARAM -7  // wrong number of parameters
#define ERROR_CPU -8    // unable to read CPU name
#define ERROR_MEM -9    // allocation error
#define ERROR_NAME -10  // unable to read hostname
#define ERROR_LOAD -11  // cpu load reading failed
#define ERROR_CLOSE -12 // closing fptr created by open() failed
#define ERROR_WRITE -13 // writing HTTP response to socket failed

#endif //HTTPSERVER_ERRNO_H
