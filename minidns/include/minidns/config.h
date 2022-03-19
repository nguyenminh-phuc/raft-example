#ifndef MD_CONFIG_H
#define MD_CONFIG_H

#ifdef _MSC_VER
#define MD_RESTRICT __restrict
#else
#define MD_RESTRICT //restrict
#endif

#ifdef _WIN32

// define _WIN32_WINNT
#include <sdkddkver.h>

// Visibility: https://gcc.gnu.org/wiki/Visibility
#define MD_DLL_IMPORT __declspec(dllimport)
#define MD_DLL_EXPORT __declspec(dllexport)
#else
#define MD_DLL_IMPORT __attribute__ ((visibility ("default")))
#define MD_DLL_EXPORT __attribute__ ((visibility ("default")))
#endif

#ifdef MD_DLL
#ifdef MD_DLL_EXPORTS
#define MD_API MD_DLL_EXPORT
#else
#define MD_API MD_DLL_IMPORT
#endif
#else
#define MD_API
#endif

#endif
