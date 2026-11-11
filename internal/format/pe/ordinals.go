package pe

// The ordinal tables below name the well-known exports of ws2_32.dll,
// wsock32.dll and oleaut32.dll so that an import by ordinal contributes the same
// text to the import hash as the equivalent import by name. They are
// deliberately PARTIAL: only ordinals that are certain are listed (the
// Winsock 1.1 core, the Winsock 1.1 asynchronous API and the classic OLE
// automation block). Any other ordinal falls back to "ord<N>", which is also
// what pefile does for ordinals missing from its own tables, so an import
// hash can differ from pefile's when an image imports one of the ordinals that
// pefile knows and these tables do not.

// ws232Ordinals covers ws2_32.dll.
var ws232Ordinals = map[uint16]string{
	1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername", 6: "getsockname",
	7: "getsockopt", 8: "htonl", 9: "htons", 10: "ioctlsocket", 11: "inet_addr", 12: "inet_ntoa",
	13: "listen", 14: "ntohl", 15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select", 19: "send",
	20: "sendto", 21: "setsockopt", 22: "shutdown", 23: "socket",
	51: "gethostbyaddr", 52: "gethostbyname", 53: "getprotobyname", 54: "getprotobynumber",
	55: "getservbyname", 56: "getservbyport", 57: "gethostname",
	101: "WSAAsyncSelect", 102: "WSAAsyncGetHostByAddr", 103: "WSAAsyncGetHostByName",
	104: "WSAAsyncGetProtoByNumber", 105: "WSAAsyncGetProtoByName", 106: "WSAAsyncGetServByPort",
	107: "WSAAsyncGetServByName", 108: "WSACancelAsyncRequest", 109: "WSASetBlockingHook",
	110: "WSAUnhookBlockingHook", 111: "WSAGetLastError", 112: "WSASetLastError",
	113: "WSACancelBlockingCall", 114: "WSAIsBlocking", 115: "WSAStartup", 116: "WSACleanup",
	151: "__WSAFDIsSet",
}

// wsock32Ordinals covers wsock32.dll, which follows the Winsock 1.1 numbering.
var wsock32Ordinals = map[uint16]string{
	1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername", 6: "getsockname",
	7: "getsockopt", 8: "htonl", 9: "htons", 10: "inet_addr", 11: "inet_ntoa", 12: "ioctlsocket",
	13: "listen", 14: "ntohl", 15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select", 19: "send",
	20: "sendto", 21: "setsockopt", 22: "shutdown", 23: "socket",
	51: "gethostbyaddr", 52: "gethostbyname", 53: "getprotobyname", 54: "getprotobynumber",
	55: "getservbyname", 56: "getservbyport", 57: "gethostname",
	101: "WSAAsyncSelect", 102: "WSAAsyncGetHostByAddr", 103: "WSAAsyncGetHostByName",
	104: "WSAAsyncGetProtoByNumber", 105: "WSAAsyncGetProtoByName", 106: "WSAAsyncGetServByPort",
	107: "WSAAsyncGetServByName", 108: "WSACancelAsyncRequest", 109: "WSASetBlockingHook",
	110: "WSAUnhookBlockingHook", 111: "WSAGetLastError", 112: "WSASetLastError",
	113: "WSACancelBlockingCall", 114: "WSAIsBlocking", 115: "WSAStartup", 116: "WSACleanup",
	151: "__WSAFDIsSet",
}

// oleaut32Ordinals covers the classic BSTR, VARIANT, SAFEARRAY and IDispatch
// helpers of oleaut32.dll.
var oleaut32Ordinals = map[uint16]string{
	2: "SysAllocString", 3: "SysReAllocString", 4: "SysAllocStringLen", 5: "SysReAllocStringLen",
	6: "SysFreeString", 7: "SysStringLen", 8: "VariantInit", 9: "VariantClear", 10: "VariantCopy",
	11: "VariantCopyInd", 12: "VariantChangeType", 13: "VariantTimeToDosDateTime",
	14: "DosDateTimeToVariantTime", 15: "SafeArrayCreate", 16: "SafeArrayDestroy",
	17: "SafeArrayGetDim", 18: "SafeArrayGetElemsize", 19: "SafeArrayGetUBound",
	20: "SafeArrayGetLBound", 21: "SafeArrayLock", 22: "SafeArrayUnlock", 23: "SafeArrayAccessData",
	24: "SafeArrayUnaccessData", 25: "SafeArrayGetElement", 26: "SafeArrayPutElement",
	27: "SafeArrayCopy", 28: "DispGetParam", 29: "DispGetIDsOfNames", 30: "DispInvoke",
	31: "CreateDispTypeInfo", 32: "CreateStdDispatch", 33: "RegisterActiveObject",
	34: "RevokeActiveObject", 35: "GetActiveObject", 149: "SysStringByteLen", 150: "SysAllocStringByteLen",
}
