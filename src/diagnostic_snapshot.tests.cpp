#include "doctest.h"

#include "DiagnosticSnapshotSeams.h"

TEST_SUITE_BEGIN("diagnostic_snapshot");

TEST_CASE("network redaction masks IPv4 addresses without keeping the host")
{
	CHECK(DiagnosticSnapshotSeams::RedactNetworkAddress(_T("203.0.113.42")) == _T("203.0.113.x"));
	CHECK(DiagnosticSnapshotSeams::RedactNetworkAddress(_T(" 10.54.218.144 ")) == _T("10.54.218.x"));
}

TEST_CASE("network redaction hides non IPv4 endpoint names")
{
	CHECK(DiagnosticSnapshotSeams::RedactNetworkAddress(_T("example.invalid")) == _T("[redacted]"));
	CHECK(DiagnosticSnapshotSeams::RedactNetworkAddress(_T("2001:db8::1")) == _T("[redacted]"));
	CHECK(DiagnosticSnapshotSeams::RedactNetworkAddress(CString()).IsEmpty());
}

TEST_CASE("path redaction masks Windows profile names and preserves useful suffixes")
{
	CHECK(DiagnosticSnapshotSeams::RedactPath(_T("C:\\Users\\Alice\\AppData\\Roaming\\eMule\\config\\preferences.ini"))
		== _T("C:\\Users\\<user>\\AppData\\Roaming\\eMule\\config\\preferences.ini"));
	CHECK(DiagnosticSnapshotSeams::RedactPath(_T("D:\\Portable\\eMule\\config\\preferences.ini"))
		== _T("D:\\Portable\\eMule\\config\\preferences.ini"));
}

TEST_SUITE_END();
