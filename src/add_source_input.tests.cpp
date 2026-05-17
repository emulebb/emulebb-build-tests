#include "../third_party/doctest/doctest.h"

#include "AddSourceInputSeams.h"

namespace
{
	/**
	 * @brief Returns the scalar form used by inet_addr for dotted IPv4 text.
	 */
	uint32_t NetworkOrderIPv4(unsigned u1, unsigned u2, unsigned u3, unsigned u4)
	{
		return u1 | (u2 << 8u) | (u3 << 16u) | (u4 << 24u);
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Add source input seam parses source-client endpoints")
{
	const AddSourceInputSeams::SourceClientInput embedded = AddSourceInputSeams::ParseSourceClientInput(CString(_T("5.6.7.8:61000")), CString(_T("4662")));
	CHECK(embedded.Valid);
	CHECK(embedded.AddressContainedPort);
	CHECK(embedded.NetworkOrderAddress == NetworkOrderIPv4(5, 6, 7, 8));
	CHECK(embedded.Port == 61000);

	const AddSourceInputSeams::SourceClientInput separate = AddSourceInputSeams::ParseSourceClientInput(CString(_T("5.6.7.8")), CString(_T("4662")));
	CHECK(separate.Valid);
	CHECK_FALSE(separate.AddressContainedPort);
	CHECK(separate.Port == 4662);
}

TEST_CASE("Add source input seam rejects endpoint truncation risks")
{
	CHECK_FALSE(AddSourceInputSeams::ParseSourceClientInput(CString(_T("5.6.7.8:70000")), CString(_T("4662"))).Valid);
	CHECK_FALSE(AddSourceInputSeams::ParseSourceClientInput(CString(_T("5.6.7.8")), CString(_T("999999"))).Valid);
	CHECK_FALSE(AddSourceInputSeams::ParseSourceClientInput(CString(_T("5.6.7")), CString(_T("4662"))).Valid);
	CHECK_FALSE(AddSourceInputSeams::ParseSourceClientInput(CString(_T("5.6.7.8")), CString(_T("abc"))).Valid);
}

TEST_CASE("Add source input seam extracts supported URL sources")
{
	const AddSourceInputSeams::UrlSourceInput input = AddSourceInputSeams::ParseUrlSourceInput(CString(_T(" https://user:pass@example.net/files/test.bin ")));
	CHECK(input.Valid);
	CHECK(input.Url == CString(_T("https://user:pass@example.net/files/test.bin")));
	CHECK(input.Scheme == CString(_T("https")));
	CHECK(input.HostName == CString(_T("example.net")));

	CHECK(AddSourceInputSeams::ParseUrlSourceInput(CString(_T("ftp://mirror.example.net/pub/file.dat"))).Valid);
	CHECK_FALSE(AddSourceInputSeams::ParseUrlSourceInput(CString(_T("file://C:/temp/file.dat"))).Valid);
	CHECK_FALSE(AddSourceInputSeams::ParseUrlSourceInput(CString(_T("https:///missing-host"))).Valid);
}

TEST_SUITE_END();
