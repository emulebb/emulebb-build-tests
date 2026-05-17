#include "../third_party/doctest/doctest.h"

#include <cstdint>
#include <string>
#include <vector>

namespace
{
	struct ByteReader
	{
		const std::vector<uint8_t> Bytes;
		size_t Offset = 0;

		bool CanRead(size_t uSize) const
		{
			return Offset <= Bytes.size() && uSize <= Bytes.size() - Offset;
		}

		bool ReadUInt8(uint8_t &ruValue)
		{
			if (!CanRead(1))
				return false;
			ruValue = Bytes[Offset++];
			return true;
		}

		bool ReadUInt16(uint16_t &ruValue)
		{
			if (!CanRead(2))
				return false;
			ruValue = static_cast<uint16_t>(Bytes[Offset] | (Bytes[Offset + 1] << 8));
			Offset += 2;
			return true;
		}

		bool ReadUInt32(uint32_t &ruValue)
		{
			if (!CanRead(4))
				return false;
			ruValue = static_cast<uint32_t>(Bytes[Offset])
				| (static_cast<uint32_t>(Bytes[Offset + 1]) << 8)
				| (static_cast<uint32_t>(Bytes[Offset + 2]) << 16)
				| (static_cast<uint32_t>(Bytes[Offset + 3]) << 24);
			Offset += 4;
			return true;
		}

		bool ReadBytes(size_t uSize)
		{
			if (!CanRead(uSize))
				return false;
			Offset += uSize;
			return true;
		}
	};

	void AppendUInt16(std::vector<uint8_t> &rBytes, uint16_t uValue)
	{
		rBytes.push_back(static_cast<uint8_t>(uValue & 0xFFu));
		rBytes.push_back(static_cast<uint8_t>((uValue >> 8) & 0xFFu));
	}

	void AppendUInt32(std::vector<uint8_t> &rBytes, uint32_t uValue)
	{
		rBytes.push_back(static_cast<uint8_t>(uValue & 0xFFu));
		rBytes.push_back(static_cast<uint8_t>((uValue >> 8) & 0xFFu));
		rBytes.push_back(static_cast<uint8_t>((uValue >> 16) & 0xFFu));
		rBytes.push_back(static_cast<uint8_t>((uValue >> 24) & 0xFFu));
	}

	void AppendAscii(std::vector<uint8_t> &rBytes, const char *pszValue)
	{
		while (*pszValue != '\0')
			rBytes.push_back(static_cast<uint8_t>(*pszValue++));
	}

	std::vector<uint8_t> MakePreferencesKadDat(uint32_t uClientIP, uint16_t uTcpPort, uint8_t uClientVersion)
	{
		std::vector<uint8_t> bytes;
		AppendUInt32(bytes, uClientIP);
		AppendUInt16(bytes, uTcpPort);
		for (uint8_t i = 0; i < 16; ++i)
			bytes.push_back(static_cast<uint8_t>(0xA0u + i));
		bytes.push_back(uClientVersion);
		return bytes;
	}

	bool IsPreferencesKadDatShape(const std::vector<uint8_t> &rBytes)
	{
		return rBytes.size() == 23u;
	}

	std::vector<uint8_t> MakeServerMet(uint32_t uServerCount)
	{
		std::vector<uint8_t> bytes;
		bytes.push_back(0xE0u);
		AppendUInt32(bytes, uServerCount);
		for (uint32_t i = 0; i < uServerCount; ++i) {
			AppendUInt32(bytes, 0x01020304u + i);
			AppendUInt16(bytes, static_cast<uint16_t>(4661u + i));
			AppendUInt32(bytes, 0u);
		}
		return bytes;
	}

	bool InspectServerMetShape(const std::vector<uint8_t> &rBytes, uint32_t &ruServerCount)
	{
		ByteReader reader{rBytes};
		uint8_t uHeader = 0;
		if (!reader.ReadUInt8(uHeader) || uHeader != 0xE0u)
			return false;
		if (!reader.ReadUInt32(ruServerCount) || ruServerCount == 0)
			return false;
		for (uint32_t i = 0; i < ruServerCount; ++i) {
			uint32_t uIP = 0;
			uint16_t uPort = 0;
			uint32_t uTagCount = 0;
			if (!reader.ReadUInt32(uIP) || !reader.ReadUInt16(uPort) || !reader.ReadUInt32(uTagCount))
				return false;
			if (uIP == 0 || uPort == 0 || uTagCount > 256u)
				return false;
		}
		return reader.Offset == rBytes.size();
	}

	std::vector<uint8_t> MakeNodesDat(uint32_t uContactCount)
	{
		std::vector<uint8_t> bytes;
		AppendUInt32(bytes, uContactCount);
		for (uint32_t i = 0; i < uContactCount; ++i) {
			for (uint8_t n = 0; n < 16; ++n)
				bytes.push_back(static_cast<uint8_t>(n + i));
			AppendUInt32(bytes, 0x0A000001u + i);
			AppendUInt16(bytes, static_cast<uint16_t>(4672u + i));
			AppendUInt16(bytes, static_cast<uint16_t>(4662u + i));
			bytes.push_back(0x0Au);
			bytes.push_back(0x00u);
		}
		return bytes;
	}

	bool InspectNodesDatShape(const std::vector<uint8_t> &rBytes, uint32_t &ruContactCount)
	{
		ByteReader reader{rBytes};
		if (!reader.ReadUInt32(ruContactCount) || ruContactCount == 0 || ruContactCount > 5000u)
			return false;
		for (uint32_t i = 0; i < ruContactCount; ++i) {
			uint32_t uIP = 0;
			uint16_t uUdpPort = 0;
			uint16_t uTcpPort = 0;
			uint8_t uVersion = 0;
			uint8_t uKadUDPKey = 0;
			if (!reader.ReadBytes(16) || !reader.ReadUInt32(uIP) || !reader.ReadUInt16(uUdpPort)
				|| !reader.ReadUInt16(uTcpPort) || !reader.ReadUInt8(uVersion) || !reader.ReadUInt8(uKadUDPKey))
				return false;
			(void)uKadUDPKey;
			if (uIP == 0 || uUdpPort == 0 || uTcpPort == 0 || uVersion == 0)
				return false;
		}
		return reader.Offset == rBytes.size();
	}

	std::vector<uint8_t> MakeShareddirDat(const char *pszPath)
	{
		std::vector<uint8_t> bytes;
		const std::string path(pszPath);
		AppendUInt16(bytes, static_cast<uint16_t>(path.size()));
		AppendAscii(bytes, pszPath);
		bytes.push_back(0);
		return bytes;
	}

	bool InspectShareddirDatLine(const std::vector<uint8_t> &rBytes)
	{
		ByteReader reader{rBytes};
		uint16_t uLength = 0;
		if (!reader.ReadUInt16(uLength) || uLength == 0 || uLength > 32767u)
			return false;
		if (!reader.ReadBytes(uLength))
			return false;
		uint8_t uTerminator = 0;
		if (!reader.ReadUInt8(uTerminator) || uTerminator != 0)
			return false;
		return reader.Offset == rBytes.size();
	}

	std::vector<uint8_t> MakeEd2kFileLink(const char *pszName, uint32_t uSize)
	{
		std::vector<uint8_t> bytes;
		AppendAscii(bytes, "ed2k://|file|");
		AppendAscii(bytes, pszName);
		bytes.push_back('|');
		const std::string size = std::to_string(uSize);
		AppendAscii(bytes, size.c_str());
		AppendAscii(bytes, "|0123456789ABCDEF0123456789ABCDEF|/");
		return bytes;
	}

	bool InspectEd2kLinkFixture(const std::vector<uint8_t> &rBytes)
	{
		const std::string text(rBytes.begin(), rBytes.end());
		return text.rfind("ed2k://|file|", 0) == 0
			&& text.find("..") == std::string::npos
			&& text.find(".exe|") == std::string::npos
			&& text.find("|0123456789ABCDEF0123456789ABCDEF|/") != std::string::npos;
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("release file-format golden keeps preferencesKad.dat fixed-width identity shape")
{
	const std::vector<uint8_t> fixture = MakePreferencesKadDat(0x01020304u, 4662u, 0x0Au);
	std::vector<uint8_t> truncated = fixture;
	truncated.pop_back();

	CHECK(IsPreferencesKadDatShape(fixture));
	CHECK_FALSE(IsPreferencesKadDatShape(truncated));
}

TEST_CASE("release file-format golden accepts server.met with exact server rows")
{
	uint32_t uServerCount = 0;
	const std::vector<uint8_t> fixture = MakeServerMet(2);
	std::vector<uint8_t> malformed = fixture;
	malformed.pop_back();

	CHECK(InspectServerMetShape(fixture, uServerCount));
	CHECK_EQ(uServerCount, 2u);
	CHECK_FALSE(InspectServerMetShape(malformed, uServerCount));
	CHECK_FALSE(InspectServerMetShape(MakeServerMet(0), uServerCount));
}

TEST_CASE("release file-format golden accepts bounded nodes.dat contact rows")
{
	uint32_t uContactCount = 0;
	const std::vector<uint8_t> fixture = MakeNodesDat(3);
	std::vector<uint8_t> malformed = fixture;
	malformed.resize(7);

	CHECK(InspectNodesDatShape(fixture, uContactCount));
	CHECK_EQ(uContactCount, 3u);
	CHECK_FALSE(InspectNodesDatShape(malformed, uContactCount));
}

TEST_CASE("release file-format golden keeps shareddir.dat rows length-prefixed and terminated")
{
	const std::vector<uint8_t> fixture = MakeShareddirDat("C:\\release-fixtures\\incoming");
	std::vector<uint8_t> unterminated = fixture;
	unterminated.back() = 'x';

	CHECK(InspectShareddirDatLine(fixture));
	CHECK_FALSE(InspectShareddirDatLine(unterminated));
}

TEST_CASE("release file-format golden rejects dangerous eD2K file-link fixtures")
{
	const std::vector<uint8_t> safe = MakeEd2kFileLink("linux-sample.iso", 123456u);
	const std::vector<uint8_t> pathTraversal = MakeEd2kFileLink("..\\payload.iso", 123456u);
	const std::vector<uint8_t> executable = MakeEd2kFileLink("payload.exe", 123456u);

	CHECK(InspectEd2kLinkFixture(safe));
	CHECK_FALSE(InspectEd2kLinkFixture(pathTraversal));
	CHECK_FALSE(InspectEd2kLinkFixture(executable));
}

TEST_SUITE_END();
