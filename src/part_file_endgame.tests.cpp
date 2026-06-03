#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include "PartFileEndgameSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Part file endgame seam starts speed-first scheduling at ninety percent")
{
	CHECK_FALSE(PartFileEndgameSeams::IsLateDownload(89999u, 100000u));
	CHECK(PartFileEndgameSeams::IsLateDownload(90000u, 100000u));
	CHECK(PartFileEndgameSeams::IsLateDownload(100000u, 100000u));
	CHECK_FALSE(PartFileEndgameSeams::IsLateDownload(1u, 0u));
}

TEST_CASE("Part file endgame seam detects final ranges by percentage or remaining time")
{
	CHECK(PartFileEndgameSeams::IsEndgame(99900u, 100000u, 100u, 0u, 0u));
	CHECK(PartFileEndgameSeams::IsEndgame(99900u, 100000u, 100u, 0u, 1u));
	CHECK(PartFileEndgameSeams::IsEndgame(80000u, 100000u, 30000u, 1000u, 1u));
	CHECK_FALSE(PartFileEndgameSeams::IsEndgame(80000u, 100000u, 30001u, 1000u, 1u));
}

TEST_CASE("Part file endgame seam uses relative proven speed instead of a fixed cutoff")
{
	CHECK_FALSE(PartFileEndgameSeams::IsMeaningfullyFasterPeer(10u * 1024u, 49u * 1024u));
	CHECK(PartFileEndgameSeams::IsMeaningfullyFasterPeer(10u * 1024u, 50u * 1024u));
	CHECK(PartFileEndgameSeams::IsMeaningfullyFasterPeer(0u, 1u));
	CHECK_FALSE(PartFileEndgameSeams::IsMeaningfullyFasterPeer(0u, 0u));
}

TEST_CASE("Part file endgame seam caps slow reservations in late download")
{
	const uint64 fullBlockBytes = 184320u;

	const PartFileEndgameSeams::ReservationDecision ordinary = PartFileEndgameSeams::DecideReservation(
		false,
		false,
		true,
		true,
		1024u,
		fullBlockBytes);
	CHECK_EQ(ordinary.action, PartFileEndgameSeams::ReservationAction::AllowFull);
	CHECK_EQ(ordinary.maxBytes, fullBlockBytes);

	const PartFileEndgameSeams::ReservationDecision capped = PartFileEndgameSeams::DecideReservation(
		true,
		false,
		true,
		true,
		4u * 1024u,
		fullBlockBytes);
	CHECK_EQ(capped.action, PartFileEndgameSeams::ReservationAction::AllowCapped);
	CHECK_EQ(capped.maxBytes, 40u * 1024u);

	const PartFileEndgameSeams::ReservationDecision unique = PartFileEndgameSeams::DecideReservation(
		true,
		true,
		false,
		false,
		4u * 1024u,
		fullBlockBytes);
	CHECK_EQ(unique.action, PartFileEndgameSeams::ReservationAction::AllowFull);
	CHECK_EQ(unique.maxBytes, fullBlockBytes);
}

TEST_CASE("Part file endgame seam withholds final blocks briefly then falls back")
{
	const uint64 fullBlockBytes = 184320u;

	const PartFileEndgameSeams::ReservationDecision withheld = PartFileEndgameSeams::DecideReservation(
		true,
		true,
		true,
		false,
		4u * 1024u,
		fullBlockBytes);
	CHECK_EQ(withheld.action, PartFileEndgameSeams::ReservationAction::Withhold);
	CHECK_EQ(withheld.maxBytes, 0u);

	const PartFileEndgameSeams::ReservationDecision fallback = PartFileEndgameSeams::DecideReservation(
		true,
		true,
		true,
		true,
		4u * 1024u,
		fullBlockBytes);
	CHECK_EQ(fallback.action, PartFileEndgameSeams::ReservationAction::AllowCapped);
	CHECK_EQ(fallback.maxBytes, 40u * 1024u);
}

TEST_CASE("Part file endgame seam steals slow final reservations for active faster peers")
{
	CHECK(PartFileEndgameSeams::ShouldStealEndgameReservation(
		true,
		true,
		10u * 1024u,
		50u * 1024u,
		120000u,
		0u,
		0u));
	CHECK_FALSE(PartFileEndgameSeams::ShouldStealEndgameReservation(
		true,
		true,
		10u * 1024u,
		50u * 1024u,
		120000u,
		0u,
		64u * 1024u));
}

TEST_CASE("Part file endgame seam refuses slow-owner steals without endgame, matching part, fast peer, or cooldown")
{
	CHECK_FALSE(PartFileEndgameSeams::ShouldStealEndgameReservation(
		false,
		true,
		10u * 1024u,
		50u * 1024u,
		120000u,
		0u,
		0u));
	CHECK_FALSE(PartFileEndgameSeams::ShouldStealEndgameReservation(
		true,
		false,
		10u * 1024u,
		50u * 1024u,
		120000u,
		0u,
		0u));
	CHECK_FALSE(PartFileEndgameSeams::ShouldStealEndgameReservation(
		true,
		true,
		10u * 1024u,
		49u * 1024u,
		120000u,
		0u,
		0u));
	CHECK_FALSE(PartFileEndgameSeams::ShouldStealEndgameReservation(
		true,
		true,
		10u * 1024u,
		50u * 1024u,
		120000u,
		121000u,
		0u));
	CHECK(PartFileEndgameSeams::ShouldStealEndgameReservation(
		true,
		true,
		10u * 1024u,
		50u * 1024u,
		121000u,
		121000u,
		0u));
}

TEST_CASE("Part file endgame seam clamps reservation sizes and preserves useful tails")
{
	const uint64 fullBlockBytes = 184320u;

	CHECK_EQ(PartFileEndgameSeams::CalculateCappedReservationBytes(1u, fullBlockBytes), PartFileEndgameSeams::kMinCappedReservationBytes);
	CHECK_EQ(PartFileEndgameSeams::CalculateCappedReservationBytes(100u * 1024u, fullBlockBytes), fullBlockBytes);

	CHECK_EQ(PartFileEndgameSeams::ClampReservationEnd(100u, 100u + 20u * 1024u + 2u * 1024u - 1u, 20u * 1024u),
		100u + 20u * 1024u + 2u * 1024u - 1u);
	CHECK_EQ(PartFileEndgameSeams::ClampReservationEnd(100u, 100u + 20u * 1024u + 4u * 1024u - 1u, 20u * 1024u),
		100u + 20u * 1024u - 1u);
}

TEST_SUITE_END;
