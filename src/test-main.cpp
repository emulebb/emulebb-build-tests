#define DOCTEST_CONFIG_IMPLEMENT
#include "../third_party/doctest/doctest.h"

#include "../include/FullHashProbe.h"
#include "../include/HashProbe.h"
#include "../include/TimerResolutionProbe.h"

#ifndef EMULEBB_TESTS_HAS_MAPPED_FILE_READER
#define EMULEBB_TESTS_HAS_MAPPED_FILE_READER 0
#endif

#if !EMULEBB_TESTS_HAS_MAPPED_FILE_READER
/**
 * @brief Returns the standard "not requested" sentinel when the real full hash probe is not compiled for this workspace.
 */
int RunFullHashProbeIfRequested(int, char **)
{
	return -1;
}

/**
 * @brief Returns the standard "not requested" sentinel when the real hash probe is not compiled for this workspace.
 */
int RunHashProbeIfRequested(int, char **)
{
	return -1;
}
#endif

/**
 * @brief Runs the standalone hash probe when explicitly requested, otherwise executes doctest.
 */
int main(int argc, char **argv)
{
	const int nFullHashProbeResult = RunFullHashProbeIfRequested(argc, argv);
	if (nFullHashProbeResult >= 0)
		return nFullHashProbeResult;

	const int nProbeResult = RunHashProbeIfRequested(argc, argv);
	if (nProbeResult >= 0)
		return nProbeResult;

	const int nTimerResolutionProbeResult = RunTimerResolutionProbeIfRequested(argc, argv);
	if (nTimerResolutionProbeResult >= 0)
		return nTimerResolutionProbeResult;

	doctest::Context context;
	context.applyCommandLine(argc, argv);
	return context.run();
}
