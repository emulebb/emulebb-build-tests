#pragma once

/**
 * @brief Runs the standalone timer-resolution probe when the current command line requests it.
 *
 * @return Probe exit code when `--timer-resolution-probe` was supplied, otherwise `-1`.
 */
int RunTimerResolutionProbeIfRequested(int argc, char **argv);
