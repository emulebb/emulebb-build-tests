"""Guest-side script templates for Windows VM harness runs."""

from __future__ import annotations


def package_smoke_script() -> str:
    """Returns the PowerShell package-smoke script executed inside a Hyper-V guest."""

    return r"""
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
$credential = [pscredential]::new($payload.username, $secure)
$vm = Get-VM -Name $payload.vmName -ErrorAction Stop
if ($vm.State -ne 'Off') {
  Stop-VM -Name $payload.vmName -TurnOff -Force
}
$snapshot = Get-VMSnapshot -VMName $payload.vmName -Name $payload.checkpointName -ErrorAction Stop
Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
Start-VM -Name $payload.vmName
$deadline = (Get-Date).AddMinutes(10)
$session = $null
do {
  Start-Sleep -Seconds 3
  try {
    $session = New-PSSession -VMName $payload.vmName -Credential $credential -ErrorAction Stop
  } catch {
    if ((Get-Date) -gt $deadline) { throw }
  }
} while (-not $session)
$guestRoot = 'C:\eMuleBBVmTest\' + $payload.runId + '\' + $payload.target
$guestZip = Join-Path $guestRoot (Split-Path -Leaf $payload.packageZip)
try {
  Invoke-Command -Session $session -ScriptBlock {
    param($root)
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $root | Out-Null
  } -ArgumentList $guestRoot
  Copy-Item -ToSession $session -Path $payload.packageZip -Destination $guestZip
  $guestResult = Invoke-Command -Session $session -ScriptBlock {
    param($root, $zipPath)
    $ErrorActionPreference = 'Stop'
    function New-Check($name, $status, $details) {
      [pscustomobject]@{ name = $name; status = $status; details = $details }
    }
    function Invoke-SmokeProcess($name, [string[]] $command, $expectedCode, $timeoutSeconds) {
      $stdout = Join-Path $script:artifacts ($name + '.stdout.txt')
      $stderr = Join-Path $script:artifacts ($name + '.stderr.txt')
      $process = Start-Process -FilePath $command[0] -ArgumentList $command[1..($command.Length - 1)] -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
      if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        return New-Check $name 'failed' @{ exitCode = $null; expectedExitCode = $expectedCode; timedOut = $true; stdout = $stdout; stderr = $stderr }
      }
      $status = if ($process.ExitCode -eq $expectedCode) { 'passed' } else { 'failed' }
      return New-Check $name $status @{ exitCode = $process.ExitCode; expectedExitCode = $expectedCode; stdout = $stdout; stderr = $stderr }
    }
    $script:artifacts = Join-Path $root 'artifacts'
    New-Item -ItemType Directory -Force -Path $script:artifacts | Out-Null
    $checks = @()
    $errors = @()
    $expanded = Join-Path $root 'expanded'
    Expand-Archive -LiteralPath $zipPath -DestinationPath $expanded -Force
    $appRoot = Join-Path $expanded 'eMuleBB'
    $exe = Join-Path $appRoot 'emulebb.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
      $errors += 'Package did not contain eMuleBB\emulebb.exe.'
    } else {
      $checks += Invoke-SmokeProcess 'help' @($exe, '--help') 0 30
      $checks += Invoke-SmokeProcess 'unknown-switch' @($exe, '--not-a-real-emulebb-switch') 2 30
      $certDir = Join-Path $script:artifacts 'generated-cert'
      New-Item -ItemType Directory -Force -Path $certDir | Out-Null
      $checks += Invoke-SmokeProcess 'generate-webserver-cert' @(
        $exe,
        '--generate-webserver-cert',
        '--cert', (Join-Path $certDir 'webserver.crt'),
        '--key', (Join-Path $certDir 'webserver.key'),
        '--host', '127.0.0.1'
      ) 0 60
      $profile = Join-Path $root 'profile'
      $configDir = Join-Path $profile 'config'
      New-Item -ItemType Directory -Force -Path $configDir | Out-Null
      New-Item -ItemType Directory -Force -Path (Join-Path $profile 'incoming') | Out-Null
      New-Item -ItemType Directory -Force -Path (Join-Path $profile 'temp') | Out-Null
      @"
[eMule]
ConfirmExit=0
IncomingDir=$(Join-Path $profile 'incoming')
TempDir=$(Join-Path $profile 'temp')
BindAddr=
BindInterface=
NetworkED2K=0
NetworkKademlia=0
[WebServer]
Enabled=1
ApiKey=vm-smoke-api-key
Port=4711
BindAddr=127.0.0.1
UseHTTPS=0
[UPnP]
EnableUPnP=0
"@ | Set-Content -Path (Join-Path $configDir 'preferences.ini') -Encoding Unicode
      $appProcess = Start-Process -FilePath $exe -ArgumentList @('-ignoreinstances', '-c', $profile) -PassThru
      $restStatus = 'failed'
      try {
        $restDeadline = (Get-Date).AddSeconds(90)
        do {
          Start-Sleep -Seconds 2
          try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:4711/api/v1/status' -Headers @{ 'X-API-Key' = 'vm-smoke-api-key' } -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
              $restStatus = 'passed'
              break
            }
          } catch {
          }
        } while ((Get-Date) -lt $restDeadline)
      } finally {
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
      }
      $checks += New-Check 'first-run-rest-status' $restStatus @{ profile = $profile; url = 'http://127.0.0.1:4711/api/v1/status' }
    }
    $eventLogPath = Join-Path $script:artifacts 'application-events.json'
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-2) } -MaxEvents 50 |
      Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
      ConvertTo-Json -Depth 4 | Set-Content -Path $eventLogPath -Encoding UTF8
    $guest = @{
      computerName = $env:COMPUTERNAME
      os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    }
    $status = if ($errors.Count -eq 0 -and (@($checks) | Where-Object { $_.status -ne 'passed' }).Count -eq 0) { 'passed' } else { 'failed' }
    $result = [pscustomobject]@{
      schema = 'emulebb.windows-vm-target-result.v1'
      status = $status
      generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
      guest = $guest
      packageZip = $zipPath
      appExe = $exe
      checks = $checks
      errors = $errors
      artifactsDir = $script:artifacts
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $root 'target-result.json') -Encoding UTF8
    $result
  } -ArgumentList $guestRoot, $guestZip
  New-Item -ItemType Directory -Force -Path $payload.hostReportDir | Out-Null
  Copy-Item -FromSession $session -Path (Join-Path $guestRoot '*') -Destination $payload.hostReportDir -Recurse -Force
  $guestResult | ConvertTo-Json -Depth 8
}
finally {
  if ($session) { Remove-PSSession $session }
  if (-not $payload.keepRunning) {
    Stop-VM -Name $payload.vmName -Force
    Restore-VMSnapshot -VMName $payload.vmName -Name $payload.checkpointName -Confirm:$false
  }
}
"""
