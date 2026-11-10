<#
  packaging\build.ps1 -- build a Haltline release (plan 5.6, build step 7):
    1. edr_sensor with the endpoints and keys baked in, encrypted with obfstr
    2. Nuitka standalone builds: haltline-agent.exe (the service) and haltline-helper.exe
    3. self-signed Authenticode signatures (testers only: Windows shows "Unknown publisher")
    4. the Inno Setup installer, signed too
    5. with -ReleaseKey and -InstallerUrl: the signed update manifest (build\latest.json + .sig)

  powershell -ExecutionPolicy Bypass -File packaging\build.ps1 `
      -Endpoints "https://<worker>.workers.dev,https://<id>.lambda-url.<region>.on.aws" `
      -ServerPubkey <base64 Ed25519 public key of RESPONSE_SIGNING_SEED> `
      [-UpdateUrl https://.../latest.json -UpdatePubkey <from make_manifest.py new-key>] `
      [-ReleaseKey $HOME\.haltline\release.key -InstallerUrl https://.../Haltline-Setup-x.y.z.exe]

  Needs Rust (MSVC), Python 3.10 with requirements.txt + nuitka + maturin, and Inno Setup 6.
  Output in build\: Haltline-Setup-<version>.exe, haltline-signing.cer (testers import it into
  "Trusted People" to silence the publisher warning), and the manifest.
#>
param(
    [Parameter(Mandatory)] [string]$Endpoints,
    [Parameter(Mandatory)] [string]$ServerPubkey,
    [string]$UpdateUrl = "",
    [string]$UpdatePubkey = "",
    [string]$ReleaseKey = "",
    [string]$InstallerUrl = "",
    [switch]$SkipNuitka          # reuse build\nuitka from the last run (installer / signing changes only)
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Build = Join-Path $Root "build"
$Py = (Get-Command python).Source
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }

$Version = (Select-String -Path (Join-Path $Root "agent.py") -Pattern 'AGENT_VERSION\s*=\s*"([\d.]+)"').Matches[0].Groups[1].Value
if ($UpdateUrl -and -not $UpdatePubkey) { throw "-UpdateUrl needs -UpdatePubkey" }
New-Item -ItemType Directory -Force -Path $Build | Out-Null
Write-Host "Haltline $Version"

if (-not $SkipNuitka) {
    Step "edr_sensor with the release settings (obfstr)"
    $env:HALTLINE_ENDPOINTS = $Endpoints
    $env:HALTLINE_SERVER_PUBKEY = $ServerPubkey
    $env:HALTLINE_UPDATE_URL = $UpdateUrl
    $env:HALTLINE_UPDATE_PUBKEY = $UpdatePubkey
    & $Py -m maturin build --release -m (Join-Path $Root "edr_sensor\Cargo.toml") -o (Join-Path $Build "wheels"); Check "maturin"
    $whl = Get-ChildItem (Join-Path $Build "wheels") -Filter "edr_sensor-*.whl" | Sort-Object LastWriteTime | Select-Object -Last 1
    $site = Join-Path $Build "release-site"
    if (Test-Path $site) { Remove-Item -Recurse -Force $site }
    & $Py -m pip install --disable-pip-version-check --no-deps --target $site $whl.FullName; Check "pip install (release edr_sensor)"
    $env:PYTHONPATH = $site   # Nuitka picks up this edr_sensor, not the dev build in site-packages

    $common = @("--standalone", "--assume-yes-for-downloads", "--msvc=latest", "--output-dir=$Build\nuitka",
                "--company-name=Haltline", "--file-version=$Version", "--product-version=$Version", "--remove-output")
    # Optional imports Nuitka would otherwise follow (onnxruntime's tooling pulls in torch); the agent never uses them.
    foreach ($m in "torch", "scipy", "pandas", "matplotlib", "sklearn", "transformers", "sympy", "PIL", "streamlit",
                   "pytest", "onnxruntime.transformers", "onnxruntime.training", "onnxruntime.quantization", "onnxruntime.tools") {
        $common += "--nofollow-import-to=$m"
    }

    Step "Nuitka: haltline-agent.exe (service)"
    & $Py -m nuitka @common --output-filename=haltline-agent.exe --product-name="Haltline Agent" `
        --file-description="Haltline Agent service" `
        "--include-data-files=$Root\tier1_behavioral.onnx=tier1_behavioral.onnx" `
        "--include-data-files=$Root\tier1_behavioral.onnx.data=tier1_behavioral.onnx.data" `
        "--include-data-files=$Root\dataset\behavioral_dataset_meta.json=dataset\behavioral_dataset_meta.json" `
        "--include-data-files=$Root\packaging\pinned_roots.pem=pinned_roots.pem" `
        (Join-Path $Root "haltline_service.py"); Check "Nuitka (agent)"

    Step "Nuitka: haltline-helper.exe (the alert dialog, no console window)"
    & $Py -m nuitka @common --output-filename=haltline-helper.exe --product-name="Haltline" `
        --file-description="Haltline alerts" --enable-plugin=tk-inter --windows-console-mode=disable `
        (Join-Path $Root "telltale_helper.py"); Check "Nuitka (helper)"
    Remove-Item Env:PYTHONPATH
}

Step "Self-signed code-signing certificate"
$Subject = "CN=Haltline Test Signing"
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq $Subject | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3)
}
Export-Certificate -Cert $cert -FilePath (Join-Path $Build "haltline-signing.cer") | Out-Null
function Sign($path) {
    Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256 | Out-Null
    # Self-signed, so the status is "UnknownError" (untrusted root); what matters is that our cert signed it.
    if ((Get-AuthenticodeSignature $path).SignerCertificate.Thumbprint -ne $cert.Thumbprint) { throw "signing $path failed" }
    Write-Host "signed $path"
}
Sign (Join-Path $Build "nuitka\haltline_service.dist\haltline-agent.exe")
Sign (Join-Path $Build "nuitka\telltale_helper.dist\haltline-helper.exe")

Step "Inno Setup installer"
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found (winget install JRSoftware.InnoSetup)" }
& $iscc /Q "/DAppVersion=$Version" (Join-Path $Root "packaging\haltline.iss"); Check "ISCC"
$setup = Join-Path $Build "Haltline-Setup-$Version.exe"
Sign $setup

if ($ReleaseKey -and $InstallerUrl) {
    Step "Signed update manifest"
    & $Py (Join-Path $Root "packaging\make_manifest.py") sign $ReleaseKey $setup $InstallerUrl $Build; Check "make_manifest"
}
Write-Host "`nDone: $setup"
