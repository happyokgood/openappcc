param([string]$Stage = 'all')
# build.ps1 — build openappcc Android APK using raw Android SDK tools (no Gradle).
# Stages: res, link, javac, dex, package, sign, all
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
$do = { param($s) $Stage -eq 'all' -or $Stage -eq $s }

function Find-Tool([string[]]$candidates, [string]$name) {
    foreach ($root in $candidates) {
        if ($root -and (Test-Path $root)) {
            $hit = Get-ChildItem -Path $root -Recurse -Filter $name -File -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$jdkCandidates = @(
    $env:JAVA_HOME,
    'D:\Program Files\Java',
    'C:\Program Files\Java\latest',
    'C:\Program Files\Java'
)
$sdkCandidates = @(
    $env:ANDROID_HOME,
    $env:ANDROID_SDK_ROOT,
    'D:\Android\sdk',
    "$env:LOCALAPPDATA\Android\Sdk"
)

$keytool = Find-Tool $jdkCandidates 'keytool.exe'
if (-not $keytool) { throw 'keytool.exe not found' }
$jdkBin = Split-Path $keytool -Parent
$javac = Join-Path $jdkBin 'javac.exe'
$jar = Join-Path $jdkBin 'jar.exe'
$apksigner = Find-Tool $sdkCandidates 'apksigner.bat'
$androidJar = Find-Tool $sdkCandidates 'android.jar'
if (-not (Test-Path $javac)) { throw "javac.exe not found at $javac" }
if (-not $apksigner) { throw 'apksigner.bat not found (set ANDROID_HOME)' }
if (-not $androidJar) { throw 'android.jar not found (set ANDROID_HOME)' }

$jdkHome = Split-Path $jdkBin -Parent
$env:JAVA_HOME = $jdkHome
$env:PATH = "$jdkBin;$env:PATH"

$btDir = Split-Path $apksigner -Parent
$aapt2 = Join-Path $btDir 'aapt2.exe'
$d8 = Join-Path $btDir 'd8.bat'
$zipalign = Join-Path $btDir 'zipalign.exe'
$apksignerJar = Join-Path $btDir 'lib\apksigner.jar'

if (-not (Test-Path $apksignerJar)) { throw "apksigner.jar not found at $apksignerJar" }

$assetsDir = Join-Path $here 'assets'
$keystore = Join-Path $assetsDir 'openappcc.p12'
$ksAlias = if ($env:OPENAPPCC_KS_ALIAS) { $env:OPENAPPCC_KS_ALIAS } else { 'openappcc' }
$ksPass = if ($env:OPENAPPCC_KS_PASS) { $env:OPENAPPCC_KS_PASS } else { 'openappcc' }
New-Item -ItemType Directory -Force $assetsDir | Out-Null
if (-not (Test-Path $keystore)) {
    Write-Host '== generating openappcc.p12 keystore'
    & $keytool -genkeypair -keystore $keystore -storetype PKCS12 -storepass $ksPass `
        -alias $ksAlias -keypass $ksPass -keyalg RSA -keysize 2048 -validity 10000 `
        -dname 'CN=openappcc,O=openappcc,C=US' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'keytool failed' }
}

$build = Join-Path $here 'build'
if ($Stage -eq 'all' -or $Stage -eq 'res') {
    Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force "$build\gen", "$build\classes", "$build\dex", "$build\hook-classes", "$build\hook-dex", "$build\log" | Out-Null

function Run([string]$exe, [string[]]$arguments, [string]$tag) {
    $out = "$build\log\$tag.out"
    $err = "$build\log\$tag.err"
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    if ((Test-Path $err) -and (Get-Item $err).Length -gt 0) {
        Get-Content $err | Where-Object { $_ -ne '' } | ForEach-Object { Write-Host "  ! $_" }
    }
    if ($p.ExitCode -ne 0) {
        if (Test-Path $out) { Get-Content $out | ForEach-Object { Write-Host "  > $_" } }
        throw "$tag failed with exit code $($p.ExitCode)"
    }
}

if (& $do 'res') {
    $hookSrc = Join-Path $here 'hook\io\openappcc\hook\BootstrapProvider.java'
    if (Test-Path $hookSrc) {
        Write-Host '== hook dex'
        Run $javac @('--release', '11', '-nowarn', '-encoding', 'UTF-8', '-cp', $androidJar, '-d', "$build\hook-classes", $hookSrc) 'javac-hook'
        $hookJar = "$build\hook.jar"
        Run $jar @('--create', '--file', $hookJar, '-C', "$build\hook-classes", '.') 'jar-hook'
        Run $d8 @('--lib', $androidJar, '--min-api', '24', '--output', "$build\hook-dex", $hookJar) 'd8-hook'
        Copy-Item "$build\hook-dex\classes.dex" (Join-Path $assetsDir 'hook.dex') -Force
    }
    Write-Host '== aapt2 compile'
    Run $aapt2 @('compile', '--dir', 'res', '-o', "$build\res.zip") 'aapt2-compile'
}

if (& $do 'link') {
    Write-Host '== aapt2 link'
    Run $aapt2 @('link', '-o', "$build\base.apk", '-I', $androidJar,
        '--manifest', 'AndroidManifest.xml', '--java', "$build\gen", "$build\res.zip",
        '-A', 'assets', '--auto-add-overlay') 'aapt2-link'
}

if (& $do 'javac') {
    Write-Host '== javac'
    $srcs = @()
    $srcs += Get-ChildItem -Recurse -Filter *.java src | ForEach-Object { $_.FullName }
    $srcs += Get-ChildItem -Recurse -Filter *.java "$build\gen" | ForEach-Object { $_.FullName }
    $srcListFile = "$build\javac_sources.txt"
    $srcs | ForEach-Object { '"' + ($_ -replace '\\', '/') + '"' } | Set-Content -Encoding ASCII $srcListFile
    $javacArgs = @('--release', '11', '-nowarn', '-encoding', 'UTF-8', '-cp', "$androidJar;$apksignerJar", '-d', "$build\classes", "@$srcListFile")
    Run $javac $javacArgs 'javac'
}

if (& $do 'dex') {
    Write-Host '== d8'
    $appJar = "$build\app.jar"
    Run $jar @('--create', '--file', $appJar, '-C', "$build\classes", '.') 'jar-classes'
    $d8Args = @('--lib', $androidJar, '--min-api', '29', '--output', "$build\dex", $appJar, $apksignerJar)
    Run $d8 $d8Args 'd8'
}

if (& $do 'package') {
    Write-Host '== package dex'
    $dexFiles = Get-ChildItem "$build\dex" -Filter 'classes*.dex' | Sort-Object Name | ForEach-Object { $_.Name }
    if (-not $dexFiles) { throw 'No classes*.dex produced by d8' }
    $jarArgs = @('--update', '--file', "$build\base.apk")
    foreach ($df in $dexFiles) {
        $jarArgs += @('-C', "$build\dex", $df)
    }
    Run $jar $jarArgs 'jar-dex'
    Write-Host '== zipalign'
    Run $zipalign @('-f', '-P', '16', '4', "$build\base.apk", "$build\aligned.apk") 'zipalign'
}

if (& $do 'sign') {
    Write-Host '== sign'
    $outApk = Join-Path $here 'openappcc-release.apk'
    Run $apksigner @('sign', '--ks', $keystore, '--ks-key-alias', $ksAlias,
        '--ks-pass', "pass:$ksPass", '--key-pass', "pass:$ksPass",
        '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true', '--v3-signing-enabled', 'true',
        '--out', $outApk, "$build\aligned.apk") 'apksigner-sign'
    Write-Host '== verify'
    Run $apksigner @('verify', '--print-certs', '--verbose', $outApk) 'apksigner-verify'
    Get-Content "$build\log\apksigner-verify.out" | ForEach-Object { Write-Host "  $_" }
    Write-Host "== built $outApk"
}
