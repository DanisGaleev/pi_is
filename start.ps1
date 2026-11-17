$ErrorActionPreference = "Stop"

if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
    Write-Error "cloudflared не найден. Установите: winget install Cloudflare.cloudflared"
}

$root = $PSScriptRoot
$logFile = Join-Path $env:TEMP "cloudflared-pi-is.log"
if (Test-Path $logFile) { Remove-Item $logFile -Force }

$backend = Start-Process -FilePath "uv" -ArgumentList "run", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000" -WorkingDirectory $root -PassThru -NoNewWindow
$frontend = Start-Process -FilePath "npm.cmd" -ArgumentList "--prefix", "frontend", "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173" -WorkingDirectory $root -PassThru -NoNewWindow
$tunnel = Start-Process -FilePath "cloudflared" -ArgumentList "tunnel", "--url", "http://127.0.0.1:5173" -RedirectStandardError $logFile -PassThru -NoNewWindow

try {
    Write-Host "Запуск бэкенда, фронтенда и Cloudflare-туннеля..."
    $url = $null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Path $logFile) {
            $match = Select-String -Path $logFile -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" -AllMatches | Select-Object -First 1
            if ($match) {
                $url = $match.Matches[0].Value
                break
            }
        }
    }

    Write-Host ""
    Write-Host "Локально:  http://127.0.0.1:5173"
    if ($url) {
        Write-Host "Публично:  $url" -ForegroundColor Green
    } else {
        Write-Host "Туннель запускается, смотрите URL в логе: $logFile" -ForegroundColor Yellow
    }
    Write-Host "Нажмите Ctrl+C для остановки всех сервисов."

    while (-not $backend.HasExited -and -not $frontend.HasExited -and -not $tunnel.HasExited) {
        Start-Sleep -Seconds 1
    }
} finally {
    foreach ($p in @($tunnel, $frontend, $backend)) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
