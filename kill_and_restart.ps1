# Kill everything on ports 8000 and 8001, then restart on 8000
foreach ($port in @(8000, 8001)) {
    $pids = (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue).OwningProcess
    foreach ($p in $pids) {
        Write-Host "Killing PID $p on port $port"
        taskkill /F /T /PID $p 2>$null
    }
}
Start-Sleep -Seconds 2

Set-Location "C:\Users\AkashShaw\OneDrive - Uniqus Consultech Inc\Desktop\AI Security Agent\ai-trust-agent"
Write-Host "Starting server on port 8000..."
Start-Process -FilePath "C:\Users\AkashShaw\anaconda3\python.exe" `
    -ArgumentList "-m", "uvicorn", "trust_agent.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload" `
    -WorkingDirectory "C:\Users\AkashShaw\OneDrive - Uniqus Consultech Inc\Desktop\AI Security Agent\ai-trust-agent" `
    -NoNewWindow
Write-Host "Done. Server starting on http://localhost:8000"
