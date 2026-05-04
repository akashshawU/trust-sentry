# Kill any process on port 8000 and restart the server
$port = 8000
$pids = (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue).OwningProcess
foreach ($p in $pids) {
    Write-Host "Killing PID $p on port $port"
    Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

# Start server
$env:PYTHONPATH = "C:\Users\AkashShaw\OneDrive - Uniqus Consultech Inc\Desktop\AI Security Agent\ai-trust-agent"
Set-Location "C:\Users\AkashShaw\OneDrive - Uniqus Consultech Inc\Desktop\AI Security Agent\ai-trust-agent"
Write-Host "Starting server..."
Start-Process -FilePath "C:\Users\AkashShaw\anaconda3\python.exe" `
    -ArgumentList "-m", "uvicorn", "trust_agent.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload" `
    -WorkingDirectory "C:\Users\AkashShaw\OneDrive - Uniqus Consultech Inc\Desktop\AI Security Agent\ai-trust-agent" `
    -NoNewWindow
Write-Host "Server started. Waiting 5 seconds..."
Start-Sleep -Seconds 5
Write-Host "Done."
