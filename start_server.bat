@echo off
title AI Trust Agent Server
echo ================================================
echo  AI Trust Agent — Starting Server
echo  Dashboard : http://localhost:8000
echo  API Docs  : http://localhost:8000/docs
echo ================================================
echo.

cd /d "C:\Users\AkashShaw\OneDrive - Uniqus Consultech Inc\Desktop\AI Security Agent\ai-trust-agent"

C:\Users\AkashShaw\anaconda3\python.exe ^
  -m uvicorn trust_agent.api.main:app ^
  --host 0.0.0.0 ^
  --port 8000 ^
  --reload

pause
