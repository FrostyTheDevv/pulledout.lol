# Build and Run Script
# Builds the React frontend and starts the Flask server on localhost:5000

Write-Host "Building React frontend..." -ForegroundColor Cyan
Set-Location frontend
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Frontend build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`nFrontend built successfully!" -ForegroundColor Green
Write-Host "Starting Flask server on http://localhost:5000..." -ForegroundColor Cyan
Set-Location ..

python web_server.py
