$ErrorActionPreference = "Stop"

Remove-Item -Recurse -Force package -ErrorAction SilentlyContinue
Remove-Item -Force lambda_deploy.zip -ErrorAction SilentlyContinue

python -m pip install `
  --platform manylinux2014_x86_64 `
  --implementation cp `
  --python-version 3.12 `
  --only-binary=:all: `
  --upgrade `
  -r requirements.txt `
  -t package

Copy-Item -Recurse .\app .\package\app

Compress-Archive `
  -Path .\package\* `
  -DestinationPath .\lambda_deploy.zip `
  -Force

Write-Host "lambda_deploy.zip 생성 완료"