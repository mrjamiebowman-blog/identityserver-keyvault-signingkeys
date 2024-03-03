clear

# environment variables
$NUGET_USER = [System.Environment]::GetEnvironmentVariable('NUGET_USER','user')
$NUGET_PAT = [System.Environment]::GetEnvironmentVariable('NUGET_PAT','user')

Write-Host "NuGet User: $NUGET_USER, PAT: $NUGET_PAT"

# variables
$VERSION = 'dev'

docker build --no-cache -f "src\MrJB.IdentityServer\Dockerfile" `
    --build-arg NUGET_USER=$NUGET_USER --build-arg NUGET_PAT=$NUGET_PAT `
    --label "company=MRJb" `
    -t mrjb/identityserver:$VERSION .

# display built images
docker images | findstr mrjb