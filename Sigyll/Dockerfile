# Build context: the repository root (set by DockerfileContext in Sigyll.csproj)
#
# VS builds this automatically via Docker launch profile.
# Aspire builds it with AddDockerfile when Sigyll:HostMode is "docker".

# Base images are pinned by digest; Dependabot proposes new digests as Microsoft publishes them.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee AS base
WORKDIR /app
EXPOSE 5200
EXPOSE 7200

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS build
WORKDIR /src

COPY Directory.Build.props                                 ./
COPY Sigyll/Sigyll.csproj                                 Sigyll/
COPY Sigyll.Common/Sigyll.Common.csproj                    Sigyll.Common/
COPY Sigyll.Contracts/Sigyll.Contracts.csproj              Sigyll.Contracts/
COPY Sigyll.Did/Sigyll.Did.csproj                          Sigyll.Did/
COPY Sigyll.Vc/Sigyll.Vc.csproj                            Sigyll.Vc/
COPY Sigyll.UI/Sigyll.UI.csproj                            Sigyll.UI/
COPY Sigyll.ServiceDefaults/Sigyll.ServiceDefaults.csproj  Sigyll.ServiceDefaults/
COPY Sigyll.Vault/Sigyll.Vault.csproj                      Sigyll.Vault/
COPY Sigyll.Gcp/Sigyll.Gcp.csproj                          Sigyll.Gcp/
COPY Sigyll.FileSystem/Sigyll.FileSystem.csproj             Sigyll.FileSystem/

RUN dotnet restore Sigyll/Sigyll.csproj

COPY Sigyll/               Sigyll/
COPY Sigyll.Common/        Sigyll.Common/
COPY Sigyll.Contracts/     Sigyll.Contracts/
COPY Sigyll.Did/           Sigyll.Did/
COPY Sigyll.Vc/            Sigyll.Vc/
COPY Sigyll.UI/            Sigyll.UI/
COPY Sigyll.ServiceDefaults/ Sigyll.ServiceDefaults/
COPY Sigyll.Vault/         Sigyll.Vault/
COPY Sigyll.Gcp/           Sigyll.Gcp/
COPY Sigyll.FileSystem/    Sigyll.FileSystem/

ARG BUILD_CONFIGURATION=Release
RUN dotnet publish Sigyll/Sigyll.csproj -c $BUILD_CONFIGURATION -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# Run as the image's unprivileged "app" user, not root.
USER $APP_UID

ENTRYPOINT ["dotnet", "Sigyll.dll"]
