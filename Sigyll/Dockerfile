# Build context: the repository root (set by DockerfileContext in Sigyll.csproj)
#
# VS builds this automatically via Docker launch profile.
# Aspire builds it with AddDockerfile when Sigyll:HostMode is "docker".

# Base images are pinned by digest; Dependabot proposes new digests as Microsoft publishes them.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:1a48394b6f29d3a32c79d9edecd4abda0ecbe8776d567dbfc4590ed6979c740c AS base

# Ubuntu security updates not yet in the newest Microsoft image: apt and libapt-pkg (CVE-2026-109518) and
# libpcre2. Drop a package from this list once a base image digest ships the fixed version.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg6.0t64 libpcre2-8-0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
EXPOSE 7200

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS build
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
COPY Sigyll.Pkcs11/Sigyll.Pkcs11.csproj                    Sigyll.Pkcs11/
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
COPY Sigyll.Pkcs11/        Sigyll.Pkcs11/
COPY Sigyll.FileSystem/    Sigyll.FileSystem/

ARG BUILD_CONFIGURATION=Release
RUN dotnet publish Sigyll/Sigyll.csproj -c $BUILD_CONFIGURATION -o /app/publish

# The licences and notices of the packages Sigyll ships with travel with it, as /app/THIRD-PARTY-NOTICES.txt.
COPY LICENSE /app/publish/LICENSE
COPY tools/third-party-notices/ tools/third-party-notices/
RUN dotnet run tools/third-party-notices/ThirdPartyNotices.cs -- \
      /app/publish/THIRD-PARTY-NOTICES.txt /app/publish/Sigyll.deps.json

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# Run as the image's unprivileged "app" user, not root.
USER $APP_UID

ENTRYPOINT ["dotnet", "Sigyll.dll"]
