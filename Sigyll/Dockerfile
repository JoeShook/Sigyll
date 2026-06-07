# Build context: examples/CA/ (set by DockerfileContext in Sigyll.csproj)
#
# VS builds this automatically via Docker launch profile.
# Aspire uses the pre-built image via AddContainer("sigil", "sigil", "dev").

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 5200
EXPOSE 7200

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Sigyll/Sigyll.csproj                                 Sigyll/
COPY Sigyll.Common/Sigyll.Common.csproj                    Sigyll.Common/
COPY Sigyll.UI/Sigyll.UI.csproj                            Sigyll.UI/
COPY Sigyll.ServiceDefaults/Sigyll.ServiceDefaults.csproj  Sigyll.ServiceDefaults/
COPY Sigyll.Vault/Sigyll.Vault.csproj                      Sigyll.Vault/
COPY Sigyll.Gcp/Sigyll.Gcp.csproj                          Sigyll.Gcp/
COPY Sigyll.FileSystem/Sigyll.FileSystem.csproj             Sigyll.FileSystem/

RUN dotnet restore Sigyll/Sigyll.csproj

COPY Sigyll/               Sigyll/
COPY Sigyll.Common/        Sigyll.Common/
COPY Sigyll.UI/            Sigyll.UI/
COPY Sigyll.ServiceDefaults/ Sigyll.ServiceDefaults/
COPY Sigyll.Vault/         Sigyll.Vault/
COPY Sigyll.Gcp/           Sigyll.Gcp/
COPY Sigyll.FileSystem/    Sigyll.FileSystem/

ARG BUILD_CONFIGURATION=Release
RUN dotnet publish Sigyll/Sigyll.csproj -c $BUILD_CONFIGURATION -o /app/publish

# Generate dev cert in the SDK stage (aspnet runtime doesn't have dev-certs tool)
FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "Sigyll.dll"]
