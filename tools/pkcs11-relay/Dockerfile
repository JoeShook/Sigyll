# The relay server with SoftHSM behind it: a stand-in for a network HSM, for development and tests only.
# Build context: tools/pkcs11-relay
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb AS build
WORKDIR /src
COPY Shared Shared
COPY Server Server
RUN dotnet publish Server -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:bfd912c83295ce66d4b706ebb8541b9f14259b0e76fbb88b2751f58ce2399d2e
RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app .
EXPOSE 5696
ENTRYPOINT ["dotnet", "sigyll-pkcs11-relay-server.dll"]
