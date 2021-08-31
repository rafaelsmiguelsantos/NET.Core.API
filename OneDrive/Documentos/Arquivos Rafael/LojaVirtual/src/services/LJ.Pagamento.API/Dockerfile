#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /src
COPY ["src/services/LJ.Pagamento.API/LJ.Pagamento.API.csproj", "src/services/LJ.Pagamento.API/"]
RUN dotnet restore "src/services/LJ.Pagamento.API/LJ.Pagamento.API.csproj"
COPY . .
WORKDIR "/src/src/services/LJ.Pagamento.API"
RUN dotnet build "LJ.Pagamento.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "LJ.Pagamento.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "LJ.Pagamento.API.dll"]