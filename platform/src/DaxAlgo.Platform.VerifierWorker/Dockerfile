FROM mcr.microsoft.com/dotnet/sdk@sha256:cb9d975bf57fd1b0915858d1db1184bea20f7f746f0536323fcab49673144e8c AS build

WORKDIR /src
COPY Directory.Build.targets ./Directory.Build.targets
COPY platform/Directory.Build.props ./platform/Directory.Build.props
COPY platform/src/DaxAlgo.Platform.VerifierWorker/ ./platform/src/DaxAlgo.Platform.VerifierWorker/
COPY public/Directory.Build.props ./public/Directory.Build.props
COPY public/Directory.Build.targets ./public/Directory.Build.targets
COPY public/assets/DaxAlgoLogo.png ./public/assets/DaxAlgoLogo.png
COPY public/src/windows/Core/TradingTerminal.Core/ ./public/src/windows/Core/TradingTerminal.Core/
COPY public/src/windows/Sdk/DaxAlgo.Sdk/ ./public/src/windows/Sdk/DaxAlgo.Sdk/

RUN dotnet publish \
    platform/src/DaxAlgo.Platform.VerifierWorker/DaxAlgo.Platform.VerifierWorker.csproj \
    --configuration Release \
    --output /out \
    --nologo

FROM mcr.microsoft.com/dotnet/runtime@sha256:3584400cee1cf9952ec0c0101add15022a0e8fcecffda97faece90edd71e3d75 AS runtime

# Copy runtime files through scratch so the final image inherits no base-image
# metadata. Docker supplies only its fixed default PATH; the controller verifies
# that exact value plus the absent user, entrypoint, command, and volumes.
FROM scratch
COPY --from=runtime / /
COPY --from=build /out/ /opt/daxalgo/bin/
