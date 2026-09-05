{
  lib,
  stdenvNoCC,
  fetchurl,
}:

let
  version = "0.1.2";
  assets = {
    "x86_64-linux" = {
      suffix = "linux-x86_64";
      hash = "sha256-osO+SH3G4ELT/lhdIwz0vGgwOGhJaUGO8fkkGNH1RGQ=";
    };
    "aarch64-linux" = {
      suffix = "linux-arm64";
      hash = "sha256-75cKpI8Y75RXe1QUL877MUCBMtC6PhZxnVW296QB/NE=";
    };
    "x86_64-darwin" = {
      suffix = "darwin-x86_64";
      hash = "sha256-b5CzMvLXBKDbGwZV9ZzTIBGykZpUGptJZXl0n944eAc=";
    };
    "aarch64-darwin" = {
      suffix = "darwin-arm64";
      hash = "sha256-jDgSF/pKleyVjQ43pQ2RQQsSnOkQq20lB646Q4bq52Q=";
    };
  };
  asset =
    assets.${stdenvNoCC.hostPlatform.system}
      or (throw "Unsupported system: ${stdenvNoCC.hostPlatform.system}");
  archiveName = "keyring-rs-v${version}-${asset.suffix}.tar.gz";
in
stdenvNoCC.mkDerivation {
  pname = "keyring-rs-bin";
  inherit version;

  src = fetchurl {
    url = "https://github.com/tsln1998/keyring-rs/releases/download/v${version}/${archiveName}";
    inherit (asset) hash;
  };

  sourceRoot = lib.removeSuffix ".tar.gz" archiveName;
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    install -Dm755 keyring "$out/bin/keyring"
    ln -s keyring "$out/bin/keyring-rs"
    install -Dm644 README.md "$out/share/doc/keyring-rs/README.md"
    install -Dm644 LICENSE "$out/share/licenses/keyring-rs/LICENSE"

    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    "$out/bin/keyring-rs" --help >/dev/null
  '';

  meta = with lib; {
    description = "Prebuilt keyring-rs SSH agent service with pluggable key providers";
    homepage = "https://github.com/tsln1998/keyring-rs";
    license = licenses.mit;
    mainProgram = "keyring-rs";
    platforms = builtins.attrNames assets;
    sourceProvenance = [ sourceTypes.binaryNativeCode ];
  };
}
