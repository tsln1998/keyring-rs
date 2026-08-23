{
  lib,
  stdenvNoCC,
  fetchurl,
}:

let
  version = "0.1.1";
  assets = {
    "x86_64-linux" = {
      suffix = "linux-x86_64";
      hash = "sha256-ahp1sgsG/zIl3rixkER5DnSI9XY7ugWVAj4q85Q60zU=";
    };
    "aarch64-linux" = {
      suffix = "linux-arm64";
      hash = "sha256-a0mWSUx/N71vNTEtNbo9y0yh8TMR2ASGTqmIQFs+QXw=";
    };
    "x86_64-darwin" = {
      suffix = "darwin-x86_64";
      hash = "sha256-vpKHzANVoXmAxwObd/zfgnWqQ7sWNaPwb4CoK/tp5xs=";
    };
    "aarch64-darwin" = {
      suffix = "darwin-arm64";
      hash = "sha256-4+7IPZ3e8d6aVqeTpthdV8X/uKyRdrbL/NcjDri9Cyw=";
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
