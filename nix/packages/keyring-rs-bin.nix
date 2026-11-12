# Install a published platform archive without compiling the Rust workspace.
{
  lib,
  stdenvNoCC,
  fetchurl,
}:

let
  inherit (builtins.fromJSON (builtins.readFile ./update.json)) version platforms;
  inherit (stdenvNoCC.hostPlatform) system;
  # Select for the installation platform and reject systems without a release asset.
  asset = platforms.${system} or (throw "Unsupported system: ${system}");
  archiveName = builtins.baseNameOf asset.url;
in
stdenvNoCC.mkDerivation {
  pname = "keyring-rs-bin";
  inherit version;

  src = fetchurl asset;

  # The release workflow wraps each archive in a directory with the same base name.
  sourceRoot = lib.removeSuffix ".tar.gz" archiveName;
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    install -Dm755 keyring "$out/bin/keyring"
    install -Dm644 README.md "$out/share/doc/keyring-rs/README.md"
    install -Dm644 LICENSE "$out/share/licenses/keyring-rs/LICENSE"

    runHook postInstall
  '';

  # Exercise argument parsing to catch an archive that cannot run on this platform.
  doInstallCheck = true;
  installCheckPhase = ''
    "$out/bin/keyring" --help >/dev/null
  '';

  meta = with lib; {
    description = "Bitwarden SSH agent with platform key stores";
    homepage = "https://github.com/tsln1998/keyring-rs";
    license = licenses.mit;
    mainProgram = "keyring-rs";
    platforms = builtins.attrNames platforms;
    sourceProvenance = [ sourceTypes.binaryNativeCode ];
  };
}
