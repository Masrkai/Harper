{ lib, rustPlatform, iproute2, nftables, ... }:

rustPlatform.buildRustPackage {
  pname   = "harper";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ iproute2 nftables ];


  meta = with lib; {
    description = "Per-device bandwidth shaping and network traffic management";
    license     = licenses.mit;
    maintainers = [ "Masrkai" ];
    platforms   = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "harper";
  };
}
