# shell.nix
{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    llvmPackages_21.llvm   # match the version rustc uses

    cargo
    cargo-watch
    cargo-nextest
    cargo-llvm-cov
  ];

  LLVM_COV      = "${pkgs.llvmPackages_21.llvm}/bin/llvm-cov";
  LLVM_PROFDATA = "${pkgs.llvmPackages_21.llvm}/bin/llvm-profdata";

  shellHook = ''
    alias build='cargo build --release'
    alias test='cargo llvm-cov nextest --ignore-filename-regex="rustc-" --html'
    alias review='[ -f target/llvm-cov/html/index.html ] && xdg-open target/llvm-cov/html/index.html || { echo "No report found, run test first"; }'

    alias package-test-remote='nix-build -E "with import <nixpkgs> {}; callPackage ./default.nix {}"'
    alias package-test-local='nix-build -E "with import <nixpkgs> {}; callPackage ./default-local.nix {}'

    alias state='
      echo "=== 1. Routing table ==="
      ip route show
      echo ""
      echo "=== 2. ARP cache ==="
      ip neigh show
      echo ""
      echo "=== 3. tc state ==="
      echo "== Generally"
      tc qdisc show
      echo "-- eth0 --"
      tc qdisc show dev eth0
      echo "-- ifb0 --"
      tc qdisc show dev ifb0
      echo ""
      echo "=== 4. Kernel parameters ==="
      echo "ip_forward:"
      cat /proc/sys/net/ipv4/ip_forward
      echo "rp_filter:"
      cat /proc/sys/net/ipv4/conf/all/rp_filter
      echo ""
      echo "=== 5. rpfilter chain ==="
      sudo nft list chain inet nixos-fw rpfilter
    '
  '';
}
