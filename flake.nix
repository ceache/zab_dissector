{
  description = "Development environment and unit test for the ZAB Wireshark dissector";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:

        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              stylua
              luaPackages.luacheck
              tshark
              python3
            ];
          };
        }
      );

      apps = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          runScript = pkgs.writeShellScriptBin "run-tests" ''
            PATH="${pkgs.wireshark-cli}/bin:${pkgs.python3}/bin:$PATH"
            exec ${pkgs.python3}/bin/python3 ${./tests/run_tests.py} "$@"
          '';
        in
        {
          tests = {
            type = "app";
            program = "${runScript}/bin/run-tests";
          };
          default = self.apps.${system}.tests;
        });

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          dissector = pkgs.runCommand "zab-dissector-tests"
            {
              nativeBuildInputs = [ pkgs.wireshark-cli pkgs.python3 ];
            }
            ''
              mkdir -p $out
              export HOME=$TMPDIR
              cp -r ${./zab.lua} zab.lua
              cp -r ${./tests} tests
              python3 tests/run_tests.py
              touch $out/success
            '';
        });
    };
}
