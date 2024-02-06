# zk-clique

A command line tool for clique circuits

## Usage
```bash 
zk-clique-p256-ecdsa 0.1.0
p256-ecdsa commands

USAGE:
    zk-clique p256-ecdsa <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    gen-solidity    
    help            Prints this message or the help of the given subcommand(s)
    prove           Create a hex-encoded proof with 0x prefix based on given input
    setup           
    verify          Verify a hex-encoded proof with 0x prefix based on given input

```

**NOTE**: For development usage, you should invoke `setup` at first


## Examples

**Create Proof**

```bash
zk-clique p256-ecdsa prove --msghash 0x9c8adb93585642008f6defe84b014d3db86e65ec158f32c1fe8b78974123c264 --signature 0x89e7242b7a0be99f7c668a8bdbc1fcaf6fa7562dd28538dbab4b059e9d6955c2c434593d3ccb0e7e5825effb14e251e6e5efb738d6042647ed2e2faac9191718 --pubkey 0x04cd8fdae57e9fcc6638b7e0bdf1cfe6eb4783c29ed13916f10c121c70b7173dd61291422f9ef68a1b6a7e9cccbe7cc2c0738f81a996f7e62e9094c1f80bc0d788 --output proof.bin
```

**Verify Proof**
```bash
zk-clique p256-ecdsa verify --msghash 0x9c8adb93585642008f6defe84b014d3db86e65ec158f32c1fe8b78974123c264 --signature 0x89e7242b7a0be99f7c668a8bdbc1fcaf6fa7562dd28538dbab4b059e9d6955c2c434593d3ccb0e7e5825effb14e251e6e5efb738d6042647ed2e2faac9191718 --pubkey 0x04cd8fdae57e9fcc6638b7e0bdf1cfe6eb4783c29ed13916f10c121c70b7173dd61291422f9ef68a1b6a7e9cccbe7cc2c0738f81a996f7e62e9094c1f80bc0d788 --proof proof.bin
```

**Generate solidity**
```bash
zk-clique p256-ecdsa gen-solidity -o verifier.sol
```

