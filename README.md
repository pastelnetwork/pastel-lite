# pastel-lite

## Build Setup

### 0. Clone the repository
``` bash
git clone git@github.com:pastelnetwork/pastel-lite.git
cd pastel-lite
```

#### Get submodules
``` bash
git submodule update --init --recursive
```

### 1. Install `cmake`, if not already installed
#### Linux
``` bash
sudo apt install cmake
```
#### Mac
``` bash
brew install cmake
```
#### Windows
``` bash
choco install cmake
```

### 2. Install `vcpkg`
``` bash
git clone https://github.com/Microsoft/vcpkg.git
```
#### Linux or Mac
``` bash
cd vcpkg
./bootstrap-vcpkg.sh
```
#### Windows
``` bash
cd vcpkg
bootstrap-vcpkg.bat
```
The last command output will be similar to:
``` bash
CMake projects should use: "-DCMAKE_TOOLCHAIN_FILE=/Users/name/vcpkg/scripts/buildsystems/vcpkg.cmake"
```
> Remember that line, you will need it later.

Add `vcpkg` to your `PATH` environment variable.
```bash
export PATH=$PATH:/Users/name/vcpkg
```

### 3. Install `Emscripten`
#### Linux or Mac
``` bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
```
#### Windows
``` bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
emsdk install latest
emsdk activate latest
```
Add `Emscripten` to your `PATH` environment variable.
```bash
export PATH=$PATH:/Users/name/emsdk/upstream/emscripten/
```

### 4. Install 3rd party packages with `vcpkg` - for native build ONLY
``` bash
cd pastel-light
vcpkg install
```
`vcpkg` uses packages described in the `vcpkg.json`
Currently they are:
* `libsodium`

### 5. Build native library `libpastel` and test tool `pastel_lite` 
``` bash
mkdir build-native-debug
cd build-native-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build .
```
> Replace `<path-to-vcpkg>` with the path from step 2.

### 6. Build WebAssembly library `libpastel-wasm` 
``` bash
mkdir build-wasm-debug
cd build-wasm-debug
emcmake cmake .. -DCMAKE_BUILD_TYPE=Debug
emmake cmake --build .
```

### 7. Build python bindings

#### 7.1 Build the docker image  
``` bash
docker build -t pastel_python_build -f Dockerfile.python_build .
```

#### 7.2 Build the python bindings
``` bash
docker run pastel_python_build /src/build_python_package_in_docker.sh
```

#### 7.3 Copy the python package to the host
``` bash
docker cp pastel_python_build_container:/src/python_bindings/wheelhouse/libpastelid-0.3.2-cp310-cp310-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl . 
```

#### 7.4 Upload the python package to pypi
``` bash
twine upload libpastelid-0.3.2-cp310-cp310-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl
```

## Appendix

### Install Clang/LLVM/libc++ 18
```shell
sudo add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"
sudo add-apt-repository "deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"
sudo apt-get install libllvm-18-ocaml-dev libllvm18 llvm-18 llvm-18-dev llvm-18-doc llvm-18-examples llvm-18-runtime
sudo apt-get install libc++-18-dev libc++abi-18-dev
sudo apt-get install clang-18 clang-tools-18 clang-18-doc libclang-common-18-dev libclang-18-dev libclang1-18 clang-format-18 python3-clang-18 clangd-18 clang-tidy-18
```

---

## Documentation:

## **Complete List of `pastelInstance` JavaScript Methods**

### **1. `CreateNewWallet`**

- **Signature:**
  ```javascript
  CreateNewWallet(password: string) => string
  ```
- **Parameters:**
  - `password` (`string`): The password used to secure the new wallet.
- **Returns:**
  - `mnemonic` (`string`): A mnemonic phrase generated for the new wallet.
- **Usage Example:**
  ```javascript
  let mnemonic = pastelInstance.CreateNewWallet("securepassword");
  console.log("Mnemonic:", mnemonic);
  ```

---

### **2. `CreateWalletFromMnemonic`**

- **Signature:**
  ```javascript
  CreateWalletFromMnemonic(password: string, mnemonic: string) => string
  ```
- **Parameters:**
  - `password` (`string`): The password to secure the wallet.
  - `mnemonic` (`string`): The mnemonic phrase used to restore the wallet.
- **Returns:**
  - `resultMnemonic` (`string`): The mnemonic phrase returned after wallet creation (should match the input mnemonic).
- **Usage Example:**
  ```javascript
  let restoredMnemonic = pastelInstance.CreateWalletFromMnemonic("securepassword", mnemonic);
  console.log("Restored Mnemonic:", restoredMnemonic);
  ```

---

### **3. `ExportWallet`**

- **Signature:**
  ```javascript
  ExportWallet() => string
  ```
- **Parameters:**
  - None
- **Returns:**
  - `walletData` (`string`): The exported wallet data as a string.
- **Usage Example:**
  ```javascript
  let walletData = pastelInstance.ExportWallet();
  console.log("Exported Wallet Data:", walletData);
  ```

---

### **4. `ImportWallet`**

- **Signature:**
  ```javascript
  ImportWallet(walletData: string) => boolean
  ```
- **Parameters:**
  - `walletData` (`string`): The wallet data to import.
- **Returns:**
  - `success` (`boolean`): Indicates whether the import was successful.
- **Usage Example:**
  ```javascript
  let success = pastelInstance.ImportWallet(walletData);
  console.log("Wallet Import Successful:", success);
  ```

---

### **5. `UnlockWallet`**

- **Signature:**
  ```javascript
  UnlockWallet(password: string) => boolean
  ```
- **Parameters:**
  - `password` (`string`): The password to unlock the wallet.
- **Returns:**
  - `success` (`boolean`): Indicates whether the wallet was successfully unlocked.
- **Usage Example:**
  ```javascript
  let unlocked = pastelInstance.UnlockWallet("securepassword");
  console.log("Wallet Unlocked:", unlocked);
  ```

---

### **6. `LockWallet`**

- **Signature:**
  ```javascript
  LockWallet() => boolean
  ```
- **Parameters:**
  - None
- **Returns:**
  - `success` (`boolean`): Indicates whether the wallet was successfully locked.
- **Usage Example:**
  ```javascript
  let locked = pastelInstance.LockWallet();
  console.log("Wallet Locked:", locked);
  ```

---

### **7. `MakeNewAddress`**

- **Signature:**
  ```javascript
  MakeNewAddress(mode: number) => string
  ```
- **Parameters:**
  - `mode` (`number`): The network mode, typically an enumeration value (e.g., Mainnet = 0, Testnet = 1, Devnet = 2).
- **Returns:**
  - `address` (`string`): A newly generated address.
- **Usage Example:**
  ```javascript
  const NetworkMode = { MAINNET: 0, TESTNET: 1, DEVNET: 2 };
  let newAddress = pastelInstance.MakeNewAddress(NetworkMode.MAINNET);
  console.log("New Address:", newAddress);
  ```

---

### **8. `GetAddress`**

- **Signature:**
  ```javascript
  GetAddress(index: number, mode: number) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the address to retrieve.
  - `mode` (`number`): The network mode, typically an enumeration value.
- **Returns:**
  - `address` (`string`): The address corresponding to the given index and mode.
- **Usage Example:**
  ```javascript
  let address = pastelInstance.GetAddress(0, NetworkMode.MAINNET);
  console.log("Retrieved Address:", address);
  ```

---

### **9. `GetAddresses`**

- **Signature:**
  ```javascript
  GetAddresses(mode?: number) => string[]
  ```
- **Parameters:**
  - `mode` (`number`, optional): The network mode. If omitted, retrieves addresses for all network modes.
- **Returns:**
  - `addresses` (`string[]`): A list of wallet addresses.
- **Usage Examples:**
  ```javascript
  // Retrieve all addresses
  let allAddresses = pastelInstance.GetAddresses();
  console.log("All Addresses:", allAddresses);
  
  // Retrieve addresses for Mainnet
  let mainnetAddresses = pastelInstance.GetAddresses(NetworkMode.MAINNET);
  console.log("Mainnet Addresses:", mainnetAddresses);
  ```

---

### **10. `GetAddressesCount`**

- **Signature:**
  ```javascript
  GetAddressesCount() => number
  ```
- **Parameters:**
  - None
- **Returns:**
  - `count` (`number`): The total number of addresses.
- **Usage Example:**
  ```javascript
  let addressCount = pastelInstance.GetAddressesCount();
  console.log("Total Addresses:", addressCount);
  ```

---

### **11. `MakeNewPastelID`**

- **Signature:**
  ```javascript
  MakeNewPastelID(flag: boolean) => string
  ```
- **Parameters:**
  - `flag` (`boolean`): A boolean flag, purpose inferred from context (e.g., whether to associate with a specific key type).
- **Returns:**
  - `pastelID` (`string`): A newly generated PastelID.
- **Usage Example:**
  ```javascript
  let pastelID = pastelInstance.MakeNewPastelID(true);
  console.log("New PastelID:", pastelID);
  ```

---

### **12. `GetPastelIDByIndex`**

- **Signature:**
  ```javascript
  GetPastelIDByIndex(index: number, type: number) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the PastelID to retrieve.
  - `type` (`number`): The type of PastelID, typically an enumeration value (e.g., PastelID = 0, LegRoast = 1).
- **Returns:**
  - `pastelID` (`string`): The PastelID corresponding to the given index and type.
- **Usage Example:**
  ```javascript
  const PastelIDType = { PASTELID: 0, LEGROAST: 1 };
  let pastelID = pastelInstance.GetPastelIDByIndex(0, PastelIDType.PASTELID);
  console.log("PastelID:", pastelID);
  
  let legRoastID = pastelInstance.GetPastelIDByIndex(0, PastelIDType.LEGROAST);
  console.log("LegRoast ID:", legRoastID);
  ```

---

### **13. `GetPastelID`**

- **Signature:**
  ```javascript
  GetPastelID(pastelID: string, type: number) => string
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier.
  - `type` (`number`): The type of PastelID to retrieve, typically an enumeration value (e.g., PastelID = 0, LegRoast = 1).
- **Returns:**
  - `pastel_id` (`string`): The retrieved PastelID based on the provided type.
- **Usage Example:**
  ```javascript
  let pastel_id = pastelInstance.GetPastelID("jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw", PastelIDType.PASTELID);
  console.log("PastelID:", pastel_id);
  
  let legRoast = pastelInstance.GetPastelID("jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw", PastelIDType.LEGROAST);
  console.log("LegRoast:", legRoast);
  ```

---

### **14. `ImportPastelIDKeys`**

- **Signature:**
  ```javascript
  ImportPastelIDKeys(pastelID: string, passPhrase: string, dirPath: string) => any
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier.
  - `passPhrase` (`string`): The passphrase associated with the PastelID.
  - `dirPath` (`string`): The directory path where the keys are stored.
- **Returns:**
  - `result` (`any`): The result of the import operation. The exact structure depends on the implementation but is typically used for logging or error handling.
- **Usage Example:**
  ```javascript
  let result = pastelInstance.ImportPastelIDKeys("jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw", "passphrase", "/path/to/keys");
  console.log("Import PastelID Keys Result:", result);
  ```

---

### **15. `GetSecret`**

- **Signature:**
  ```javascript
  GetSecret(address: string, mode: number) => string
  ```
- **Parameters:**
  - `address` (`string`): The address whose secret (private key) is to be retrieved.
  - `mode` (`number`): The network mode.
- **Returns:**
  - `secret` (`string`): The private key associated with the address.
- **Usage Example:**
  ```javascript
  let secret = pastelInstance.GetSecret("PtiMyKSofCEt9X9FuaXDzjhyvZ27uadqXsa", NetworkMode.MAINNET);
  console.log("Private Key:", secret);
  ```

---

### **16. `GetAddressSecret`**

- **Signature:**
  ```javascript
  GetAddressSecret(address: string, mode: number) => string
  ```
- **Parameters:**
  - `address` (`string`): The address whose secret is to be retrieved.
  - `mode` (`number`): The network mode.
- **Returns:**
  - `secret` (`string`): The private key associated with the address.
- **Usage Example:**
  ```javascript
  let secret = pastelInstance.GetAddressSecret("PtiMyKSofCEt9X9FuaXDzjhyvZ27uadqXsa", NetworkMode.MAINNET);
  console.log("Private Key:", secret);
  ```

---

### **17. `ImportLegacyPrivateKey`**

- **Signature:**
  ```javascript
  ImportLegacyPrivateKey(privKey: string, mode: number) => string
  ```
- **Parameters:**
  - `privKey` (`string`): The legacy private key to import.
  - `mode` (`number`): The network mode.
- **Returns:**
  - `address` (`string`): The address associated with the imported private key.
- **Usage Example:**
  ```javascript
  let importedAddress = pastelInstance.ImportLegacyPrivateKey("Kxb6W74ZrtRTZX7viSUtWeJxvSaxxfcQpCCpSuore2VR8vv9kM37", NetworkMode.MAINNET);
  console.log("Imported Address:", importedAddress);
  ```

---

### **18. `GetPubKeyAt`**

- **Signature:**
  ```javascript
  GetPubKeyAt(index: number) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the public key to retrieve.
- **Returns:**
  - `pubKey` (`string`): The public key at the specified index.
- **Usage Example:**
  ```javascript
  let pubKey = pastelInstance.GetPubKeyAt(3);
  console.log("Public Key at Index 3:", pubKey);
  ```

---

### **19. `SignWithKeyAt`**

- **Signature:**
  ```javascript
  SignWithKeyAt(index: number, message: string) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the key to use for signing.
  - `message` (`string`): The message to be signed.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithKeyAt(3, "Hello, Pastel!");
  console.log("Signature:", signature);
  ```

---

### **20. `SignWithWalletKey`**

- **Signature:**
  ```javascript
  SignWithWalletKey(message: string) => string
  ```
- **Parameters:**
  - `message` (`string`): The message to be signed using the wallet's key.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithWalletKey("Hello, Wallet!");
  console.log("Wallet Signature:", signature);
  ```

---

### **21. `GetWalletPubKey`**

- **Signature:**
  ```javascript
  GetWalletPubKey() => string
  ```
- **Parameters:**
  - None
- **Returns:**
  - `walletPubKey` (`string`): The public key of the wallet.
- **Usage Example:**
  ```javascript
  let walletPubKey = pastelInstance.GetWalletPubKey();
  console.log("Wallet Public Key:", walletPubKey);
  ```

---

### **22. `CreateSendToTransaction`**

- **Signature:**
  ```javascript
  CreateSendToTransaction(mode: number, sendTo: string, optionalField: string, utxos: string, fee: number) => string
  ```
- **Parameters:**
  - `mode` (`number`): The network mode.
  - `sendTo` (`string`): A JSON string representing an array of recipients and amounts.
    ```json
    [
      {"address": "recipient_address_1", "amount": 100},
      {"address": "recipient_address_2", "amount": 50}
    ]
    ```
  - `optionalField` (`string`): An optional field, purpose inferred from context (e.g., memo or note).
  - `utxos` (`string`): A JSON string representing an array of unspent transaction outputs (UTXOs).
    ```json
    [
      {
        "address": "your_address",
        "txid": "txid1",
        "outputIndex": 0,
        "script": "script1",
        "patoshis": 2000000,
        "height": 76270
      },
      ...
    ]
    ```
  - `fee` (`number`): The transaction fee in patoshis.
- **Returns:**
  - `transaction` (`string`): The created transaction data as a serialized string.
- **Usage Example:**
  ```javascript
  const sendTo = JSON.stringify([
    { "address": "44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg", "amount": 100 }
  ]);
  
  const utxos = JSON.stringify([
    {
      "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
      "txid": "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc",
      "outputIndex": 0,
      "script": "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac",
      "patoshis": 200000000,
      "height": 76270
    }
  ]);
  
  let transaction = pastelInstance.CreateSendToTransaction(NetworkMode.DEVNET, sendTo, "", utxos, 76270);
  console.log("Created Transaction:", transaction);
  ```

---

### **23. `CreateSendToTransactionJson`**

- **Signature:**
  ```javascript
  CreateSendToTransactionJson(mode: number, sendToJson: string, optionalField: string, utxoJson: string, fee: number) => string
  ```
- **Parameters:**
  - `mode` (`number`): The network mode.
  - `sendToJson` (`string`): A JSON-formatted string detailing recipients and amounts.
    ```json
    [
      {
        "address": "44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg",
        "amount": 100
      }
    ]
    ```
  - `optionalField` (`string`): An optional field, purpose inferred from context.
  - `utxoJson` (`string`): A JSON-formatted string detailing unspent transaction outputs (UTXOs).
    ```json
    [
      {
        "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
        "txid": "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc",
        "outputIndex": 0,
        "script": "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac",
        "patoshis": 200000000,
        "height": 76270
      }
    ]
    ```
  - `fee` (`number`): The transaction fee in patoshis.
- **Returns:**
  - `transactionJson` (`string`): The created transaction data in JSON format.
- **Usage Example:**
  ```javascript
  let sendToJson = JSON.stringify([
    { "address": "44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg", "amount": 100 }
  ]);
  
  let utxoJson = JSON.stringify([
    {
      "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
      "txid": "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc",
      "outputIndex": 0,
      "script": "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac",
      "patoshis": 200000000,
      "height": 76270
    }
  ]);
  
  let transactionJson = pastelInstance.CreateSendToTransactionJson(NetworkMode.DEVNET, sendToJson, "", utxoJson, 76270);
  console.log("Created Transaction JSON:", transactionJson);
  ```

---

### **24. `CreateRegisterPastelIdTransaction`**

- **Signature:**
  ```javascript
  CreateRegisterPastelIdTransaction(mode: number, pastelID: string, address: string, utxos: string, fee: number) => string
  ```
- **Parameters:**
  - `mode` (`number`): The network mode.
  - `pastelID` (`string`): The PastelID to register.
  - `address` (`string`): The address associated with the PastelID.
  - `utxos` (`string`): A JSON-formatted string representing an array of unspent transaction outputs (UTXOs).
    ```json
    [
      {
        "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
        "txid": "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc",
        "outputIndex": 0,
        "script": "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac",
        "patoshis": 200000000,
        "height": 76270
      }
    ]
    ```
  - `fee` (`number`): The transaction fee in patoshis.
- **Returns:**
  - `registrationTransaction` (`string`): The created PastelID registration transaction data as a serialized string.
- **Usage Example:**
  ```javascript
  let pastelID = "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw";
  let address = "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo";
  
  let utxos = JSON.stringify([
    {
      "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
      "txid": "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc",
      "outputIndex": 0,
      "script": "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac",
      "patoshis": 200000000,
      "height": 76270
    }
  ]);
  
  let registrationTx = pastelInstance.CreateRegisterPastelIdTransaction(NetworkMode.DEVNET, pastelID, address, utxos, 76270);
  console.log("Registration Transaction:", registrationTx);
  ```

---

### **25. `CreateRegisterPastelIdTransactionJson`**

- **Signature:**
  ```javascript
  CreateRegisterPastelIdTransactionJson(mode: number, pastelID: string, address: string, utxoJson: string, fee: number) => string
  ```
- **Parameters:**
  - `mode` (`number`): The network mode.
  - `pastelID` (`string`): The PastelID to register.
  - `address` (`string`): The address associated with the PastelID.
  - `utxoJson` (`string`): A JSON-formatted string representing an array of unspent transaction outputs (UTXOs).
  - `fee` (`number`): The transaction fee in patoshis.
- **Returns:**
  - `registrationTransactionJson` (`string`): The created PastelID registration transaction data in JSON format.
- **Usage Example:**
  ```javascript
  let utxoJson = JSON.stringify([
    {
      "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
      "txid": "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc",
      "outputIndex": 0,
      "script": "76a914d9c9353a034ca3f4ff703f89ab4e1b6fed6bfeb488ac",
      "patoshis": 200000000,
      "height": 76270
    }
  ]);
  
  let registrationTxJson = pastelInstance.CreateRegisterPastelIdTransactionJson(NetworkMode.DEVNET, pastelID, address, utxoJson, 84001);
  console.log("Registration Transaction JSON:", registrationTxJson);
  ```

---

### **26. `SignWithPastelID`**

- **Signature:**
  ```javascript
  SignWithPastelID(pastelID: string, data: string, type: number, flag: boolean) => string
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier used for signing.
  - `data` (`string`): The data to be signed.
  - `type` (`number`): The type of PastelID, typically an enumeration value (e.g., PastelID = 0, LegRoast = 1).
  - `flag` (`boolean`): A boolean flag, purpose inferred from context (e.g., whether to use a specific signing algorithm).
- **Returns:**
  - `result` (`string`): A JSON string containing the signature data.
    ```json
    {
      "data": "signature_string_here"
    }
    ```
- **Usage Example:**
  ```javascript
  let signatureResult = pastelInstance.SignWithPastelID(pastelID, "test", PastelIDType.PASTELID, true);
  let signatureData = JSON.parse(signatureResult).data;
  console.log("Signature:", signatureData);
  ```

---

### **27. `VerifyWithPastelID`**

- **Signature:**
  ```javascript
  VerifyWithPastelID(pastelID: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier used for verification.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValid = pastelInstance.VerifyWithPastelID(pastelID, "test", signatureData, true);
  console.log("Is Signature Valid:", isValid);
  ```

---

### **28. `VerifyWithLegRoast`**

- **Signature:**
  ```javascript
  VerifyWithLegRoast(pubLegRoast: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pubLegRoast` (`string`): The public key of the LegRoast.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValidLegRoast = pastelInstance.VerifyWithLegRoast(pubLegRoast, "test", legRoastSignature, true);
  console.log("Is LegRoast Signature Valid:", isValidLegRoast);
  ```

---

### **29. `GetSecret`**

- **Signature:**
  ```javascript
  GetSecret(address: string, mode: number) => string
  ```
- **Parameters:**
  - `address` (`string`): The address whose secret (private key) is to be retrieved.
  - `mode` (`number`): The network mode.
- **Returns:**
  - `secret` (`string`): The private key associated with the address.
- **Usage Example:**
  ```javascript
  let secret = pastelInstance.GetSecret("PtiMyKSofCEt9X9FuaXDzjhyvZ27uadqXsa", NetworkMode.MAINNET);
  console.log("Private Key:", secret);
  ```

---

### **30. `GetWalletPubKey`**

- **Signature:**
  ```javascript
  GetWalletPubKey() => string
  ```
- **Parameters:**
  - None
- **Returns:**
  - `walletPubKey` (`string`): The public key of the wallet.
- **Usage Example:**
  ```javascript
  let walletPubKey = pastelInstance.GetWalletPubKey();
  console.log("Wallet Public Key:", walletPubKey);
  ```

---

### **31. `GetPubKeyAt`**

- **Signature:**
  ```javascript
  GetPubKeyAt(index: number) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the public key to retrieve.
- **Returns:**
  - `pubKey` (`string`): The public key at the specified index.
- **Usage Example:**
  ```javascript
  let pubKey = pastelInstance.GetPubKeyAt(3);
  console.log("Public Key at Index 3:", pubKey);
  ```

---

### **32. `SignWithKeyAt`**

- **Signature:**
  ```javascript
  SignWithKeyAt(index: number, message: string) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the key to use for signing.
  - `message` (`string`): The message to be signed.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithKeyAt(3, "Hello, Pastel!");
  console.log("Signature:", signature);
  ```

---

### **33. `SignWithWalletKey`**

- **Signature:**
  ```javascript
  SignWithWalletKey(message: string) => string
  ```
- **Parameters:**
  - `message` (`string`): The message to be signed using the wallet's key.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithWalletKey("Hello, Wallet!");
  console.log("Wallet Signature:", signature);
  ```

---

### **34. `VerifyWithPastelID`**

- **Signature:**
  ```javascript
  VerifyWithPastelID(pastelID: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier used for verification.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValid = pastelInstance.VerifyWithPastelID("pastelID", "test", "signature_string_here", true);
  console.log("Is Signature Valid:", isValid);
  ```

---

### **35. `VerifyWithLegRoast`**

- **Signature:**
  ```javascript
  VerifyWithLegRoast(pubLegRoast: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pubLegRoast` (`string`): The public key of the LegRoast.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValidLegRoast = pastelInstance.VerifyWithLegRoast("pubLegRoast_key", "test", "signature_string_here", true);
  console.log("Is LegRoast Signature Valid:", isValidLegRoast);
  ```

---

### **36. `GetPastelIDs`**

- **Signature:**
  ```javascript
  GetPastelIDs() => string[]
  ```
- **Parameters:**
  - None
- **Returns:**
  - `pastelIDs` (`string[]`): A list of all PastelIDs associated with the wallet.
- **Usage Example:**
  ```javascript
  let pastelIDs = pastelInstance.GetPastelIDs();
  console.log("All PastelIDs:", pastelIDs);
  ```

---

### **37. `GetPubKeyAt`**

- **Signature:**
  ```javascript
  GetPubKeyAt(index: number) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the public key to retrieve.
- **Returns:**
  - `pubKey` (`string`): The public key at the specified index.
- **Usage Example:**
  ```javascript
  let pubKey = pastelInstance.GetPubKeyAt(3);
  console.log("Public Key at Index 3:", pubKey);
  ```

---

### **38. `GetPastelID`**

- **Signature:**
  ```javascript
  GetPastelID(pastelID: string, type: number) => string
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier.
  - `type` (`number`): The type of PastelID to retrieve (e.g., PastelID = 0, LegRoast = 1).
- **Returns:**
  - `pastelIDData` (`string`): The retrieved PastelID data based on the provided type.
- **Usage Example:**
  ```javascript
  let pastelIDData = pastelInstance.GetPastelID("pastelID", PastelIDType.PASTELID);
  console.log("PastelID Data:", pastelIDData);
  
  let legRoastData = pastelInstance.GetPastelID("pastelID", PastelIDType.LEGROAST);
  console.log("LegRoast Data:", legRoastData);
  ```

---

### **39. `ImportLegacyPrivateKey`**

- **Signature:**
  ```javascript
  ImportLegacyPrivateKey(privKey: string, mode: number) => string
  ```
- **Parameters:**
  - `privKey` (`string`): The legacy private key to import.
  - `mode` (`number`): The network mode.
- **Returns:**
  - `address` (`string`): The address associated with the imported private key.
- **Usage Example:**
  ```javascript
  let importedAddress = pastelInstance.ImportLegacyPrivateKey("Kxb6W74ZrtRTZX7viSUtWeJxvSaxxfcQpCCpSuore2VR8vv9kM37", NetworkMode.MAINNET);
  console.log("Imported Address:", importedAddress);
  ```

---

### **40. `GetAddressSecret`**

- **Signature:**
  ```javascript
  GetAddressSecret(address: string, mode: number) => string
  ```
- **Parameters:**
  - `address` (`string`): The address whose secret is to be retrieved.
  - `mode` (`number`): The network mode.
- **Returns:**
  - `secret` (`string`): The private key associated with the address.
- **Usage Example:**
  ```javascript
  let secret = pastelInstance.GetAddressSecret("PtiMyKSofCEt9X9FuaXDzjhyvZ27uadqXsa", NetworkMode.MAINNET);
  console.log("Private Key:", secret);
  ```

---

### **41. `GetWalletPubKey`**

- **Signature:**
  ```javascript
  GetWalletPubKey() => string
  ```
- **Parameters:**
  - None
- **Returns:**
  - `walletPubKey` (`string`): The public key of the wallet.
- **Usage Example:**
  ```javascript
  let walletPubKey = pastelInstance.GetWalletPubKey();
  console.log("Wallet Public Key:", walletPubKey);
  ```

---

### **42. `SignWithWalletKey`**

- **Signature:**
  ```javascript
  SignWithWalletKey(message: string) => string
  ```
- **Parameters:**
  - `message` (`string`): The message to be signed using the wallet's key.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithWalletKey("Hello, Wallet!");
  console.log("Wallet Signature:", signature);
  ```

---

### **43. `GetPubKeyAt`**

- **Signature:**
  ```javascript
  GetPubKeyAt(index: number) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the public key to retrieve.
- **Returns:**
  - `pubKey` (`string`): The public key at the specified index.
- **Usage Example:**
  ```javascript
  let pubKey = pastelInstance.GetPubKeyAt(3);
  console.log("Public Key at Index 3:", pubKey);
  ```

---

### **44. `SignWithKeyAt`**

- **Signature:**
  ```javascript
  SignWithKeyAt(index: number, message: string) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the key to use for signing.
  - `message` (`string`): The message to be signed.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithKeyAt(3, "Hello, Pastel!");
  console.log("Signature:", signature);
  ```

---

### **45. `VerifyWithPastelID`**

- **Signature:**
  ```javascript
  VerifyWithPastelID(pastelID: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier used for verification.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValid = pastelInstance.VerifyWithPastelID("pastelID", "test", "signature_string_here", true);
  console.log("Is Signature Valid:", isValid);
  ```

---

### **46. `VerifyWithLegRoast`**

- **Signature:**
  ```javascript
  VerifyWithLegRoast(pubLegRoast: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pubLegRoast` (`string`): The public key of the LegRoast.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValidLegRoast = pastelInstance.VerifyWithLegRoast("pubLegRoast_key", "test", "signature_string_here", true);
  console.log("Is LegRoast Signature Valid:", isValidLegRoast);
  ```

---

### **47. `GetPastelIDs`**

- **Signature:**
  ```javascript
  GetPastelIDs() => string[]
  ```
- **Parameters:**
  - None
- **Returns:**
  - `pastelIDs` (`string[]`): A list of all PastelIDs associated with the wallet.
- **Usage Example:**
  ```javascript
  let pastelIDs = pastelInstance.GetPastelIDs();
  console.log("All PastelIDs:", pastelIDs);
  ```

---

### **48. `GetPastelID`**

- **Signature:**
  ```javascript
  GetPastelID(pastelID: string, type: number) => string
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier.
  - `type` (`number`): The type of PastelID to retrieve (e.g., PastelID = 0, LegRoast = 1).
- **Returns:**
  - `pastelIDData` (`string`): The retrieved PastelID data based on the provided type.
- **Usage Example:**
  ```javascript
  let pastelIDData = pastelInstance.GetPastelID("pastelID", PastelIDType.PASTELID);
  console.log("PastelID Data:", pastelIDData);
  
  let legRoastData = pastelInstance.GetPastelID("pastelID", PastelIDType.LEGROAST);
  console.log("LegRoast Data:", legRoastData);
  ```

---

### **49. `ExportPastelIDKeys`**

- **Signature:**
  ```javascript
  ExportPastelIDKeys(pastelID: string, password: string, path: string) => boolean
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier.
  - `password` (`string`): The password for exporting keys.
  - `path` (`string`): The file system path where keys will be exported.
- **Returns:**
  - `success` (`boolean`): Indicates whether the export was successful.
- **Usage Example:**
  ```javascript
  let success = pastelInstance.ExportPastelIDKeys("pastelID", "exportPassword", "/path/to/export");
  console.log("Export PastelID Keys Successful:", success);
  ```

---

### **50. `GetWalletPubKey`**

- **Signature:**
  ```javascript
  GetWalletPubKey() => string
  ```
- **Parameters:**
  - None
- **Returns:**
  - `walletPubKey` (`string`): The public key of the wallet.
- **Usage Example:**
  ```javascript
  let walletPubKey = pastelInstance.GetWalletPubKey();
  console.log("Wallet Public Key:", walletPubKey);
  ```

---

### **51. `SignWithWalletKey`**

- **Signature:**
  ```javascript
  SignWithWalletKey(message: string) => string
  ```
- **Parameters:**
  - `message` (`string`): The message to be signed using the wallet's key.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithWalletKey("Hello, Wallet!");
  console.log("Wallet Signature:", signature);
  ```

---

### **52. `SignWithKeyAt`**

- **Signature:**
  ```javascript
  SignWithKeyAt(index: number, message: string) => string
  ```
- **Parameters:**
  - `index` (`number`): The index of the key to use for signing.
  - `message` (`string`): The message to be signed.
- **Returns:**
  - `signature` (`string`): The generated signature.
- **Usage Example:**
  ```javascript
  let signature = pastelInstance.SignWithKeyAt(3, "Hello, Pastel!");
  console.log("Signature:", signature);
  ```

---

### **53. `SignWithPastelID`**

- **Signature:**
  ```javascript
  SignWithPastelID(pastelID: string, data: string, type: number, flag: boolean) => string
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier used for signing.
  - `data` (`string`): The data to be signed.
  - `type` (`number`): The type of PastelID, typically an enumeration value.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `result` (`string`): A JSON string containing the signature data.
    ```json
    {
      "data": "signature_string_here"
    }
    ```
- **Usage Example:**
  ```javascript
  let signatureResult = pastelInstance.SignWithPastelID("pastelID", "test", PastelIDType.PASTELID, true);
  let signatureData = JSON.parse(signatureResult).data;
  console.log("Signature:", signatureData);
  ```

---

### **54. `VerifyWithPastelID`**

- **Signature:**
  ```javascript
  VerifyWithPastelID(pastelID: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pastelID` (`string`): The PastelID identifier used for verification.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValid = pastelInstance.VerifyWithPastelID("pastelID", "test", "signature_string_here", true);
  console.log("Is Signature Valid:", isValid);
  ```

---

### **55. `VerifyWithLegRoast`**

- **Signature:**
  ```javascript
  VerifyWithLegRoast(pubLegRoast: string, data: string, signature: string, flag: boolean) => boolean
  ```
- **Parameters:**
  - `pubLegRoast` (`string`): The public key of the LegRoast.
  - `data` (`string`): The original data that was signed.
  - `signature` (`string`): The signature to verify against the data.
  - `flag` (`boolean`): A boolean flag, purpose inferred from context.
- **Returns:**
  - `isValid` (`boolean`): The result of the verification (`true` if valid, `false` otherwise).
- **Usage Example:**
  ```javascript
  let isValidLegRoast = pastelInstance.VerifyWithLegRoast("pubLegRoast_key", "test", "signature_string_here", true);
  console.log("Is LegRoast Signature Valid:", isValidLegRoast);
  ```

---

### **56. `GetPastelIDs`**

- **Signature:**
  ```javascript
  GetPastelIDs() => string[]
  ```
- **Parameters:**
  - None
- **Returns:**
  - `pastelIDs` (`string[]`): A list of all PastelIDs associated with the wallet.
- **Usage Example:**
  ```javascript
  let pastelIDs = pastelInstance.GetPastelIDs();
  console.log("All PastelIDs:", pastelIDs);
  ```

---

## **Enumerations Used**

To properly use some of these methods, you'll need to reference specific enumeration values. Below are the inferred enumerations based on the method contexts:

### **1. `NetworkMode`**

An enumeration representing different network modes.

- **Values:**
  ```javascript
  const NetworkMode = {
    MAINNET: 0,
    TESTNET: 1,
    DEVNET: 2
  };
  ```
- **Usage Example:**
  ```javascript
  let mode = NetworkMode.MAINNET;
  ```

### **2. `PastelIDType`**

An enumeration representing different types of PastelIDs.

- **Values:**
  ```javascript
  const PastelIDType = {
    PASTELID: 0,
    LEGROAST: 1
  };
  ```
- **Usage Example:**
  ```javascript
  let type = PastelIDType.PASTELID;
  ```

---

## **Additional Data Structures**

### **1. `sendto_address`**

A structure representing a recipient address and the amount to send.

- **Definition Example:**
  ```javascript
  const sendto_address = [
    { "address": "recipient_address_1", "amount": 100 },
    { "address": "recipient_address_2", "amount": 50 }
  ];
  ```

### **2. `utxo`**

A structure representing an unspent transaction output.

- **Definition Example:**
  ```javascript
  const utxo = [
    {
      "address": "your_address",
      "txid": "txid1",
      "outputIndex": 0,
      "script": "script1",
      "patoshis": 200000000,
      "height": 76270
    },
    // Add more UTXOs as needed
  ];
  ```

---

## **Example Usage Scenarios**

### **A. Creating and Managing a Wallet**

```javascript
// Define Enumerations
const NetworkMode = { MAINNET: 0, TESTNET: 1, DEVNET: 2 };
const PastelIDType = { PASTELID: 0, LEGROAST: 1 };

// Create a new wallet
let mnemonic = pastelInstance.CreateNewWallet("securepassword");
console.log("Mnemonic:", mnemonic);

// Unlock the wallet
let unlocked = pastelInstance.UnlockWallet("securepassword");
console.log("Wallet Unlocked:", unlocked);

// Generate a new address
let newAddress = pastelInstance.MakeNewAddress(NetworkMode.MAINNET);
console.log("New Address:", newAddress);

// Export the wallet
let walletData = pastelInstance.ExportWallet();
console.log("Exported Wallet Data:", walletData);

// Lock the wallet
let locked = pastelInstance.LockWallet();
console.log("Wallet Locked:", locked);
```

---

### **B. Importing an Existing Wallet and Restoring Addresses**

```javascript
// Import wallet data
let importSuccess = pastelInstance.ImportWallet(walletData);
console.log("Wallet Import Successful:", importSuccess);

// Unlock the wallet
let unlocked = pastelInstance.UnlockWallet("securepassword");
console.log("Wallet Unlocked:", unlocked);

// Retrieve all addresses
let addresses = pastelInstance.GetAddresses(NetworkMode.MAINNET);
console.log("Wallet Addresses:", addresses);

// Get the count of addresses
let addressCount = pastelInstance.GetAddressesCount();
console.log("Total Addresses:", addressCount);
```

---

### **C. Creating and Registering a PastelID**

```javascript
// Create a new PastelID
let pastelID = pastelInstance.MakeNewPastelID(true);
console.log("New PastelID:", pastelID);

// Export PastelID keys
let exportSuccess = pastelInstance.ImportPastelIDKeys(pastelID, "exportPassword", "/path/to/export");
console.log("Export PastelID Keys Successful:", exportSuccess);

// Sign data with PastelID
let signatureResult = pastelInstance.SignWithPastelID(pastelID, "test message", PastelIDType.PASTELID, true);
let parsedSignature = JSON.parse(signatureResult);
let signature = parsedSignature.data;
console.log("Signature:", signature);

// Verify the signature with PastelID
let isValid = pastelInstance.VerifyWithPastelID(pastelID, "test message", signature, true);
console.log("Is Signature Valid?", isValid);

// Sign data with LegRoast
let legRoastSignatureResult = pastelInstance.SignWithPastelID(pastelID, "test message", PastelIDType.LEGROAST, true);
let parsedLegRoastSignature = JSON.parse(legRoastSignatureResult);
let legRoastSignature = parsedLegRoastSignature.data;
console.log("LegRoast Signature:", legRoastSignature.substring(0, 50) + "...");

// Verify the LegRoast signature
let isLegRoastValid = pastelInstance.VerifyWithPastelID(pastelID, "test message", legRoastSignature, true);
console.log("Is LegRoast Signature Valid?", isLegRoastValid);
```

---

### **D. Address Management**

```javascript
// Generate a new address in Mainnet and Devnet
let mainnetAddress = pastelInstance.MakeNewAddress(NetworkMode.MAINNET);
let devnetAddress = pastelInstance.MakeNewAddress(NetworkMode.DEVNET);
console.log("New Mainnet Address:", mainnetAddress);
console.log("New Devnet Address:", devnetAddress);

// Retrieve existing addresses by index
let retrievedMainnetAddress = pastelInstance.GetAddress(0, NetworkMode.MAINNET);
let retrievedDevnetAddress = pastelInstance.GetAddress(1, NetworkMode.DEVNET);
console.log("Retrieved Mainnet Address:", retrievedMainnetAddress);
console.log("Retrieved Devnet Address:", retrievedDevnetAddress);

// Import a legacy private key and retrieve its corresponding address
let legacyPrivateKey = "YourLegacyPrivateKey";
let importedAddress = pastelInstance.ImportLegacyPrivateKey(legacyPrivateKey, NetworkMode.MAINNET);
console.log("Imported Address from Legacy Private Key:", importedAddress);

// Retrieve the private key of an address
let secretKey = pastelInstance.GetAddressSecret(importedAddress, NetworkMode.MAINNET);
console.log("Private Key for Address", importedAddress, ":", secretKey);
```

---

### **E. Exporting and Importing Wallets**

```javascript
// Export the current wallet
let exportedWallet = pastelInstance.ExportWallet();
console.log("Exported Wallet Data:", exportedWallet);

// Import the wallet
try {
    pastelInstance.ImportWallet(exportedWallet);
    console.log("Wallet imported successfully.");
} catch (error) {
    console.error("Error importing wallet:", error);
}

// Unlock the imported wallet
try {
    pastelInstance.UnlockWallet("password");
    console.log("Imported wallet unlocked successfully.");
} catch (error) {
    console.error("Error unlocking imported wallet:", error);
}

// Lock the wallet
try {
    pastelInstance.LockWallet();
    console.log("Wallet locked successfully.");
} catch (error) {
    console.error("Error locking wallet:", error);
}
```

---

### **F. Transaction Creation and Management**

```javascript
// Define recipients and amounts
let sendToJSON = JSON.stringify([
    {
        "address": "44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg",
        "amount": 100
    },
    {
        "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
        "amount": 50
    }
]);

// Define UTXOs in JSON format
let utxoJSON = JSON.stringify([
    {
        "address": "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
        "txid": "4bd5ef071fc9b1acddd081c6f76cb32d0aed754784a27d746363733feac79fcc",
        "outputIndex": 0,
        "script": "76a91425ca0dc39e74770fa739e9ced36912f0251842b488ac",
        "patoshis": 200000000,
        "height": 76270
    }
]);

// Create a send transaction
let sendTransaction = pastelInstance.CreateSendToTransactionJson(
    NetworkMode.DEVNET,
    sendToJSON,
    "",
    utxoJSON,
    1000 // fee in patoshis
);
console.log("Send Transaction JSON:", sendTransaction);

// Register a PastelID with a transaction
let registerPastelIDTransaction = pastelInstance.CreateRegisterPastelIdTransactionJson(
    NetworkMode.DEVNET,
    pastelID,
    "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo",
    utxoJSON,
    1000 // fee in patoshis
);
console.log("Register PastelID Transaction JSON:", registerPastelIDTransaction);
```

---

### **G. Signing and Verifying Messages**

```javascript
// Initialize PastelSigner
let signer = new PastelSigner("/path/to/pastel_ids");

// Sign a message with PastelID
let message = "This is a secure message.";
let pastelID = "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw";
let signatureResult = pastelInstance.SignWithPastelID(pastelID, message, PastelIDType.PASTELID, true);
console.log("Signature Result:", signatureResult);

// Parse the signature result
let parsedSignature = JSON.parse(signatureResult);
let signature = parsedSignature.data;
console.log("Parsed Signature:", signature);

// Verify the signature
let isSignatureValid = pastelInstance.VerifyWithPastelID(pastelID, message, signature, true);
console.log("Is Signature Valid?", isSignatureValid);
```

---

### **H. Verifying External Signatures**

```javascript
// External signatures (abbreviated for brevity)
let externalEdSig = "gH+KRIkxlDkpb9KMvRQztuK1OAWrE+wnCpFPN3NNahv..."; // Truncated
let externalLRSig = "lLgN4387fcyvNeTtjl1wu3goDuuGlNuHFmgiLj9WdpaC87D..."; // Truncated

// Original PastelID and message
let pastelID = "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw";
let pubLegRoast = "jXaczRW4MgeiioV1DAte38aj6FK2dwL7ykEajmm6K7J1XQc5qcJfkJYD24pSt1MUAbPjfhDv1iSYrSsxAqp1Mb";
let message = "test";

// Verify external ED448 signature
let isEdValid = pastelInstance.VerifyWithPastelID(pastelID, message, externalEdSig.substring(0, 100) + "...", true);
console.log("ED448 Signature Valid:", isEdValid);

// Verify external LegRoast signature
let isLrValid = pastelInstance.VerifyWithLegRoast(pubLegRoast, message, externalLRSig.substring(0, 100) + "...", true);
console.log("LegRoast Signature Valid:", isLrValid);
```

---

### **I. Working with the PastelSigner Class**

```javascript
// Instantiate PastelSigner with the path to PastelID keys
let signer = new PastelSigner("/path/to/pastel_ids");

// Sign a message with PastelID
let signature = signer.SignWithPastelID("test message", "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw", "passphrase");
console.log("Signature:", signature);

// Verify the signature with PastelID
let isSignatureValid = signer.VerifyWithPastelID("test message", signature, "jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw");
console.log("Is signature valid?", isSignatureValid);

// Retrieve PastelID data
let pastelIDData = signer.GetPastelID("jXYZbUhjAu6VM84LtggkGV9TR9EFjYAcZbdXdyor5aT7tjPsy3ZkzcDLGmx1ZtoTJNXoAVv2CDkBzx8T94XNDw", PastelIDType.PASTELID);
console.log("PastelID Data:", pastelIDData);

// Verify a signature using LegRoast
let isLegRoastValid = signer.VerifyWithLegRoast(pubLegRoast, "test message", "externalLRSig...", true);
console.log("Is LegRoast Signature Valid?", isLegRoastValid);
```

---

### **J. External Wallet Integration**

```javascript
// Import an external wallet using its serialized string
let externalWalletStr = "54E4KZKgzqgBeWpdKPX5kz7ECfcXwS7xQkXgHbRvkCd5ehSwZwMgR4dXt5Zbxj2DegbB5MKpVHH19SgH4UH9PA4iUpCqmr75aH54oKkjpDi8JfvE1drd3PhM9hK1Dd29deebKjkuEP72KM7Rc4udJcuiAUQiqhmdh7Y8Pzrx7qsh2Hbkcnb8VpLZgUNGG6sMWzewZQ4HNHcG3XorG2RAGKMhWiHkdUv1KJtSoUGMGHSv4GdoJgG4s64ojcKsg4iVRZJfzFqsRwxiPDHGutXbxKaDSzNhsyx68ZujQUqVYhDSx3AyERRmoiJ95HYXE1WEUrf2NNCnHkJGRnPSvjAzJVgxd3FAQWtX1ZPGKLFA2WvDXgNTAx7RQf6nKEfDpjWwb32A6bhk3MCgEaVgRtUBZFvFzsuGtz3twMA6V8g98ZNLN37F8wvVDVi7";
let importExternalWalletSuccess = pastelInstance.ImportWallet(externalWalletStr);
console.log("Import External Wallet Successful:", importExternalWalletSuccess);

// Unlock the imported wallet with the correct password
pastelInstance.UnlockWallet("12341234");
console.log("External Wallet Unlocked.");

// Attempt to create new addresses in the unlocked external wallet
let newExternalAddresses = [
    pastelInstance.MakeNewAddress(NetworkMode.MAINNET),
    pastelInstance.MakeNewAddress(NetworkMode.MAINNET)
];
console.log("New Addresses in External Wallet:", newExternalAddresses);
```

---

### **K. End-to-End Example**

```javascript
// Initialize Pastel instance
let pastelInstance = new Pastel();

// 1. Create a new wallet
let mnemonic = pastelInstance.CreateNewWallet("password");
console.log("Mnemonic:", mnemonic);

// 2. Unlock the wallet
pastelInstance.UnlockWallet("password");
console.log("Wallet unlocked.");

// 3. Generate new addresses
let addresses = [
    pastelInstance.MakeNewAddress(NetworkMode.MAINNET),
    pastelInstance.MakeNewAddress(NetworkMode.MAINNET)
];
console.log("Generated Addresses:", addresses);

// 4. Create a new PastelID
let pastelID = pastelInstance.MakeNewPastelID(true);
console.log("New PastelID:", pastelID);

// 5. Export PastelID keys
let exportSuccess = pastelInstance.ImportPastelIDKeys(pastelID, "exportPassword", "/path/to/export");
console.log("Export PastelID Keys Successful:", exportSuccess);

// 6. Sign a message with PastelID
let signatureResult = pastelInstance.SignWithPastelID(pastelID, "Hello, Pastel!", PastelIDType.PASTELID, true);
let parsedSignature = JSON.parse(signatureResult);
let signature = parsedSignature.data;
console.log("Signature:", signature);

// 7. Verify the signature
let isValid = pastelInstance.VerifyWithPastelID(pastelID, "Hello, Pastel!", signature, true);
console.log("Is signature valid?", isValid);

// 8. Create a transaction to send funds
let sendTo = [
    { address: "44oKWEAmQCb3tcGmksPvhebT1JfPEVNre3fg", amount: 100 }
];
let utxos = [
    {
        address: addresses[0],
        txid: "4bd5ef07...fcc", // Truncated
        outputIndex: 0,
        script: "76a91425ca0dc39e74770fa739e9ced36912f0251842b488ac",
        patoshis: 200000000,
        height: 76263
    }
];
let transaction = pastelInstance.CreateSendToTransaction(NetworkMode.MAINNET, sendTo, "", utxos, 1000);
console.log("Send Transaction:", transaction);

// 9. Register the PastelID
let registerTx = pastelInstance.CreateRegisterPastelIdTransaction(NetworkMode.MAINNET, pastelID, addresses[0], utxos, 1000);
console.log("Register PastelID Transaction:", registerTx);

// 10. Verify external signatures (abbreviated)
let externalEdSig = "gH+KRIkxlDkpb9KMvRQztuK1OAWrE+wnCpFPN3NNahv..."; // Truncated
let externalLRSig = "lLgN4387fcyvNeTtjl1wu3goDuuGlNuHFmgiLj9WdpaC87D..."; // Truncated
let pubLegRoast = "jXaczRW4MgeiioV1DAte38aj6FK2dwL7ykEajmm6K7J1XQc5qcJfkJYD24pSt1MUAbPjfhDv1iSYrSsxAqp1Mb";
let message = "Hello, Pastel!";

// Verify external ED448 signature
let isEdValid = pastelInstance.VerifyWithPastelID(pastelID, message, externalEdSig.substring(0, 100) + "...", true);
console.log("External ED448 Signature Valid:", isEdValid);

// Verify external LegRoast signature
let isLrValid = pastelInstance.VerifyWithLegRoast(pubLegRoast, message, externalLRSig.substring(0, 100) + "...", true

);
console.log("External LegRoast Signature Valid:", isLrValid);
```

---

### **L. Error Handling and Validation**

```javascript
try {
    // Attempt to unlock the wallet with an incorrect password
    let unlockResult = pastelInstance.UnlockWallet("wrongPassword");
    if (!unlockResult) {
        throw new Error("Failed to unlock wallet: Incorrect password.");
    }
} catch (error) {
    console.error(error.message);
}

try {
    // Attempt to import an invalid wallet string
    let invalidWalletStr = "invalid_wallet_data";
    let importResult = pastelInstance.ImportWallet(invalidWalletStr);
    if (!importResult) {
        throw new Error("Failed to import wallet: Invalid wallet data.");
    }
} catch (error) {
    console.error(error.message);
}

try {
    // Verify a tampered signature
    let tamperedSignature = "tamperedSignature...";
    let isTamperedValid = pastelInstance.VerifyWithPastelID(pastelID, "Hello, Pastel!", tamperedSignature, true);
    if (!isTamperedValid) {
        console.warn("Warning: Tampered signature is invalid as expected.");
    }
} catch (error) {
    console.error("Error during signature verification:", error.message);
}
```

---

### **M. Additional Functionalities and Utilities**

```javascript
// Retrieve the total number of addresses in the wallet
let addressCount = pastelInstance.GetAddressesCount();
console.log("Total Addresses:", addressCount);

// Retrieve all wallet addresses
let allAddresses = pastelInstance.GetAddresses(NetworkMode.MAINNET);
console.log("All Addresses:", allAddresses);

// Retrieve all PastelIDs associated with the wallet
let allPastelIDs = pastelInstance.GetPastelIDs();
console.log("All PastelIDs:", allPastelIDs);

// Get the private key (secret) associated with a specific address
let specificAddress = "44oEMCAvFTNuHZrJvsG1xknpyHKA8owdMEKo";
let privateKey = pastelInstance.GetAddressSecret(specificAddress, NetworkMode.MAINNET);
console.log(`Private Key for ${specificAddress}:`, privateKey);
```
