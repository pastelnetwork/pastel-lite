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




sudo add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"
sudo add-apt-repository "deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"
sudo apt-get install libllvm-18-ocaml-dev libllvm18 llvm-18 llvm-18-dev llvm-18-doc llvm-18-examples llvm-18-runtime
sudo apt-get install libc++-18-dev libc++abi-18-dev
sudo apt-get install clang-18 clang-tools-18 clang-18-doc libclang-common-18-dev libclang-18-dev libclang1-18 clang-format-18 python3-clang-18 clangd-18 clang-tidy-18