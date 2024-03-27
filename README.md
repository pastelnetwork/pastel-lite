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

### 4. Install `zig`, if not already installed
#### Linux
``` bash
sudo snap install zig --classic --beta
```
#### Mac
``` bash
brew install zig
```
#### Windows
``` bash
choco install zig
```

### 5. Install 3rd party packages with `vcpkg` - for native build ONLY
``` bash
cd pastel-light
vcpkg install
```
`vcpkg` uses packages described in the `vcpkg.json`
Currently they are:
* `libsodium`
* `OpenSLL`

### 6. Build native library `libpastel` and test tool `pastel_lite` 
``` bash
mkdir build-native-debug
cd build-native-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build .
```
> Replace `<path-to-vcpkg>` with the path from step 2.

### 7. Build WebAssembly library `libpastel-wasm` 
``` bash
mkdir build-wasm-debug
cd build-wasm-debug
emcmake cmake .. -DCMAKE_BUILD_TYPE=Debug
emmake cmake --build .
```
