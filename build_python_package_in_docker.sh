#!/bin/bash
set -e

# Navigate to the python_bindings directory
cd /src/python_bindings

# Ensure pip and required packages are installed for Python 3
python3 -m ensurepip
python3 -m pip install --upgrade pip
python3 -m pip install wheel setuptools pybind11 twine auditwheel

# Check for required libraries
echo "Checking for required libraries..."
libraries=(
    "build-python-bindings/lib/libpastel.a"
    "build-python-bindings/libbotan-lib/lib/libbotan-3.a"
    "build-python-bindings/vcpkg_installed/x64-linux/lib/libsodium.a"
    "build-python-bindings/vcpkg_installed/x64-linux/lib/libzstd.a"
    "build-python-bindings/_deps/fmt-build/libfmtd.a"
    "build-python-bindings/_deps/libsecp256k1-build/src/libsecp256k1.a"
)

for lib in "${libraries[@]}"; do
    if [ -f "/src/$lib" ]; then
        echo "Found $lib"
    else
        echo "Warning: $lib not found"
    fi
done

# Set LD_LIBRARY_PATH to include all library locations
export LD_LIBRARY_PATH="/src/build-python-bindings/lib:/src/build-python-bindings/libbotan-lib/lib:/src/build-python-bindings/vcpkg_installed/x64-linux/lib:/src/build-python-bindings/_deps/fmt-build:/src/build-python-bindings/_deps/libsecp256k1-build/src:$LD_LIBRARY_PATH"

# Build the Python wheel
echo "Building Python wheel..."
python3 setup.py bdist_wheel BUILD_DIR_NAME=build-python-bindings -v 2>&1 | tee wheel_build.log

# Check if the wheel was built successfully
wheel_count=$(ls dist/*.whl 2>/dev/null | wc -l)
 if [ "$wheel_count" -eq 0 ]; then
     echo "Error: No wheel file found. Check wheel_build.log for details."
     exit 1
 elif [ "$wheel_count" -gt 1 ]; then
     echo "Warning: Multiple wheel files found. Using the first one."
 fi

 wheel_file=$(ls -r dist/*.whl 2>/dev/null | head -n 1)
 if [ -z "$wheel_file" ]; then
     echo "Error: Unable to determine wheel file. Check wheel_build.log for details."
     exit 1
 fi

 echo "Found wheel file: $wheel_file"

 # Check the dependencies of the built extension
 echo "Checking shared library dependencies:"
 find . -name "*.so" -exec ldd {} \; 2>&1 | tee ldd_output.log
+
 # Use auditwheel to check and repair the wheel
 echo "Checking wheel with auditwheel..."
 auditwheel show "$wheel_file" 2>&1 | tee auditwheel_show.log
 echo "Repairing wheel with auditwheel..."
 auditwheel repair "$wheel_file" 2>&1 | tee auditwheel_repair.log

echo "Build logs have been saved. Please check wheel_build.log, ldd_output.log, auditwheel_show.log, and auditwheel_repair.log for details."

if [ -d "wheelhouse" ]; then
    echo "Checking final wheel:"
    final_wheel_file=$(ls -r wheelhouse/*.whl 2>/dev/null | head -n 1)
    auditwheel show "$final_wheel_file" 2>&1 | tee final_wheel_check.log
else
    echo "Warning: No wheelhouse directory found. The wheel may not be manylinux compatible."
fi
