# Building and Installing the `libpastelid` Python Package

This guide outlines the steps to build and install the `libpastelid` Python package.

## Prerequisites

Ensure you have the following dependencies installed on your Ubuntu system:

1. **Install Python 3 and pip**:
   ```shell
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip
   ```

2. **Install Development Tools and Libraries**:
   ```shell
   sudo apt-get install -y python3-dev build-essential cmake
   ```

3. **Install Required Python Packages**:
   Install the required Python packages listed in `Requirements.txt`:
   ```shell
   pip install -r Requirements.txt
   ```

## Building the Package

### 1. Build the C++ libraries - See top level README

The CMake that builds libraries will also generate the `setup.py` file from `setup.py.in`.

### 2. Build the Wheel

Navigate to the generated `setup.py` file and build the wheel:
```
cd python_bindings
python setup.py bdist_wheel
```

### 3. Install the Package

After building the wheel, you can install the package manually:
```
pip install dist/libpastelid-0.1-cp36-cp36m-linux_x86_64.whl
```

## Summary

1. Install the necessary system and Python dependencies.
2. Use CMake to generate the `setup.py` file.
3. Build the wheel using `python setup.py bdist_wheel`.
4. Install the generated wheel using `pip install`.

