from setuptools import setup, Extension
import sys
import os
import sysconfig
import pybind11
from distutils.command.build_ext import build_ext
import distutils.sysconfig

print(sys.argv)

build_dir_name = None
for arg in sys.argv:
    if arg.startswith('BUILD_DIR_NAME='):
        build_dir_name = arg.split('=')[1]
        sys.argv.remove(arg)
        break

# Paths inside the Docker container
SRC_DIR = os.path.dirname(os.getcwd())
LIB_DIR = os.path.join(SRC_DIR, "lib")
INCLUDE_DIR = os.path.join(LIB_DIR, "include")
BUILD_DIR = os.path.join(SRC_DIR, build_dir_name)

# Get Python include path
python_include = sysconfig.get_path('include')

ext_modules = [
    Extension(
        "libpastelid",
        ["pybind_wrapper.cpp"],
        include_dirs=[
            INCLUDE_DIR,
            pybind11.get_include(),
            pybind11.get_include(user=True),
            os.path.join(BUILD_DIR, "libbotan-lib/include/botan-3"),        # botan-3
            os.path.join(BUILD_DIR, "vcpkg_installed/x64-linux/include"),   # sodium, zstd
            os.path.join(BUILD_DIR, "_deps/libsecp256k1-src/include"),      # secp256k1
            os.path.join(BUILD_DIR, "_deps/fmt-src/include"),               # fmt
            python_include,
        ],
        library_dirs=[
            os.path.join(BUILD_DIR, "lib"),
            os.path.join(BUILD_DIR, "libbotan-lib", "lib"),                 # libbotan-3.so
            os.path.join(BUILD_DIR, "vcpkg_installed", "x64-linux", "lib"), # libsodium.so, libzstd.so
            os.path.join(BUILD_DIR, "_deps", "fmt-build"),                  # libfmt.a
            os.path.join(BUILD_DIR, "_deps", "libsecp256k1-build", "src"),  # libsecp256k1.a
        ],
        libraries=["zstd", "secp256k1", "pastel"],
        language="c++",
        extra_compile_args=["-std=c++20"],
        extra_link_args=[
            "-Wl,-rpath,../"
            "-Wl,--whole-archive",
            "-lsodium",
            "-lbotan-3",
            "-lfmtd",
            "-Wl,--no-whole-archive",
        ],
    ),
]

setup(
    name="libpastelid",
    version="0.3",
    description="Python bindings for the libpastelid C++ library - PastelID signer/verifier",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author_email="alexey@pastel.network",
    ext_modules=ext_modules,
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.9",
)

