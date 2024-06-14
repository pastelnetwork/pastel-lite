// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <libpastel.h>

namespace py = pybind11;

PYBIND11_MODULE(libpastelid, m) {
    py::class_<PastelSigner>(m, "PastelSigner")
        .def(py::init<const std::string&>())
//        .def("SignWithPastelID",
//             py::overload_cast<const std::vector<uint8_t>&, const std::string&, const SecureString&>(&PastelSigner::SignWithPastelID))
//        .def("SignWithPastelID",
//             py::overload_cast<const std::string&, const std::string&, const SecureString&>(&PastelSigner::SignWithPastelID))
        .def("SignWithPastelID", &PastelSigner::SignWithPastelID)
        .def("SignWithPastelIDBase64", &PastelSigner::SignWithPastelIDBase64)
        .def("VerifyWithPastelID", &PastelSigner::VerifyWithPastelID)
        .def("VerifyWithPastelIDBase64", &PastelSigner::VerifyWithPastelIDBase64);
}
