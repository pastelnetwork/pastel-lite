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
        .def("sign_with_pastel_id", &PastelSigner::SignWithPastelID)
        .def("sign_with_pastel_id_base64", &PastelSigner::SignWithPastelIDBase64)
        .def("verify_with_pastel_id", &PastelSigner::VerifyWithPastelID)
        .def("verify_with_pastel_id_base64", &PastelSigner::VerifyWithPastelIDBase64)
        .def("get_pastelid", &PastelSigner::GetPastelID);
    py::class_<PastelID>(m, "PastelID")
        .def(py::init<const std::string&, const std::string&, const std::string&>())
        .def("sign", &PastelID::Sign)
        .def("sign_base64", &PastelID::SignBase64)
        .def("verify", &PastelID::Verify)
        .def("verify_base64", &PastelID::VerifyBase64);
}
