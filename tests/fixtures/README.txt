OFFLINE REFERENCE FIXTURES

oracle_fixtures.json is the unchanged independently generated reference artifact.
SHA256: f428ed92fae66673fbc1fd368db612a3d7ecfaddfb35ab942aa5e465a0241561
It records 34 message configurations, every post-key window and an independently
enumerated 17,576-start-position search. See each record's provenance. Expected
values are stored; tests never generate them using the application under test.

The external generator used Py-Enigma 1.0.2, whose wheel SHA256 is
84e9bb019450d6b65d0bde2cba234190587378a064259d02ecf41aa41a508b07.
The application and this suite do not import the comparison package, need network
access or require files outside this repository. Acquisition and generation
records are retained separately; fixture provenance is recorded in each artifact.
Preserved Py-Enigma fixture/example attribution: PY_ENIGMA_LICENSE.txt.

The external-C-cross-check record also preserves a fixture from Ondoher/enigma.
Its MIT notice is retained in ONDOHER_ENIGMA_LICENSE.txt. These third-party notices
apply to their source material and do not license the entire application.
Source: https://raw.githubusercontent.com/Ondoher/enigma/main/LICENSE

published_cases.json is the unchanged historical reference snapshot, not a current
status report. Its old statements about unrun checks, missing reflector-C
evidence and unsupported rings describe the original prototype at the time.
The independent reference corpus and current regression results supersede those limitations.
Tests read its reference values only. Published vectors and derived mechanical
traces remain distinguished in its records and in test_reference.py.
SHA256: fe4316190fab61a66c6c564ccfc2c3cccd0bbbd9f02a19ab6fd3d88435a024e5

Software agreement is bounded by these configurations. These are not new
physical-machine measurements, exhaustive proof across all keys, or evidence
for variants outside the documented three-rotor I-V, wide-B/C subset.
