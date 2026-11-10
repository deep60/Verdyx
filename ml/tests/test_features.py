import numpy as np
from sklearn.feature_extraction import FeatureHasher

from conftest import build_pe
from verdyx_ml import pe_features as pf


def test_every_feature_has_a_name():
    infos = pf.feature_infos()
    assert len(infos) == pf.FEATURE_DIM == pf.extractor().dim
    assert [i.index for i in infos] == list(range(pf.FEATURE_DIM))


def test_names_line_up_with_thrember_categorical_columns():
    # thrember's train_model marks these as categorical; our names must agree.
    infos = pf.feature_infos()
    names = [infos[i].name for i in pf.CATEGORICAL_FEATURES]
    assert names == [
        "is a parsable PE", "start byte 0", "start byte 1", "start byte 2", "start byte 3",
        "machine type", "subsystem",
    ]


def test_group_slices_cover_the_vector():
    slices = pf.group_slices()
    covered = sorted((s.start, s.stop) for s in slices.values())
    assert covered[0][0] == 0 and covered[-1][1] == pf.FEATURE_DIM
    assert all(a[1] == b[0] for a, b in zip(covered, covered[1:]))
    for info in pf.feature_infos():
        assert slices[info.group].start <= info.index < slices[info.group].stop


def test_extract_parses_a_real_pe():
    ext = pf.extract(build_pe(b".text", b"\xc3" * 64))
    assert ext.is_pe
    assert ext.vector.shape == (pf.FEATURE_DIM,)
    assert ext.vector.dtype == np.float32
    infos = pf.feature_infos()
    by_name = {i.name: i.index for i in infos if i.group == "section"}
    assert ext.vector[by_name["number of sections"]] == 1


def test_non_pe_is_not_applicable():
    ext = pf.extract(b"%PDF-1.7 not a program at all")
    assert not ext.is_pe


def test_bucket_tokens_match_sklearn_feature_hasher():
    raw = {
        "imports": {
            "KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "ADVAPI32.dll": ["RegSetValueExA"],
        }
    }
    infos = pf.feature_infos()
    funcs = [i for i in infos if i.hashed and i.hashed[0] == "import_function"]
    tokens = [lib.lower() + ":" + f for lib, fs in raw["imports"].items() for f in fs]
    hashed = FeatureHasher(1024, input_type="string", alternate_sign=False).transform([tokens]).toarray()[0]
    for b in np.nonzero(hashed)[0]:
        info = funcs[b]
        assert pf.bucket_tokens(raw, info), f"bucket {b} should name a token"
    # Every token is attributed to exactly the bucket sklearn put it in.
    for tok in tokens:
        b = int(np.nonzero(FeatureHasher(1024, input_type="string", alternate_sign=False).transform([[tok]]).toarray()[0])[0][0])
        assert tok in pf.bucket_tokens(raw, funcs[b], limit=10)


def test_vectorize_raw_matches_extract():
    data = build_pe(b"UPX0", bytes(range(256)) * 8)
    ext = pf.extract(data)
    assert np.array_equal(pf.vectorize_raw(ext.raw), ext.vector)
