#include "fic/core/integrity/ContentDigest.h"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void testKnownVectors() {
    // Well-known SHA-256 vectors: an ownership fingerprint must be exactly
    // the standard hash of the exact bytes, otherwise a proof computed on two
    // different FIC versions would silently disagree.
    require(fic::core::ContentDigest::sha256Hex("") ==
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "empty string digest mismatch");
    require(fic::core::ContentDigest::sha256Hex("abc") ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "\"abc\" digest mismatch");
    require(fic::core::ContentDigest::sha256Hex("abcdbcdecdefdefgefghfghighijhi"
                                                "jkijkljklmklmnlmnomnopnopq") ==
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "two-block digest mismatch");
}

void testDeterministicAndDistinct() {
    const std::string first = fic::core::ContentDigest::sha256Hex("payload");
    const std::string second = fic::core::ContentDigest::sha256Hex("payload");
    require(first == second, "digest must be deterministic");
    require(first != fic::core::ContentDigest::sha256Hex("payload "),
            "a one-byte difference must change the digest");
    require(first != fic::core::ContentDigest::sha256Hex("payloae"),
            "a different payload must change the digest");
}

void testCanonicalShape() {
    const std::string digest = fic::core::ContentDigest::sha256Hex("x");
    require(digest.size() == 64, "digest must be 64 hex characters");
    require(fic::core::ContentDigest::isCanonicalSha256Hex(digest),
            "produced digest must be canonical");

    require(!fic::core::ContentDigest::isCanonicalSha256Hex(""),
            "empty digest must be rejected");
    require(!fic::core::ContentDigest::isCanonicalSha256Hex("abc"),
            "short digest must be rejected");
    std::string upper = digest;
    for (char& c : upper) {
        if (c >= 'a' && c <= 'f') {
            c = static_cast<char>(c - 'a' + 'A');
        }
    }
    require(!fic::core::ContentDigest::isCanonicalSha256Hex(upper),
            "uppercase hex must be rejected as non-canonical");
    require(!fic::core::ContentDigest::isCanonicalSha256Hex(
                digest.substr(0, 63) + "z"),
            "non-hex characters must be rejected");
}

} // namespace

int main() {
    try {
        testKnownVectors();
        testDeterministicAndDistinct();
        testCanonicalShape();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}