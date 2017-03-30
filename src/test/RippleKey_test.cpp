//------------------------------------------------------------------------------
/*
    This file is part of ripple-sign-serialize:
        https://github.com/ximinez/ripple-sign-serialize
    Copyright (c) 2017 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <RippleKey.h>
#include <Serialize.h>
#include <test/KnownTestData.h>
#include <test/KeyFileGuard.h>
#include <ripple/beast/unit_test.h>
#include <ripple/json/json_reader.h>
#include <ripple/protocol/JsonFields.h>

namespace serialize {

namespace test {

class RippleKey_test : public beast::unit_test::suite
{
private:
    const char* passphrase = "masterpassphrase";

    void
    testRandom(ripple::KeyType const kt)
    {
        using namespace ripple;

        testcase("Random key");
        RippleKey const key(kt);
        // Not much you can check with a random key
        BEAST_EXPECT(key.keyType() == kt);
        auto const pubkey = toBase58(TOKEN_ACCOUNT_PUBLIC, key.publicKey());
        BEAST_EXPECT(pubkey.length() == 52);
    }

    void
    testSeed(ripple::KeyType const kt)
    {
        using namespace ripple;

        testcase("Known seed");

        // Cases to check: string passphrase, string seed, and Seed
        auto const seed = generateSeed(passphrase);

        RippleKey const key(kt, seed);
        auto const pubkey = toBase58(TOKEN_ACCOUNT_PUBLIC, key.publicKey());
        BEAST_EXPECT(key.keyType() == kt);
        BEAST_EXPECT(pubkey == (kt == KeyType::secp256k1 ?
            "aBQG8RQAzjs1eTKFEAQXr2gS4utcDiEC9wmi7pfUPTi27VCahwgw" :
            "aKGheSBjmCsKJVuLNKRAKpZXT6wpk2FCuEZAXJupXgdAxX5THCqR"));

        auto const key2 = RippleKey::make_RippleKey(kt, passphrase);
        auto const key3 = RippleKey::make_RippleKey(kt, toBase58(seed));
        BEAST_EXPECT(key2.keyType() == kt);
        BEAST_EXPECT(key2.publicKey() == key.publicKey());
        BEAST_EXPECT(key3.keyType() == kt);
        BEAST_EXPECT(key3.publicKey() == key.publicKey());

    }

    void
    testFile(ripple::KeyType const kt)
    {
        using namespace boost::filesystem;

        auto const key = RippleKey::make_RippleKey(kt, passphrase);

        std::string const subdir = "test_key_file";
        KeyFileGuard g(*this, subdir);
        path const keyFile = subdir / ".ripple" / "secret-key.txt";

        // Try some failure cases before writing the file
        auto badFile = [&](const char* toWrite,
            std::string const& expectedException)
        {
            path const badKeyFile = subdir / "bad-key.txt";
            if(toWrite)
            {
                std::ofstream o(badKeyFile.string(), std::ios_base::trunc);
                if (BEAST_EXPECT(!o.fail()))
                {
                    o << toWrite;
                }
            }
            try
            {
                auto const keyBad = RippleKey::make_RippleKey(badKeyFile);
                fail();
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() ==
                    std::string{ expectedException +
                    badKeyFile.string() });
            }
        };
        // No file
        badFile(nullptr, "Failed to open key file: ");
        // Write some nonsense to the file
        badFile("{ seed = \"Hello, world\" }",
            "Unable to parse json key file: ");
        // Write valid but incomplete json to the file
        badFile(R"({ "ponies": ["sparkleberry"] })",
            "Field 'key_type' is missing from key file: ");
        // Write a valid seed with an invalid keytype
        badFile(R"({ "key_type": "sha1", "master_seed": "masterpassphrase" })",
            R"(Invalid 'key_type' field "sha1" found in key file: )");
        {
            // Write a file over keyFile's directory
            auto badPath = keyFile.parent_path();
            {
                std::ofstream o(badPath.string(),
                    std::ios_base::trunc);
            }
            try
            {
                key.writeToFile(keyFile);
                fail();
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() ==
                    "Cannot create directory: " + badPath.string());
            }
            remove(badPath);
            create_directories(keyFile);
            try
            {
                key.writeToFile(keyFile);
                fail();
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() ==
                    "Cannot open key file: " + keyFile.string());
            }
            remove_all(badPath);
        }

        key.writeToFile(keyFile);

        auto const key2 = RippleKey::make_RippleKey(keyFile);
        BEAST_EXPECT(key.keyType() == key2.keyType());
        BEAST_EXPECT(key.publicKey() == key2.publicKey());

        // Read the keyfile as a Json object to ensure it wrote
        // what we expected
        auto const jKeys = [&]
        {
            std::ifstream ifsKeys(keyFile.c_str(), std::ios::in);

            if (BEAST_EXPECT(ifsKeys))
            {

                Json::Reader reader;
                Json::Value jKeys;
                BEAST_EXPECT(reader.parse(ifsKeys, jKeys));
                return jKeys;
            }
            return Json::Value{};
        }();

        using namespace ripple;
        auto const seed = generateSeed(passphrase);
        auto const secretKey = generateKeyPair(kt, seed).second;

        // Make sure there are no extra fields
        BEAST_EXPECT(jKeys.size() == 9);
        BEAST_EXPECT(jKeys[jss::account_id] ==
            toBase58(calcAccountID(key.publicKey())));
        BEAST_EXPECT(jKeys[jss::key_type] == to_string(kt));
        BEAST_EXPECT(jKeys[jss::master_key] == seedAs1751(seed));
        BEAST_EXPECT(jKeys[jss::master_seed] == toBase58(seed));
        BEAST_EXPECT(jKeys[jss::master_seed_hex] ==
            strHex(seed.data(), seed.size()));
        BEAST_EXPECT(jKeys[jss::public_key] ==
            toBase58(TOKEN_ACCOUNT_PUBLIC, key.publicKey()));
        BEAST_EXPECT(jKeys[jss::public_key_hex] ==
            strHex(key.publicKey().data(), key.publicKey().size()));
        BEAST_EXPECT(jKeys["secret_key"] ==
            toBase58(TOKEN_ACCOUNT_SECRET, secretKey));
        BEAST_EXPECT(jKeys["secret_key_hex"] ==
            strHex(secretKey.data(), secretKey.size()));
    }

    void
    testSign(ripple::KeyType const kt)
    {
        using namespace serialize;
        using namespace ripple;

        auto const key = RippleKey::make_RippleKey(kt, passphrase);

        auto obj = deserialize(getKnownTx().SerializedText);

        BEAST_EXPECT(obj);
        ripple::STTx tx{ std::move(*obj) };
        // The hard-coded version is signed
        auto check = tx.checkSign(true);
        BEAST_EXPECT(check.first);

        // Remove the signature
        auto const origSignature = tx.getFieldVL(sfTxnSignature);
        auto const origSigningKey = tx.getFieldVL(sfSigningPubKey);
        tx.makeFieldAbsent(sfTxnSignature);
        check = tx.checkSign(true);
        BEAST_EXPECT(!check.first);
        BEAST_EXPECT(check.second == "Invalid signature.");

        // Now sign it with the test key
        key.singleSign(tx);
        BEAST_EXPECT(tx.checkSign(true).first);
        // Different signature
        BEAST_EXPECT(tx.getFieldVL(sfTxnSignature) != origSignature);
        BEAST_EXPECT(tx.getFieldVL(sfSigningPubKey) != origSigningKey);
        BEAST_EXPECT(!tx.isFieldPresent(sfSigners));

        // Now multisign it with the test key
        key.multiSign(tx);
        BEAST_EXPECT(tx.checkSign(true).first);
        // No single signature
        BEAST_EXPECT(!tx.isFieldPresent(sfTxnSignature));
        BEAST_EXPECT(tx.getFieldVL(sfSigningPubKey).empty());
        if(BEAST_EXPECT(tx.isFieldPresent(sfSigners)))
        {
            auto signers = tx.getFieldArray(sfSigners);
            BEAST_EXPECT(signers.size() == 1);
        }

        // Sign with another key
        auto const key2 = RippleKey::make_RippleKey(kt, "bob");
        key2.multiSign(tx);
        BEAST_EXPECT(tx.checkSign(true).first);
        // No single signature
        BEAST_EXPECT(!tx.isFieldPresent(sfTxnSignature));
        BEAST_EXPECT(tx.getFieldVL(sfSigningPubKey).empty());
        if (BEAST_EXPECT(tx.isFieldPresent(sfSigners)))
        {
            auto signers = tx.getFieldArray(sfSigners);
            BEAST_EXPECT(signers.size() == 2);
            BEAST_EXPECT(signers[0].getAccountID(sfAccount) <
                signers[1].getAccountID(sfAccount));
        }

    }

public:
    void
    run() override
    {
        using namespace ripple;

        std::array<KeyType, 2> constexpr keyTypes{ {
                KeyType::ed25519,
                KeyType::secp256k1 } };

        for (auto const& kt : keyTypes)
        {
            testRandom(kt);
            testSeed(kt);
            testFile(kt);
            testSign(kt);
        }
    }
};

BEAST_DEFINE_TESTSUITE(RippleKey, keys, serialize);

} // test

} // serialize
