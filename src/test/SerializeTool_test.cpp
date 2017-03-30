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

#include <SerializeTool.h>
#include <RippleKey.h>
#include <Serialize.h>
#include <test/KnownTestData.h>
#include <test/KeyFileGuard.h>
#include <ripple/beast/unit_test.h>
#include <ripple/protocol/SecretKey.h>
#include <boost/format.hpp>

namespace serialize {

namespace test {

class SerializeTool_test : public beast::unit_test::suite
{
private:

    // Allow cout to be redirected.  Destructor restores old cout streambuf.
    class CoutRedirect
    {
    public:
        CoutRedirect(std::stringstream& sStream)
            : old_(std::cout.rdbuf(sStream.rdbuf()))
        {
        }

        ~CoutRedirect()
        {
            std::cout.rdbuf(old_);
        }

    private:
        std::streambuf* const old_;
    };

    class CInRedirect
    {
    public:
        CInRedirect(std::stringstream& sStream)
            : old_(std::cin.rdbuf(sStream.rdbuf()))
        {
        }

        ~CInRedirect()
        {
            std::cin.rdbuf(old_);
        }

    private:
        std::streambuf* const old_;
    };

    void
    testSerialize()
    {
        testcase("Serialize");

        auto test = [&](TestItem const& testItem)
        {
            {
                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                doSerialize(testItem.JsonText);

                BEAST_EXPECT(capture.str() == testItem.SerializedText + "\n");
            }
            {
                std::stringstream jsoninput(testItem.JsonText);
                CInRedirect cinRedirect{ jsoninput };

                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                runCommand("serialize", {}, {});

                BEAST_EXPECT(capture.str() == testItem.SerializedText + "\n");
            }
        };

        test(getKnownTx());
        test(getKnownMetadata());
        //test(getKnownLedger());
        {
            std::stringstream capture;
            CoutRedirect coutRedirect{ capture };

            // Send it nonsense
            doSerialize("Hello, world!");

            BEAST_EXPECT(capture.str() ==
                "Unable to serialize \"Hello, world!\"\n");
        };

    }

    void
    testDeserialize()
    {
        testcase("Deserialize");

        auto test = [&](TestItem const& testItem,
            std::function<std::string(std::string)> modifySerialized = nullptr,
            std::function<void(Json::Value&)> modifyKnownJson = nullptr)
        {
            {
                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                try
                {
                    doDeserialize(modifySerialized ?
                        modifySerialized(testItem.SerializedText) :
                        testItem.SerializedText);
                }
                catch (...)
                {
                    fail();
                }

                auto captured = parseJson(capture.str());
                auto known = parseJson(testItem.JsonText);
                if (modifyKnownJson)
                    modifyKnownJson(known);
                BEAST_EXPECT(captured == known);
            }
            {
                std::stringstream serinput(modifySerialized ?
                    modifySerialized(testItem.SerializedText) :
                    testItem.SerializedText);
                CInRedirect cinRedirect{ serinput };

                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                runCommand("deserialize", {}, {});

                auto captured = parseJson(capture.str());
                auto known = parseJson(testItem.JsonText);
                if (modifyKnownJson)
                    modifyKnownJson(known);
                BEAST_EXPECT(captured == known);
            }
        };
        test(getKnownTx(),
            [](auto serialized)
            {
                // include some extra whitespace, since deserialization
                // is sensitive to that.
                return "  " + serialized + "\n\n";
            },
            [](auto& known)
            {
                // The hash field is STTx-specific (and computed),
                // so it won't be in the generic output.
                known.removeMember("hash");
            });
        test(getKnownMetadata());
        //test(getKnownLedger());
        {
            std::stringstream capture;
            CoutRedirect coutRedirect{ capture };

            // Send it nonsense
            doDeserialize("Hello, world!");

            BEAST_EXPECT(capture.str() ==
                "Unable to deserialize \"Hello, world!\"\n");
        }
    }

    void
    testSingleSign()
    {
        testcase("Single Sign");

        using namespace boost::filesystem;

        std::string const subdir = "test_key_file";
        KeyFileGuard g(*this, subdir);
        path const keyFile = subdir / ".ripple" / "secret-key.txt";

        {
            RippleKey key;
            key.writeToFile(keyFile);
        }

        auto const& knownTx = getKnownTx();
        auto const origTx = serialize::deserialize(knownTx.SerializedText);

        auto test = [&](std::string const& testData)
        {
            using namespace ripple;
            {
                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                try
                {
                    doSingleSign(testData, keyFile);
                }
                catch (...)
                {
                    fail();
                }

                auto const tx = make_sttx(capture.str());
                if (BEAST_EXPECT(tx))
                {
                    BEAST_EXPECT(tx->checkSign(true).first);
                    BEAST_EXPECT((*tx)[sfSigningPubKey] !=
                        (*origTx)[sfSigningPubKey]);
                    BEAST_EXPECT((*tx)[sfTxnSignature] !=
                        (*origTx)[sfTxnSignature]);
                    BEAST_EXPECT(!tx->isFieldPresent(sfSigners));
                }
            }
            {
                std::stringstream serinput(testData);
                CInRedirect cinRedirect{ serinput };

                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                runCommand("sign", {}, keyFile);

                auto const tx = make_sttx(capture.str());
                if (BEAST_EXPECT(tx))
                {
                    BEAST_EXPECT(tx->checkSign(true).first);
                    BEAST_EXPECT((*tx)[sfSigningPubKey] !=
                        (*origTx)[sfSigningPubKey]);
                    BEAST_EXPECT((*tx)[sfTxnSignature] !=
                        (*origTx)[sfTxnSignature]);
                    BEAST_EXPECT(!tx->isFieldPresent(sfSigners));
                }
            }
        };
        test(knownTx.SerializedText);
        test(knownTx.JsonText);
        {
            std::stringstream capture;
            CoutRedirect coutRedirect{ capture };

            // Send it nonsense
            doSingleSign("Hello, world!", keyFile);

            BEAST_EXPECT(capture.str() ==
                "Unable to sign \"Hello, world!\"\n");
        }
    }

    void
    testMultiSign()
    {
        testcase("Multi Sign");

        using namespace boost::filesystem;

        std::string const subdir = "test_key_file";
        KeyFileGuard g(*this, subdir);
        path const keyFile = subdir / ".ripple" / "secret-key.txt";

        {
            RippleKey key;
            key.writeToFile(keyFile);
        }

        auto const& knownTx = getKnownTx();
        auto const origTx = serialize::deserialize(knownTx.SerializedText);

        auto test = [&](std::string const& testData)
        {
            using namespace ripple;
            {
                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                try
                {
                    doMultiSign(testData, keyFile);
                }
                catch (...)
                {
                    fail();
                }

                auto const tx = make_sttx(capture.str());
                if (BEAST_EXPECT(tx))
                {
                    BEAST_EXPECT(tx->checkSign(true).first);
                    BEAST_EXPECT(tx->isFieldPresent(sfSigningPubKey));
                    BEAST_EXPECT((*tx)[sfSigningPubKey].empty());
                    BEAST_EXPECT(!tx->isFieldPresent(sfTxnSignature));
                    BEAST_EXPECT(tx->isFieldPresent(sfSigners));
                }
            }
            {
                std::stringstream serinput(testData);
                CInRedirect cinRedirect{ serinput };

                std::stringstream capture;
                CoutRedirect coutRedirect{ capture };

                runCommand("multiSign", {}, keyFile);

                auto const tx = make_sttx(capture.str());
                if (BEAST_EXPECT(tx))
                {
                    BEAST_EXPECT(tx->checkSign(true).first);
                    BEAST_EXPECT(tx->isFieldPresent(sfSigningPubKey));
                    BEAST_EXPECT((*tx)[sfSigningPubKey].empty());
                    BEAST_EXPECT(!tx->isFieldPresent(sfTxnSignature));
                    BEAST_EXPECT(tx->isFieldPresent(sfSigners));
                }
            }
        };
        test(knownTx.SerializedText);
        test(knownTx.JsonText);
        {
            std::stringstream capture;
            CoutRedirect coutRedirect{ capture };

            // Send it nonsense
            doMultiSign("Hello, world!", keyFile);

            BEAST_EXPECT(capture.str() ==
                "Unable to sign \"Hello, world!\"\n");
        }
    }

    void testCreateKeyfile()
    {
        testcase("Create keyfile");

        using namespace boost::filesystem;
        using namespace ripple;

        std::string const subdir = "test_key_file";
        KeyFileGuard g(*this, subdir);
        path const keyFile = subdir / ".ripple" / "secret-key.txt";

        auto test = [&](std::string const kt,
            boost::optional<std::string> const seed)
        {
            std::stringstream capture;
            CoutRedirect coutRedirect{ capture };

            doCreateKeyfile(keyFile, kt, seed);

            auto key = RippleKey::make_RippleKey(keyFile);

            auto known = boost::str(
                boost::format("New ripple key created.\n"
                "Stored in %s.\n"
                "Key type is %s.\n"
                "Account ID is %s.\n"
                "\n\nThis file should be stored securely and not shared.\n\n")
                % keyFile.string()
                % to_string(key.keyType())
                % toBase58(calcAccountID(key.publicKey())));

            // Test that the function will not overwrite
            try
            {
                doCreateKeyfile(keyFile, {}, {});
                fail();
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() ==
                    std::string{ "Refusing to overwrite existing key file: " +
                    keyFile.string()});
            }

            remove(keyFile);

            BEAST_EXPECT(capture.str() == known);
        };

        test("", boost::none);
        test("", std::string{ "masterpassphrase" });
        test(to_string(KeyType::ed25519), boost::none);
        test(to_string(KeyType::secp256k1), std::string{ "alice" });

        // edge cases
        {
            // invalid keytype
            std::stringstream capture;
            CoutRedirect coutRedirect{ capture };

            doCreateKeyfile(keyFile, "NSA special", boost::none);

            BEAST_EXPECT(!exists(keyFile));

            auto known = "Invalid key type: \"NSA special\"\n";

            BEAST_EXPECT(capture.str() == known);
        }
        {
            // empty seed
            try
            {
                doCreateKeyfile(keyFile, "ed25519", std::string{ "" });
                fail();
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() ==
                    std::string{ "Unable to parse seed: " });
            }

            BEAST_EXPECT(!exists(keyFile));
        }
    }

    void testRepairKeyfile()
    {
        testcase("Repair keyfile");

        using namespace boost::filesystem;
        using namespace ripple;

        std::string const subdir = "test_key_file";
        KeyFileGuard g(*this, subdir);
        path const keyFile = subdir / ".ripple" / "secret-key.txt";

        {
            std::stringstream capture;
            CoutRedirect coutRedirect{ capture };
            doCreateKeyfile(keyFile, {}, {});
        }

        // Not much to test directly here.
        std::stringstream capture;
        CoutRedirect coutRedirect{ capture };
        doRepairKeyfile(keyFile);

        auto backup = keyFile;
        backup += ".bak.0";
        BEAST_EXPECT(exists(backup));

        auto key = RippleKey::make_RippleKey(keyFile);

        auto known = boost::str(
            boost::format("Ripple key in %s repaired.\n"
                "Key type is %s.\n"
                "Account ID is %s.\n"
                "\n\nThis file should be stored securely and not shared.\n\n")
            % keyFile.string()
            % to_string(key.keyType())
            % toBase58(calcAccountID(key.publicKey())));

        BEAST_EXPECT(capture.str() == known);
    }

    void
    testRunCommand ()
    {
        testcase ("Run Command");

        std::stringstream capture;
        CoutRedirect coutRedirect{ capture };

        using namespace boost::filesystem;

        std::string const subdir = "test_key_file";
        KeyFileGuard g(*this, subdir);
        path const keyFile = subdir / ".ripple" / "secret-key.txt";

        auto testCommand = [this](
            std::string const& command,
            std::vector <std::string> const& args,
            path const& keyFile,
            std::string const& expectedError)
        {
            try
            {
                runCommand(command, args, keyFile);
                BEAST_EXPECT(expectedError.empty());
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() == expectedError);
            }
        };

        std::stringstream emptyinput;
        CInRedirect cinRedirect{ emptyinput };

        std::vector <std::string> const noArgs;
        std::vector <std::string> const oneArg = { "some data" };
        std::vector <std::string> const twoArgs = { "data", "more data" };
        std::vector <std::string> const threeArgs = { "one", "two", "five" };
        std::string const noError = "";
        std::string const argError = "Syntax error: Wrong number of arguments";
        {
            std::string const command = "unknown";
            std::string const expectedError = "Unknown command: " + command;
            testCommand(command, noArgs, keyFile, expectedError);
            testCommand(command, oneArg, keyFile, expectedError);
            testCommand(command, twoArgs, keyFile, expectedError);
            testCommand(command, threeArgs, keyFile, expectedError);
        }
        {
            std::string const command = "serialize";
            testCommand(command, noArgs, keyFile, noError);
            testCommand(command, oneArg, keyFile, noError);
            testCommand(command, twoArgs, keyFile, argError);
            testCommand(command, threeArgs, keyFile, argError);
        }
        {
            std::string const command = "deserialize";
            testCommand(command, noArgs, keyFile, noError);
            testCommand(command, oneArg, keyFile, noError);
            testCommand(command, twoArgs, keyFile, argError);
            testCommand(command, threeArgs, keyFile, argError);
        }
        {
            std::string const command = "sign";
            testCommand(command, noArgs, keyFile, noError);
            testCommand(command, oneArg, keyFile, noError);
            testCommand(command, twoArgs, keyFile, argError);
            testCommand(command, threeArgs, keyFile, argError);
        }
        {
            std::string const command = "multiSign";
            testCommand(command, noArgs, keyFile, noError);
            testCommand(command, oneArg, keyFile, noError);
            testCommand(command, twoArgs, keyFile, argError);
            testCommand(command, threeArgs, keyFile, argError);
        }
        {
            std::string const command = "create_keyfile";
            testCommand(command, noArgs, keyFile, noError);
            remove(keyFile);
            testCommand(command, oneArg, keyFile, noError);
            remove(keyFile);
            testCommand(command, twoArgs, keyFile, noError);
            remove(keyFile);
            testCommand(command, threeArgs, keyFile, argError);
        }
        {
            doCreateKeyfile(keyFile, {}, {});
            std::string const command = "repair_keyfile";
            testCommand(command, noArgs, keyFile, noError);
            testCommand(command, oneArg, keyFile, argError);
            testCommand(command, twoArgs, keyFile, argError);
            testCommand(command, threeArgs, keyFile, argError);
        }
    }

public:
    void
    run() override
    {
        BEAST_EXPECT(!getVersionString().empty());

        testSerialize();
        testDeserialize();
        testSingleSign();
        testMultiSign();
        testCreateKeyfile();
        testRepairKeyfile();
        testRunCommand ();
    }
};

BEAST_DEFINE_TESTSUITE(SerializeTool, keys, serialize);

} // test

} // serialize
