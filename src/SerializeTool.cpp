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
#include <ripple/beast/core/SemanticVersion.h>
#include <ripple/beast/unit_test.h>
#include <beast/unit_test/dstream.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>

//------------------------------------------------------------------------------
char const* const versionString =

    //--------------------------------------------------------------------------
    //  The build version number. You must edit this for each release
    //  and follow the format described at http://semver.org/
    //
        "0.1.0"

#if defined(DEBUG) || defined(SANITIZER)
       "+"
#ifdef DEBUG
        "DEBUG"
#ifdef SANITIZER
        "."
#endif
#endif

#ifdef SANITIZER
        BEAST_PP_STR1_(SANITIZER)
#endif
#endif

    //--------------------------------------------------------------------------
    ;

static
int
runUnitTests ()
{
    using namespace beast::unit_test;
    beast::unit_test::dstream dout{std::cout};
    reporter r{dout};
    bool const anyFailed = r.run_each(global_suites());
    if(anyFailed)
        return EXIT_FAILURE;    //LCOV_EXCL_LINE
    return EXIT_SUCCESS;
}

void
doSerialize(std::string const& data)
{
    auto tx = [&]
    {
        auto json = serialize::parseJson(data);
        return json ? serialize::makeObject(json) : boost::none;
    }();
    if (!tx)
    {
        std::cout << "Unable to serialize \"" << data << "\"" <<
            std::endl;
        return;
    }

    auto result = serialize::serialize(*tx);

    std::cout << result << std::endl;
}

void
doDeserialize(std::string const& data)
{
    auto result = serialize::deserialize(boost::trim_copy(data));

    if (result)
        std::cout << result->getJson(0).toStyledString() << std::endl;
    else
        std::cout << "Unable to deserialize \"" << data << "\"" <<
            std::endl;
}

void
doSingleSign(std::string const& data,
    boost::filesystem::path const& keyFile)
{
    using namespace serialize;
    auto tx = make_sttx(boost::trim_copy(data));
    if (tx)
    {
        auto rippleKey = RippleKey::make_RippleKey(keyFile);

        rippleKey.singleSign(*tx);

        std::cout << tx->getJson(0).toStyledString() << std::endl;
    }
    else
        std::cout << "Unable to sign \"" << data << "\"" << std::endl;
}

void
doMultiSign(std::string const& data,
    boost::filesystem::path const& keyFile)
{
    using namespace serialize;
    auto tx = make_sttx(boost::trim_copy(data));
    if (tx)
    {
        auto rippleKey = RippleKey::make_RippleKey(keyFile);

        rippleKey.multiSign(*tx);

        std::cout << tx->getJson(0).toStyledString() << std::endl;
    }
    else
        std::cout << "Unable to sign \"" << data << "\"" << std::endl;
}

void
doCreateKeyfile(boost::filesystem::path const& keyFile,
    std::string const& keytype,
    boost::optional<std::string> const& seed)
{
    using namespace ripple;
    using namespace serialize;

    if (exists(keyFile))
        throw std::runtime_error(
            "Refusing to overwrite existing key file: " +
            keyFile.string());

    auto kt = [&]
    {
        return !keytype.empty() ? keyTypeFromString(keytype) :
            boost::optional<KeyType>{};
    }();
    if (kt && *kt == KeyType::invalid)
    {
        std::cout << "Invalid key type: \"" << keytype << "\"" <<
            std::endl;
        return;
    }

    auto key = RippleKey::make_RippleKey(kt, seed);

    key.writeToFile(keyFile);

    std::cout << "New ripple key created.\n" <<
        "Stored in " << keyFile.string() << ".\n" <<
        "Key type is " << to_string(key.keyType()) << ".\n" <<
        "Account ID is " <<
        toBase58(calcAccountID(key.publicKey())) << ".\n" <<
        "\n\nThis file should be stored securely and not shared.\n\n";

}

void
doRepairKeyfile(boost::filesystem::path const& keyFile)
{
    using namespace serialize;
    using namespace boost::filesystem;
    // Back up the keyfile. If there are already 1000
    // backups, assume the user knows what they're doing.
    for (auto i = 0; i < 1000; ++i )
    {
        auto backup = keyFile;
        backup += ".bak." + std::to_string(i);
        if (!exists(backup))
        {
            copy_file(keyFile, backup, copy_option::fail_if_exists);
            break;
        }
    }
    // Read
    auto key = RippleKey::make_RippleKey(keyFile);
    // And overwrite
    key.writeToFile(keyFile);

    std::cout << "Ripple key in " << keyFile.string() << " repaired.\n" <<
        "Key type is " << to_string(key.keyType()) << ".\n" <<
        "Account ID is " <<
        toBase58(calcAccountID(key.publicKey())) << ".\n" <<
        "\n\nThis file should be stored securely and not shared.\n\n";
}

void
runCommand (const std::string& command,
    std::vector <std::string> const& args,
    boost::filesystem::path const& keyFile)
{
    using namespace std;

    static map<string, tuple<vector<string>::size_type,
        vector<string>::size_type, bool>>
        const commandArgs = {
            { "serialize", make_tuple(0, 1, true) },
            { "deserialize", make_tuple(0, 1, true) },
            { "sign", make_tuple(0, 1, true) },
            { "multiSign", make_tuple(0, 1, true) },
            { "create_keyfile", make_tuple(0, 2, false) },
            { "repair_keyfile", make_tuple(0, 0, false) }
    };

    auto const iArgs = commandArgs.find(command);

    if (iArgs == commandArgs.end())
        throw std::runtime_error("Unknown command: " + command);

    if (args.size() < get<0>(iArgs->second) ||
            args.size() > get<1>(iArgs->second))
        throw std::runtime_error("Syntax error: Wrong number of arguments");

    auto const input = [&]
    {
        if (args.size() == 0)
        {
            if (get<2>(iArgs->second))
            {
                std::ostringstream stdinput;
                stdinput << std::cin.rdbuf();
                return string{ stdinput.str() };
            }
            else
                return string{};
        }
        else
            return args[0];
    }();

    if (command == "serialize")
        doSerialize(input);
    else if (command == "deserialize")
        doDeserialize(input);
    else if (command == "sign")
        doSingleSign(input, keyFile);
    else if (command == "multiSign")
        doMultiSign(input, keyFile);
    else if (command == "create_keyfile")
    {
        auto const seed = args.size() >= 2 ? args[1] : boost::optional<string>{};
        doCreateKeyfile(keyFile, input, seed);
    }
    else if (command == "repair_keyfile")
        doRepairKeyfile(keyFile);
}

//LCOV_EXCL_START
static
std::string
getEnvVar (char const* name)
{
    std::string value;

    auto const v = getenv (name);

    if (v != nullptr)
        value = v;

    return value;
}

void printHelp (const boost::program_options::options_description& desc,
    boost::filesystem::path const& defaultKeyfile)
{
    static std::string const name = "ripple-serialize";

    std::cerr
        << name << " [options] <command> [<argument> ...]\n"
        << desc << std::endl <<
R"(Commands:
  Serialization:
    serialize [<argument>]              Serialize from JSON.
    deserialize [<argument>]            Deserialize to JSON.

  Transaction signing:
    sign [<argument>]                   Sign for submission.
    multiSign [<argument>]              Apply a multi-signature.
      Signing commands require a valid keyfile.
      Input can be serialized or unserialized JSON.
      Output will always be unserialized JSON.

      If an <argument> is not provided, the data will be
      read from stdin.

  Key Management:
    create_keyfile [<keytype> [<seed>]] Create a new keyfile.
      Specifying <seed> on the command line is strongly discouraged,
      particularly on a shared machine. Instead, create a random seed,
      edit the keyfile "master_seed", then run repair_keyfile.
    repair_keyfile                      Resync "master_seed"-derived fields.

      Default keyfile is: )" << defaultKeyfile << "\n";
}
//LCOV_EXCL_STOP

std::string const&
getVersionString ()
{
    static std::string const value = [] {
        std::string const s = versionString;
        beast::SemanticVersion v;
        if (!v.parse (s) || v.print () != s)
            throw std::logic_error (s + ": Bad version string"); //LCOV_EXCL_LINE
        return s;
    }();
    return value;
}

int main (int argc, char** argv)
{
#if defined(__GNUC__) && !defined(__clang__)
    auto constexpr gccver = (__GNUC__ * 100 * 100) +
                            (__GNUC_MINOR__ * 100) +
                            __GNUC_PATCHLEVEL__;

    static_assert (gccver >= 50100,
        "GCC version 5.1.0 or later is required to compile validator-keys.");
#endif

    static_assert (BOOST_VERSION >= 105700,
        "Boost version 1.57 or later is required to compile validator-keys");

    namespace po = boost::program_options;

    po::variables_map vm;

    // Set up option parsing.
    //
    po::options_description general ("General Options");
    general.add_options ()
    ("help,h", "Display this message.")
    ("keyfile", po::value<std::string> (), "Specify the key file.")
    ("unittest,u", "Perform unit tests.")
    ("version", "Display the build version.")
    ;

    // Interpret positional arguments as --parameters.
    po::options_description hidden("Hidden options");
    hidden.add_options()
    ("command", po::value< std::string > (), "Command.")
    ("arguments",po::value< std::vector<std::string> > ()->default_value(
        std::vector <std::string> (), "empty"), "Arguments.")
    ;
    po::positional_options_description p;
    p.add ("command", 1).add ("arguments", -1);

    po::options_description cmdline_options;
    cmdline_options.add(general).add(hidden);

    // Parse options, if no error.
    try
    {
        po::store (po::command_line_parser (argc, argv)
            .options (cmdline_options)    // Parse options.
            .positional (p)               // Remainder as --parameters.
            .run (),
            vm);
        po::notify (vm);                  // Invoke option notify functions.
    }
    //LCOV_EXCL_START
    catch (std::exception const&)
    {
        std::cerr << "ripple-serialize: Incorrect command line syntax." << std::endl;
        std::cerr << "Use '--help' for a list of options." << std::endl;
        return EXIT_FAILURE;
    }
    //LCOV_EXCL_STOP

    // Run the unit tests if requested.
    // The unit tests will exit the application with an appropriate return code.
    if (vm.count ("unittest"))
        return runUnitTests();

    //LCOV_EXCL_START
    if (vm.count("version"))
    {
        std::cout << "validator-keys version " <<
            getVersionString() << std::endl;
        return EXIT_SUCCESS;
    }

    boost::filesystem::path const homeDir = getEnvVar("HOME");
    auto const defaultKeyfile =
        (homeDir.empty() ?
            boost::filesystem::current_path() : homeDir) /
        ".ripple" / "secret-key.txt";

    if (vm.count ("help") || ! vm.count ("command"))
    {
        printHelp (general, defaultKeyfile);
        return EXIT_SUCCESS;
    }

    try
    {
        using namespace boost::filesystem;

        path keyFile = vm.count("keyfile") ?
            vm["keyfile"].as<std::string>() :
            defaultKeyfile;

        runCommand(
            vm["command"].as<std::string>(),
            vm["arguments"].as<std::vector<std::string>>(),
            keyFile);
        return EXIT_SUCCESS;
    }
    catch (std::exception const& e)
    {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
    //LCOV_EXCL_STOP
}
