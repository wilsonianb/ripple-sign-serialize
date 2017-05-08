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

#include <ripple/protocol/st.h>

namespace boost
{
namespace filesystem
{
class path;
}
}

namespace serialize {

class RippleKey
{
private:
    static ripple::KeyType constexpr defaultKeyType()
    {
        return ripple::KeyType::secp256k1;
    }
    ripple::KeyType keyType_;
    ripple::Seed seed_;
    ripple::PublicKey publicKey_;
    ripple::SecretKey secretKey_;

public:
    RippleKey()
        : RippleKey(RippleKey::defaultKeyType())
    {}

    explicit
    RippleKey(ripple::KeyType const& keyType)
        : RippleKey(keyType, ripple::randomSeed())
    {}


    RippleKey(
        ripple::KeyType const& keyType,
        ripple::Seed const& seed);

    /** Attempt to construct RippleKey by parsing a seed

        @param keyType Key type
        @param rawseed String containing the seed

        @throws std::runtime_error if the `rawseed` can not be parsed
                into a `Seed`
    */
    static
    RippleKey
    make_RippleKey(ripple::KeyType const& keyType,
        std::string rawseed);

    /** Attempt to construct RippleKey with variable parameters

        @param keyType Optional key type
        @param rawseed Optional string containing the seed

        @throws std::runtime_error if the `rawseed` is set and can not
            be parsed into a `Seed`
    */
    static
    RippleKey
    make_RippleKey(boost::optional<ripple::KeyType> const& keyType,
        boost::optional<std::string> const& rawseed);

    /** Returns RippleKey constructed from JSON file

        @param keyFile Path to JSON key file

        @throws std::runtime_error if file content is invalid
    */
    static
    RippleKey
    make_RippleKey(
        boost::filesystem::path const& keyFile);

    /** Write key to JSON file

        @param keyFile Path to file to write

        @note Overwrites existing key file

        @throws std::runtime_error if unable to create parent directory
    */
    void
    writeToFile (boost::filesystem::path const& keyFile) const;

    /** Signs a transaction with the key

        @param tx Transaction to single sign
    */
    void
    singleSign(ripple::STTx& tx) const;

    /** Add a signer to the transaction with the key

    @param tx Transaction to multi sign
    */
    void
    multiSign(ripple::STTx& tx) const;

    ripple::KeyType const&
    keyType() const
    {
        return keyType_;
    }

    ripple::PublicKey const&
    publicKey () const
    {
        return publicKey_;
    }
};
} // serialize
