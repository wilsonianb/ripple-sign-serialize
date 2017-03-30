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

#include <Serialize.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/json/json_reader.h>
#include <ripple/json/to_string.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>
#include <beast/core/detail/base64.hpp>
#include <boost/filesystem.hpp>
#include <fstream>

namespace serialize {

Json::Value
parseJson(std::string const& raw)
{
    using namespace ripple;

    Json::Value jv;
    Json::Reader{}.parse(raw, jv);

    return jv;
}

boost::optional<ripple::STObject>
makeObject(Json::Value const& json)
{
    using namespace ripple;

    STParsedJSONObject parsed("", json);

    return parsed.object;
}

std::string
serialize(ripple::STObject const& object)
{
    using namespace ripple;

    return strHex(object.getSerializer().peekData());
}

boost::optional<ripple::STObject>
deserialize(std::string const& blob)
{
    using namespace ripple;

    auto unhex{ strUnHex(blob) };

    if (!unhex.second || !unhex.first.size())
        return{};

    SerialIter sitTrans{ makeSlice(unhex.first) };
    // Can Throw
    return STObject{ std::ref(sitTrans), sfGeneric };
}

boost::optional<ripple::STTx>
make_sttx(std::string const& data)
{
    auto obj = deserialize(data);
    if (!obj)
    {
        obj = [&]
        {
            auto json = serialize::parseJson(data);
            return json ? serialize::makeObject(json) : boost::none;
        }();
    }
    if (!obj)
        return{};

    using namespace ripple;

    STTx tx{ std::move(*obj) };

    return tx;
}

} // serialize
