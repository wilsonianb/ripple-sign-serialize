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

#include <boost/optional.hpp>
#include <vector>

namespace boost
{
namespace filesystem
{
class path;
}
}

void
doSerialize(std::string const& data);

void
doDeserialize(std::string const& data);

void
doSingleSign(std::string const& data,
    boost::filesystem::path const& keyFile);

void
doMultiSign(std::string const& data,
    boost::filesystem::path const& keyFile);

void
doCreateKeyfile(boost::filesystem::path const& keyFile,
    std::string const& keytype,
    boost::optional<std::string> const& seed);

void
doRepairKeyfile(boost::filesystem::path const& keyFile);

void
runCommand (const std::string& command,
    std::vector <std::string> const& args,
    boost::filesystem::path const& keyFile);

std::string const&
getVersionString();
