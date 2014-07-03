#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include "cryptonote_core/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "cryptonote_protocol/blobdatatype.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "common/base58.h"
#include "serialization/binary_utils.h"

using namespace node;
using namespace v8;
using namespace cryptonote;

Handle<Value> except(const char* msg) {
    return ThrowException(Exception::Error(String::New(msg)));
}

blobdata uint64be_to_blob(uint64_t num) {
    blobdata res = "        ";
    res[0] = num >> 56 & 0xff;
    res[1] = num >> 48 & 0xff;
    res[2] = num >> 40 & 0xff;
    res[3] = num >> 32 & 0xff;
    res[4] = num >> 24 & 0xff;
    res[5] = num >> 16 & 0xff;
    res[6] = num >> 8  & 0xff;
    res[7] = num       & 0xff;
    return res;
}

Handle<Value> convert_blob(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b)) {
        return except("Failed to parse block");
    }
    output = get_block_hashing_blob(b);

    Buffer* buff = Buffer::New(output.data(), output.size());
    return scope.Close(buff->handle_);
}

Handle<Value> convert_blob_bb(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    bb_block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b)) {
        return except("Failed to parse block");
    }
    output = get_block_hashing_blob(b);

    Buffer* buff = Buffer::New(output.data(), output.size());
    return scope.Close(buff->handle_);
}

Handle<Value> address_decode(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data))
        return scope.Close(Undefined());

    account_public_address adr;
    if (!::serialization::parse_binary(data, adr))
        return scope.Close(Undefined());

    if (!crypto::check_key(adr.m_spend_public_key) || !crypto::check_key(adr.m_view_public_key))
        return scope.Close(Undefined());

    return scope.Close(Integer::New(static_cast<uint32_t>(prefix)));
}

void init(Handle<Object> exports) {
    exports->Set(String::NewSymbol("convert_blob"), FunctionTemplate::New(convert_blob)->GetFunction());
    exports->Set(String::NewSymbol("convert_blob_bb"), FunctionTemplate::New(convert_blob_bb)->GetFunction());
    exports->Set(String::NewSymbol("address_decode"), FunctionTemplate::New(address_decode)->GetFunction());
}

NODE_MODULE(cryptonote, init)
