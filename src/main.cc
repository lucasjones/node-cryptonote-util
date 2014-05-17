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

using namespace node;
using namespace v8;
using namespace cryptonote;

Handle<Value> except(const char* msg) {
    return ThrowException(Exception::Error(String::New(msg)));
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
//    crypto::hash tree_root_hash = get_tx_tree_hash(b);
//    blob.append((const char*)&tree_root_hash, sizeof(tree_root_hash ));
//    blob.append(tools::get_varint_data(b.tx_hashes.size()+1));

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
    blobdata output = "";

    uint64_t prefix;

    tools::base58::decode_addr(input, prefix, output);

    Buffer* buff = Buffer::New(output.data(), output.size());
    return scope.Close(buff->handle_);
}

void init(Handle<Object> exports) {
    exports->Set(String::NewSymbol("convert_blob"), FunctionTemplate::New(convert_blob)->GetFunction());
    exports->Set(String::NewSymbol("address_decode"), FunctionTemplate::New(address_decode)->GetFunction());
}

NODE_MODULE(cryptonote, init)
