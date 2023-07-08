#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <iomanip>
#include <openssl/evp.h>
#include <iostream>
#include <redisclient/redissyncclient.h>
#include <regex>
#include <string>

const bool UseVerbose = true;      // Whether or not to print all the debugging messages
const bool UseCRC = true;          // Control flag for using CRC
const size_t MaxFrameSize = 1232;  // Max frame size in bytes
const size_t ChecksumSize = 8;     // Checksum size in bytes
const size_t FragmentSize = UseCRC ? MaxFrameSize - ChecksumSize : MaxFrameSize;

// Function to extract base domain from a given URL
std::string get_base_domain(const std::string& domain) {
    std::regex base_domain_regex("(?:https?:\\/\\/)?(?:www\\.)?([^\\/]+)");
    std::smatch sm;
    std::regex_search(domain, sm, base_domain_regex);
    return sm[1];
}

// Function to calculate SHA256 hash of given data, string length=32
std::string sha256(const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    std::string hashed_str;
    hashed_str.reserve(hash_len);
    for (int i = 0; i < hash_len; i++) {
        hashed_str.push_back(static_cast<char>(hash[i]));
    }
    assert(hashed_str.length() == 32);
    return hashed_str;
}

// Function to convert a 32-byte string to a 64-byte hexadecimal string
std::string to_hex_string(const std::string& data) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (char c : data) {
        ss << std::setw(2) << static_cast<unsigned>(static_cast<unsigned char>(c));
    }
    return ss.str();
}

// Function to calculate CRC32 checksum of given data
std::string calculate_checksum(const std::string& data) {
    boost::crc_32_type result;
    result.process_bytes(data.data(), data.size());
    std::ostringstream oss;
    oss << std::hex << std::setw(ChecksumSize) << std::setfill('0') << result.checksum();
    std::string checksum = oss.str();
    // Assert that checksum is the correct size
    assert(checksum.size() == ChecksumSize);
    return checksum;
}

int main() {
    boost::asio::io_service io_service;
    boost::asio::ip::udp::socket socket(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 5300));
    redisclient::RedisSyncClient redis(io_service);

    boost::system::error_code ec;
    boost::asio::ip::address address = boost::asio::ip::address::from_string("127.0.0.1");
    unsigned short port = 6379;
    boost::asio::ip::tcp::endpoint endpoint(address, port);

    redis.connect(endpoint, ec);

    if(ec) {
        std::cerr << "Cannot connect to Redis server: " << ec.message() << std::endl;
        return 1;
    }

    std::cout << "Server is listening...\n";

    for (;;) {
        char request[MaxFrameSize + ChecksumSize];
        boost::asio::ip::udp::endpoint sender_endpoint;
        size_t length = socket.receive_from(boost::asio::buffer(request), sender_endpoint);

        std::string request_str(request, length);
        if (request_str == "?") {
            std::string reply = "!";
            socket.send_to(boost::asio::buffer(reply), sender_endpoint);
            continue;
        }
        
        std::string domain = get_base_domain(request_str.substr(0, request_str.find(',')));
        std::string index_str = request_str.substr(request_str.find(',') + 1);
        // Check for an optional nonce
        int nonce = 0;
        size_t nonce_pos = index_str.find(',');
        if (nonce_pos != std::string::npos) {
            std::string nonce_str = index_str.substr(nonce_pos + 1);
            nonce = std::stoi(nonce_str);
            index_str = index_str.substr(0, nonce_pos);
        }
        int index = std::stoi(index_str);

        if(UseVerbose) std::cout << "Received request for domain: " << domain << ", index: " << index << std::endl;
        if(UseVerbose) if(index == 0) std::cout << "\tNonce=" << nonce << std::endl;

        std::string key = domain + "," + index_str;
        std::deque<redisclient::RedisBuffer> args = { key };
        auto redisReply = redis.command("GET", args);

        if (redisReply.isOk() && redisReply.toString().length() > 0) {
            std::string reply = redisReply.toString();
            if(index == 0) {
                // Update the total hash to include the nonce
                std::string hash = reply.substr(0, 32);
                //if(UseVerbose) std::cout << "Previous total hash: " << to_hex_string(hash) << std::endl;
                hash = sha256(hash + "," + std::to_string(nonce));
                //if(UseVerbose) std::cout << "Updated total hash:  " << to_hex_string(hash) << std::endl;
                reply.replace(0, 32, hash);
            }
            if (UseCRC) {
                std::string checksum = calculate_checksum(reply);
                reply += checksum;  // Append the checksum without a comma
            }
            //if(UseVerbose) std::cout << "Sending " << reply << std::endl;
            socket.send_to(boost::asio::buffer(reply), sender_endpoint);
        } else {
            std::string reply = "N";
            socket.send_to(boost::asio::buffer(reply), sender_endpoint);
        }
    }

    return 0;
}
