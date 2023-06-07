#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <regex>
#include <redisclient/redissyncclient.h>

const size_t MaxFrameSize = 1232;  // Max frame size in bytes
const size_t ChecksumSize = 8;     // Checksum size in bytes
const bool USE_CRC = false;        // Control flag for using CRC

// Function to extract base domain from a given URL
std::string get_base_domain(const std::string& domain) {
    std::regex base_domain_regex("(?:https?:\\/\\/)?(?:www\\.)?([^\\/]+)");
    std::smatch sm;
    std::regex_search(domain, sm, base_domain_regex);
    return sm[1];
}

// Function to calculate CRC32 checksum of given data
std::string calculate_checksum(const std::string& data) {
    boost::crc_32_type result;
    result.process_bytes(data.data(), data.size());
    return std::to_string(result.checksum());
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
        std::cerr << "Cannot connect to Redis server: " << ec.message() << "\n";
        return 1;
    }

    std::cout << "Server is listening...\n";

    for (;;) {
        char request[MaxFrameSize + ChecksumSize];
        boost::asio::ip::udp::endpoint sender_endpoint;
        size_t length = socket.receive_from(boost::asio::buffer(request), sender_endpoint);

        std::string request_str(request, length);
        std::string domain = get_base_domain(request_str.substr(0, request_str.find(',')));
        std::string index_str = request_str.substr(request_str.find(',') + 1);
        int index = std::stoi(index_str);

        std::cout << "Received request for domain: " << domain << ", index: " << index << "\n";

        std::string key = domain + "," + index_str;
        std::deque<redisclient::RedisBuffer> args = { key };
        auto redisReply = redis.command("GET", args);

        if (redisReply.isOk() && redisReply.toString().length() > 0) {
            std::string data = redisReply.toString();
            std::string reply = data;
            if (USE_CRC) {
                std::string checksum = calculate_checksum(data);
                reply += "," + checksum;
            }
            //std::cout << "Sending " << reply << "\n";
            socket.send_to(boost::asio::buffer(reply), sender_endpoint);
        } else {
            std::string reply = "N";
            socket.send_to(boost::asio::buffer(reply), sender_endpoint);
        }
    }

    return 0;
}
