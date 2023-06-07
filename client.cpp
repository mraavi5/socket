#include <iostream>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <openssl/sha.h>
#include <oqs/oqs.h>
#include <fstream>

const size_t MaxFrameSize = 1232;  // Max frame size in bytes
const size_t ChecksumSize = 8;     // Checksum size in bytes
const bool USE_CRC = false;        // Control flag for using CRC

// Function to calculate CRC32 checksum of given data
std::string calculate_checksum(const std::string& data) {
    boost::crc_32_type result;
    result.process_bytes(data.data(), data.size());
    return std::to_string(result.checksum());
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server IP> <domain>\n";
        return 1;
    }

    std::string server_ip = argv[1];
    std::string domain = argv[2];

    boost::asio::io_service io_service;
    boost::asio::ip::udp::resolver resolver(io_service);
    boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), server_ip, "5300");
    boost::asio::ip::udp::endpoint receiver_endpoint = *resolver.resolve(query);

    boost::asio::ip::udp::socket socket(io_service);
    socket.open(boost::asio::ip::udp::v4());

    std::vector<std::string> buffer;

    // Repeatedly request data from server
    for (int index = 0;; ++index) {
        std::string request = domain + "," + std::to_string(index);
        socket.send_to(boost::asio::buffer(request), receiver_endpoint);

        char reply[MaxFrameSize + ChecksumSize];
        boost::asio::ip::udp::endpoint sender_endpoint;
        size_t length = socket.receive_from(boost::asio::buffer(reply), sender_endpoint);

        std::string reply_str(reply, length);
        std::string data = reply_str;
        std::string checksum;
        if (USE_CRC) {
            data = reply_str.substr(0, reply_str.size() - ChecksumSize - 1);
            checksum = reply_str.substr(reply_str.size() - ChecksumSize);
        }

        // Check the received checksum
        if (!USE_CRC || calculate_checksum(data) == checksum) {
            std::cout << "Received " << length << " bytes\n";
            if (data == "N") {  // Not acknowledged
                break;
            } else {
                buffer.push_back(data);
            }
        } else {
            --index;  // Re-request this packet
        }
    }

    // Read the public key from file
    std::ifstream pub_file("pubkey.key");
    if (!pub_file.is_open()) {
        std::cerr << "Failed to open pubkey.key\n";
        return 1;
    }
    std::string pubkey((std::istreambuf_iterator<char>(pub_file)), std::istreambuf_iterator<char>());
    uint8_t *public_key = (uint8_t *)pubkey.c_str();

    // Read the algorithm from file
    std::ifstream alg_file("algorithm.txt");
    if (!alg_file.is_open()) {
        std::cerr << "Failed to open algorithm.txt\n";
        return 1;
    }
    std::string algorithm((std::istreambuf_iterator<char>(alg_file)), std::istreambuf_iterator<char>());


    // Concatenate all received fragments
    std::string contents;
    for (const auto& str : buffer) {
        contents += str;
    }
    size_t firstCommaIndex = contents.find(",");
    size_t secondCommaIndex = contents.find(",", firstCommaIndex + 1);
    if (secondCommaIndex != std::string::npos) {
        std::string signature = contents.substr(secondCommaIndex + 1);
        std::cout << "!!!!!" << signature << "!!!!!\n";
        // Verify the signature
        OQS_SIG *sig = OQS_SIG_new(algorithm.c_str());
        uint8_t *message = (uint8_t *)domain.c_str();
        size_t message_len = domain.length();
        uint8_t *signature_bytes = (uint8_t *)signature.c_str();
        size_t signature_len = signature.length();

        if (OQS_SIG_verify(sig, message, message_len, signature_bytes, signature_len, public_key) == OQS_SUCCESS) {
            std::cout << "SUCCESS\n";
        } else {
            std::cout << "INVALID\n";
        }
        OQS_SIG_free(sig);
    } else {
        std::cout << "INVALID (signature not found)\n";
    }

    

    return 0;
}
