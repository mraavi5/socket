// Client Code

#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <iomanip>
#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <chrono>
#include <thread>


const bool UseCRC = true;          // Control flag for using CRC
const size_t ChecksumSize = 8;     // Checksum size in bytes

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

// Check at the checksum matches, returning <true, data> if it matches, otherwise <false, data>
std::pair<bool, std::string> check_checksum(const std::string& data) {
    if (!UseCRC || data.size() < ChecksumSize)
        return {true, data};
    std::string received_checksum = data.substr(data.size() - ChecksumSize);
    std::string original_data = data.substr(0, data.size() - ChecksumSize);
    std::string calculated_checksum = calculate_checksum(original_data);
    return {calculated_checksum == received_checksum, original_data};
}

void receiveFile(const std::string& request, const std::string& filename, boost::asio::ip::udp::socket& socket, boost::asio::ip::udp::endpoint& receiver_endpoint) {
    bool isValid = false;
    while (!isValid) {
        socket.send_to(boost::asio::buffer(request), receiver_endpoint);
        std::array<char, 1024> reply;
        size_t length = socket.receive_from(boost::asio::buffer(reply), receiver_endpoint);
        std::string data(reply.data(), length);
        auto [valid, responseData] = check_checksum(data);
        isValid = valid;
        if (isValid) {
            std::ofstream file(filename, std::ios::binary);
            file.write(responseData.data(), responseData.size());
            std::cout << "Successfully downloaded " << filename << "\n";
        } else {
            std::cout << "Invalid checksum for " << filename << ". Resending request...\n";
            std::this_thread::sleep_for(std::chrono::seconds(1));  // pause before resending request
        }
    }
}

int main(int argc, char* argv[]) {
    std::string server_ip = "127.0.0.1";
    if (argc == 2) {
        server_ip = argv[1];
    } else if (argc > 2) {
        std::cerr << "Usage: " << argv[0] << " <server IP>\n";
        return 1;
    }


    while (true) {
        std::array<char, 128> buffer;
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("./is_server_up", "r"), pclose);
        if (!pipe) {
            throw std::runtime_error("popen() failed!");
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }

        if (result.find("OFFLINE") == std::string::npos) {
            break;
        }
        std::cout << "Server is not up yet. Retrying...\n";

        sleep(1); // Sleep for a second before retrying
    }

    boost::asio::io_service io_service;
    boost::asio::ip::udp::resolver resolver(io_service);
    boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), server_ip, "5300");
    boost::asio::ip::udp::endpoint receiver_endpoint = *resolver.resolve(query);
    boost::asio::ip::udp::socket socket(io_service);
    socket.open(boost::asio::ip::udp::v4());

    std::string request = "?pubkey";
    socket.send_to(boost::asio::buffer(request), receiver_endpoint);
        
    // First receive "algorithm.txt"
    std::array<char, 1024> reply_alg;
    std::string responseDataAlg;
    bool isValidAlg = false;
    while (!isValidAlg) {
        size_t length_alg = socket.receive_from(boost::asio::buffer(reply_alg), receiver_endpoint);
        std::string data_alg(reply_alg.data(), length_alg);
        auto resultAlg = check_checksum(data_alg);
        isValidAlg = resultAlg.first;
        responseDataAlg = resultAlg.second;
        if (!isValidAlg) {
            std::cout << "Invalid checksum for algorithm.txt. Resending request...\n";
            std::string request = "?";
            socket.send_to(boost::asio::buffer(request), receiver_endpoint);
        }
    }
    std::ofstream file_alg("algorithm.txt", std::ios::binary);
    file_alg.write(responseDataAlg.data(), responseDataAlg.size());

    // Then receive "pubkey.key"
    std::array<char, 1024> reply_pub;
    std::string responseDataPub;
    bool isValidPub = false;
    while (!isValidPub) {
        size_t length_pub = socket.receive_from(boost::asio::buffer(reply_pub), receiver_endpoint);
        std::string data_pub(reply_pub.data(), length_pub);
        auto resultPub = check_checksum(data_pub);
        isValidPub = resultPub.first;
        responseDataPub = resultPub.second;
        if (!isValidPub) {
            std::cout << "Invalid checksum for pubkey.key. Resending request...\n";
            std::string request = "?pubkey";
            socket.send_to(boost::asio::buffer(request), receiver_endpoint);
        }
    }
    std::ofstream file_pub("pubkey.key", std::ios::binary);
    file_pub.write(responseDataPub.data(), responseDataPub.size());

    std::cout << "Successfully downloaded algorithm.txt and pubkey.key" << std::endl;

    return 0;
}
