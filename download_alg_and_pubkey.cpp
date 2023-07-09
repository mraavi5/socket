// Client Code

#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <cstdlib>

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
    size_t length_alg = socket.receive_from(boost::asio::buffer(reply_alg), receiver_endpoint);
    std::ofstream file_alg("algorithm.txt", std::ios::binary);
    file_alg.write(reply_alg.data(), length_alg);

    // Then receive "pubkey.key"
    std::array<char, 1024> reply_pub;
    size_t length_pub = socket.receive_from(boost::asio::buffer(reply_pub), receiver_endpoint);
    std::ofstream file_pub("pubkey.key", std::ios::binary);
    file_pub.write(reply_pub.data(), length_pub);

    std::cout << "Successfully downloaded algorithm.txt and pubkey.key" << std::endl;

    return 0;
}
