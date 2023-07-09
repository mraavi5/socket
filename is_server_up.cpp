#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <iomanip>
#include <iostream>
#include <string>

bool received_response = false;

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

void handle_receive(const boost::system::error_code& error, std::size_t bytes_transferred,
                    boost::asio::deadline_timer& timer, char* reply,
                    boost::asio::ip::udp::socket& socket, boost::asio::ip::udp::endpoint& receiver_endpoint)
{
    if (!error) {
        std::string data(reply, bytes_transferred);
        auto [isValid, responseData] = check_checksum(data);
        if (isValid) {
            std::cout << responseData;
            received_response = true;
            timer.cancel();
        } else {
            std::cout << "OFFLINE";
        }
    } else if (error == boost::asio::error::operation_aborted) {
        if (!received_response) {
            std::cout << "OFFLINE";
        }
    } else {
        std::cout << "OFFLINE";
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

    boost::asio::io_service io_service;
    boost::asio::ip::udp::resolver resolver(io_service);
    boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), server_ip, "5300");
    boost::asio::ip::udp::endpoint receiver_endpoint = *resolver.resolve(query);
    boost::asio::ip::udp::socket socket(io_service);
    socket.open(boost::asio::ip::udp::v4());

    std::string request = "?";
    socket.send_to(boost::asio::buffer(request), receiver_endpoint);

    char reply[256] = {0};
    boost::asio::ip::udp::endpoint sender_endpoint;

    // Setup a deadline timer.
    boost::asio::deadline_timer timer(io_service);
    timer.expires_from_now(boost::posix_time::seconds(3));

// Start an asynchronous receive and pass in the handler.
socket.async_receive_from(boost::asio::buffer(reply), sender_endpoint,
                          [&](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                              handle_receive(ec, bytes_transferred, timer, reply, socket, receiver_endpoint);
                          });


    // Start an asynchronous wait on the timer.
    timer.async_wait([&socket](const boost::system::error_code& error)
    {
        if (!error) { // no error occurred
            socket.cancel(); // cancel all asynchronous operations associated with the socket.
        }
    });

    // This will block until all asynchronous operations have finished.
    io_service.run();

    return 0;
}
