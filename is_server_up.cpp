#include <boost/asio.hpp>
#include <iostream>
#include <string>

bool received_response = false;

void handle_receive(const boost::system::error_code& error, std::size_t /*bytes_transferred*/,
                    boost::asio::deadline_timer& timer)
{
    if (!error) {
        std::cout << "Online";
        received_response = true;
        timer.cancel();
    } else if (error == boost::asio::error::operation_aborted) {
        // Don't output anything if operation was aborted because we received a response.
        if (!received_response) {
            std::cout << "Offline";
        }
    } else {
        std::cout << "Offline";
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

    char reply[1];
    boost::asio::ip::udp::endpoint sender_endpoint;

    // Setup a deadline timer.
    boost::asio::deadline_timer timer(io_service);
    timer.expires_from_now(boost::posix_time::seconds(3));

    // Start an asynchronous receive and pass in the handler.
    socket.async_receive_from(boost::asio::buffer(reply), sender_endpoint,
                              [&](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                  handle_receive(ec, bytes_transferred, timer);
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
