#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <oqs/oqs.h>
#include <regex>
#include <sstream>
#include <string>
#include <vector>
//#include <openssl/sha.h>

const bool UseVerbose = true;      // Whether or not to print all the debugging messages
const bool UseCRC = true;          // Control flag for using CRC
const size_t MaxFrameSize = 1232;  // Max frame size in bytes
const size_t ChecksumSize = 8;     // Checksum size in bytes
const size_t FragmentSize = UseCRC ? MaxFrameSize - ChecksumSize : MaxFrameSize;

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

// Request a chunk at an index from the server
std::string requestChunkAtIndex(boost::asio::ip::udp::socket &socket, boost::asio::ip::udp::endpoint &receiver_endpoint, std::string domain, int index) {
    std::string request = domain + "," + std::to_string(index);
    socket.send_to(boost::asio::buffer(request), receiver_endpoint);

    char reply[MaxFrameSize];
    boost::asio::ip::udp::endpoint sender_endpoint;
    size_t length = socket.receive_from(boost::asio::buffer(reply), sender_endpoint);

    std::string reply_str(reply, length);
    return reply_str;
}

// Check at the checksum matches, returning <true, data> if it matches, otherwise <false, data>
std::pair<bool, std::string> checkChecksum(const std::string& data) {
    if (!UseCRC || data.size() < ChecksumSize)
        return {true, data};
    std::string received_checksum = data.substr(data.size() - ChecksumSize);
    std::string original_data = data.substr(0, data.size() - ChecksumSize);
    std::string calculated_checksum = calculate_checksum(original_data);
    return {calculated_checksum == received_checksum, original_data};
}

// Function to extract base domain from a given URL
std::string get_base_domain(const std::string& domain) {
    std::regex base_domain_regex("(?:https?:\\/\\/)?(?:www\\.)?([^\\/]+)");
    std::smatch sm;
    std::regex_search(domain, sm, base_domain_regex);
    return sm[1];
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server IP> <domain>\n";
        return 1;
    }

    std::string server_ip = argv[1];
    std::string domain = get_base_domain(argv[2]);

    boost::asio::io_service io_service;
    boost::asio::ip::udp::resolver resolver(io_service);
    boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), server_ip, "5300");
    boost::asio::ip::udp::endpoint receiver_endpoint = *resolver.resolve(query);
    boost::asio::ip::udp::socket socket(io_service);
    socket.open(boost::asio::ip::udp::v4());

    if(UseVerbose) std::cout << "PROCESS 1: Extract the totalHash and NumChunks" << std::endl;

    std::string data = "";
    bool isValid = false;
    while(!isValid) {
        data = requestChunkAtIndex(socket, receiver_endpoint, domain, 0);
        std::pair<bool, std::string> resultPair = checkChecksum(data);
        isValid = resultPair.first;
        if (!isValid) {
            if(UseVerbose) std::cout << "Checksum verification failed for chunk at index 0.\n";
        } else {
            data = resultPair.second;
        }
    }
    std::string totalHash = data.substr(0, 32);
    int totalNumHashes = static_cast<int>(data.substr(32, 1)[0]);
    std::string totalManualHash = "";
    int numChunks = static_cast<int>(data.substr(33, 1)[0]);
    if(UseVerbose) std::cout << "totalHash = " << to_hex_string(totalHash) << ", totalNumHashes = " << totalNumHashes << ", numChunks = " << numChunks << std::endl;

    if(UseVerbose) std::cout << "PROCESS 2: Extract each of the hashes" << std::endl;
    int numReceivedChunks = 1;
    std::vector<std::string> hashes;
    std::string contents = data.substr(34);
    while(totalNumHashes > 0 && numReceivedChunks < numChunks) {
        if(contents.length() >= 32) {
            std::string chunk = contents.substr(0, 32);
            contents = contents.substr(32);
            hashes.push_back(chunk);
            if(UseVerbose) std::cout << "\tHash " << hashes.size() << " = " << to_hex_string(hashes[hashes.size() - 1]) << std::endl;
            totalNumHashes--;
            totalManualHash += chunk;
        } else {
            isValid = false;
            while(!isValid) {
                data = requestChunkAtIndex(socket, receiver_endpoint, domain, numReceivedChunks);
                std::pair<bool, std::string> resultPair = checkChecksum(data);
                isValid = resultPair.first;
                data = resultPair.second;
            }
            numReceivedChunks++;
            contents += data;
        }
    }
    assert(totalNumHashes == 0);
    totalManualHash = sha256(totalManualHash);
    assert(totalManualHash == totalHash);
    if(UseVerbose) std::cout << "Total hash of hashes successfully verified!" << std::endl;
    if(UseVerbose) std::cout << "PROCESS 3: Fetch all the other data" << std::endl;
    std::string finalVerifiedData = "";
    while(true) {
        while(contents.length() >= FragmentSize) {
            std::string chunk = contents.substr(0, FragmentSize);
            contents = contents.substr(FragmentSize);
            std::string chunkHash = sha256(chunk);
            bool isValid = (chunkHash == hashes[totalNumHashes]);
            assert(isValid);
            // If it's not valid, we could request the previous numReceivedChunks, keep track of how offset it is, then take the substr(offset) of it to retry the hash.
            totalNumHashes++;
            finalVerifiedData += chunk;
            if(UseVerbose) std::cout << "\tHash " << totalNumHashes << " successfully verified!" << std::endl;
        }

        if(numReceivedChunks >= numChunks) break;

        isValid = false;
        while(!isValid) {
            data = requestChunkAtIndex(socket, receiver_endpoint, domain, numReceivedChunks);
            std::pair<bool, std::string> resultPair = checkChecksum(data);
            isValid = resultPair.first;
            data = resultPair.second;
        }
        numReceivedChunks++;
        contents += data;

    }
    // Verify the last chunk
    if(contents.length() > 0) {
        std::string chunk = contents;
        std::string chunkHash = sha256(chunk);
        bool isValid = (chunkHash == hashes[totalNumHashes]);
        assert(isValid);
        // If it's not valid, we could request the previous numReceivedChunks, keep track of how offset it is, then take the substr(offset) of it to retry the hash.
        totalNumHashes++;
        finalVerifiedData += chunk;
        if(UseVerbose) std::cout << "\tHash " << totalNumHashes << " successfully verified!" << std::endl;
    }


    if(UseVerbose) std::cout << "PROCESS 4: Interpret the data and verify signature" << std::endl;

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
    contents = finalVerifiedData;
    size_t firstCommaIndex = contents.find(",");
    size_t secondCommaIndex = contents.find(",", firstCommaIndex + 1);
    assert(firstCommaIndex != std::string::npos && secondCommaIndex != std::string::npos);

    std::string receivedDomain = contents.substr(0, firstCommaIndex);
    std::string receivedIP = contents.substr(firstCommaIndex + 1, secondCommaIndex - firstCommaIndex - 1);
    std::string signature = contents.substr(secondCommaIndex + 1);

    assert(domain == receivedDomain);
    if(UseVerbose) std::cout << "\tReceived domain matches." << std::endl;
    if(UseVerbose) std::cout << "\tReceived IP: " << receivedIP << std::endl;
    if(UseVerbose) std::cout << "\tReceived signature hash: " << to_hex_string(sha256(signature)) << std::endl;

    OQS_SIG *sig = OQS_SIG_new(algorithm.c_str());
    std::string message = domain + "," + receivedIP;
    uint8_t *message_bytes = (uint8_t *)message.c_str();
    size_t message_len = message.length();
    uint8_t *signature_bytes = (uint8_t *)signature.c_str();
    size_t signature_len = signature.length();

    if(UseVerbose) if (OQS_SIG_verify(sig, message_bytes, message_len, signature_bytes, signature_len, public_key) == OQS_SUCCESS) {
        std::cout << "Signature verification was successful!\n";
    } else {
        std::cout << "SIGNATURE VERIFICATION FAILED\n";
    }
    OQS_SIG_free(sig);
    
    if(UseVerbose) {
        std::cout << receivedIP << std::endl;
    } else {
        std::cout << "\nFinal verified result: " << receivedIP << std::endl;
    }
    return 0;
}
