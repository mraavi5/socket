// If you get this error:
//      ./database_filler: error while loading shared libraries: libredis++.so.1: cannot open shared object file: No such file or directory
// Solution, paste this:
//      export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <regex>
#include <sw/redis++/redis++.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

const size_t MaxFrameSize = 1232;  // Max frame size in bytes
const size_t ChecksumSize = 8;     // Checksum size in bytes
const bool USE_CRC = false;        // Control flag for using CRC
const size_t FragmentSize = USE_CRC ? MaxFrameSize - ChecksumSize : MaxFrameSize;

// Function to extract base domain from a given URL
std::string get_base_domain(const std::string& domain) {
    std::regex base_domain_regex("(?:https?:\\/\\/)?(?:www\\.)?([^\\/]+)");
    std::smatch sm;
    std::regex_search(domain, sm, base_domain_regex);
    return sm[1];
}

// Function to sign a message
std::string sign_message(const std::string& message, OQS_SIG* signer, const uint8_t* secret_key) {
    std::vector<uint8_t> signature(signer->length_signature);
    size_t signature_len;

    if (OQS_SIG_sign(signer, signature.data(), &signature_len, reinterpret_cast<const uint8_t*>(message.data()), message.size(), secret_key) != OQS_SUCCESS) {
        std::cerr << "Failed to sign message\n";
        exit(1);
    }

    return std::string(signature.begin(), signature.begin() + signature_len);
}

// Function to calculate SHA256 hash of given data
std::string sha256(const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream hashed_ss;
    hashed_ss << std::hex << std::setfill('0');
    for (int i = 0; i < hash_len; i++) {
        hashed_ss << std::setw(2) << static_cast<unsigned>(hash[i]);
    }

    return hashed_ss.str();
}

// Function to compute the SHA-256 hash of a string
// std::string sha256(const std::string& str) {
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256_CTX sha256;
//     SHA256_Init(&sha256);
//     SHA256_Update(&sha256, str.c_str(), str.size());
//     SHA256_Final(hash, &sha256);
//     std::stringstream ss;
//     for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
//         ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
//     }
//     return ss.str();
// }

// Function to write data to Redis
void write_to_redis(const std::string& domain, int index, const std::string& data) {
    sw::redis::Redis redis("tcp://127.0.0.1:6379");

    try {
        redis.set(domain + "," + std::to_string(index), data);
    } catch (const sw::redis::Error &err) {
        std::cerr << "Failed to write to Redis: " << err.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <algorithm>\n";
        return 1;
    }

    std::string algorithm = argv[1];

    OQS_SIG* signer = OQS_SIG_new(algorithm.c_str());
    if (signer == NULL) {
        std::cerr << "Failed to initialize " << algorithm << " signer\n";
        return 1;
    }
    
    // Allocate space for the public and secret keys
    uint8_t *public_key = (uint8_t *) malloc(signer->length_public_key);
    uint8_t *secret_key = (uint8_t *) malloc(signer->length_secret_key);
    
    // Generate the key pair
    if (OQS_SIG_keypair(signer, public_key, secret_key) != OQS_SUCCESS) {
        std::cerr << "Failed to generate key pair" << std::endl;
        return 1;
    }

    // Write to the files
    std::ofstream algorithm_file("algorithm.txt", std::ios::binary);
    if (!algorithm_file.is_open()) {
        std::cerr << "Failed to open algorithm.txt\n";
        return 1;
    }
    algorithm_file.write(algorithm.c_str(), algorithm.size());
    algorithm_file.close();

    std::ofstream public_file("pubkey.key", std::ios::binary);
    if (!public_file.is_open()) {
        std::cerr << "Failed to open pubkey.key\n";
        return 1;
    }
    public_file.write(reinterpret_cast<char*>(public_key), signer->length_public_key);
    public_file.close();

    std::ofstream private_file("privkey.key", std::ios::binary);
    if (!private_file.is_open()) {
        std::cerr << "Failed to open privkey.key\n";
        return 1;
    }
    private_file.write(reinterpret_cast<char*>(secret_key), signer->length_secret_key);
    private_file.close();


    sw::redis::Redis redis("tcp://127.0.0.1:6379");
    redis.set("ALGORITHM_USED", algorithm);
    redis.set("PUBLIC_KEY", std::string(reinterpret_cast<char*>(public_key), signer->length_public_key));
    redis.set("PRIVATE_KEY", std::string(reinterpret_cast<char*>(secret_key), signer->length_secret_key));

    std::ifstream file("alexa_top_1000.csv");
    std::string line;

    // Ignore header
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::string domain, ip;
        std::stringstream ss(line);

        std::getline(ss, domain, ',');
        std::getline(ss, ip, ',');

        domain = get_base_domain(domain);

        std::string message = domain + ip;
        std::string signature = sign_message(message, signer, secret_key);
        if(domain == "google.com") {
            std::cout << "!!!!!" << signature << "!!!!!\n";
        }
        std::string buffer = domain + "," + ip + "," + signature;

        std::vector<std::string> hashes;
        for (size_t i = 0; i < buffer.size(); i += FragmentSize) {
            std::string fragment = buffer.substr(i, FragmentSize);
            hashes.push_back(sha256(fragment));
        }

        std::string new_buffer;
        for (const auto& hash : hashes) {
            new_buffer += hash;
        }
        new_buffer += buffer;

        write_to_redis(domain, -1, std::to_string(hashes.size()));

        for (size_t i = 0; i < new_buffer.size(); i += FragmentSize) {
            std::string fragment = new_buffer.substr(i, FragmentSize);
            int index = i / FragmentSize;
            std::cout << "\tFragment " << (index + 1) << ", " << fragment.length() << " bytes\n";
            write_to_redis(domain, index, fragment);
        }

        std::cout << "Wrote " << (1 + new_buffer.size() / FragmentSize) << " fragments for " << domain << " = " << ip << "\n";
    }

    OQS_SIG_free(signer);
    std::cout << "Done!\n";

    return 0;
}
