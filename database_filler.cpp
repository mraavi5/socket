// If you get this error:
//      ./database_filler: error while loading shared libraries: libredis++.so.1: cannot open shared object file: No such file or directory
// Solution, paste this:
//      export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <oqs/oqs.h>
#include <regex>
#include <sstream>
#include <string>
#include <sw/redis++/redis++.h>
#include <vector>

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

// // Function to verify a message
// bool verify_message(const std::string& message, OQS_SIG* signer, std::string signature, std::string public_key) {
//     std::cout << "Verifying " << message << std::endl;
//     std::vector<uint8_t> signature_vec(signature.begin(), signature.end());
//     std::vector<uint8_t> public_key_vec(public_key.begin(), public_key.end());
//     // Verify the signature
//     OQS_STATUS status = OQS_SIG_verify(signer, reinterpret_cast<const uint8_t*>(message.data()), message.size(), signature_vec.data(), signature_vec.size(), public_key_vec.data());
//     if (status == OQS_SUCCESS) {
//         return true;
//     } else {
//         return false;
//     }
// }

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


    // Write to redis
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

        std::string message = domain + "," + ip;
        std::string signature = sign_message(message, signer, secret_key);

        //std::string public_key_str(reinterpret_cast<char*>(public_key), signer->length_public_key);
        // Read the public key from file
        // std::ifstream pub_file("pubkey.key");
        // if (!pub_file.is_open()) {
        //     std::cerr << "Failed to open pubkey.key\n";
        //     return 1;
        // }
        // std::string pubkey((std::istreambuf_iterator<char>(pub_file)), std::istreambuf_iterator<char>());
        //assert(verify_message(message, signer, signature, pubkey));

        if(domain == "google.com") {
            std::cout << "SIGNATURE HASH " << to_hex_string(sha256(signature)) << std::endl;
            //std::cout << "!!!!!" << signature << "!!!!!\n";
        }
        std::string buffer = domain + "," + ip + "," + signature;

        std::string totalHash = "";
        int totalNumHashes = 0;
        std::vector<std::string> hashes;
        for (size_t i = 0; i < buffer.size(); i += FragmentSize) {
            std::string hash = sha256(buffer.substr(i, FragmentSize));
            hashes.push_back(hash);
            totalHash += hash;
            totalNumHashes++;
        }
        totalHash = sha256(totalHash);

        std::string new_buffer = totalHash + " " + " "; // The spaces will be replaced with the number of hashes, and chunks
        for (const auto& hash : hashes) {
            new_buffer += hash;
        }
        new_buffer += buffer;

        // Insert the number of chunks after the total hash
        int numChunks = 0;
        for (size_t i = 0; i < new_buffer.size(); i += FragmentSize) {
            numChunks += 1;
        }
        new_buffer.replace(32, 1, std::string(1, static_cast<char>(totalNumHashes)));
        new_buffer.replace(33, 1, std::string(1, static_cast<char>(numChunks)));

        // Now the formatting of new_buffer is like so:
        // - Total hash
        // - Number of fragments
        // - Hash 1
        // - Hash 2
        // - Hash 3
        // - ...
        // - Hash N
        // - Domain,
        // - IP,
        // - Signature(Domain, IP)

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
