#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>
#include <regex>
#include <sstream>
#include <string>
#include <sw/redis++/redis++.h>
#include <vector>

std::string alexa_file_name;  // Global variable

const bool UseVerbose = false;     // Whether or not to print all the debugging messages
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

// Determine if an algorithm is classical (true) or post-quantum (false)
bool is_algorithm_classical(const std::string& algorithm) {
    return (algorithm.compare(0, 3, "rsa") == 0 ||
            algorithm.compare(0, 4, "secp") == 0 ||
            algorithm.compare(0, 4, "sect") == 0);
}

// Generate a key pair, supported algorithms are as follows:
// "secp224r1", "secp256k1", "secp384r1", "secp521r1", "sect571r1",
// "rsa1024", "rsa2048", "rsa4096", "Dilithium2", "Dilithium3", "Dilithium5",
// "Falcon-512", "Falcon-1024", "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple",
// "SPHINCS+-SHA2-192f-simple", "SPHINCS+-SHA2-192s-simple", "SPHINCS+-SHA2-256f-simple",
// "SPHINCS+-SHA2-256s-simple", "SPHINCS+-SHAKE-128f-simple", "SPHINCS+-SHAKE-128s-simple",
// "SPHINCS+-SHAKE-192f-simple", "SPHINCS+-SHAKE-192s-simple", "SPHINCS+-SHAKE-256f-simple", "SPHINCS+-SHAKE-256s-simple"
std::tuple<uint8_t*, uint8_t*, size_t, size_t> generate_key(const std::string& algorithm, OQS_SIG* signer = NULL) {
    if (is_algorithm_classical(algorithm)) {
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY_keygen_init(pctx);

        if (algorithm == "secp224r1")
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp224r1);
        else if (algorithm == "secp256k1")
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1);
        else if (algorithm == "secp384r1")
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
        else if (algorithm == "secp521r1")
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1);
        else if (algorithm == "sect571r1")
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sect571r1);
        else if (algorithm == "rsa1024" || algorithm == "rsa2048" || algorithm == "rsa4096")
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, stoi(algorithm.substr(3)));
        else {
            std::cerr << "Unsupported algorithm." << std::endl;
            return std::make_tuple(nullptr, nullptr, 0, 0);
        }

        EVP_PKEY_keygen(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);

        uint8_t *secret_key = nullptr, *public_key = nullptr;
        int secret_key_len = i2d_PrivateKey(pkey, &secret_key);
        int public_key_len = i2d_PUBKEY(pkey, &public_key);

        EVP_PKEY_free(pkey);

        return std::make_tuple(secret_key, public_key, secret_key_len, public_key_len);

    } else { // Post-quantum signature algorithms

        uint8_t *public_key = (uint8_t *) malloc(signer->length_public_key);
        uint8_t *secret_key = (uint8_t *) malloc(signer->length_secret_key);

        // Generate the key pair
        if (OQS_SIG_keypair(signer, public_key, secret_key) != OQS_SUCCESS) {
            std::cerr << "Failed to generate key pair" << std::endl;
            return std::make_tuple(nullptr, nullptr, 0, 0);
        }

        return std::make_tuple(secret_key, public_key, signer->length_secret_key, signer->length_public_key);
    }
}


// Function to sign a message
std::string sign_message(const std::string& algorithm, const std::string& message, const uint8_t* secret_key, size_t secret_key_length, OQS_SIG* signer = NULL) {
    if (is_algorithm_classical(algorithm)) {
        const EVP_MD* md;
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = NULL;
        EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &secret_key, secret_key_length);
        size_t signature_len;

        if (algorithm.find("rsa") != std::string::npos)
            md = EVP_sha256(); // Set the digest method directly. Here, I've used SHA256 as an example.
        else
            md = EVP_get_digestbynid(EVP_PKEY_type(EVP_PKEY_id(pkey))); // Get the digest method based on key type

        EVP_DigestSignInit(mdctx, &pctx, md, NULL, pkey);
        EVP_DigestSignUpdate(mdctx, reinterpret_cast<const unsigned char*>(message.c_str()), message.size());

        EVP_DigestSignFinal(mdctx, NULL, &signature_len); // Determine the buffer length

        std::vector<uint8_t> signature_vec(signature_len);
        EVP_DigestSignFinal(mdctx, signature_vec.data(), &signature_len);

        EVP_MD_CTX_free(mdctx);

        return std::string(signature_vec.begin(), signature_vec.end());

    } else {
        std::vector<uint8_t> signature(signer->length_signature);
        size_t signature_len;

        if (OQS_SIG_sign(signer, signature.data(), &signature_len, reinterpret_cast<const uint8_t*>(message.data()), message.size(), secret_key) != OQS_SUCCESS) {
            std::cerr << "Failed to sign message\n";
            exit(1);
        }

        return std::string(signature.begin(), signature.begin() + signature_len);
    }
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
        std::cerr << "Usage: " << argv[0] << " <algorithm> [alexa_file_name]\n";
        return 1;
    }
    std::string algorithm = argv[1];
    // Set Alexa file name if provided
    alexa_file_name = (argc >= 3) ? argv[2] : "alexa_top_1.csv";

    uint8_t *secret_key, *public_key;
    size_t public_key_length, secret_key_length;
    OQS_SIG* signer = NULL;

    if (!is_algorithm_classical(algorithm)) {
        signer = OQS_SIG_new(algorithm.c_str());
        if (signer == NULL) {
            std::cerr << "Failed to initialize " << algorithm << " signer\n";
            return 1;
        }
        std::tie(secret_key, public_key, secret_key_length, public_key_length) = generate_key(algorithm, signer);
    } else {
        std::tie(secret_key, public_key, secret_key_length, public_key_length) = generate_key(algorithm);
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
    public_file.write(reinterpret_cast<char*>(public_key), public_key_length);
    public_file.close();

    std::ofstream private_file("privkey.key", std::ios::binary);
    if (!private_file.is_open()) {
        std::cerr << "Failed to open privkey.key\n";
        return 1;
    }
    private_file.write(reinterpret_cast<char*>(secret_key), secret_key_length);
    private_file.close();


    // Write to redis
    sw::redis::Redis redis("tcp://127.0.0.1:6379");
    redis.set("ALGORITHM_USED", algorithm);
    redis.set("PUBLIC_KEY", std::string(reinterpret_cast<char*>(public_key), public_key_length));
    redis.set("PRIVATE_KEY", std::string(reinterpret_cast<char*>(secret_key), secret_key_length));

    std::ifstream file(alexa_file_name);
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
        std::string signature = sign_message(algorithm, message, secret_key, secret_key_length, signer);

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
            if(UseVerbose) {
                std::cout << "\tFragment " << (index + 1) << ", " << fragment.length() << " bytes\n";
            }
            write_to_redis(domain, index, fragment);
        }

        if(UseVerbose) {
            std::cout << "Wrote " << (1 + new_buffer.size() / FragmentSize) << " fragments for " << domain << " = " << ip << "\n";
        }
    }
    
    // Cleanup
    if (is_algorithm_classical(algorithm)) {
        // For classical algorithms, the private and public keys are stored in OpenSSL's BIO buffers
        // The memory must be manually freed
        BIO *secret_bio = BIO_new(BIO_s_mem());
        BIO_write(secret_bio, secret_key, secret_key_length); // Write to BIO
        BIO_free(secret_bio);

        BIO *public_bio = BIO_new(BIO_s_mem());
        BIO_write(public_bio, public_key, public_key_length); // Write to BIO
        BIO_free(public_bio);
    } else {
        // For post-quantum algorithms, the keys are allocated with malloc and must be freed with free
        free(secret_key);
        free(public_key);
        OQS_SIG_free(signer);
    }

    if(UseVerbose) {
        std::cout << "Done!\n";
    }

    return 0;
}
