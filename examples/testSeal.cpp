
#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>


using namespace std;
using namespace seal;


inline void print_example_banner(std::string title)
{
    if (!title.empty())
    {
        std::size_t title_length = title.length();
        std::size_t banner_length = title_length + 2 * 10;
        std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
        std::string banner_middle = "|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

        std::cout << std::endl << banner_top << std::endl << banner_middle << std::endl << banner_top << std::endl;
    }
}


inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}


inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
           << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);

    return stream;
}


template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}


template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    std::size_t print_size = 5;

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
}


inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}


inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}


int main()
{
    print_example_banner("Example: Serialization");

    stringstream parms_stream;
    stringstream data_stream;
    stringstream sk_stream;

    {
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(1024);

        auto size = parms.save(parms_stream);
        print_line(__LINE__);
        cout << "EncryptionParameters: wrote " << size << " bytes" << endl;

        print_line(__LINE__);
        cout << "EncryptionParameters: data size upper bound (compr_mode_type::none): "
             << parms.save_size(compr_mode_type::none) << endl;
        cout << "             "
             << "EncryptionParameters: data size upper bound (compression): "
             << parms.save_size(/* Serialization::compr_mode_default */) << endl;

        /*
        As an example, we now serialize the encryption parameters to a fixed size
        buffer.
        */
        vector<seal_byte> byte_buffer(static_cast<size_t>(parms.save_size()));
        parms.save(reinterpret_cast<seal_byte *>(byte_buffer.data()), byte_buffer.size());


        EncryptionParameters parms2;
        parms2.load(reinterpret_cast<const seal_byte *>(byte_buffer.data()), byte_buffer.size());

        print_line(__LINE__);
        cout << "EncryptionParameters: parms == parms2: " << boolalpha << (parms == parms2) << endl;

    }


    {
        EncryptionParameters parms;
        parms.load(parms_stream);


        parms_stream.seekg(0, parms_stream.beg);

        SEALContext context(parms);
        KeyGenerator keygen(context);

        auto sk = keygen.secret_key();
        PublicKey pk;
        keygen.create_public_key(pk);
        

        sk.save(sk_stream);

        Serializable<RelinKeys> rlk = keygen.create_relin_keys();

        RelinKeys rlk_big;
        keygen.create_relin_keys(rlk_big);

        auto size_rlk = rlk.save(data_stream);
        auto size_rlk_big = rlk_big.save(data_stream);

        print_line(__LINE__);
        cout << "Serializable<RelinKeys>: wrote " << size_rlk << " bytes" << endl;
        cout << "             "
             << "RelinKeys wrote " << size_rlk_big << " bytes" << endl;


        data_stream.seekp(-size_rlk_big, data_stream.cur);


        uint64_t x = 6;
        Plaintext plain1(uint64_to_hex_string(x));
        Plaintext plain2(uint64_to_hex_string(x));

        Encryptor encryptor(context, pk);

        auto size_encrypted1 = encryptor.encrypt(plain1).save(data_stream);

        encryptor.set_secret_key(sk);
        auto size_sym_encrypted2 = encryptor.encrypt_symmetric(plain2).save(data_stream);

        /*
        Aluji: test the size of the ciphertext in seal.
        */
        print_line(__LINE__);
        cout << "Serializable<Ciphertext> (public-key): wrote " << size_encrypted1 << " bytes" << endl;
        cout << "             "
             << "Serializable<Ciphertext> (seeded secret-key): wrote " << size_sym_encrypted2 << " bytes" << endl;

        /*
        We have seen how creating seeded objects can result in huge space
        savings compared to creating unseeded objects. This is particularly
        important when creating Galois keys, which can be very large. We have
        seen how secret-key encryption can be used to achieve much smaller
        ciphertext sizes when the public-key functionality is not needed.

        We would also like to draw attention to the fact there we could easily
        serialize multiple Microsoft SEAL objects sequentially in a stream. Each
        object writes its own size into the stream, so deserialization knows
        exactly how many bytes to read. We will see this working below.
        */
    }

    /*
    The server can now compute on the encrypted data. We will recreate the
    SEALContext and set up an Evaluator here.
    */
    {
        EncryptionParameters parms;
        parms.load(parms_stream);
        parms_stream.seekg(0, parms_stream.beg);
        SEALContext context(parms);

        Evaluator evaluator(context);

        /*
        Next we need to load relinearization keys and the ciphertexts from our
        data_stream.
        */
        RelinKeys rlk;
        Ciphertext encrypted1, encrypted2;

        /*
        Deserialization is as easy as serialization.
        */
        rlk.load(context, data_stream);
        encrypted1.load(context, data_stream);
        encrypted2.load(context, data_stream);

        /*
        Compute the product, rescale, and relinearize.
        */
        Ciphertext encrypted_prod;
        evaluator.multiply(encrypted1, encrypted2, encrypted_prod);
        evaluator.relinearize_inplace(encrypted_prod, rlk);
        evaluator.rescale_to_next_inplace(encrypted_prod);

        /*
        we use data_stream to communicate encrypted_prod back to the client.
        there is no way to save the encrypted_prod as a seeded object: only
        freshly encrypted secret-key ciphertexts can be seeded. Note how the
        size of the result ciphertext is smaller than the size of a fresh
        ciphertext because it is at a lower level due to the rescale operation.
        */
        data_stream.seekp(0, parms_stream.beg);
        data_stream.seekg(0, parms_stream.beg);
        auto size_encrypted_prod = encrypted_prod.save(data_stream);

        print_line(__LINE__);
        cout << "Ciphertext (secret-key): wrote " << size_encrypted_prod << " bytes" << endl;
    }

    /*
    In the final step the client decrypts the result.
    */
    {
        EncryptionParameters parms;
        parms.load(parms_stream);
        parms_stream.seekg(0, parms_stream.beg);
        SEALContext context(parms);

        /*
        Load back the secret key from sk_stream.
        */
        SecretKey sk;
        sk.load(context, sk_stream);
        Decryptor decryptor(context, sk);
        CKKSEncoder encoder(context);

        Ciphertext encrypted_result;
        encrypted_result.load(context, data_stream);

        Plaintext plain_result;
        decryptor.decrypt(encrypted_result, plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);

        print_line(__LINE__);
        cout << "Result: " << endl;
        print_vector(result, 3, 7);
    }

    /*
    Finally, we give a little bit more explanation of the structure of data
    serialized by Microsoft SEAL. Serialized data always starts with a 16-byte
    SEALHeader struct, as defined in native/src/seal/serialization.h, and is
    followed by the possibly compressed data for the object.

    A SEALHeader contains the following data:

        [offset 0] 2-byte magic number 0xA15E (Serialization::seal_magic)
        [offset 2] 1-byte indicating the header size in bytes (always 16)
        [offset 3] 1-byte indicating the Microsoft SEAL major version number
        [offset 4] 1-byte indicating the Microsoft SEAL minor version number
        [offset 5] 1-byte indicating the compression mode type
        [offset 6] 2-byte reserved field (unused)
        [offset 8] 8-byte size in bytes of the serialized data, including the header

    Currently Microsoft SEAL supports only little-endian systems.

    As an example, we demonstrate the SEALHeader created by saving a plaintext.
    Note that the SEALHeader is never compressed, so there is no need to specify
    the compression mode.
    */
    Plaintext pt("1x^2 + 3");
    stringstream stream;
    auto data_size = pt.save(stream);

    /*
    We can now load just the SEALHeader back from the stream as follows.
    */
    Serialization::SEALHeader header;
    Serialization::LoadHeader(stream, header);

    /*
    Now confirm that the size of data written to stream matches with what is
    indicated by the SEALHeader.
    */
    print_line(__LINE__);
    cout << "Size written to stream: " << data_size << " bytes" << endl;
    cout << "             "
         << "Size indicated in SEALHeader: " << header.size << " bytes" << endl;
    cout << endl;
}


