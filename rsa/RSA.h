#pragma once
#include <utility>
#include <vector>
#include <cstdint>

typedef long long n_type;
class RSA {
private:
	n_type p, q, n, e, d, euler;
public:
	// generating key variables
	void set_euler();
	void generate_n();
	n_type generate_prime();
	void set_e();
	void set_d();
	
	// init
	void initialize();

	//encryption and decryption
	std::vector<n_type> encrypt(const std::vector<uint8_t>& plaintext);
	std::vector<uint8_t> decrypt(const std::vector<n_type>& plaintext);

	// utility
	n_type gcd(n_type a, n_type b);
	std::tuple<n_type, n_type, n_type> extended_gcd(n_type a, n_type b);
	n_type mod_pow(n_type base, n_type exponent, n_type modulus);
	void print_results();

	// example
	void example();

	// getters
	std::pair<n_type, n_type> get_public();
	std::pair<n_type, n_type> get_private();
};