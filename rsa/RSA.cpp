#include "RSA.h"
#include <random>
#include <iostream>
#include <iomanip>
#include <fstream>
void RSA::set_euler()
{
	this->euler = (this->q - 1) * (this->p - 1);
}

void RSA::generate_n()
{
	bool q_flag = false;
	this->p = generate_prime();
	this->q = generate_prime();
	while (this->p == this->q) {
		this->q = generate_prime();
	}
	this->n = this->p * this->q;
}

n_type RSA::generate_prime()
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<std::mt19937::result_type> dist(100, 1000);
	n_type res = dist(gen);
	
	auto is_prime = [](n_type& n) {
		for (int d = 2; d <= sqrt(n); d++) {
			if (n % d == 0) return false;
		}
		return true;
	};
	while (!is_prime(res)) {
		res = dist(gen);
	}
	return res;
}



std::pair<n_type, n_type> RSA::get_public()
{
	return std::pair<n_type, n_type>(e,n);
}
std::pair<n_type, n_type> RSA::get_private()
{
	return std::pair<n_type, n_type>(d, n);
}

void RSA::print_results() {
	std::cout << std::dec << "p: " << this->p << " q: " << this->q << " n: " << this->n << " e: " << this->e << " d: " << this->d << std::endl;
}

void RSA::initialize()
{
	this->generate_n();
	this->set_euler();
	this->set_e();
	this->set_d();
	this->print_results();
}

void RSA::set_e()
{
	for (n_type i = 2; i < this->euler - 1; i++)
	{
		if (this->gcd(this->euler, i) == 1) {
			this->e = i;
			break;
		}
	}
}

n_type RSA::gcd(n_type a, n_type b)
{
	if (b == 0) {
		return a;
	}else {
		return this->gcd(b, a % b);
	}

}
std::tuple<n_type, n_type, n_type> RSA::extended_gcd(n_type a, n_type b) {
	if (b == 0) {
		return { a, 1, 0 };
	}

	auto [gcd, x1, y1] = extended_gcd(b, a % b);
	n_type x = y1;
	n_type y = x1 - (a / b) * y1;

	return { gcd, x, y };
}
void RSA::set_d()
{
	// ������: e * d = 1 (mod phi(n))
	auto [gcd, x, y] = extended_gcd(this->e, this->euler);

	if (gcd != 1) {
		throw std::runtime_error("e � phi(n) �� ������� ������");
	}

	n_type _d = x % this->euler;
	if (_d < 0) {
		_d += this->euler; 
	}

	this->d = _d;
}
n_type RSA::mod_pow(n_type base, n_type exponent, n_type modulus) {
	n_type result = 1;
	base = base % modulus;

	while (exponent > 0) {
		if (exponent & 1) {
			result = (result * base) % modulus;
		}
		base = (base * base) % modulus;
		exponent >>= 1;
	}
	return result;
}

std::vector<n_type> RSA::encrypt(const std::vector<uint8_t>& plaintext) {
	std::vector<n_type> result;
	for (auto byte : plaintext) {
		result.push_back(this->mod_pow(byte, this->e, this->n));
	}
	return result;
}

std::vector<uint8_t> RSA::decrypt(const std::vector<n_type>& ciphertext) {
	std::vector<uint8_t> result;
	for (auto num : ciphertext) {
		n_type decrypted = this->mod_pow(num, this->d, this->n);
		if (decrypted > 255) {
			throw std::runtime_error("�������������� �������� ��������� 255");
		}
		result.push_back(static_cast<uint8_t>(decrypted));
	}
	return result;
}

void RSA::example() {
	//n_type message = 31;
	//n_type encrypted = mod_pow(message, e, n);
	//n_type decrypted = mod_pow(encrypted, d, n);

	//std::cout << "Message " << message << std::endl;
	//std::cout << "Encrypted " << encrypted << std::endl;
	//std::cout << "Decrypted " << decrypted << std::endl;

	//std::cout << "######## Encrypting file ########" << std::endl;

	std::vector<uint8_t> ifile_content;
	std::ifstream file("test.txt", std::ios::binary);
	if (file.is_open()) {
		char ch;
		while (file.get(ch)) {
			ifile_content.push_back(static_cast<uint8_t>(ch));
		}
		file.close();
	}

	std::cout << "File content: ";
	for (auto ch : ifile_content) {
		std::cout << static_cast<char>(ch);
	}
	std::cout << std::endl;

	auto encrypted_text = this->encrypt(ifile_content);
	std::cout << "Encrypted file: ";
	for (auto byte : encrypted_text) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
	}
	std::cout << std::endl;

	
	auto decrypted_text = this->decrypt(encrypted_text);
	std::cout << "Decrypted file: ";
	for (auto byte : decrypted_text) {
		//std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
		std::cout << static_cast<char>(byte);
	}
	std::cout << std::endl;

}
