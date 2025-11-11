#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDir>
#include <QMessageBox>
#include <QString>
#include <fstream>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // ensure directories
    fs::create_directories("certs");
    fs::create_directories("messages");



    // populate file lists (Alice/Bob)
    ui->listAliceFiles->clear();
    ui->listAliceFiles->addItem("messages/message.txt");
    ui->listBobFiles->clear();
    ui->listBobFiles->addItem("messages/received.bin (output)");

    logCA("Ready. Use CA -> Generate CA keys, then Issue certs.");
    logAlice("Write message into messages/message.txt or use the UI.");
    logBob("Waiting for incoming message.");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::logCA(const QString &msg) {
    ui->plainCAInfo->appendPlainText(msg);
}
void MainWindow::logAlice(const QString &msg) {
    ui->plainAliceLog->appendPlainText(msg);
}
void MainWindow::logBob(const QString &msg) {
    ui->plainBobLog->appendPlainText(msg);
}

// Save/load certificates as simple text (subject,pub_e,pub_n,signature list)
void MainWindow::saveCertificate(const Certificate& cert, const std::string& filename) {
    std::ofstream f(filename, std::ios::trunc);
    f << "subject:" << cert.subject << "\n";
    f << "pub_e:" << cert.pub_e << "\n";
    f << "pub_n:" << cert.pub_n << "\n";
    f << "signature:";
    for (auto s : cert.signature) f << s << " ";
    f << "\n";
    f.close();
}

Certificate MainWindow::loadCertificate(const std::string& filename) {
    Certificate cert;
    std::ifstream f(filename);
    if (!f.is_open()) throw std::runtime_error("Cannot open certificate file: " + filename);
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("subject:", 0) == 0) cert.subject = line.substr(8);
        else if (line.rfind("pub_e:", 0) == 0) cert.pub_e = std::stoll(line.substr(6));
        else if (line.rfind("pub_n:", 0) == 0) cert.pub_n = std::stoll(line.substr(6));
        else if (line.rfind("signature:", 0) == 0) {
            std::istringstream s(line.substr(10));
            n_type val;
            while (s >> val) cert.signature.push_back(val);
        }
    }
    f.close();
    return cert;
}

// Sign certificate using rsaSigner (CA)
std::vector<n_type> MainWindow::signCert(const Certificate& cert, RSA& rsaSigner) {
    std::string data = cert.subject + std::to_string(cert.pub_e) + std::to_string(cert.pub_n);
    std::vector<uint8_t> bytes(data.begin(), data.end());
    std::vector<uint8_t> h = md5.hash(bytes);
    std::vector<n_type> sig;
    for (auto b : h) {
        sig.push_back(rsaSigner.mod_pow(b, rsaSigner.get_private().first, rsaSigner.get_private().second));
    }
    return sig;
}

// Verify certificate signed by CA
bool MainWindow::verifyCert(const Certificate& cert, const Certificate& caCert) {
    std::string data = cert.subject + std::to_string(cert.pub_e) + std::to_string(cert.pub_n);
    std::vector<uint8_t> bytes(data.begin(), data.end());
    std::vector<uint8_t> h = md5.hash(bytes);
    for (size_t i = 0; i < cert.signature.size(); ++i) {
        n_type decrypted = RSA().mod_pow(cert.signature[i], caCert.pub_e, caCert.pub_n);
        if (i < h.size()) {
            if (decrypted != h[i]) return false;
        } else {
            // signature longer than hash: fail
            return false;
        }
    }
    return true;
}

// ------------------ Slots (buttons) -----------------------

void MainWindow::on_btnGenCA_clicked()
{
    rsaCA.initialize();
    certCA.subject = "CA";
    certCA.pub_e = rsaCA.get_public().first;
    certCA.pub_n = rsaCA.get_public().second;
    certCA.signature.clear(); // CA is trusted (no signature)
    saveCertificate(certCA, "certs/CA.txt");
    logCA(QString("CA keys generated. public (e,n) = (%1,%2)")
              .arg(QString::number(certCA.pub_e)).arg(QString::number(certCA.pub_n)));
    logCA(QString("CA private (d,n) saved in memory for signing (not on disk in this demo)."));
}

void MainWindow::on_btnIssueCerts_clicked()
{
    // generate keys for Alice and Bob and issue certs signed by CA
    rsaAlice.initialize();
    certAlice.subject = "Alice";
    certAlice.pub_e = rsaAlice.get_public().first;
    certAlice.pub_n = rsaAlice.get_public().second;
    certAlice.signature = signCert(certAlice, rsaCA);
    saveCertificate(certAlice, "certs/Alice.txt");
    logCA(QString("Alice cert issued: (e,n)=(%1,%2)").arg(QString::number(certAlice.pub_e)).arg(QString::number(certAlice.pub_n)));

    rsaBob.initialize();
    certBob.subject = "Bob";
    certBob.pub_e = rsaBob.get_public().first;
    certBob.pub_n = rsaBob.get_public().second;
    certBob.signature = signCert(certBob, rsaCA);
    saveCertificate(certBob, "certs/Bob.txt");
    logCA(QString("Bob cert issued: (e,n)=(%1,%2)").arg(QString::number(certBob.pub_e)).arg(QString::number(certBob.pub_n)));

    logAlice("Certificates for Alice and Bob saved to certs/ folder.");
}

void MainWindow::on_btnReqBobCert_clicked()
{
    try {
        certBob = loadCertificate("certs/Bob.txt");
    } catch (const std::exception &ex) {
        QMessageBox::warning(this, "Request cert", "Cannot load certs/Bob.txt: " + QString::fromStdString(ex.what()));
        return;
    }
    if (!verifyCert(certBob, certCA)) {
        logAlice("Bob certificate verification: INVALID (reject).");
        QMessageBox::warning(this, "Bob cert", "Bob certificate invalid!");
    } else {
        logAlice("Bob certificate verification: VALID (accepted).");
        // show to Alice: Bob public key used for encrypting RC4 key
        logAlice(QString("Bob pub (e,n) = (%1,%2)").arg(QString::number(certBob.pub_e)).arg(QString::number(certBob.pub_n)));
    }
}

void MainWindow::on_btnEncrypt_clicked()
{
    // читаем сообщение
    std::string message;
    QString uiMsg = ui->plainAliceMessage->toPlainText();
    if (!uiMsg.trimmed().isEmpty()) {
        message = uiMsg.toStdString();
    } else {
        std::ifstream in("messages/message.txt", std::ios::binary);
        if (!in.is_open()) {
            QMessageBox::warning(this, "Encrypt", "No message provided in UI and messages/message.txt not found.");
            return;
        }
        message.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    std::vector<uint8_t> plaintext(message.begin(), message.end());
    logAlice(QString("Plaintext size: %1 bytes").arg((int)plaintext.size()));

    // RC4 ключ
    rc4Key = {1,2,3,4,5,6,7,8}; // demo
    logAlice("RC4 key generated (demo constant).");

    // шифруем RC4
    RC4 rc4(rc4Key);
    ciphertext = rc4.encrypt(plaintext);
    logAlice(QString("Message encrypted with RC4 (%1 bytes)").arg((int)ciphertext.size()));

    // подпись (оставим как в оригинале)
    std::vector<uint8_t> combined = rc4Key;
    combined.insert(combined.end(), plaintext.begin(), plaintext.end());
    std::vector<uint8_t> hh = md5.hash(combined);

    signature.clear();
    for (auto b : hh) {
        signature.push_back(RSA().mod_pow(b, rsaAlice.get_private().first, rsaAlice.get_private().second));
    }
    logAlice("Signature generated (ready to send).");

}

void MainWindow::on_btnSend_clicked()
{
    if (ciphertext.empty() || rc4Key.empty()) {
        QMessageBox::warning(this, "Send", "Message not encrypted yet.");
        return;
    }

    // сохраняем зашифрованное сообщение
    std::ofstream fout("messages/message.enc", std::ios::binary);
    fout.write(reinterpret_cast<const char*>(ciphertext.data()), (std::streamsize)ciphertext.size());
    fout.close();
    logAlice(QString("Message saved to messages/message.enc (%1 bytes)").arg((int)ciphertext.size()));

    // шифруем RC4 ключ с использованием публичного ключа Боба
    if (certBob.pub_n == 0 || certBob.pub_e == 0) {
        QMessageBox::warning(this, "Send", "Bob certificate not loaded. Click 'Request Bob Cert' first.");
        return;
    }
    rc4KeyEncrypted.clear();
    for (auto b : rc4Key) {
        rc4KeyEncrypted.push_back(RSA().mod_pow(b, certBob.pub_e, certBob.pub_n));
    }

    std::ofstream kf("messages/rc4key.enc", std::ios::binary);
    for (auto n : rc4KeyEncrypted) kf << n << " ";
    kf.close();
    logAlice("RC4 key encrypted with Bob's public key and saved to messages/rc4key.enc");


    std::ofstream sf("messages/signature.sig", std::ios::binary);
    for (auto s : signature) sf << s << " ";
    sf.close();

    // имитация отправки
    fs::copy_file("messages/message.enc", "messages/received.enc", fs::copy_options::overwrite_existing);
    fs::copy_file("messages/rc4key.enc", "messages/received_rc4key.enc", fs::copy_options::overwrite_existing);
    fs::copy_file("messages/signature.sig", "messages/received_signature.sig", fs::copy_options::overwrite_existing);

    logAlice("Files sent. Bob can now press 'Decrypt message'.");
}


void MainWindow::on_btnDecrypt_clicked()
{
    // Bob decrypts rc4 key using his private key
    std::ifstream kf("messages/received_rc4key.enc", std::ios::binary);
    if (!kf.is_open()) {
        QMessageBox::warning(this, "Decrypt", "No encrypted rc4 key found (messages/received_rc4key.enc).");
        return;
    }
    // read numbers
    rc4KeyEncrypted.clear();
    n_type tmp;
    while (kf >> tmp) rc4KeyEncrypted.push_back(tmp);
    kf.close();
    if (rc4KeyEncrypted.empty()) {
        logBob("Received rc4 key file empty.");
        return;
    }

    // decrypt each number with Bob private key
    std::vector<uint8_t> rc4Recovered;
    for (auto n : rc4KeyEncrypted) {
        uint8_t b = static_cast<uint8_t>(RSA().mod_pow(n, rsaBob.get_private().first, rsaBob.get_private().second));
        rc4Recovered.push_back(b);
    }
    logBob("RC4 key recovered by Bob.");

    // read ciphertext
    std::ifstream fin("messages/received.enc", std::ios::binary);
    if (!fin.is_open()) {
        QMessageBox::warning(this, "Decrypt", "No received.enc found.");
        return;
    }
    std::vector<uint8_t> ctext((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    // decrypt message
    RC4 rc4b(rc4Recovered);
    std::vector<uint8_t> plain = rc4b.decrypt(ctext);
    std::string out(plain.begin(), plain.end());
    ui->plainDecrypted->setPlainText(QString::fromStdString(out));
    logBob("Message decrypted and displayed.");
}

void MainWindow::on_btnVerify_clicked()
{
    // read signature file
    std::ifstream sf("messages/received_signature.sig", std::ios::binary);
    if (!sf.is_open()) {
        QMessageBox::warning(this, "Verify", "No signature found (messages/received_signature.sig).");
        return;
    }
    std::vector<n_type> recvSig;
    n_type v;
    while (sf >> v) recvSig.push_back(v);
    sf.close();

    // read message and rc4 recovered
    std::ifstream fin("messages/received.enc", std::ios::binary);
    if (!fin.is_open()) { QMessageBox::warning(this, "Verify", "No received.enc"); return; }
    std::vector<uint8_t> ctext((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    // decrypt rc4key (again)
    std::ifstream kf("messages/received_rc4key.enc", std::ios::binary);
    if (!kf.is_open()) { QMessageBox::warning(this, "Verify", "No received_rc4key.enc"); return; }
    std::vector<n_type> recvEnc;
    n_type tmp;
    while (kf >> tmp) recvEnc.push_back(tmp);
    kf.close();
    std::vector<uint8_t> rc4Recovered;
    for (auto n : recvEnc) rc4Recovered.push_back(static_cast<uint8_t>(RSA().mod_pow(n, rsaBob.get_private().first, rsaBob.get_private().second)));

    // decrypt message
    RC4 rc4b(rc4Recovered);
    std::vector<uint8_t> plain = rc4b.decrypt(ctext);

    // recompute hash (rc4Key + message)
    std::vector<uint8_t> combined = rc4Recovered;
    combined.insert(combined.end(), plain.begin(), plain.end());
    std::vector<uint8_t> hh = md5.hash(combined);

    // decrypt signature using Alice's public key from cert (we have certAlice on CA issue)
    std::vector<uint8_t> decryptedHash;
    for (auto s : recvSig) {
        uint8_t val = static_cast<uint8_t>(RSA().mod_pow(s, certAlice.pub_e, certAlice.pub_n));
        decryptedHash.push_back(val);
    }

    if (decryptedHash == hh) {
        logBob("Signature verification: VALID");
        QMessageBox::information(this, "Verify", "Signature VALID");
    } else {
        logBob("Signature verification: INVALID");
        QMessageBox::warning(this, "Verify", "Signature INVALID");
    }
}
