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

    // создаем директории
    fs::create_directories("certs");         // только CA
    fs::create_directories("Alice");
    fs::create_directories("Alice/outbox");
    fs::create_directories("Bob");
    fs::create_directories("Bob/inbox");

    // инициализация UI
    ui->listAliceFiles->clear();
    ui->listAliceFiles->addItem("Alice/message.txt");
    ui->listBobFiles->clear();
    ui->listBobFiles->addItem("Bob/inbox/received.enc (output)");

    logCA("Ready. Use CA -> Generate CA keys, then Issue certs.");
    logAlice("Write message into Alice/message.txt or use the UI.");
    logBob("Waiting for incoming message.");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::logCA(const QString &msg) { ui->plainCAInfo->appendPlainText(msg); }
void MainWindow::logAlice(const QString &msg) { ui->plainAliceLog->appendPlainText(msg); }
void MainWindow::logBob(const QString &msg) { ui->plainBobLog->appendPlainText(msg); }

// ---------------------------------------------------------------------

void MainWindow::saveCertificate(const Certificate& cert, const std::string& filename) {
    std::ofstream f(filename, std::ios::trunc);
    f << "subject:" << cert.subject << "\n";
    f << "pub_e:" << cert.pub_e << "\n";
    f << "pub_n:" << cert.pub_n << "\n";
    f << "signature:";
    for (auto s : cert.signature) f << s << " ";
    f << "\n";
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
    return cert;
}

std::vector<n_type> MainWindow::signCert(const Certificate& cert, RSA& rsaSigner) {
    std::string data = cert.subject + std::to_string(cert.pub_e) + std::to_string(cert.pub_n);
    std::vector<uint8_t> bytes(data.begin(), data.end());
    std::vector<uint8_t> h = md5.hash(bytes);
    std::vector<n_type> sig;
    for (auto b : h)
        sig.push_back(rsaSigner.mod_pow(b, rsaSigner.get_private().first, rsaSigner.get_private().second));
    return sig;
}

bool MainWindow::verifyCert(const Certificate& cert, const Certificate& caCert) {
    std::string data = cert.subject + std::to_string(cert.pub_e) + std::to_string(cert.pub_n);
    std::vector<uint8_t> bytes(data.begin(), data.end());
    std::vector<uint8_t> h = md5.hash(bytes);
    for (size_t i = 0; i < cert.signature.size(); ++i) {
        n_type decrypted = RSA().mod_pow(cert.signature[i], caCert.pub_e, caCert.pub_n);
        if (i >= h.size() || decrypted != h[i]) return false;
    }
    return true;
}

// ---------------------------------------------------------------------

void MainWindow::on_btnGenCA_clicked()
{
    rsaCA.initialize();
    certCA.subject = "CA";
    certCA.pub_e = rsaCA.get_public().first;
    certCA.pub_n = rsaCA.get_public().second;
    certCA.signature.clear(); // корневой сертификат самоподписан
    saveCertificate(certCA, "certs/CA.txt");

    logCA(QString("CA keys generated. public (e,n) = (%1,%2)")
              .arg(QString::number(certCA.pub_e))
              .arg(QString::number(certCA.pub_n)));
    logCA("CA private key stored in memory for signing.");
}

void MainWindow::on_btnIssueCerts_clicked()
{
    // Генерируем сертификат Алисы
    rsaAlice.initialize();
    certAlice.subject = "Alice";
    certAlice.pub_e = rsaAlice.get_public().first;
    certAlice.pub_n = rsaAlice.get_public().second;
    certAlice.signature = signCert(certAlice, rsaCA);
    saveCertificate(certAlice, "Alice/cert_Alice.txt");
    logCA("Issued certificate for Alice (saved in Alice/cert_Alice.txt)");

    // Генерируем сертификат Боба
    rsaBob.initialize();
    certBob.subject = "Bob";
    certBob.pub_e = rsaBob.get_public().first;
    certBob.pub_n = rsaBob.get_public().second;
    certBob.signature = signCert(certBob, rsaCA);
    saveCertificate(certBob, "Bob/cert_Bob.txt");
    logCA("Issued certificate for Bob (saved in Bob/cert_Bob.txt)");
}

void MainWindow::on_btnReqBobCert_clicked()
{
    try {
        // Алиса получает сертификат Боба
        fs::copy_file("Bob/cert_Bob.txt", "Alice/Bob_cert.txt", fs::copy_options::overwrite_existing);
        certBob = loadCertificate("Alice/Bob_cert.txt");
    } catch (const std::exception &ex) {
        QMessageBox::warning(this, "Request cert", "Cannot load Bob cert: " + QString::fromStdString(ex.what()));
        return;
    }

    if (!verifyCert(certBob, certCA)) {
        logAlice("Bob certificate verification: INVALID");
        QMessageBox::warning(this, "Bob cert", "Bob certificate invalid!");
    } else {
        logAlice("Bob certificate verification: VALID");
        logAlice(QString("Bob pub (e,n) = (%1,%2)")
                     .arg(QString::number(certBob.pub_e))
                     .arg(QString::number(certBob.pub_n)));
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
        std::ifstream in("Alice/message.txt", std::ios::binary);
        if (!in.is_open()) {
            QMessageBox::warning(this, "Encrypt", "No message provided in UI or Alice/message.txt not found.");
            return;
        }
        message.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    std::vector<uint8_t> plaintext(message.begin(), message.end());
    logAlice(QString("Plaintext size: %1 bytes").arg((int)plaintext.size()));

    rc4Key = {1,2,3,4,5,6,7,8}; // demo key
    logAlice("RC4 key generated (demo constant).");

    RC4 rc4(rc4Key);
    ciphertext = rc4.encrypt(plaintext);
    logAlice(QString("Message encrypted with RC4 (%1 bytes)").arg((int)ciphertext.size()));

    // подписываем (RC4 ключ + исходное сообщение)
    std::vector<uint8_t> combined = rc4Key;
    combined.insert(combined.end(), plaintext.begin(), plaintext.end());
    std::vector<uint8_t> hh = md5.hash(combined);

    signature.clear();
    for (auto b : hh)
        signature.push_back(RSA().mod_pow(b, rsaAlice.get_private().first, rsaAlice.get_private().second));

    // сохраняем локально у Алисы
    std::ofstream("Alice/message.enc", std::ios::binary)
        .write((const char*)ciphertext.data(), ciphertext.size());
    std::ofstream sf("Alice/signature.sig", std::ios::binary);
    for (auto s : signature) sf << s << " ";
    sf.close();

    logAlice("Message encrypted and signed (stored locally).");
}

void MainWindow::on_btnSend_clicked()
{
    if (ciphertext.empty() || rc4Key.empty()) {
        QMessageBox::warning(this, "Send", "Message not encrypted yet.");
        return;
    }

    if (certBob.pub_n == 0 || certBob.pub_e == 0) {
        QMessageBox::warning(this, "Send", "Bob certificate not loaded.");
        return;
    }

    // шифруем RC4 ключ публичным ключом Боба
    rc4KeyEncrypted.clear();
    for (auto b : rc4Key)
        rc4KeyEncrypted.push_back(RSA().mod_pow(b, certBob.pub_e, certBob.pub_n));

    std::ofstream kf("Alice/rc4key.enc", std::ios::binary);
    for (auto n : rc4KeyEncrypted) kf << n << " ";
    kf.close();

    // копируем все файлы в Bob/inbox
    fs::copy_file("Alice/message.enc", "Bob/inbox/received.enc", fs::copy_options::overwrite_existing);
    fs::copy_file("Alice/rc4key.enc", "Bob/inbox/received_rc4key.enc", fs::copy_options::overwrite_existing);
    fs::copy_file("Alice/signature.sig", "Bob/inbox/received_signature.sig", fs::copy_options::overwrite_existing);
    fs::copy_file("Alice/cert_Alice.txt", "Bob/inbox/Alice_cert.txt", fs::copy_options::overwrite_existing);

    logAlice("Files sent to Bob/inbox (message, rc4key, signature, cert).");
}

void MainWindow::on_btnDecrypt_clicked()
{
    // читаем зашифрованный RC4 ключ
    std::ifstream kf("Bob/inbox/received_rc4key.enc", std::ios::binary);
    if (!kf.is_open()) {
        QMessageBox::warning(this, "Decrypt", "No encrypted rc4 key found (Bob/inbox/received_rc4key.enc).");
        return;
    }

    rc4KeyEncrypted.clear();
    n_type tmp;
    while (kf >> tmp) rc4KeyEncrypted.push_back(tmp);
    kf.close();

    std::vector<uint8_t> rc4Recovered;
    for (auto n : rc4KeyEncrypted)
        rc4Recovered.push_back(static_cast<uint8_t>(RSA().mod_pow(n, rsaBob.get_private().first, rsaBob.get_private().second)));

    logBob("RC4 key recovered by Bob.");

    // читаем шифртекст
    std::ifstream fin("Bob/inbox/received.enc", std::ios::binary);
    if (!fin.is_open()) {
        QMessageBox::warning(this, "Decrypt", "No received.enc found.");
        return;
    }
    std::vector<uint8_t> ctext((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    RC4 rc4b(rc4Recovered);
    std::vector<uint8_t> plain = rc4b.decrypt(ctext);
    std::string out(plain.begin(), plain.end());
    ui->plainDecrypted->setPlainText(QString::fromStdString(out));

    std::ofstream("Bob/decrypted.txt", std::ios::binary).write(out.data(), out.size());
    logBob("Message decrypted and saved to Bob/decrypted.txt.");
}

void MainWindow::on_btnVerify_clicked()
{
    std::ifstream sf("Bob/inbox/received_signature.sig", std::ios::binary);
    if (!sf.is_open()) {
        QMessageBox::warning(this, "Verify", "No signature found (Bob/inbox/received_signature.sig).");
        return;
    }
    std::vector<n_type> recvSig;
    n_type v;
    while (sf >> v) recvSig.push_back(v);
    sf.close();

    // читаем rc4key
    std::ifstream kf("Bob/inbox/received_rc4key.enc", std::ios::binary);
    if (!kf.is_open()) { QMessageBox::warning(this, "Verify", "No received_rc4key.enc"); return; }
    std::vector<n_type> recvEnc;
    while (kf >> v) recvEnc.push_back(v);
    kf.close();

    std::vector<uint8_t> rc4Recovered;
    for (auto n : recvEnc)
        rc4Recovered.push_back(static_cast<uint8_t>(RSA().mod_pow(n, rsaBob.get_private().first, rsaBob.get_private().second)));

    // читаем сообщение
    std::ifstream fin("Bob/inbox/received.enc", std::ios::binary);
    if (!fin.is_open()) { QMessageBox::warning(this, "Verify", "No received.enc"); return; }
    std::vector<uint8_t> ctext((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    RC4 rc4b(rc4Recovered);
    std::vector<uint8_t> plain = rc4b.decrypt(ctext);

    // пересчитываем хэш
    std::vector<uint8_t> combined = rc4Recovered;
    combined.insert(combined.end(), plain.begin(), plain.end());
    std::vector<uint8_t> hh = md5.hash(combined);

    // проверяем подпись Алисы
    try {
        certAlice = loadCertificate("Bob/cert_Alice.txt");
    } catch (...) {
        QMessageBox::warning(this, "Verify", "Cannot load Alice certificate.");
        return;
    }

    std::vector<uint8_t> decryptedHash;
    for (auto s : recvSig)
        decryptedHash.push_back(static_cast<uint8_t>(RSA().mod_pow(s, certAlice.pub_e, certAlice.pub_n)));

    if (decryptedHash == hh) {
        logBob("Signature verification: VALID");
        QMessageBox::information(this, "Verify", "Signature VALID");
    } else {
        logBob("Signature verification: INVALID");
        QMessageBox::warning(this, "Verify", "Signature INVALID");
    }
}
