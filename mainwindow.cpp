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
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // создаем структуру директорий
    fs::create_directories("certs");
    fs::create_directories("Alice/inbox");
    fs::create_directories("Alice/outbox");
    fs::create_directories("Alice/certs");
    fs::create_directories("Bob/inbox");
    fs::create_directories("Bob/outbox");
    fs::create_directories("Bob/certs");

    ui->listAliceFiles->clear();
    ui->listAliceFiles->addItem("Alice/outbox/message.enc");
    ui->listBobFiles->clear();
    ui->listBobFiles->addItem("Bob/inbox/message.enc");

    logCA("Ready. Use CA -> Generate CA keys, then Issue certs.");
    logAlice("Write message and press Encrypt + Send.");
    logBob("Waiting for message from Alice.");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::logCA(const QString &msg) { ui->plainCAInfo->appendPlainText(msg); }
void MainWindow::logAlice(const QString &msg) { ui->plainAliceLog->appendPlainText(msg); }
void MainWindow::logBob(const QString &msg) { ui->plainBobLog->appendPlainText(msg); }

// ---------- Сертификаты ----------

void MainWindow::saveCertificate(const Certificate &cert, const std::string &filename)
{
    std::ofstream f(filename, std::ios::trunc);
    f << "subject:" << cert.subject << "\n";
    f << "pub_e:" << cert.pub_e << "\n";
    f << "pub_n:" << cert.pub_n << "\n";
    f << "signature:";
    for (auto s : cert.signature)
        f << s << " ";
    f << "\n";
    f.close();
}

Certificate MainWindow::loadCertificate(const std::string &filename)
{
    Certificate cert;
    std::ifstream f(filename);
    if (!f.is_open())
        throw std::runtime_error("Cannot open certificate file: " + filename);

    std::string line;
    while (std::getline(f, line))
    {
        if (line.rfind("subject:", 0) == 0)
            cert.subject = line.substr(8);
        else if (line.rfind("pub_e:", 0) == 0)
            cert.pub_e = std::stoll(line.substr(6));
        else if (line.rfind("pub_n:", 0) == 0)
            cert.pub_n = std::stoll(line.substr(6));
        else if (line.rfind("signature:", 0) == 0)
        {
            std::istringstream s(line.substr(10));
            n_type val;
            while (s >> val)
                cert.signature.push_back(val);
        }
    }
    f.close();
    return cert;
}

std::vector<n_type> MainWindow::signCert(const Certificate &cert, RSA &rsaSigner)
{
    std::string data = cert.subject + std::to_string(cert.pub_e) + std::to_string(cert.pub_n);
    std::vector<uint8_t> bytes(data.begin(), data.end());
    std::vector<uint8_t> h = md5.hash(bytes);

    std::vector<n_type> sig;
    for (auto b : h)
    {
        sig.push_back(rsaSigner.mod_pow(b, rsaSigner.get_private().first, rsaSigner.get_private().second));
    }
    return sig;
}

bool MainWindow::verifyCert(const Certificate &cert, const Certificate &caCert)
{
    std::string data = cert.subject + std::to_string(cert.pub_e) + std::to_string(cert.pub_n);
    std::vector<uint8_t> bytes(data.begin(), data.end());
    std::vector<uint8_t> h = md5.hash(bytes);

    for (size_t i = 0; i < cert.signature.size(); ++i)
    {
        n_type decrypted = RSA().mod_pow(cert.signature[i], caCert.pub_e, caCert.pub_n);
        if (i < h.size())
        {
            if (decrypted != h[i])
                return false;
        }
        else
            return false;
    }
    return true;
}

// ---------- Слоты ----------

void MainWindow::on_btnGenCA_clicked()
{
    rsaCA.initialize();
    certCA.subject = "CA";
    certCA.pub_e = rsaCA.get_public().first;
    certCA.pub_n = rsaCA.get_public().second;
    certCA.signature.clear();
    saveCertificate(certCA, "certs/CA.txt");

    logCA("CA keys generated and saved to certs/CA.txt");
}

void MainWindow::on_btnIssueCerts_clicked()
{
    // Alice
    rsaAlice.initialize();
    certAlice.subject = "Alice";
    certAlice.pub_e = rsaAlice.get_public().first;
    certAlice.pub_n = rsaAlice.get_public().second;
    certAlice.signature = signCert(certAlice, rsaCA);
    saveCertificate(certAlice, "Alice/certs/Alice_cert.txt");

    // Bob
    rsaBob.initialize();
    certBob.subject = "Bob";
    certBob.pub_e = rsaBob.get_public().first;
    certBob.pub_n = rsaBob.get_public().second;
    certBob.signature = signCert(certBob, rsaCA);
    saveCertificate(certBob, "Bob/certs/Bob_cert.txt");

    logCA("Alice and Bob certificates issued.");
}

void MainWindow::on_btnReqBobCert_clicked()
{
    try
    {
        fs::copy_file("Bob/certs/Bob_cert.txt", "Alice/certs/Bob_cert.txt", fs::copy_options::overwrite_existing);
        certBob = loadCertificate("Alice/certs/Bob_cert.txt");
    }
    catch (const std::exception &ex)
    {
        QMessageBox::warning(this, "Request Cert", QString("Failed to get Bob certificate: ") + ex.what());
        return;
    }

    if (!verifyCert(certBob, certCA))
    {
        logAlice("Bob certificate verification: INVALID");
    }
    else
    {
        logAlice("Bob certificate verification: VALID");
        logAlice(QString("Bob pubkey: e=%1 n=%2").arg(QString::number(certBob.pub_e)).arg(QString::number(certBob.pub_n)));
    }
}

void MainWindow::on_btnEncrypt_clicked()
{
    std::string message;
    QString uiMsg = ui->plainAliceMessage->toPlainText();
    if (!uiMsg.trimmed().isEmpty())
        message = uiMsg.toStdString();
    else
    {
        QMessageBox::warning(this, "Encrypt", "No message in UI");
        return;
    }

    std::vector<uint8_t> plaintext(message.begin(), message.end());
    logAlice(QString("Plaintext size: %1 bytes").arg((int)plaintext.size()));

    rc4Key = {1, 2, 3, 4, 5, 6, 7, 8};
    RC4 rc4(rc4Key);
    ciphertext = rc4.encrypt(plaintext);
    logAlice("Message encrypted with RC4.");

    // подписываем хэш (ключ + сообщение)
    std::vector<uint8_t> combined = rc4Key;
    combined.insert(combined.end(), plaintext.begin(), plaintext.end());
    std::vector<uint8_t> hh = md5.hash(combined);

    signature.clear();
    for (auto b : hh)
        signature.push_back(RSA().mod_pow(b, rsaAlice.get_private().first, rsaAlice.get_private().second));

    logAlice("Signature generated.");

    // сохраняем все во временный outbox
    std::ofstream("Alice/outbox/message.enc", std::ios::binary).write((char *)ciphertext.data(), ciphertext.size());

    std::ofstream keyfile("Alice/outbox/rc4key.enc", std::ios::binary);
    for (auto n : rc4Key)
        keyfile << RSA().mod_pow(n, certBob.pub_e, certBob.pub_n) << " ";
    keyfile.close();

    std::ofstream sigfile("Alice/outbox/signature.sig", std::ios::binary);
    for (auto s : signature)
        sigfile << s << " ";
    sigfile.close();

    logAlice("Encrypted data saved to Alice/outbox/.");
}

void MainWindow::on_btnSend_clicked()
{
    try
    {
        fs::copy_file("Alice/outbox/message.enc", "Bob/inbox/message.enc", fs::copy_options::overwrite_existing);
        fs::copy_file("Alice/outbox/rc4key.enc", "Bob/inbox/rc4key.enc", fs::copy_options::overwrite_existing);
        fs::copy_file("Alice/outbox/signature.sig", "Bob/inbox/signature.sig", fs::copy_options::overwrite_existing);

        // передаем сертификат Алисы
        fs::copy_file("Alice/certs/Alice_cert.txt", "Bob/certs/Alice_cert.txt", fs::copy_options::overwrite_existing);

        logAlice("Message sent to Bob (files copied to Bob/inbox/).");
        logBob("New message received from Alice in Bob/inbox/.");
    }
    catch (const std::exception &ex)
    {
        QMessageBox::warning(this, "Send", QString("Error sending files: ") + ex.what());
    }
}

void MainWindow::on_btnDecrypt_clicked()
{
    // Расшифровка ключа
    std::ifstream kf("Bob/inbox/rc4key.enc", std::ios::binary);
    if (!kf.is_open())
    {
        QMessageBox::warning(this, "Decrypt", "No rc4key.enc in Bob/inbox/");
        return;
    }

    std::vector<n_type> encKey;
    n_type tmp;
    while (kf >> tmp)
        encKey.push_back(tmp);
    kf.close();

    std::vector<uint8_t> rc4Recovered;
    for (auto n : encKey)
        rc4Recovered.push_back((uint8_t)RSA().mod_pow(n, rsaBob.get_private().first, rsaBob.get_private().second));

    // Расшифровка сообщения
    std::ifstream fin("Bob/inbox/message.enc", std::ios::binary);
    std::vector<uint8_t> ctext((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    RC4 rc4b(rc4Recovered);
    std::vector<uint8_t> plain = rc4b.decrypt(ctext);
    ui->plainDecrypted->setPlainText(QString::fromStdString(std::string(plain.begin(), plain.end())));
    logBob("Message decrypted.");
}

void MainWindow::on_btnVerify_clicked()
{
    // читаем подпись
    std::ifstream sf("Bob/inbox/signature.sig", std::ios::binary);
    if (!sf.is_open())
    {
        QMessageBox::warning(this, "Verify", "No signature file in Bob/inbox/");
        return;
    }

    std::vector<n_type> recvSig;
    n_type v;
    while (sf >> v)
        recvSig.push_back(v);
    sf.close();

    // читаем зашифрованный ключ
    std::ifstream kf("Bob/inbox/rc4key.enc", std::ios::binary);
    std::vector<n_type> recvEnc;
    while (kf >> v)
        recvEnc.push_back(v);
    kf.close();

    std::vector<uint8_t> rc4Recovered;
    for (auto n : recvEnc)
        rc4Recovered.push_back((uint8_t)RSA().mod_pow(n, rsaBob.get_private().first, rsaBob.get_private().second));

    // расшифровываем сообщение
    std::ifstream fin("Bob/inbox/message.enc", std::ios::binary);
    std::vector<uint8_t> ctext((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    RC4 rc4b(rc4Recovered);
    std::vector<uint8_t> plain = rc4b.decrypt(ctext);

    // загружаем сертификат Алисы
    try
    {
        certAlice = loadCertificate("Bob/certs/Alice_cert.txt");
    }
    catch (...)
    {
        QMessageBox::warning(this, "Verify", "Cannot load Alice certificate.");
        return;
    }

    // проверяем подпись
    std::vector<uint8_t> combined = rc4Recovered;
    combined.insert(combined.end(), plain.begin(), plain.end());
    std::vector<uint8_t> hh = md5.hash(combined);

    std::vector<uint8_t> decryptedHash;
    for (auto s : recvSig)
        decryptedHash.push_back((uint8_t)RSA().mod_pow(s, certAlice.pub_e, certAlice.pub_n));

    if (decryptedHash == hh)
    {
        logBob("Signature verification: VALID");
        QMessageBox::information(this, "Verify", "Signature VALID");
    }
    else
    {
        logBob("Signature verification: INVALID");
        QMessageBox::warning(this, "Verify", "Signature INVALID");
    }
}
