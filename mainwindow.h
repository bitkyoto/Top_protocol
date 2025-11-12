#pragma once

#include <QMainWindow>
#include <vector>
#include <string>

#include "rc4/RC4.h"
#include "rsa/RSA.h"
#include "md5/md5.h"
#include "md5/rmd5.h"

#include "utils/utils.cpp"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

struct Certificate {
    std::string subject;
    n_type pub_e;
    n_type pub_n;
    std::vector<n_type> signature;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_btnGenCA_clicked();
    void on_btnIssueCerts_clicked();
    void on_btnReqBobCert_clicked();
    void on_btnEncrypt_clicked();
    void on_btnSend_clicked();
    void on_btnDecrypt_clicked();
    void on_btnVerify_clicked();

private:
    Ui::MainWindow *ui;

    // crypto primitives
    // MD5 md5;
    RSA rsaCA;
    RSA rsaAlice;
    RSA rsaBob;

    // certificates
    Certificate certCA;
    Certificate certAlice;
    Certificate certBob;

    // session data
    std::vector<uint8_t> rc4Key;                   // plain rc4 key at Alice side
    std::vector<n_type> rc4KeyEncrypted;           // rc4 key encrypted with Bob's pubkey
    std::vector<uint8_t> ciphertext;               // rc4 ciphertext
    std::vector<n_type> signature;                 // signature over hash

    // helpers
    void logCA(const QString &msg);
    void logAlice(const QString &msg);
    void logBob(const QString &msg);

    void saveCertificate(const Certificate& cert, const std::string& filename);
    Certificate loadCertificate(const std::string& filename);
    std::vector<n_type> signCert(const Certificate& cert, RSA& rsaSigner);
    bool verifyCert(const Certificate& cert, const Certificate& caCert);
};
