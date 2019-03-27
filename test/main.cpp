#include <QCoreApplication>
#include "PamHandle.h"

class PasswordPrompt : QObject
{
    Q_OBJECT
public:
    PasswordPrompt();
    void login(const QString &service, const QString &user);
private:
    PamHandle *m_pam;

};

int main(int argc, char** argv)
{
    qunsetenv("PAM_KWALLET5_LOGIN");
    QCoreApplication app(argc, argv);
    PasswordPrompt prompt;
    prompt.login("dave", "david");
    app.exec();
}

PasswordPrompt::PasswordPrompt():
    m_pam(new PamHandle(this))
{
}

void PasswordPrompt::login(const QString &service, const QString &user)
{
    m_pam->start(service, user);
    m_pam->authenticate();
    m_pam->openSession();
    m_pam->end();
    QProcess::execute("/opt/kde5/lib64/libexec/pam_kwallet_init");
}

#include "main.moc"
