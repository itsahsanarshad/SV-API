#pragma once

#include <string>
#include <curl/curl.h>
#include <sstream>
#include <memory>
#include <vector>
#include "config/config.h"

namespace services {

class EmailService {
public:
    explicit EmailService(const config::EmailConfig& email_config)
        : config_(email_config) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~EmailService() {
        curl_global_cleanup();
    }

    struct EmailResult {
        bool success = false;
        std::string message;
    };

    EmailResult send_password_reset_email(
        const std::string& to_email,
        const std::string& reset_token,
        const std::string& locale = "en"
    ) {
        std::string reset_link = config_.frontend_url + "/reset-password?token=" + reset_token;
        std::string subject = get_subject(locale);
        std::string html_body = get_email_template(locale, reset_link, to_email);

        return send_email(to_email, subject, html_body);
    }

private:
    config::EmailConfig config_;

    static size_t payload_source(char* ptr, size_t size, size_t nmemb, void* userp) {
        auto* upload_ctx = static_cast<std::string*>(userp);
        size_t room = size * nmemb;

        if (room < 1 || upload_ctx->empty()) {
            return 0;
        }

        size_t len = std::min(room, upload_ctx->length());
        memcpy(ptr, upload_ctx->c_str(), len);
        upload_ctx->erase(0, len);
        
        return len;
    }

    EmailResult send_email(
        const std::string& to_email,
        const std::string& subject,
        const std::string& html_body
    ) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            return {false, "Failed to initialize CURL"};
        }

        CURLcode res = CURLE_OK;
        struct curl_slist* recipients = nullptr;
        std::string payload_text = build_email_payload(to_email, subject, html_body);

        try {
            // ProtonMail SMTP settings
            std::string url = "smtp://" + config_.smtp_host + ":" + config_.smtp_port;
            
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            
            // Use STARTTLS (not implicit SSL)
            curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
            
            // Set username and password
            curl_easy_setopt(curl, CURLOPT_USERNAME, config_.smtp_user.c_str());
            curl_easy_setopt(curl, CURLOPT_PASSWORD, config_.smtp_password.c_str());
            
            // Set mail from
            std::string mail_from = "<" + config_.from_email + ">";
            curl_easy_setopt(curl, CURLOPT_MAIL_FROM, mail_from.c_str());
            
            // Set mail to
            std::string mail_to = "<" + to_email + ">";
            recipients = curl_slist_append(recipients, mail_to.c_str());
            curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
            
            // Set payload
            curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
            curl_easy_setopt(curl, CURLOPT_READDATA, &payload_text);
            curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
            
            // Enable verbose output for debugging
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            
            // Set timeout
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
            
            // Perform the send
            res = curl_easy_perform(curl);
            
            curl_slist_free_all(recipients);
            curl_easy_cleanup(curl);
            
            if (res != CURLE_OK) {
                return {false, std::string("Failed to send email: ") + curl_easy_strerror(res)};
            }
            
            return {true, "Email sent successfully"};
            
        } catch (const std::exception& e) {
            curl_slist_free_all(recipients);
            curl_easy_cleanup(curl);
            return {false, std::string("Exception while sending email: ") + e.what()};
        }
    }

    std::string build_email_payload(
        const std::string& to_email,
        const std::string& subject,
        const std::string& html_body
    ) {
        std::ostringstream payload;
        
        payload << "From: " << config_.from_name << " <" << config_.from_email << ">\r\n";
        payload << "To: <" << to_email << ">\r\n";
        payload << "Subject: " << subject << "\r\n";
        payload << "MIME-Version: 1.0\r\n";
        payload << "Content-Type: text/html; charset=UTF-8\r\n";
        payload << "\r\n";
        payload << html_body << "\r\n";
        
        return payload.str();
    }

    std::string get_subject(const std::string& locale) {
        if (locale == "es") {
            return "Restablecer tu contraseña - Serenity Vault";
        } else if (locale == "fr") {
            return "Réinitialiser votre mot de passe - Serenity Vault";
        }
        return "Reset Your Password - Serenity Vault";
    }

    std::string get_email_template(
        const std::string& locale,
        const std::string& reset_link,
        const std::string& user_email
    ) {
        if (locale == "es") {
            return get_spanish_template(reset_link, user_email);
        } else if (locale == "fr") {
            return get_french_template(reset_link, user_email);
        }
        return get_english_template(reset_link, user_email);
    }

    std::string get_english_template(const std::string& reset_link, const std::string& user_email) {
        return R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background-color: #f4f4f4; border-radius: 10px; padding: 30px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center; }
        .content { background-color: white; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>We received a request to reset the password for your Serenity Vault account associated with <strong>)" + user_email + R"(</strong>.</p>
            <p>Click the button below to reset your password:</p>
            <p style="text-align: center;">
                <a href=")" + reset_link + R"(" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 12px;">)" + reset_link + R"(</p>
            <div class="warning">
                <strong>⚠️ Important:</strong> This link will expire in <strong>1 hour</strong> for security reasons.
            </div>
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
            <p>Best regards,<br><strong>Serenity Vault Team</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
            <p>&copy; 2026 Serenity Vault. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
)";
    }

    std::string get_spanish_template(const std::string& reset_link, const std::string& user_email) {
        return R"(
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Restablecer Contraseña</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background-color: #f4f4f4; border-radius: 10px; padding: 30px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center; }
        .content { background-color: white; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Solicitud de Restablecimiento de Contraseña</h1>
        </div>
        <div class="content">
            <p>Hola,</p>
            <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta de Serenity Vault asociada con <strong>)" + user_email + R"(</strong>.</p>
            <p>Haz clic en el botón a continuación para restablecer tu contraseña:</p>
            <p style="text-align: center;">
                <a href=")" + reset_link + R"(" class="button">Restablecer Contraseña</a>
            </p>
            <p>O copia y pega este enlace en tu navegador:</p>
            <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 12px;">)" + reset_link + R"(</p>
            <div class="warning">
                <strong>⚠️ Importante:</strong> Este enlace expirará en <strong>1 hora</strong> por razones de seguridad.
            </div>
            <p>Si no solicitaste restablecer tu contraseña, ignora este correo o contacta con soporte si tienes alguna preocupación.</p>
            <p>Saludos cordiales,<br><strong>Equipo de Serenity Vault</strong></p>
        </div>
        <div class="footer">
            <p>Este es un mensaje automático, por favor no respondas a este correo.</p>
            <p>&copy; 2026 Serenity Vault. Todos los derechos reservados.</p>
        </div>
    </div>
</body>
</html>
)";
    }

    std::string get_french_template(const std::string& reset_link, const std::string& user_email) {
        return R"(
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Réinitialisation du Mot de Passe</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background-color: #f4f4f4; border-radius: 10px; padding: 30px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center; }
        .content { background-color: white; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Demande de Réinitialisation du Mot de Passe</h1>
        </div>
        <div class="content">
            <p>Bonjour,</p>
            <p>Nous avons reçu une demande de réinitialisation du mot de passe pour votre compte Serenity Vault associé à <strong>)" + user_email + R"(</strong>.</p>
            <p>Cliquez sur le bouton ci-dessous pour réinitialiser votre mot de passe :</p>
            <p style="text-align: center;">
                <a href=")" + reset_link + R"(" class="button">Réinitialiser le Mot de Passe</a>
            </p>
            <p>Ou copiez et collez ce lien dans votre navigateur :</p>
            <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 12px;">)" + reset_link + R"(</p>
            <div class="warning">
                <strong>⚠️ Important :</strong> Ce lien expirera dans <strong>1 heure</strong> pour des raisons de sécurité.
            </div>
            <p>Si vous n'avez pas demandé de réinitialisation de mot de passe, veuillez ignorer cet e-mail ou contacter le support si vous avez des préoccupations.</p>
            <p>Cordialement,<br><strong>L'équipe Serenity Vault</strong></p>
        </div>
        <div class="footer">
            <p>Ceci est un message automatique, veuillez ne pas répondre à cet e-mail.</p>
            <p>&copy; 2026 Serenity Vault. Tous droits réservés.</p>
        </div>
    </div>
</body>
</html>
)";
    }
};

} // namespace services
