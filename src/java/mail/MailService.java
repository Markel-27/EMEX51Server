/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mail;

import java.util.Properties;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

/**
 *
 * @author endika
 */
public class MailService {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(MailService.class.getName());

    private static ResourceBundle rb = ResourceBundle.getBundle("mail.mailCredentials");
    //Ficheros donde se almacena la información del mail.
    private static String ficheroUser;
    private static String ficheroPassword;

    // Server mail user & pass account
    private static String user = null;
    private static String pass = null;

    // DNS Host + SMTP Port
    private static String smtp_host = null;
    private static int smtp_port = 0;

    public MailService() {
        smtp_host = rb.getString("smtpHost");
        smtp_port = Integer.parseInt(rb.getString("smtpPort"));
        ficheroUser = rb.getString("ficheroUserMail");
        ficheroPassword = rb.getString("ficheroPasswordMail");
    }

    /**
     * Sends the given <b>text</b> from the <b>sender</b> to the
     * <b>receiver</b>. In any case, both the <b>sender</b> and <b>receiver</b>
     * must exist and be valid mail addresses. The sender, mail's FROM part, is
     * taken from this.user by default<br/>
     * <br/>
     *
     * Note the <b>user</b> and <b>pass</b> for the authentication is provided
     * in the class constructor. Ideally, the <b>sender</b> and the <b>user</b>
     * coincide.
     *
     * @param receiver The mail's TO part
     * @param subject The mail's SUBJECT
     * @param text The proper MESSAGE
     * @throws MessagingException Is something awry happens
     *
     */
    private void sendMail(String receiver, String subject, String text) throws MessagingException {
        LOGGER.log(Level.INFO, "Metodo sendMail de la clase MailService");
        //user = CifradoPrivadoMail.descifrarTexto(rb.getString("clavePrivada"), ficheroUser);
        //pass = CifradoPrivadoMail.descifrarTexto(rb.getString("clavePrivada"), ficheroPassword);
        user = CifradoPrivadoMail.descifrarTexto(rb.getString("clavePrivada"), "mail/userMail.dat");
        pass = CifradoPrivadoMail.descifrarTexto(rb.getString("clavePrivada"), "mail/passwordMail.dat");

        // Mail properties   
        Properties properties = new Properties();
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.smtp.host", smtp_host);
        properties.put("mail.smtp.port", smtp_port);
        properties.put("mail.smtp.ssl.enable", "true");
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.ssl.trust", smtp_host);
        properties.put("mail.imap.partialfetch", false);
        properties.put("mail.smtp.ssl.enable", false);
        properties.put("mail.smtp.auth", true);

        // Authenticator knows how to obtain authentication for a network connection.
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(user, pass);
            }
        });

        // MIME message to be sent
        Message message = new MimeMessage(session);
        try {
            message.setFrom(new InternetAddress(user));
            message.setRecipients(RecipientType.TO, InternetAddress.parse(receiver)); // Ej: receptor@gmail.com
            message.setSubject(subject); // Asunto del mensaje

            // A mail can have several parts
            Multipart multipart = new MimeMultipart();

            // A message part (the message, but can be also a File, etc...)
            MimeBodyPart mimeBodyPart = new MimeBodyPart();
            mimeBodyPart.setContent(text, "text/html");
            multipart.addBodyPart(mimeBodyPart);

            // Adding up the parts to the MIME message
            message.setContent(multipart);

            // And here it goes...
            Transport.send(message);
        } catch (AddressException ex) {
            Logger.getLogger(MailService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (javax.mail.MessagingException ex) {
            Logger.getLogger(MailService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void sendRecoveryMail(String receiver, String tempPassword) throws MessagingException {
        LOGGER.log(Level.INFO, "Metodo sendRecoveryMail de la clase MailService");
        MailService servicioMail = new MailService();
        String message = "Your password has been reset. "
                + "You can access your account using this temporal password: " + tempPassword;
        System.out.println(message);
        servicioMail.sendMail(receiver, "Password Reset", message);
    }

    public static void sendPasswordChangedMail(String receiver, String newPassword) throws MessagingException {
        LOGGER.log(Level.INFO, "Metodo sendPasswordChangedMail de la clase MailService");
        MailService servicioMail = new MailService();
        String message = "Your password has been reset. "
                + "You can access your account using this temporal password: " + newPassword;
        servicioMail.sendMail(receiver, "Password change", message);
    }
}
