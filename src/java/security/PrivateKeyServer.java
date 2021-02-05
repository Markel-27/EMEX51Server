/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import mail.CifradoPrivadoMail;

/**
 * This class contains the methods to decrypt passwords.
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 */
public class PrivateKeyServer {

    /**
     * Descifra un texto con RSA, modo ECB y padding PKCS1Padding (asim�trica) y
     * lo retorna
     *
     * @param mensaje El mensaje a descifrar
     * @return El mensaje descifrado
     */
    public static byte[] descifrarTexto(String mensaje) {
        byte[] decodedMessage = hexToByte(mensaje);
        try {
            ResourceBundle rb = ResourceBundle.getBundle("security.privateKeyFile");
            byte fileKey[] = getPublicFileKey(rb.getString("filepath"));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(fileKey);
            PrivateKey privateKey = keyFactory.generatePrivate(pKCS8EncodedKeySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decodedMessage = cipher.doFinal(decodedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decodedMessage;
    }

    /**
     * This method converts the hexadecimal string text received to byte array.
     *
     * @param s
     * @return converted text in byte array.
     */
    public static byte[] hexToByte(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Retorna el contenido de un fichero
     *
     * @param path
     * @return El texto del fichero
     */
    public static byte[] getPublicFileKey(String path) throws IOException {

        InputStream keyfis = CifradoPrivadoMail.class.getClassLoader()
                .getResourceAsStream(path);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        // read bytes from the input stream and store them in buffer
        while ((len = keyfis.read(buffer)) != -1) {
            // write bytes from the buffer into output stream
            os.write(buffer, 0, len);
        }
        keyfis.close();
        return os.toByteArray();
    }
}
