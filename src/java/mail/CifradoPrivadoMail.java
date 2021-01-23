/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author endika
 */
public class CifradoPrivadoMail {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(CifradoPrivadoMail.class.getName());
    // Fíjate que el String es de exactamente 16 bytes
    private static byte[] salt = "esta es la salt!".getBytes();

    /**
     * Descifra un texto con AES, modo CBC y padding PKCS5Padding (simétrica) y
     * lo retorna
     *
     * @param clave La clave del usuario
     */
    public static String descifrarTexto(String clave, String fichero) {
        try {
            LOGGER.log(Level.INFO, "Metodo descifrarTexto de la clase CifradoPrivadoMail");
            String ret = null;
            // Fichero leído
            byte[] fileContent = getPublicFileKey(fichero);
            KeySpec keySpec = null;
            SecretKeyFactory secretKeyFactory = null;
            try {
                // Obtenemos el keySpec
                keySpec = new PBEKeySpec(clave.toCharArray(), salt, 65536, 128); // AES-128
                
                // Obtenemos una instancide de SecretKeyFactory con el algoritmo "PBKDF2WithHmacSHA1"
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                // Generamos la clave
                byte[] key = secretKeyFactory.generateSecret(keySpec).getEncoded();
                
                // Creamos un SecretKey usando la clave + salt
                SecretKey privateKey = new SecretKeySpec(key, 0, key.length, "AES");
                
                // Obtenemos una instancide de Cipher con el algoritmos que vamos a usar "AES/CBC/PKCS5Padding"
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                // Iniciamos el Cipher en ENCRYPT_MODE y le pasamos la clave privada
                cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                // Leemos el fichero codificado
                IvParameterSpec ivParam = new IvParameterSpec(Arrays.copyOfRange(fileContent, 0, 16));
                
                // Iniciamos el Cipher en ENCRYPT_MODE y le pasamos la clave privada y el ivParam
                cipher.init(Cipher.DECRYPT_MODE, privateKey, ivParam);
                // Le decimos que descifre
                byte[] decodedMessage = cipher.doFinal(Arrays.copyOfRange(fileContent, 16, fileContent.length));
                
                // Texto descifrado
                ret = new String(decodedMessage);
                
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                System.out.println("Entraste al catch");
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(CifradoPrivadoMail.class.getName()).log(Level.SEVERE, null, ex);
            }
            return ret;
        } catch (IOException ex) {
            Logger.getLogger(CifradoPrivadoMail.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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
