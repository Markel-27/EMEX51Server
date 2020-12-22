/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author 2dam
 */
public class Hashing {
    /**
     * Aplica SHA al texto pasado por parámetro
     * @param texto
     */
    public void cifrarTexto(String texto) {
        MessageDigest messageDigest;
        try {
            // Obtén una instancia de MessageDigest que usa SHA
            messageDigest = MessageDigest.getInstance("SHA1");
            // Convierte el texto en un array de bytes
            messageDigest.update(texto.getBytes());
            byte[] resumen = messageDigest.digest();
            // Actualiza el MessageDigest con el array de bytes
            messageDigest.update(resumen);
            // Calcula el resumen (función digest)
            messageDigest.digest(resumen);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Hashing.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    // Convierte Array de Bytes en hexadecimal
    static String Hexadecimal(byte[] resumen) {
        String HEX = "";
        for (int i = 0; i < resumen.length; i++) {
            String h = Integer.toHexString(resumen[i] & 0xFF);
            if (h.length() == 1)
                    HEX += "0";
            HEX += h;
        }
        return HEX.toUpperCase();
    }    
}
