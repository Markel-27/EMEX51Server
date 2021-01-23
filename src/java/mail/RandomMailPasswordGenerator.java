/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mail;

import java.util.Arrays;
import java.util.Random;
import java.util.ResourceBundle;

/**
 * This class generates a random password  when an user forgot the password.
 * @author Endika Ubierna
 */
public class RandomMailPasswordGenerator {
    public static String createRandomPassword(){ 
        //En un fichero de propiedades está guardao la longitud de la clave. Recoger en un Resource bundle.
        ResourceBundle rb = ResourceBundle.getBundle("mail.mailCredentials");
        int length = Integer.parseInt(rb.getString("randomPasswordLength"));
        String symbol = "-/.^&*_!@%=+>)"; 
        String cap_letter = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; 
        String small_letter = "abcdefghijklmnopqrstuvwxyz"; 
        String numbers = "0123456789"; 
        //String con todos los símbolos letras y números incluido.
        String finalString = cap_letter + small_letter + 
                    numbers + symbol; 
        Random random = new Random(); 
        
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < length; i++) { 
            sb.append(finalString.charAt(random.nextInt(finalString.length()))); 
        } 
        //Retornar el array de caracteres como String.
        return sb.toString();
    }               
}
