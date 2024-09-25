package Seguridad;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;

public class Adendum {
    public static byte obtenerAdendumClave(String claveSecreta) {
        char[] caracteres = claveSecreta.toCharArray();
        byte ultimoXor = 0;

        for (int i = 0; i < caracteres.length - 1; i++) {
            byte xorActual;
            if (i == 0)
                xorActual = (byte) ((int) caracteres[i] ^ (int) caracteres[i + 1]);
            else
                xorActual = (byte) (ultimoXor ^ (int) caracteres[i + 1]);

            ultimoXor = xorActual;
        }
        String representacionBinaria = Integer.toBinaryString(ultimoXor);

        System.out.format("El adendum para la cadena -> \"%s\" es %08d = %d", claveSecreta,
                Integer.parseInt(representacionBinaria), ultimoXor);
        return ultimoXor;
    }

    public static String cifrarAdendum(byte adendumCifrar, Key llaveCifrado) throws Exception {
        String adendum_clave_secreta = String.valueOf(adendumCifrar);
        byte[] bytesClaveSecreta = adendum_clave_secreta.getBytes(StandardCharsets.UTF_8);
        byte[] bytes_encriptadosAdendum = new EncriptadorBytes("RSA").encriptarBytes(bytesClaveSecreta, llaveCifrado);
        return Base64.getEncoder().encodeToString(bytes_encriptadosAdendum);
    }

    public static byte descifrarAdendum(String adendumCifrado, Key llaveDescifrado) throws Exception {
        byte[] bytes_desencriptados = new DesencriptadorBytes("RSA")
                .descencriptarBytes(Base64.getDecoder().decode(adendumCifrado), llaveDescifrado);
        String adendum_descifrado = new String(bytes_desencriptados, StandardCharsets.UTF_8);
        return Byte.valueOf(adendum_descifrado.trim());
    }

}
