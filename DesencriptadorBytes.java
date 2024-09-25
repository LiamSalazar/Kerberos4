package Seguridad;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.Key;

public class DesencriptadorBytes {

    private final Cipher descifrador;

    public DesencriptadorBytes(String algoritmo_de_cifrado) throws Exception {
        try {
            descifrador = Cipher.getInstance(algoritmo_de_cifrado);
        } catch (GeneralSecurityException e) {
            throw new Exception("No se pudo crear el cifrador con el algoritmo" + algoritmo_de_cifrado);
        }
    }

    public byte[] descencriptarBytes(byte[] bytes_encriptados, Key llave_de_cifrado) throws Exception {
        byte[] bytes_desencriptados = null;
        descifrador.init(Cipher.DECRYPT_MODE, llave_de_cifrado);

        bytes_desencriptados = descifrador.doFinal(bytes_encriptados);

        return bytes_desencriptados;
    }

}
