package Kerberos;

import Seguridad.Comunicacion;
import Seguridad.Conexiones;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Scanner;

@SuppressWarnings("LanguageDetectionInspection")
public class Client {

    private final String id_cliente;
    private final InetAddress address_cliente;
    private String id_Servidor;
    private SealedObject ticket_tgs;
    private String password_cliente;
    private String id_TicketGrantingServer;
    private SealedObject ticket_servicio;
    private String clave_Cliente_TicketGrantingServer;
    private String clave_cliente_servidor;

    public Client(String id_cliente, InetAddress address_cliente) {
        this.id_cliente = id_cliente;
        this.address_cliente = address_cliente;
    }

    public static void main(String[] args) throws Exception {

        System.out.println(
                "         -----------------------------------\n" +
                        "         --            KERBEROS 4         --\n" +
                        "         -------------- CLIENTE ------------\n" +
                        "         -----------------------------------\n");

        Scanner entrada = new Scanner(System.in);

        String ipCliente = "127.0.0.1";

        String ipAS = "127.0.0.1";
        int puertoAS = 2000;

        String ipTGS = "127.0.0.1";
        int puertoTGS = 2001;

        String ipServiceServer = "127.0.0.1";
        int puertoServiceServer = 2002;

        System.out.println();

        Client cliente = new Client("1", InetAddress.getByName(ipCliente));
        cliente.setId_TicketGrantingServer("1");

        System.out.println("\n" +
                "--------------------------------------------------\n" +
                "-    INTERCAMBIO DE SERVICIO DE AUNTENTIFICACION:-\n" +
                "-                PARA OBTENER TGT                -\n" +
                "--------------------------------------------------");

        Socket conexionAS = Conexiones.obtenerConexion(puertoAS, ipAS);
        InputStream inputStream = conexionAS.getInputStream();
        OutputStream outputStream = conexionAS.getOutputStream();

        cliente.realizarPeticionTGThaciaAS(outputStream);
        cliente.recibirTGTdesdeAS(inputStream);

        conexionAS.close();

        System.out.println(
                "\n" +
                        "--------------------------------------------------\n" +
                        "-    INTERCAMBIO DE TGS: PARA OBTENER UN TICKET  -\n" +
                        "-             QUE CONCEDE UN SERVICIO            -\n" +
                        "--------------------------------------------------");

        cliente.setId_Servidor("1");

        Socket conexionTGS = Conexiones.obtenerConexion(puertoTGS, ipTGS);
        inputStream = conexionTGS.getInputStream();
        outputStream = conexionTGS.getOutputStream();

        cliente.realizarPeticionTickethaciaTGS(outputStream);
        cliente.recibirTicketdesdeTGS(inputStream);

        conexionTGS.close();

        System.out.println(
                "\n" +
                        "--------------------------------------------------\n" +
                        "-          INTERCAMBIO DE AUTENTIFICACION        -\n" +
                        "-    CLIENTE/SERVIDOR: PARA OBTENER UN SERVICIO  -\n" +
                        "--------------------------------------------------");

        Socket conexionServiceServer = Conexiones.obtenerConexion(puertoServiceServer, ipServiceServer);

        inputStream = conexionServiceServer.getInputStream();
        outputStream = conexionServiceServer.getOutputStream();

        cliente.realizarPeticionServiciohaciaServidor(outputStream);
        cliente.recibirServiciodesdeServidor(inputStream);

        conexionServiceServer.close();
    }

    public void realizarPeticionTGThaciaAS(OutputStream outputStream) throws Exception {
        HashMap<String, Object> solicitudTGS = this.generarSolicitudTGS();
        Comunicacion.enviarObjeto(outputStream, solicitudTGS);
    }

    public void recibirTGTdesdeAS(InputStream inputStream) throws Exception {

        SealedObject respuetaCifrada = (SealedObject) Comunicacion.recibirObjeto(inputStream);

        HashMap<String, Object> respuestaDescifrada = (HashMap<String, Object>) AESUtils
                .desencriptarObjeto(respuetaCifrada, "ContraseniaCliente");
        System.out.printf("Repuestas recibida desde el AS: %s \n\n", respuestaDescifrada);

        this.setClave_Cliente_TicketGrantingServer((String) respuestaDescifrada.get("[K-c_tgs]"));

        this.setId_TicketGrantingServer((String) respuestaDescifrada.get("[Id-tgs]"));
        this.setTicket_tgs((SealedObject) respuestaDescifrada.get("[Ticket-tgs]"));
    }

    public void realizarPeticionTickethaciaTGS(OutputStream outputStream) throws Exception {
        HashMap<String, Object> solicitudIntercambioTGS = this.generarSolicitudIntercambioTGS();

        Comunicacion.enviarObjeto(outputStream, solicitudIntercambioTGS);
    }

    public void recibirTicketdesdeTGS(InputStream inputStream) throws Exception {
        SealedObject respuestaCifrada = (SealedObject) Comunicacion.recibirObjeto(inputStream);

        HashMap<String, Object> respuesta = (HashMap<String, Object>) AESUtils.desencriptarObjeto(respuestaCifrada,
                this.getClave_Cliente_TicketGrantingServer());

        System.out.printf("Repuestas recibida: %s \n\n", respuesta);

        this.setTicket_servicio((SealedObject) respuesta.get("[Ticket-v]"));

        this.setClave_cliente_servidor((String) respuesta.get("[K-c_v]"));

    }

    public void realizarPeticionServiciohaciaServidor(OutputStream outputStream) throws Exception {
        HashMap<String, Object> peticionServicio = this.generarSolicitudIntercambioServicio();

        Comunicacion.enviarObjeto(outputStream, peticionServicio);
        System.out.printf("Peticion Intercambio Servicio Enviada: %s\n", peticionServicio);
    }

    public void recibirServiciodesdeServidor(InputStream inputStream) throws Exception {
        SealedObject respuestaCifrada = (SealedObject) Comunicacion.recibirObjeto(inputStream);

        System.out.printf("respuesta cifrada recibida -> %s", respuestaCifrada);
        HashMap<String, Object> respuestaServicio = (HashMap<String, Object>) AESUtils
                .desencriptarObjeto(respuestaCifrada, this.getClave_cliente_servidor());

        System.out.printf("\nrespuesta recibida Servicio: ", respuestaServicio);
        String servicioRecibido = (String) respuestaServicio.get("[Servicio]");

        System.out.println(servicioRecibido);
    }

    public String getClave_cliente_servidor() {
        return clave_cliente_servidor;
    }

    public void setClave_cliente_servidor(String clave_cliente_servidor) {
        this.clave_cliente_servidor = clave_cliente_servidor;
    }

    public SealedObject getTicket_servicio() {
        return ticket_servicio;
    }

    public void setTicket_servicio(SealedObject ticket_servicio) {
        this.ticket_servicio = ticket_servicio;
    }

    public String getClave_Cliente_TicketGrantingServer() {
        return clave_Cliente_TicketGrantingServer;
    }

    public void setClave_Cliente_TicketGrantingServer(String clave_Cliente_TicketGrantingServer) {
        this.clave_Cliente_TicketGrantingServer = clave_Cliente_TicketGrantingServer;
    }

    public void setPassword_cliente(String password_cliente) {
        this.password_cliente = password_cliente;
    }

    public void setId_TicketGrantingServer(String id_TicketGrantingServer) {
        this.id_TicketGrantingServer = id_TicketGrantingServer;
    }

    public HashMap<String, Object> generarSolicitudTGS() {

        HashMap<String, Object> solicitud = new HashMap<>();
        solicitud.put("[Id-c]", id_cliente);
        solicitud.put("[Id-tgs]", id_TicketGrantingServer);
        solicitud.put("[TimeStamp-1]", LocalDateTime.now());

        return solicitud;
    }

    public HashMap<String, Object> generarSolicitudIntercambioTGS() throws Exception {

        ClientAuthentication autentificador_cliente = new ClientAuthentication(id_cliente, address_cliente);

        HashMap<String, Object> solicitud = new HashMap<>();
        solicitud.put("[Id-v]", id_Servidor);
        solicitud.put("[Ticket-tgs]", ticket_tgs);

        SecretKey clave_cliente_TGS = (SecretKey) AESUtils.getKeyFromPassword(this.clave_Cliente_TicketGrantingServer);
        SealedObject autentificadorCifrado = AESUtils.encriptarObjeto(autentificador_cliente, clave_cliente_TGS);
        solicitud.put("[Autentificador-c]", autentificadorCifrado);

        return solicitud;
    }

    public HashMap<String, Object> generarSolicitudIntercambioServicio() throws Exception {

        ClientAuthentication autentificador_cliente = new ClientAuthentication(id_cliente, address_cliente);
        SecretKey clave_cliente_servidor = AESUtils.getKeyFromPassword(this.clave_cliente_servidor);
        SealedObject autentificadorCifrado = AESUtils.encriptarObjeto(autentificador_cliente, clave_cliente_servidor);

        HashMap<String, Object> solicitud = new HashMap<>();

        solicitud.put("[Ticket-v]", ticket_servicio);
        solicitud.put("[Autentificador-c]", autentificadorCifrado);

        System.out.printf("\n[Ticket-v] cifrado y descifrado-> %s -> %s \n", ticket_servicio,
                AESUtils.desencriptarObjeto(ticket_servicio, "contraseñaServidor"));

        return solicitud;
    }

    public void setTicket_tgs(SealedObject ticket_tgs) {
        this.ticket_tgs = ticket_tgs;
    }

    public void setId_Servidor(String id_Servidor) {
        this.id_Servidor = id_Servidor;
    }

    public static class ClientAuthentication implements Serializable {

        private final String id_cliente;
        private final InetAddress address_cliente;
        private final LocalDateTime timeStamp_ClientAuthentication;

        public ClientAuthentication(String ID_cliente, String address_cliente) throws UnknownHostException {
            this.id_cliente = ID_cliente;
            this.address_cliente = InetAddress.getByName(address_cliente);
            timeStamp_ClientAuthentication = LocalDateTime.now();
        }

        public ClientAuthentication(String ID_cliente, InetAddress address_cliente) throws UnknownHostException {
            this.id_cliente = ID_cliente;
            this.address_cliente = address_cliente;
            timeStamp_ClientAuthentication = LocalDateTime.now();
        }

        public String getId_cliente() {
            return id_cliente;
        }

        public InetAddress getAddress_cliente() {
            return address_cliente;
        }

        public String getIp_cliente() {
            return address_cliente.getHostAddress();
        }

        public LocalDateTime getTimeStamp_ClientAuthentication() {
            return timeStamp_ClientAuthentication;
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("ClientAuthentication{");
            sb.append("id_cliente='").append(id_cliente).append('\'');
            sb.append(", address_cliente=").append(address_cliente);
            sb.append(", timeStamp_ClientAuthentication=").append(timeStamp_ClientAuthentication);
            sb.append('}');
            return sb.toString();
        }
    }

}
