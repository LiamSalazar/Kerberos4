package Kerberos;

import javax.crypto.SealedObject;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.LocalDateTime;
import java.util.HashMap;

import Seguridad.Conexiones;
import Seguridad.Comunicacion;
import static Kerberos.AESUtils.encriptarObjeto;

public class TicketGrantingServer {
    private String id_servidor;
    private String id_cliente;
    private InetAddress address_cliente;
    private Client.ClientAuthentication autificacionCliente;
    private AuthenticationServer.Ticket_TGS ticket_tgs;

    public static void main(String[] args) throws Exception {
        System.out.println(
                "         -----------------------------------\n" +
                        "         --   IMPLEMENTACION KERBEROS 4   --\n" +
                        "         --------------   TGT  -------------\n" +
                        "         -----------------------------------\n");

        System.out.println(
                "\n" +
                        "--------------------------------------------------\n" +
                        "- INTERCAMBIO DE TGS: PARA OBTENER UN TICKET  -\n" +
                        "-    QUE CONCEDE UN SERVICIO                     -\n" +
                        "--------------------------------------------------");

        TicketGrantingServer TGS = new TicketGrantingServer();

        int puertoServer = 2001;
        ServerSocket serverSocket = new ServerSocket(puertoServer);

        Socket conexionCliente = Conexiones.aceptarConexionEntrante(puertoServer, serverSocket);
        InputStream inputStream = conexionCliente.getInputStream();
        OutputStream outputStream = conexionCliente.getOutputStream();

        TGS.recibirPeticionTicketDesdeCliente(inputStream);

        Client.ClientAuthentication autenticacionCliente = TGS.getAutificacionCliente();

        AuthenticationServer.Ticket_TGS ticket_tgs = TGS.getTicket_tgs();
        boolean coinciden = autenticacionCliente.getIp_cliente().equals(ticket_tgs.getIp_cliente())
                && autenticacionCliente.getId_cliente().equals(ticket_tgs.getId_cliente());
        System.out.printf(
                "\n¿Coinciden los datos del cliente con los del ticket TGS? %s \n Datos cliente -> address: %s, id: %s ",
                coinciden ? "SI COINCIDEN" : "NO COINCIDEN", autenticacionCliente.getAddress_cliente(),
                autenticacionCliente.getId_cliente());

        TGS.enviarRespuestaTicketAlCliente(outputStream);

        conexionCliente.close();
    }

    public Client.ClientAuthentication getAutificacionCliente() {
        return autificacionCliente;
    }

    public void setAutificacionCliente(Client.ClientAuthentication autificacionCliente) {
        this.autificacionCliente = autificacionCliente;
    }

    public AuthenticationServer.Ticket_TGS getTicket_tgs() {
        return ticket_tgs;
    }

    public void setTicket_tgs(AuthenticationServer.Ticket_TGS ticket_tgs) {
        this.ticket_tgs = ticket_tgs;
    }

    public void recibirPeticionTicketDesdeCliente(InputStream inputStream) throws Exception {

        HashMap<String, Object> peticion = (HashMap<String, Object>) Comunicacion.recibirObjeto(inputStream);

        System.out.printf("Solicitud recibida: %s \n\n", peticion);

        Client.ClientAuthentication autenticacionCliente = (Client.ClientAuthentication) AESUtils
                .desencriptarObjeto((SealedObject) peticion.get("[Autentificador-c]"), "contraseña_C-TGS");

        this.setAutificacionCliente(autenticacionCliente);

        AuthenticationServer.Ticket_TGS ticket_tgs = (AuthenticationServer.Ticket_TGS) AESUtils
                .desencriptarObjeto((SealedObject) peticion.get("[Ticket-tgs]"), "contraseñaTGS");

        this.setTicket_tgs(ticket_tgs);

        System.out.printf("Ticket TGS descifrado: %s \n\n", ticket_tgs);
        System.out.printf("Autenticacion Cliente descifrada: %s \n\n", autenticacionCliente);

        this.setId_cliente(autenticacionCliente.getId_cliente());
        this.setAddress_cliente(autenticacionCliente.getAddress_cliente());
        this.setId_servidor((String) peticion.get("[Id-v]"));

    }

    public void enviarRespuestaTicketAlCliente(OutputStream outputStream) throws Exception {
        HashMap<String, Object> respuestaTicket = this.crearRespuestaTicket();

        SealedObject respuestaCifrada = encriptarObjeto(respuestaTicket,
                ticket_tgs.getClave_Cliente_TicketGrantingServer());

        Comunicacion.enviarObjeto(outputStream, respuestaCifrada);

        System.out.printf("\nRespuesta sin cifrar: %s", respuestaTicket);
        System.out.printf("\nRespuesta cifrada a enviar: %s", respuestaCifrada);
    }

    public void setId_servidor(String id_servidor) {
        this.id_servidor = id_servidor;
    }

    public void setId_cliente(String id_cliente) {
        this.id_cliente = id_cliente;
    }

    public void setAddress_cliente(InetAddress address_cliente) {
        this.address_cliente = address_cliente;
    }

    public HashMap<String, Object> crearRespuestaTicket() throws Exception {
        HashMap<String, Object> respuestaSolicitud = new HashMap<>();

        Ticket_servicio ticket_servidor = new Ticket_servicio("contraseñaClienteServidor", id_cliente, address_cliente,
                id_servidor, 5);

        respuestaSolicitud.put("[K-c_v]", ticket_servidor.getClave_cliente_servidor());

        respuestaSolicitud.put("[Id-v]", ticket_servidor.getId_servidor());
        respuestaSolicitud.put("[TimeStamp-4]", ticket_servidor.getCreacion_ticket());
        respuestaSolicitud.put("[TiempoVida-4]", ticket_servidor.getTiempo_vida_ticket());

        SealedObject ticket_servidor_cifrado = encriptarObjeto(ticket_servidor, "contraseñaServidor");

        respuestaSolicitud.put("[Ticket-v]", ticket_servidor_cifrado);

        System.out.printf("\n[Ticket-v] cifrado y descifrado-> %s -> %s \n", ticket_servidor, ticket_servidor_cifrado);

        return respuestaSolicitud;
    }

    public static class Ticket_servicio implements Serializable {
        final String clave_cliente_servidor;
        final String id_cliente;
        final InetAddress address_cliente;
        final LocalDateTime creacion_ticket;
        final LocalDateTime tiempo_vida_ticket;
        final String id_servidor;

        public Ticket_servicio(String clave_cliente_servidor, String id_cliente, InetAddress address_cliente,
                String id_servidor, long tiempoVida) {
            this.clave_cliente_servidor = clave_cliente_servidor;
            this.id_cliente = id_cliente;
            this.address_cliente = address_cliente;
            this.id_servidor = id_servidor;
            this.creacion_ticket = LocalDateTime.now();
            this.tiempo_vida_ticket = creacion_ticket.plusMinutes(tiempoVida);
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("Ticket_servicio{");
            sb.append("clave_cliente_servidor=").append(clave_cliente_servidor);
            sb.append(", id_cliente='").append(id_cliente).append('\'');
            sb.append(", address_cliente=").append(address_cliente);
            sb.append(", creacion_ticket=").append(creacion_ticket);
            sb.append(", tiempo_vida_ticket=").append(tiempo_vida_ticket);
            sb.append(", id_servidor='").append(id_servidor).append('\'');
            sb.append('}');
            return sb.toString();
        }

        public String getClave_cliente_servidor() {
            return clave_cliente_servidor;
        }

        public String getId_cliente() {
            return id_cliente;
        }

        public InetAddress getAddress_cliente() {
            return address_cliente;
        }

        public LocalDateTime getCreacion_ticket() {
            return creacion_ticket;
        }

        public LocalDateTime getTiempo_vida_ticket() {
            return tiempo_vida_ticket;
        }

        public String getId_servidor() {
            return id_servidor;
        }

        public String getIp_cliente() {
            return address_cliente.getHostAddress();
        }
    }

}
