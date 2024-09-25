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
import java.util.Map;

import static Kerberos.AESUtils.encriptarObjeto;
import Seguridad.Conexiones;
import Seguridad.Comunicacion;

public class AuthenticationServer {
    static final Map<String, String> BDD_usuarios = new HashMap<String, String>() {
        {
            put("1", "ContraseniaCliente");
        }
    };
    static final Map<String, String> BDD_TGS = new HashMap<String, String>() {
        {
            put("1", "ContraseñaTGS");
        }
    };
    static final Map<String, String> BDD_Servidor = new HashMap<String, String>() {
        {
            put("1", "ContraseñaServidor");
        }
    };
    private String id_cliente;
    private InetAddress address_cliente;
    private String id_TicketGrantingServer;
    private String clave_Cliente_TicketGrantingServer = "contraseña_C-TGS";
    private String clave_TicketGrantingServer = "contraseñaTGS";

    public static void main(String[] args) throws Exception {
        System.out.println(
                "         -----------------------------------\n" +
                        "         --   IMPLEMENTACION KERBEROS 4   --\n" +
                        "         --------------   AS    ------------\n" +
                        "         -----------------------------------\n");

        System.out.println("\n" +
                "--------------------------------------------------\n" +
                "-    INTERCAMBIO DE SERVICIO DE AUNTENTIFICACION:-\n" +
                "-                  PARA OBTENER TGT              -\n" +
                "--------------------------------------------------");
        AuthenticationServer AS = new AuthenticationServer();

        int puertoServer = 2000;
        ServerSocket serverSocket = new ServerSocket(puertoServer);

        Socket conexionCliente = Conexiones.aceptarConexionEntrante(puertoServer, serverSocket);

        InputStream inputStream = conexionCliente.getInputStream();
        OutputStream outputStream = conexionCliente.getOutputStream();

        AS.recibirSolicitudTGTdesdeCliente(conexionCliente);

        AS.responderSolicitudTGTalCliente(outputStream);

        conexionCliente.close();

    }

    public void recibirSolicitudTGTdesdeCliente(Socket conexionCliente) throws Exception {
        HashMap<String, Object> solicitudTGT = (HashMap<String, Object>) Comunicacion
                .recibirObjeto(conexionCliente.getInputStream());

        System.out.printf("Solicitud recibida: %s \n\n", solicitudTGT);

        this.setAddress_cliente(conexionCliente.getInetAddress());
        this.setClave_Cliente_TicketGrantingServer("contraseña_C-TGS");
        this.setId_cliente((String) solicitudTGT.get("[Id-c]"));
        this.setId_TicketGrantingServer((String) solicitudTGT.get("[Id-tgs]"));
    }

    public void responderSolicitudTGTalCliente(OutputStream outputStream) throws Exception {
        HashMap<String, Object> respuestaSolicitud = this.getRespuestaSolicitudTicket_TGS();

        SealedObject respuestaCifrada = encriptarObjeto(respuestaSolicitud, BDD_usuarios.get(this.id_cliente));

        Comunicacion.enviarObjeto(outputStream, respuestaCifrada);
    }

    public void setId_cliente(String id_cliente) {
        this.id_cliente = id_cliente;
    }

    public void setClave_Cliente_TicketGrantingServer(String clave_Cliente_TicketGrantingServer) {
        this.clave_Cliente_TicketGrantingServer = clave_Cliente_TicketGrantingServer;
    }

    public void setId_TicketGrantingServer(String id_TicketGrantingServer) {
        this.id_TicketGrantingServer = id_TicketGrantingServer;
    }

    public void setClave_TicketGrantingServer(String clave_TicketGrantingServer) {
        this.clave_TicketGrantingServer = clave_TicketGrantingServer;
    }

    public void setAddress_cliente(InetAddress address_cliente) {
        this.address_cliente = address_cliente;
    }

    HashMap<String, Object> getRespuestaSolicitudTicket_TGS() throws Exception {
        HashMap<String, Object> respuestaSolicitud = new HashMap<>();
        Ticket_TGS ticket_tgs = new Ticket_TGS(clave_Cliente_TicketGrantingServer, id_cliente, address_cliente,
                id_TicketGrantingServer, 5);

        respuestaSolicitud.put("[K-c_tgs]", ticket_tgs.getClave_Cliente_TicketGrantingServer());
        respuestaSolicitud.put("[Id-tgs]", ticket_tgs.getId_TicketGrantingServer());
        respuestaSolicitud.put("[TimeStamp-2]", ticket_tgs.getMomentoCreacion_ticket());
        respuestaSolicitud.put("[TiempoVida-2]", ticket_tgs.getTiempo_vida_ticket());

        SealedObject ticket_tgs_cifrado = encriptarObjeto(ticket_tgs, clave_TicketGrantingServer);

        respuestaSolicitud.put("[Ticket-tgs]", ticket_tgs_cifrado);

        return respuestaSolicitud;
    }

    public static class Ticket_TGS implements Serializable {
        final String clave_Cliente_TicketGrantingServer;
        final String id_cliente;
        final InetAddress address_cliente;
        final String id_TicketGrantingServer;
        final LocalDateTime creacion_ticket;
        final LocalDateTime tiempo_vida_ticket;

        public Ticket_TGS(String clave_Cliente_TicketGrantingServer, String id_cliente, InetAddress address_cliente,
                String id_TicketGrantingServer, long tiempoVida) {
            this.clave_Cliente_TicketGrantingServer = clave_Cliente_TicketGrantingServer;
            this.id_cliente = id_cliente;
            this.address_cliente = address_cliente;
            this.id_TicketGrantingServer = id_TicketGrantingServer;
            this.creacion_ticket = LocalDateTime.now();
            this.tiempo_vida_ticket = creacion_ticket.plusMinutes(tiempoVida);
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("Ticket_TGS{");
            sb.append("clave_Cliente_TicketGrantingServer=").append(clave_Cliente_TicketGrantingServer);
            sb.append(", id_cliente='").append(id_cliente).append('\'');
            sb.append(", address_cliente=").append(address_cliente);
            sb.append(", id_TicketGrantingServer='").append(id_TicketGrantingServer).append('\'');
            sb.append(", creacion_ticket=").append(creacion_ticket);
            sb.append(", tiempo_vida_ticket=").append(tiempo_vida_ticket);
            sb.append('}');
            return sb.toString();
        }

        public String getClave_Cliente_TicketGrantingServer() {
            return clave_Cliente_TicketGrantingServer;
        }

        public String getId_cliente() {
            return id_cliente;
        }

        public InetAddress getAddress_cliente() {
            return address_cliente;
        }

        public String getId_TicketGrantingServer() {
            return id_TicketGrantingServer;
        }

        public LocalDateTime getMomentoCreacion_ticket() {
            return creacion_ticket;
        }

        public LocalDateTime getTiempo_vida_ticket() {
            return tiempo_vida_ticket;
        }

        public String getIp_cliente() {
            return address_cliente.getHostAddress();
        }
    }

}
