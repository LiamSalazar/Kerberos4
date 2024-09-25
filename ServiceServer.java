package Kerberos;

import javax.crypto.SealedObject;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.LocalDateTime;
import java.util.HashMap;

import Seguridad.Conexiones;
import Seguridad.Comunicacion;

public class ServiceServer {

    public final String servicio = "--------- ACCESO CONCEDIDO A MELODYFINDER --------- KERBEROS SECURITY EXITOSO ---------";

    private LocalDateTime timestamp5;
    private String clave_cliente_servidor;
    private String clave_servidor;
    private TicketGrantingServer.Ticket_servicio ticketServicio;
    private Client.ClientAuthentication clientAuthentication;

    public static void main(String[] args) throws Exception {
        System.out.println(
                "         -----------------------------------\n" +
                        "              KERBEROS 4            \n" +
                        " -----------------------------------\n");

        System.out.println(
                "\n" +
                        "--------------------------------------------------\n" +
                        "-          INTERCAMBIO DE AUTENTIFICACION        -\n" +
                        "-    CLIENTE/SERVIDOR: PARA OBTENER UN SERVICIO  -\n" +
                        "--------------------------------------------------");

        ServiceServer serviceServer = new ServiceServer();
        serviceServer.setClave_servidor("contraseñaServidor");

        int puertoServer = 2002;
        ServerSocket serverSocket = new ServerSocket(puertoServer);

        Socket conexionCliente = Conexiones.aceptarConexionEntrante(puertoServer, serverSocket);

        InputStream inputStream = conexionCliente.getInputStream();
        OutputStream outputStream = conexionCliente.getOutputStream();

        serviceServer.recibirPeticionServicioDesdeCliente(inputStream);

        TicketGrantingServer.Ticket_servicio ticket_servicio = serviceServer.getTicketServicio();

        Client.ClientAuthentication clientAuthentication = serviceServer.getClientAuthentication();

        boolean esClienteValido = serviceServer.validarClienteConTicket(ticket_servicio, clientAuthentication);

        System.out.printf(
                "\n¿Coinciden los datos del cliente con los del ticket servidor? %s \n Datos cliente -> address: %s, id: %s ",
                esClienteValido ? "SI COINCIDEN" : "NO COINCIDEN", ticket_servicio.getAddress_cliente(),
                clientAuthentication.getId_cliente());
        if (!esClienteValido)
            return;

        serviceServer.responderPeticionServicioCliente(outputStream);

        conexionCliente.close();

    }

    public Client.ClientAuthentication getClientAuthentication() {
        return clientAuthentication;
    }

    public void setClientAuthentication(Client.ClientAuthentication clientAuthentication) {
        this.clientAuthentication = clientAuthentication;
    }

    public TicketGrantingServer.Ticket_servicio getTicketServicio() {
        return ticketServicio;
    }

    public void setTicketServicio(TicketGrantingServer.Ticket_servicio ticketServicio) {
        this.ticketServicio = ticketServicio;
    }

    public void recibirPeticionServicioDesdeCliente(InputStream inputStream) throws Exception {

        HashMap<String, Object> peticionServicio = (HashMap<String, Object>) Comunicacion.recibirObjeto(inputStream);

        SealedObject ticketServicio_cifrado = (SealedObject) peticionServicio.get("[Ticket-v]");

        TicketGrantingServer.Ticket_servicio ticket_servicio = (TicketGrantingServer.Ticket_servicio) AESUtils
                .desencriptarObjeto(ticketServicio_cifrado, this.getClave_servidor());

        this.setTicketServicio(ticket_servicio);
        this.setClave_cliente_servidor(ticket_servicio.getClave_cliente_servidor());
        ;

        SealedObject autentificadorCliente_cifrado = (SealedObject) peticionServicio.get("[Autentificador-c]");

        Client.ClientAuthentication autentificadorCliente = (Client.ClientAuthentication) AESUtils
                .desencriptarObjeto(autentificadorCliente_cifrado, this.getClave_cliente_servidor());

        this.setClientAuthentication(autentificadorCliente);
        this.setTimestamp5(autentificadorCliente.getTimeStamp_ClientAuthentication());

        System.out.printf("Peticion recibida desde el cliente: %s\n", peticionServicio);
        System.out.printf("TicketServicio descifrado : %s\n Autentificador del Cliente Descifrado\n", peticionServicio,
                autentificadorCliente);

    }

    public void responderPeticionServicioCliente(OutputStream outputStream) throws Exception {
        HashMap<String, Object> respuestaServicio = this.responderServicio();

        SealedObject respuestaServicio_cifrada = AESUtils.encriptarObjeto(respuestaServicio,
                this.getClave_cliente_servidor());

        Comunicacion.enviarObjeto(outputStream, respuestaServicio_cifrada);

        System.out.printf("\nEl servicio ha sido otorgado al cliente");

        System.out.printf("Respuesta enviada: %s", respuestaServicio_cifrada);
    }

    public HashMap<String, Object> responderServicio() throws Exception {
        HashMap<String, Object> respuestaSolicitud = new HashMap<>();

        respuestaSolicitud.put("[TimeStamp-incrementada]", timestamp5.plusMinutes(1));

        respuestaSolicitud.put("[Servicio]", servicio);

        return respuestaSolicitud;
    }

    private boolean validarClienteConTicket(TicketGrantingServer.Ticket_servicio ticket_servicio,
            Client.ClientAuthentication autentificadorCliente) {

        boolean esClienteValido;

        esClienteValido = (ticket_servicio.getId_cliente().equals(autentificadorCliente.getId_cliente()))

                && (ticket_servicio.getIp_cliente().equals(autentificadorCliente.getIp_cliente()))

                && ticket_servicio.getTiempo_vida_ticket().isAfter(LocalDateTime.now());

        return esClienteValido;
    }

    public String getClave_servidor() {
        return clave_servidor;
    }

    public void setClave_servidor(String clave_servidor) {
        this.clave_servidor = clave_servidor;
    }

    public String getClave_cliente_servidor() {
        return clave_cliente_servidor;
    }

    public void setClave_cliente_servidor(String clave_cliente_servidor) {
        this.clave_cliente_servidor = clave_cliente_servidor;
    }

    public LocalDateTime getTimestamp5() {
        return timestamp5;
    }

    public void setTimestamp5(LocalDateTime timestamp5) {
        this.timestamp5 = timestamp5;
    }

}
