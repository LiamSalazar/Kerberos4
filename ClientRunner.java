package Kerberos;

public class ClientRunner {

    // Número de clientes concurrentes que se lanzarán
    private static final int NUM_CLIENTS = 2;

    public static void main(String[] args) {
        System.out.println("Iniciando " + NUM_CLIENTS + " clientes Kerberos concurrentes...\n");

        for (int i = 0; i < NUM_CLIENTS; i++) {
            int clientId = i + 1; // identificador para cada cliente
            new Thread(() -> {
                try {
                    System.out.println("Cliente " + clientId + " iniciado.");
                    // Ejecuta el flujo del cliente
                    Kerberos.Client.main(new String[] {});
                } catch (Exception e) {
                    System.err.println("Error en Cliente " + clientId + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }).start();
        }
    }
}
