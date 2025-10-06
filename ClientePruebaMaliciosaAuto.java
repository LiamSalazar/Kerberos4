package Kerberos;

import java.io.*;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.SealedObject;

/**
 * ClientePruebaMaliciosaAuto
 *
 * - Ejecuta sin argumentos; modo por defecto = "all".
 * - Ajusta las constantes al inicio si quieres cambiar
 * puertos/intentos/timeouts.
 * - Tiene logging por progreso y medición de latencias (mean, p95).
 */
public class ClientePruebaMaliciosaAuto {

    // ====================== CONFIG ======================
    private static final String AS_HOST = "localhost";
    private static final int AS_PORT = 2000;

    private static final String TGS_HOST = "localhost";
    private static final int TGS_PORT = 2001;

    private static final String SERVICE_HOST = "localhost";
    private static final int SERVICE_PORT = 2002;

    private static final String TICKET_FILE = "ticket_valid.ser";

    // Numero de intentos por prueba (ajustar)
    private static final int REPLAY_ATTEMPTS = 200;
    private static final int CORRUPT_ATTEMPTS = 200;
    private static final int FLOOD_ATTEMPTS = 200;

    // Modo por defecto: "all", "save", "replay", "corrupt", "flood"
    private static final String MODE = "all";

    // Socket read timeout en ms para cada intento (reduce espera por intentos
    // lentos)
    private static final int SOCKET_READ_TIMEOUT_MS = 700;
    // ====================================================

    private Object ticketEnMemoria = null;

    // Latency collectors (ms)
    private final List<Double> replayLatencies = Collections.synchronizedList(new ArrayList<>());
    private final List<Double> corruptLatencies = Collections.synchronizedList(new ArrayList<>());

    public static void main(String[] args) {
        ClientePruebaMaliciosaAuto runner = new ClientePruebaMaliciosaAuto();
        System.out.println("[AutoTester] Modo: " + MODE);
        try {
            switch (MODE.toLowerCase()) {
                case "all":
                    runner.saveTicketFlow();
                    runner.replayFlow(REPLAY_ATTEMPTS);
                    runner.corruptFlow(CORRUPT_ATTEMPTS);
                    runner.floodFlow(FLOOD_ATTEMPTS);
                    break;
                case "save":
                    runner.saveTicketFlow();
                    break;
                case "replay":
                    if (!runner.loadTicketFromDiskIfAbsent()) {
                        System.err.println("[AutoTester] No hay ticket en memoria ni en disco. Ejecuta save primero.");
                        return;
                    }
                    runner.replayFlow(REPLAY_ATTEMPTS);
                    break;
                case "corrupt":
                    runner.corruptFlow(CORRUPT_ATTEMPTS);
                    break;
                case "flood":
                    runner.floodFlow(FLOOD_ATTEMPTS);
                    break;
                default:
                    System.err.println("[AutoTester] Modo desconocido: " + MODE);
            }
        } catch (Exception e) {
            System.err.println("[AutoTester] Error general: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // -------------------- Flujos --------------------

    private void saveTicketFlow() {
        System.out.println("[save] Solicitando TGT al AS...");
        Map<String, Object> respAS = solicitarTGT(AS_HOST, AS_PORT);
        if (respAS == null) {
            System.err.println("[save] No se recibió respuesta del AS. Abortando save.");
            return;
        }

        Object ticketTgs = respAS.get("[Ticket-tgs]");
        Object k_c_tgs = respAS.get("[K-c_tgs]");
        System.out.println("[save] AS OK -> claves: " + respAS.keySet());

        System.out.println("[save] Solicitando ticket de servicio al TGS...");
        Map<String, Object> respTGS = solicitarTicketServicio(TGS_HOST, TGS_PORT, ticketTgs, k_c_tgs);
        if (respTGS == null) {
            System.err.println("[save] No se recibió respuesta del TGS. Abortando save.");
            return;
        }

        Object ticketV = respTGS.get("[Ticket-v]");
        if (ticketV == null) {
            System.err.println("[save] No se encontró '[Ticket-v]' en la respuesta del TGS.");
            return;
        }

        this.ticketEnMemoria = ticketV;

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(TICKET_FILE))) {
            oos.writeObject(ticketV);
            oos.flush();
            System.out.println("[save] Ticket guardado en " + TICKET_FILE);
        } catch (Exception e) {
            System.err.println("[save] Error guardando ticket: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void replayFlow(int attempts) {
        System.out.println("[replay] Iniciando replay test con " + attempts + " intentos...");
        Object ticketObj = this.ticketEnMemoria;
        if (ticketObj == null) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(TICKET_FILE))) {
                ticketObj = ois.readObject();
                System.out.println("[replay] Ticket cargado desde disco: " + TICKET_FILE);
            } catch (Exception e) {
                System.err.println("[replay] No existe ticket en memoria ni en disco. Ejecuta save primero.");
                return;
            }
        }

        final int BATCH = Math.max(1, attempts / 20); // imprimir ~20 veces durante la prueba
        int accepted = 0, rejected = 0, errors = 0;

        for (int i = 0; i < attempts; i++) {
            long start = System.nanoTime();
            try {
                boolean ok = enviarTicketAlServiceYComprobar(SERVICE_HOST, SERVICE_PORT, ticketObj, "REPLAY_AUT_" + i);
                long end = System.nanoTime();
                double ms = (end - start) / 1_000_000.0;
                replayLatencies.add(ms);

                if (ok)
                    accepted++;
                else
                    rejected++;
            } catch (Exception e) {
                errors++;
            }
            if (i % BATCH == 0) {
                System.out.printf("[replay] progress: %d/%d (accepted=%d, rejected=%d)%n", i, attempts, accepted,
                        rejected);
            }
        }

        System.out.printf("[replay] attempts=%d, accepted=%d, rejected=%d, errors=%d%n", attempts, accepted, rejected,
                errors);
        printLatencyStats("replay", replayLatencies);
    }

    private void corruptFlow(int attempts) {
        System.out.println("[corrupt] Iniciando corrupt test con " + attempts + " intentos...");
        int accepted = 0, rejected = 0, errors = 0;
        final int BATCH = Math.max(1, attempts / 20);

        for (int i = 0; i < attempts; i++) {
            long start = System.nanoTime();
            try {
                Object candidate;
                if (this.ticketEnMemoria != null) {
                    byte[] raw = serializeObject(this.ticketEnMemoria);
                    if (raw != null && raw.length > 0) {
                        int idx = Math.max(0, (raw.length - 1) / 3);
                        raw[idx] = (byte) (raw[idx] ^ (byte) (0xFF >>> (i % 8)));
                        candidate = raw;
                    } else {
                        candidate = "CORRUPTED_STR_" + i;
                    }
                } else {
                    candidate = "CORRUPTED_STR_" + i;
                }

                boolean ok = enviarTicketAlServiceYComprobar(SERVICE_HOST, SERVICE_PORT, candidate, "CORRUPT_AUT_" + i);
                long end = System.nanoTime();
                double ms = (end - start) / 1_000_000.0;
                corruptLatencies.add(ms);

                if (ok)
                    accepted++;
                else
                    rejected++;
            } catch (Exception e) {
                errors++;
            }
            if (i % BATCH == 0) {
                System.out.printf("[corrupt] progress: %d/%d (accepted=%d, rejected=%d)%n", i, attempts, accepted,
                        rejected);
            }
        }

        System.out.printf("[corrupt] attempts=%d, accepted=%d, rejected=%d, errors=%d%n", attempts, accepted, rejected,
                errors);
        printLatencyStats("corrupt", corruptLatencies);
    }

    private void floodFlow(int attempts) {
        System.out.println("[flood] Iniciando flood test con " + attempts + " intentos...");
        int attempted = 0, errors = 0;
        final int BATCH = Math.max(1, attempts / 20);

        for (int i = 0; i < attempts; i++) {
            try (Socket s = new Socket(SERVICE_HOST, SERVICE_PORT);
                    OutputStream os = s.getOutputStream()) {
                byte[] garbage = new byte[128];
                for (int k = 0; k < garbage.length; k++)
                    garbage[k] = (byte) (Math.random() * 255);
                os.write(garbage);
                os.flush();
                attempted++;
            } catch (Exception e) {
                errors++;
            }
            if (i % BATCH == 0) {
                System.out.printf("[flood] progress: %d/%d (sent=%d, errors=%d)%n", i, attempts, attempted, errors);
            }
        }
        System.out.printf("[flood] attempts=%d, sent=%d, errors=%d%n", attempts, attempted, errors);
    }

    // -------------------- Helpers de protocolo --------------------

    /**
     * Petición al AS con orden de streams corregido (OOS -> enviar -> OIS) y
     * descifrado.
     */
    private Map<String, Object> solicitarTGT(String host, int port) {
        System.out.println("[DEBUG][AS] Intentando conectar a " + host + ":" + port + " ...");
        try (Socket s = new Socket(host, port)) {
            System.out.println("[DEBUG][AS] Socket conectado: local=" + s.getLocalAddress() + ":" + s.getLocalPort()
                    + " remote=" + s.getRemoteSocketAddress());

            System.out.println("[DEBUG][AS] Creando ObjectOutputStream...");
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());

            Map<String, Object> pet = new HashMap<>();
            String idCliente = "1";
            String idTgs = "1";
            java.time.LocalDateTime ts1 = java.time.LocalDateTime.now();

            pet.put("[Id-c]", idCliente);
            pet.put("[Id-tgs]", idTgs);
            pet.put("[TimeStamp-1]", ts1);

            System.out.println("[DEBUG][AS] Enviando petición al AS (keys): " + pet.keySet());
            oos.writeObject(pet);
            oos.flush();
            System.out.println(
                    "[DEBUG][AS] Petición enviada, creando ObjectInputStream y esperando respuesta (timeout 10s)...");

            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            s.setSoTimeout(10_000);

            Object resp;
            try {
                resp = ois.readObject();
                System.out.println(
                        "[DEBUG][AS] readObject() devolvió: " + (resp == null ? "null" : resp.getClass().getName()));
            } catch (java.net.SocketTimeoutException te) {
                System.err.println("[DEBUG][AS] TIMEOUT esperando respuesta del AS (10s).");
                return null;
            }

            if (resp instanceof SealedObject) {
                SealedObject sealed = (SealedObject) resp;
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> map = (Map<String, Object>) AESUtils.desencriptarObjeto(sealed,
                            "ContraseniaCliente");
                    System.out.println("[DEBUG][AS] SealedObject descifrado OK, keys=" + map.keySet());
                    return map;
                } catch (Exception e) {
                    System.err.println("[DEBUG][AS] Error descifrando respuesta del AS: " + e.getMessage());
                    e.printStackTrace();
                    return null;
                }
            } else if (resp instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) resp;
                System.out.println("[DEBUG][AS] Map recibido (no cifrado), keys=" + map.keySet());
                return map;
            } else {
                System.out.println("[DEBUG][AS] Tipo inesperado de respuesta: " + resp);
                return null;
            }
        } catch (Exception e) {
            System.err.println("[DEBUG][AS] Error comunicando con AS: " + e);
            e.printStackTrace();
            return null;
        }
    }

    /**
     * TGS: envía [Ticket-tgs] y [Autentificador-c], y DESCIFRA la respuesta
     * SealedObject
     * que contiene el Ticket-v. Devuelve un Map con "[Ticket-v]" si todo OK.
     */
    private Map<String, Object> solicitarTicketServicio(String host, int port, Object ticketTgs, Object k_c_tgs) {
        System.out.println("[DEBUG][TGS] Intentando conectar a " + host + ":" + port + " ...");
        try (Socket s = new Socket(host, port)) {
            System.out.println("[DEBUG][TGS] Socket conectado: " + s.getRemoteSocketAddress());

            System.out.println("[DEBUG][TGS] Creando ObjectOutputStream...");
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());

            // Construir autenticador tipo ClientAuthentication (constructor (String,
            // InetAddress))
            Object authPojo = null;
            try {
                authPojo = buildClientAuthenticationPojoStrict("1", java.net.InetAddress.getLocalHost());
            } catch (Exception e) {
                System.err.println(
                        "[DEBUG][TGS] No se pudo construir ClientAuthentication por reflection: " + e.getMessage());
                e.printStackTrace();
                return null;
            }

            // Cifrado con K-c_tgs (String)
            String claveKcTgs = (k_c_tgs == null) ? null : k_c_tgs.toString();
            Object authCifrado;
            try {
                if (claveKcTgs == null) {
                    System.err.println("[DEBUG][TGS] K-c_tgs es null; envío marcador inválido");
                    authCifrado = "AUT_INVALID_NO_KC";
                } else {
                    authCifrado = AESUtils.encriptarObjeto((java.io.Serializable) authPojo, claveKcTgs);
                }
            } catch (Exception e) {
                System.err.println("[DEBUG][TGS] Error cifrando autentificador: " + e.getMessage());
                e.printStackTrace();
                authCifrado = "AUT_ENCRYPT_ERROR";
            }

            Map<String, Object> pet = new HashMap<>();
            pet.put("[Id-v]", "1");
            pet.put("[Ticket-tgs]", ticketTgs);
            pet.put("[Autentificador-c]", authCifrado);

            System.out.println("[DEBUG][TGS] Enviando al TGS (keys): " + pet.keySet());
            oos.writeObject(pet);
            oos.flush();
            System.out.println(
                    "[DEBUG][TGS] Petición enviada, creando ObjectInputStream y esperando respuesta (timeout 10s)...");

            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            s.setSoTimeout(10_000);

            Object resp;
            try {
                resp = ois.readObject();
                System.out.println(
                        "[DEBUG][TGS] readObject() devolvió: " + (resp == null ? "null" : resp.getClass().getName()));
            } catch (java.net.SocketTimeoutException te) {
                System.err.println("[DEBUG][TGS] TIMEOUT esperando respuesta del TGS (10s).");
                return null;
            }

            if (resp instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) resp;
                System.out.println("[DEBUG][TGS] Map OK, keys=" + map.keySet());
                return map;
            }

            if (resp instanceof SealedObject) {
                SealedObject sealed = (SealedObject) resp;
                System.out.println("[DEBUG][TGS] SealedObject recibido, intentando descifrar con K-c_tgs (String)...");
                try {
                    Object desc = Kerberos.AESUtils.desencriptarObjeto(sealed, claveKcTgs);
                    if (desc instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> inner = (Map<String, Object>) desc;
                        System.out.println("[DEBUG][TGS] SealedObject descifrado. Keys internas=" + inner.keySet());
                        if (inner.containsKey("[Ticket-v]"))
                            return inner;
                        Map<String, Object> wrapper = new HashMap<>();
                        wrapper.put("[Ticket-v]", inner.get("Ticket-v") != null ? inner.get("Ticket-v") : inner);
                        return wrapper;
                    } else {
                        Map<String, Object> wrapper = new HashMap<>();
                        wrapper.put("[Ticket-v]", desc);
                        System.out.println("[DEBUG][TGS] SealedObject descifrado -> tipo: "
                                + (desc == null ? "null" : desc.getClass().getName()));
                        return wrapper;
                    }
                } catch (Exception e) {
                    System.err.println("[DEBUG][TGS] Descifrado con clave String falló: " + e.getMessage());
                    e.printStackTrace();
                    Map<String, Object> wrapper = new HashMap<>();
                    wrapper.put("[SealedObject]", sealed);
                    return wrapper;
                }
            }

            System.out.println("[DEBUG][TGS] Tipo inesperado de respuesta: " + resp);
            return null;
        } catch (Exception e) {
            System.err.println("[DEBUG][TGS] Error comunicando con TGS: " + e);
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Envía Ticket-v (o candidate) al Service y devuelve true si el Service
     * concedió acceso.
     * Timeout corto (SO_TIMEOUT) para no bloquear mucho.
     */
    private boolean enviarTicketAlServiceYComprobar(String host, int port, Object candidateTicket, String authLabel) {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(SOCKET_READ_TIMEOUT_MS);
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

            Map<String, Object> pet = new HashMap<>();
            pet.put("[Ticket-v]", candidateTicket);
            pet.put("[Autentificador-c]", authLabel);

            oos.writeObject(pet);
            oos.flush();

            Object resp = null;
            try {
                resp = ois.readObject();
            } catch (java.net.SocketTimeoutException te) {
                // timeout -> tratamos como rechazo
                return false;
            } catch (Exception e) {
                return false;
            }

            if (resp instanceof String) {
                String r = (String) resp;
                return (r.toUpperCase().contains("ACCESO") || r.toUpperCase().contains("CONCEDIDO"));
            } else if (resp == null) {
                return false;
            } else {
                String sresp = resp.toString();
                return (sresp.toUpperCase().contains("ACCESO") || sresp.toUpperCase().contains("CONCEDIDO"));
            }
        } catch (Exception e) {
            return false;
        }
    }

    // -------------------- Utilidades --------------------

    private boolean loadTicketFromDiskIfAbsent() {
        if (this.ticketEnMemoria != null)
            return true;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(TICKET_FILE))) {
            this.ticketEnMemoria = ois.readObject();
            System.out.println("[AutoTester] Ticket cargado desde disco: " + TICKET_FILE);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] serializeObject(Object o) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(o);
            oos.flush();
            return bos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static Object buildClientAuthenticationPojoStrict(String id, java.net.InetAddress addr) throws Exception {
        Class<?> clazz = Class.forName("Kerberos.Client$ClientAuthentication");
        try {
            var ctor = clazz.getDeclaredConstructor(String.class, java.net.InetAddress.class);
            ctor.setAccessible(true);
            return ctor.newInstance(id, addr);
        } catch (NoSuchMethodException e) {
            throw new NoSuchMethodException(
                    "Kerberos.Client$ClientAuthentication debe tener constructor (String, InetAddress). Ajusta si tu firma es otra.");
        }
    }

    private static void printLatencyStats(String label, List<Double> samples) {
        if (samples == null || samples.isEmpty()) {
            System.out.println("[latency][" + label + "] no hay muestras.");
            return;
        }
        List<Double> copy = new ArrayList<>(samples);
        Collections.sort(copy);
        double sum = 0.0;
        for (double v : copy)
            sum += v;
        double mean = sum / copy.size();
        int n = copy.size();
        int idx95 = (int) Math.ceil(0.95 * n) - 1;
        idx95 = Math.max(0, Math.min(n - 1, idx95));
        double p95 = copy.get(idx95);
        System.out.printf("[latency][%s] samples=%d, mean=%.3f ms, p95=%.3f ms%n", label, n, mean, p95);
    }
}
