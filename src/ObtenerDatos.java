import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.*;

/**
 * La clase ObtenerDatos implementa cuatro mÃ©todos pÃºblicos que permiten obtener
 * determinados datos de los certificados de tarjetas DNIe, Izenpe y Ona.
 *
 * @author tbc
 */
public class ObtenerDatos {

    private static final byte[] dnie_v_1_0_Atr = {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44,
        (byte) 0x4E, (byte) 0x49, (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00};
    private static final byte[] dnie_v_1_0_Mask = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};

    public ObtenerDatos() {
    }

    public Usuario LeerNIF() { // Metodo para acceder y leer el DNI.

        Usuario user = null; // Clase usuario para guardas los datos del DNI.
        byte[] datos=null; // Array de bytes para guardar los datos.
        try {
            Card c = ConexionTarjeta(); //Se crea la conexión.
            if (c == null) {
                throw new Exception("ACCESO DNIe: No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                datos = leerCertificado(ch);
                if(datos!=null)
                    user = leerDatosUsuario(datos);
            }
            c.disconnect(false);

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return user;
    }
//Devuelve la cadena completa del certificado
    public byte[] leerCertificado(CardChannel ch) throws CardException, CertificateException {


        int offset = 0;
        String completName = null;

        //[1] PRÃ�CTICA 3. Punto 1.a
        /*Comando SELECT, este comando permite la seleccion de fichero dedicado a (DF) o de un fichero elemental (EF). Esto lo podemos saber
        ya que en el siguiente array de byte presenta la misma estructura que su especificacion:
        - El primer octeto 0x00 es el campo CLA
        - El segundo octeto 0xA4 es el campo INS
        - El tercero octeto puede ser 0x00(Selecciona DF o EF por Id) o 0x04(Seleccion directa de DF por nombre) es el campo P1.
        - El cuarto octeto es 0x00 es el campo P2.
        - El quinto octeto es el campo LC, es la longitud del campo de datos.
        - Los siguientes campos son los datos.
        */
        //En este caso el tercer octeto es 0x04(Selección directa de DF(fichero dedicado) por nombre)
        byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
       // DATOS: 4D 61 73 74 65 72 2E 46 69 6C 65(hexadecimal)->ASCII----->Master.File
        //En este caso accedemos al fichero Master.File (un comando de selección por nombre del fichero maestro )
        //LC=0x0b
        ResponseAPDU r = ch.transmit(new CommandAPDU(command));
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[2] PRÃ�CTICA 3. Punto 1.a
        /*Comando SELECT, este comando permite la seleccion de fichero dedicado a (DF) o de un fichero elemental (EF). Esto lo podemos saber
        ya que en el siguiente array de byte presenta la misma estructura que su especificacion:
        - El primer octeto 0x00 es el campo CLA
        - El segundo octeto 0xA4 es el campo INS
        - El tercero octeto puede ser 0x00(Selecciona DF o EF por Id) o 0x04(Seleccion directa de DF por nombre) es el campo P1.
        - El cuarto octeto es 0x00 es el campo P2.
        - El quinto octeto es el campo LC, es la longitud del campo de datos.
        - Los siguientes campos son los datos.
        */
      //En este caso P1= 0x00(Selecciona DF o EF por Id)
      //LC=0x02
      //DATOS:50 15--->DECIMAL->80  
      //Los dos últimos valores hacen referencia al ID del fichero elemental 
      //P1=0x00 para poder seleccionar por ID. 
        
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
        
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[3] PRÃ�CTICA 3. Punto 1.a
        /*Comando SELECT, este comando permite la seleccion de fichero dedicado a (DF) o de un fichero elemental (EF). Esto lo podemos saber
        ya que en el siguiente array de byte presenta la misma estructura que su especificacion:
        - El primer octeto 0x00 es el campo CLA
        - El segundo octeto 0xA4 es el campo INS
        - El tercero octeto puede ser 0x00(Selecciona DF o EF por Id) o 0x04(Seleccion directa de DF por nombre) es el campo P1.
        - El cuarto octeto es 0x00 es el campo P2.
        - El quinto octeto es el campo LC, es la longitud del campo de datos.
        - Los siguientes campos son los datos.
        */
      //En este caso P1= 0x00(Selecciona DF o EF por Id)
      //LC=0x02
      //DATOS:60 04--->DECIMAL->96  
      //Los dos últimos valores hacen referencia al ID del fichero elemental 
      //P1=0x00 para poder seleccionar por ID. 
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
        r = ch.transmit(new CommandAPDU(command));

        byte[] responseData = null;
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        } else {
            responseData = r.getData();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] r2 = null;
        int bloque = 0;

        do {
             //[4] PRÃ�CTICA 3. Punto 1.b
        	/*Comando Read Binary, este comando devuelve en su mensaje de respuesta el contenido (o parte) de
        	un fichero elemental transparente.
        	 */
            final byte CLA = (byte) 0x00;//Este valor puede variar desde 0x00 hasta 0x0F
            final byte INS = (byte) 0xB0;//Valor donde se especifica el comando
            final byte LE = (byte) 0xFF; //FF=255, si el campo Le=0 el número de bytes a leer es 256. 
            							//LE es Número de bytes a leer

           

            //[4] PRÃ�CTICA 3. Punto 1.b
            
            //P1-P2 Salida del primer byte a leer desde el principio del fichero.
            //Aqui indicamos desde donde se va a leer
            command = new byte[]{CLA, INS, (byte) bloque/*P1*/, (byte) 0x00/*P2*/, LE};//Identificar quÃ© hacen P1 y P2
            r = ch.transmit(new CommandAPDU(command));
            
           //Mensaje de respuesta
           // System.out.println("ACCESO DNIe: Response SW1=" + String.format("%X", r.getSW1()) + " SW2=" + String.format("%X", r.getSW2()));
           //Devuelve  SW1=90 SW2=0, estos son los bytes de estado
            
            //Comprobamos que sea correcto
            if ((byte) r.getSW() == (byte) 0x9000) {
            	//Si es 9000 es Ok, cualquier otro valor estado negativo
                r2 = r.getData();

                baos.write(r2, 0, r2.length);

                for (int i = 0; i < r2.length; i++) {
                    byte[] t = new byte[1];
                    t[0] = r2[i];
                    //Los va imprimiendo en bloques de 256 bytes
                    System.out.println(i + (0xff * bloque) + String.format(" %2X", r2[i]) + " " + String.format(" %d", r2[i])+" "+new String(t));
                }
                bloque++;
            } else {
                return null;
            }

        } while (r2.length >= 0xfe);


         ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

      

        
        return baos.toByteArray();
    }

    
    
    
    /**
     * Este mÃ©todo establece la conexiÃ³n con la tarjeta. La funciÃ³n busca el
     * Terminal que contenga una tarjeta, independientemente del tipo de tarjeta
     * que sea.
     *
     * @return objeto Card con conexiÃ³n establecida
     * @throws Exception
     */
    private Card ConexionTarjeta() throws Exception {

        Card card = null;
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        //System.out.println("Terminals: " + terminals);

        for (int i = 0; i < terminals.size(); i++) {

            // get terminal
            CardTerminal terminal = terminals.get(i);

            try {
                if (terminal.isCardPresent()) {
                    card = terminal.connect("*"); //T=0, T=1 or T=CL(not needed)
                }
            } catch (Exception e) {

                System.out.println("Exception catched: " + e.getMessage());
                card = null;
            }
        }
        return card;
    }

    /**
     * Este mÃ©todo nos permite saber el tipo de tarjeta que estamos leyendo del
     * Terminal, a partir del ATR de Ã©sta.
     *
     * @param atrCard ATR de la tarjeta que estamos leyendo
     * @return tipo de la tarjeta. 1 si es DNIe, 2 si es Starcos y 0 para los
     * demÃ¡s tipos
     */
    private boolean esDNIe(byte[] atrCard) {
        int j = 0;
        boolean found = false;

        //Es una tarjeta DNIe?
        if (atrCard.length == dnie_v_1_0_Atr.length) {
            found = true;
            while (j < dnie_v_1_0_Atr.length && found) {
                if ((atrCard[j] & dnie_v_1_0_Mask[j]) != (dnie_v_1_0_Atr[j] & dnie_v_1_0_Mask[j])) {
                    found = false; //No es una tarjeta DNIe
                }
                j++;
            }
        }

        if (found == true) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Analizar los datos leÃ­dos del DNIe para obtener
     *   - nombre
     *   - apellidos
     *   - NIF
     * @param datos
     * @return 
     */
    private Usuario leerDatosUsuario(byte[] datos) {
       return null;
    }
}
