import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class mainClass {
    public static void main (String [ ] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException {

        System.out.println ("HIDS v1.0");
        Properties prop = cargaConfiguracion("config.properties");
        System.out.println("***** Configuración del sistema: ");
        System.out.println("Periodo: "+prop.getProperty("task.hours") + " Horas");
        configuracionTiempo(Integer.parseInt(prop.getProperty("task.hours")), tareaParaRealizar());
        System.out.println("Terminamos...");
        
		
 
    } //Cierre del main

    private static void configuracionTiempo(Integer periodoHoras, TimerTask task){
        //TODO: quitar el comentario para que use las horas que le pasemos como parámetro
        //Integer formatoHoraMiliSegundos = periodoHoras * 86400000;
        Integer formatoHoraMiliSegundos = 1000;
        Timer timer;
        timer = new Timer();

        timer.schedule(task, 0, formatoHoraMiliSegundos);
    }

    private static TimerTask tareaParaRealizar(){
        TimerTask task = new TimerTask() {
            @Override
            public void run()
            {
                //Aquí debe estar lo que viene siendo las tareas que se realizan cada 24 horas.
                //Obtención de Hash de ficheros en SHA-256 e introducirlo en el fichero de Hash

                //Cifrado del fichero de Hash con cifrado simétrico (Se supone que el código no lo vería el atacante por tanto puede estar aquí la pass)

                //Obtención de PID del proceso del programa y pasarlo a algún archivo de configuración donde lo recogería un programa en bash para la comprobación y alarma si se para el HIDS

                //Ofuscación de las rutas


                System.out.println("Realizando tarea...");
            }
        };
        return task;
    }

    private static Properties cargaConfiguracion(String url){
        Properties prop = new Properties();
        InputStream is = null;
		
		try {
			is = new FileInputStream(url);
			prop.load(is);
		} catch(IOException e) {
			System.out.println("Error leyendo el archivo de propiedades [" + e.toString() + "]");
		}
        
        return prop;
    }




    //Código referente a la obtención del hash de los ficheros
    private static String getHashFichero(MessageDigest digest, File fichero) throws IOException
	{
	    //creamos el file input stream para leer el contenido del archivo
	    FileInputStream fis = new FileInputStream(fichero);
	     
	    //Creamos el byte array para leer los datos en trozos
	    byte[] byteArray = new byte[8048];
	    int bytesCount = 0;
	      
	    //Lee el archivo y lo va añadiendo en el digest
	    while ((bytesCount = fis.read(byteArray)) != -1) {
	        digest.update(byteArray, 0, bytesCount);
	    };
	     
	    //Paramos la lectura del fichero, ya que ha terminado
	    fis.close();
	     
	    //Obtenemos el  hash's bytes
	    byte[] bytes = digest.digest();
	     
	    //El tipo bytes[] usa formato decimal, por tanto, hay que cambiarlo 
	    //Convierte de el formato decimal al hexadecimal
	    StringBuilder sb = new StringBuilder();
	    for(int i=0; i< bytes.length ;i++)
	    {
	        sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
	    }
	     
	    //devuelve como string el hash generado
	   return sb.toString();
    }
    /*
    Este codigo es para testear el metodo de arriba , funciona , si quieres testearlo deberias modificar la ruta de abajo(File turuta) a la correcta
            //Create checksum for this file
		File file = new File("/home/carlos/Escritorio/Seguridad/pruebas/prueba/src/principal/fichero");

		//Use  algorithm
		//habria que modificar el atributo aqui a un string , ya que lo lee del archivo .config
		MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");

		//Generar hash
		String hashArchivo = getHashFichero(sha256Digest, file);

		//mostrar hash
		System.out.println(hashArchivo);
    */




} //Cierre de la clase