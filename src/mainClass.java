import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.Key;




public class mainClass {
    public static void main (String [ ] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        System.out.println ("HIDS v1.0");
        //TODO: Hay que quitar esta ruta.
        //File file = new File("/home/carlos/Escritorio/Seguridad/pruebas/prueba/src/principal/fichero");
        File file = new File("../fichero_cifrado.txt");
        
        //Use  algorithm
		//habria que modificar el atributo aqui a un string , ya que lo lee del archivo .config
		MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");

		//Generar hash
		String hashArchivo = getHashFichero(sha256Digest, file);

		//mostrar hash
        System.out.println(hashArchivo);
        
        //Detectamos el Sistema Operativo y lo pasamos a una variable para tenerlo en cuenta:
        String sistemOp = getOpSystem();

        
        System.out.println("Cargamos la configuración inicial...");
        Properties prop = cargaConfiguracion("config.properties");
        System.out.println("Periodo: "+prop.getProperty("task.hours") + " Horas");

       
        //TODO: Pasar el path del fichero como la propiedad "file.hash.path" del archivo de configuración
        String data_fichero_hash = lecturaFicheros("../fichero_cifrado.txt",true);
        System.out.println("Archivo de hash leido en claro: "+data_fichero_hash) ;
        System.out.println("Ciframos el archivo...");
        System.out.println("Creamos la clave de cifrado simétrico...");
        Key keyGenerated = generadorClavesSimetricas(prop.getProperty("algorithm.simetric"),Integer.parseInt(prop.getProperty("algorithm.simetric.tam")));
        System.out.println("Clave de cifrado: " + keyGenerated);
        System.out.println("Guardamos la clave de cifrado... ");
        //Guardamos la clave de cifrado
        guardarPassword(keyGenerated);
        //Conseguimos la clave desde el fichero:
        Key keyPassword = getPasswordSimetrica(prop.getProperty("algorithm.simetric"));
        System.out.println("Clave de Cifrado: " + keyPassword);
        byte[] data_fichero_hash_crypt = cifrarArchivoHash(data_fichero_hash,prop.getProperty("algorithm.simetric"),keyPassword);
        System.out.println("Datos del fichero de hash cifrado: "+data_fichero_hash_crypt);
        System.out.println("Desciframos el archivo...");
        String data_fichero_hash_decrypt = descifrarArchivoHash(data_fichero_hash_crypt, prop.getProperty("algorithm.simetric"),keyPassword);
        System.out.println("Datos del fichero de hash descifrado: "+data_fichero_hash_decrypt); 
        configuracionTiempo(0, tareaParaRealizar());
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
                System.out.println("Realizando tarea...");
                //Aquí debe estar lo que viene siendo las tareas que se realizan cada 24 horas.
                //Obtención de Hash de ficheros en SHA-256 e introducirlo en el fichero de Hash

                //Cifrado del fichero de Hash con cifrado simétrico (Se supone que el código no lo vería el atacante por tanto puede estar aquí la pass)

                //Obtención de PID del proceso del programa y pasarlo a algún archivo de configuración donde lo recogería un programa en bash para la comprobación y alarma si se para el HIDS

                //Ofuscación de las rutas

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

    //método que obtiene la ruta absoluta de un fichero a partid e un nombre y un directorio donde comienza a buscar de manera recursiva
    private static String  getPathFichero(File dir,String nombreFichero) {
		String res = "";
		
        
            File[] files = dir.listFiles();
            for (File file : files) {
                if (file.isDirectory()) {
                    //System.out.println("directorio:" + file.getCanonicalPath());
                    //verContenidoFolder(file);
                	if(res!="") {
                		break;
                	}else {
                		res = getPathFichero(file,nombreFichero);
                	}
                } else {
                    if(file.getName().equals(nombreFichero)) {
                    	//System.out.println("entro aquí");
                    	res = file.getAbsolutePath();
                    	break;
                    }  
                }
            }
        
        return res;
    } 
    
    
    
    //Metodo que devuelve un map que relaciona key = nombrefichero con value= ruta absoluta, devuelve dicho map
    private static Map<String,String> getRutasAbsolutas() throws FileNotFoundException, IOException{
		Map<String, String> map = new HashMap<String, String>();
        Properties p = new Properties();
        //lee el archivo config.properties
		p.load(new FileReader("hids/src/principal/config.properties"));

		//System.out.println(p.getProperties("filelist"));
		String res1[] =  p.getProperty("filelist").split(",");
		for(int i=0;i<res1.length;i++) {
			String ruta = getPathFichero(new File("/"), res1[i]);
			if(!ruta.equals("")) {
				map.put(res1[i],getPathFichero(new File("/"), res1[i]));
			}
		}
		return map;
    }
    /*test para mis metodos subidos, habria que cambiar la ruta del config.properties
	System.out.println("------------------------pruebas path de todos los ficheros------------------");
	    Map<String, String> test = getRutasAbsolutas();
        System.out.println(test.values());
        System.out.println(test.keySet());
    */

    //Este método lo vamos a usar para cifrar el archivo que contiene la lista de Hash 
    private static byte[] cifrarArchivoHash(String data, String algorithm_simetric, Key keyGenerated){
        //Creamos las variables necesarias:
        byte[] cipherText = null;

        try{
            //Creamos el objeto Cipher y le pasamos el algoritmo a usar
            Cipher cipherObj = Cipher.getInstance("AES");

            //Iniciamos el cipher pasándole los parámetros necesarios:
            cipherObj.init(Cipher.ENCRYPT_MODE, keyGenerated);

            //Por último ciframos los datos necesarios:
            cipherText = cipherObj.doFinal(data.getBytes());
        }catch(Exception exception){
            exception.printStackTrace();
        }
        //String cryptValue = new Base64.encode(cipherText);
        //return cryptValue;
        return cipherText;
    }
    //Este método lo vamos a usar para cifrar el archivo que contiene la lista de Hash 
    private static String descifrarArchivoHash(byte[] data_crypt, String algorithm_simetric, Key keyGenerated){
        //Creamos las variables necesarias:
        String decryptTextRes = "";
        try{
            Cipher cipherObj = Cipher.getInstance(algorithm_simetric);
            //Inicializamos el cifrador para descifrar pasándole la clave generada:
            cipherObj.init(Cipher.DECRYPT_MODE, keyGenerated);
            byte[] decryptText = cipherObj.doFinal(data_crypt);
            // Texto obtenido, igual al original.
            decryptTextRes = new String(decryptText);
        }catch(Exception exception){
            exception.printStackTrace();
        }
        return decryptTextRes;
    }

    //El parámetro salt indica si debemos añadirle un salt o no para el cifrado
    private static String lecturaFicheros(String dirArchivo, Boolean salt){
        //Creamos las variables a usar:
        String ret_data = new String(); 
        File file = null;
        FileReader fileReader = null;
        BufferedReader bufferedReader = null;

        try{
            //Abrimos el fichero y creamos el buffer para poder leerlo:
            file = new File(dirArchivo);
            fileReader = new FileReader(file);
            bufferedReader = new BufferedReader(fileReader);

            //Leemos el fichero completamente:
            String var_control_string;
            while((var_control_string = bufferedReader.readLine()) != null){
                System.out.println("Línea --> "+var_control_string);
                //TODO: Pasarle la propiedad "keyword.crypt.fich.hash" del archivo config en vez de "asignaturaSSII"
                if(salt){
                    ret_data = ret_data + "asignaturaSSII" + var_control_string;
                }else{
                    ret_data = var_control_string;
                }
            }

        } catch(Exception exception){
            exception.printStackTrace();
        }finally{
            //Cerramos el fichero antes de terminar
            try{
                if( null != fileReader){
                    fileReader.close();
                }
            }catch (Exception exception2){
                exception2.printStackTrace();
            }
        }
        
        //Por último, devolvemos el String generado:
        return ret_data;
    } 

    private static Key generadorClavesSimetricas(String alg, Integer longitud){
        Key key = null;
        try{
            // Generamos una clave de 128 bits adecuada para AES
            KeyGenerator keyGenerator = KeyGenerator.getInstance(alg);
            keyGenerator.init(longitud);
            key = keyGenerator.generateKey();
            
            // Alternativamente, una clave que queramos que tenga al menos 16 bytes
            // y nos quedamos con los bytes 0 a 15
            key = new SecretKeySpec("8m[zWQq<!me_8kMg".getBytes(),  0, 16, alg);
            
        }catch(Exception exception){
            exception.printStackTrace();
        }
        return key;
    }

    //Función para detectar el sistema operativo que esta corriendo la máquina. Sería buena idea introducir los SO como propiedades en el config
    private static String getOpSystem(){
        String res_ret = "";
        String sistemOp_aux = System.getProperty("os.name").toLowerCase();
        if(sistemOp_aux.indexOf("win") >= 0 ){
            res_ret = "windows";
        } else if(sistemOp_aux.indexOf("mac") >= 0){
            res_ret = "mac";
        } else if( sistemOp_aux.indexOf("sunos") >= 0 ){
            res_ret = "solaris";
        } else {
            res_ret = "linux";
        }
        return res_ret;
    }

    private static void conexionBBDD(String username, String password){
        //Conexion con la base de datos 
    }

    private static void cerrarConexionBBDD(){
        //Cerramos la conexión con la base de datos
    }

    private static void guardarPassword(Key password){
        //En principio escribimos en un fichero:
        FileWriter fichero = null;
        try{
            fichero = new FileWriter("../fichero_password.txt");
            fichero.write(Base64.getEncoder().encodeToString(password.getEncoded()) +"\n");

            fichero.close();
        }catch(Exception exception){
            exception.printStackTrace();
        }
    }

    private static Key getPasswordSimetrica(String algorithm_simetric){
        //TODO: pasar propeidad del fichero config.properties
        String password = lecturaFicheros("../fichero_password.txt",false);
        System.out.println("pass without decrypt -> "+password);
        byte[] decKey = Base64.getDecoder().decode(password);
        System.out.println("decKey -> "+decKey.toString());
        Key retKey = new SecretKeySpec(decKey, 0, decKey.length, algorithm_simetric);
        return retKey;
    }





//Metodo que genera un map,relaciona nombre del fichero con el hash de éste
private static Map<String,String> getNombreHash() throws NoSuchAlgorithmException, FileNotFoundException, IOException{
		//ese digest es provisional deberia leerlo del config.properties
		MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
		Map<String, String> map = getRutasAbsolutas();
		Map<String, String> mapRes = new HashMap<String, String>(); // Relaciona nombres de fichero con hash
		for(String n:map.keySet()){
			File f = new File(map.get(n));
			String hash = getHashFichero(sha256Digest,f);
			mapRes.put(n, hash);
		}
		return mapRes;
	}
	
	//Metodo que genera un fichero que almacena nombreFichero:hashdefichero
	private static void generarFicheroHash() throws IOException, NoSuchAlgorithmException{
		BufferedWriter output = null;
		File file = new File("hashes.txt");//Hay que seleccionar una ruta segura
		Map<String, String> map = getNombreHash();
		String s = "";
		Boolean esPrimero = true;
		for(String n:map.keySet()) {
			if(esPrimero) {
				s=(n+":"+map.get(n)+"\n");
				esPrimero = false;
			}else {
				s+=(n+":"+map.get(n)+"\n");
			}
		}
		output = new BufferedWriter(new FileWriter(file));
        output.write(s);
        output.close();
		
		
		
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