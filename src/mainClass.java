import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.Key;
import java.sql.*;




public class mainClass {
    public static void main (String [ ] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        System.out.println("************************* HIDS v1.0 *************************");
       
        //Detectamos el Sistema Operativo y lo pasamos a una variable para tenerlo en cuenta:
        String sistemOp = getOpSystem();

        
        System.out.println("Cargamos la configuración inicial...");
        Properties prop = cargaConfiguracion("config.properties");
        System.out.println("Periodo: "+prop.getProperty("task.hours") + " Horas");
        System.out.println("Configuración inicial cargada");
        System.out.println("**************************************************");
 
        
        configuracionTiempo(Integer.parseInt(prop.getProperty("task.hours")), tareaParaRealizar(prop));
        System.out.println("Terminamos...");

 
    } //Cierre del main

    private static void configuracionTiempo(Integer periodoHoras, TimerTask task){
        //TODO: quitar el comentario para que use las horas que le pasemos como parámetro
        Integer formatoHoraMiliSegundos = periodoHoras * 86400000;
        //Integer formatoHoraMiliSegundos = 1000;
        Timer timer;
        timer = new Timer();

        timer.schedule(task, 0, formatoHoraMiliSegundos);
    }

    private static TimerTask tareaParaRealizar(Properties p){
        TimerTask task = new TimerTask() {
            @Override
            public void run()
            {
                int cont = 0;
                System.out.println("Realizando tarea...");
                //Aquí debe estar lo que viene siendo las tareas que se realizan cada 24 horas.

                //Comprobamos si tenemos la contraseña, si no la pedimos:
                Key keyGen = obtencionClave(p);
                //Obtención de Hash de ficheros en SHA-256 e introducirlo en el fichero de Hash
                String hashes = partHashingCode(p, keyGen);
                System.out.println("Archivo de hash leido en claro: "+hashes);
                
                if(cont == 0){
                    cont = 1;
                    //Ciframos el hash de los ficheros con la clave.
                    String data_fichero_hash_crypt = partCryptSimetric(p,hashes,keyGen);
                    //Guardamos la clave y el cifrado:
                    guardarPasswordAndCryptFile(keyGen, data_fichero_hash_crypt);
                }

                    String hashes_decrypt_file = descifrarArchivoHash(lecturaFicheros("../fichero_cifrado.txt", false), p.getProperty("algorithm.simetric"),keyGen);  
                    System.out.println("hashes_decrypt_file ---> "+hashes_decrypt_file);
    
                    comparaHashesString(getNombreHash(p), p, hashes_decrypt_file);
                    

                //Cifrado del fichero de Hash con cifrado simétrico (Se supone que el código no lo vería el atacante por tanto puede estar aquí la pass)
                


                //Ciframos el hash de los ficheros con la clave.
                String data_fichero_hash_crypt = partCryptSimetric(p,hashes,keyGen);
                //Guardamos la clave y el cifrado:
                guardarPasswordAndCryptFile(keyGen, data_fichero_hash_crypt);
                //Obtención de PID del proceso del programa y pasarlo a algún archivo de configuración donde lo recogería un programa en bash para la comprobación y alarma si se para el HIDS

                //Ofuscación de las rutas

            }
        };
        return task;
    }

    private static Properties cargaConfiguracion(String url){
        Properties prop = new Properties();
        InputStream is = null;
        /*
		prop.setProperty("algorithm", "SHA-256");
		prop.setProperty("task.hours", "24");
		prop.setProperty("algorithm.simetric", "AES");
		prop.setProperty("algorithm.simetric.tam", "256");
		prop.setProperty("algorithm.simetric.password", "JE3mdmrSRv3d7Gnb");
		prop.setProperty("keyword.crypt.fich.hash", "asignaturaSSII");
		prop.setProperty("file.hash.path", "fichero_cifrado.txt");
		prop.setProperty("filelist", "fichero1.txt,fichero2.txt");
        prop.setProperty("filelist.linux", "shadow,profile,protocols,hostname,deluser.conf,passwd");
        */
		try {
			is = new FileInputStream(url);
			prop.load(is);
		} catch(IOException e) {
			System.out.println("Error leyendo el archivo de propiedades [" + e.toString() + "]");
		}
        
        return prop;
    }

        //Código referente a la obtención del hash de los ficheros
        //Código referente a la obtención del hash de los ficheros
        private static String getHashFichero(MessageDigest digest, File fichero)
        {
            String hash = "";
            
            try {
            //Get file input stream for reading the file content
            FileInputStream fis = new FileInputStream(fichero);
             
            //Create byte array to read data in chunks
            byte[] byteArray = new byte[8048];
            int bytesCount = 0;
              
            //Read file data and update in message digest
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            };
             
            //close the stream; We don't need it now.
            fis.close();
             
            //Get the hash's bytes
            byte[] bytes = digest.digest();
             
            //This bytes[] has bytes in decimal format;
            //Convert it to hexadecimal format
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
             
           
           hash = sb.toString();
           
            }
            catch(IOException e) {
                System.out.println("El fichero del que se quiere obtener el hash no existe!!!");
            }
            return hash;
            
        }

    //método que obtiene la ruta absoluta de un fichero a partid e un nombre y un directorio donde comienza a buscar de manera recursiva
    private static String  getPathFichero(File dir,String nombreFichero) {
		String res = "";
		
        
            File[] files = dir.listFiles();
            for (File file : files) {
                //Comprobamos que existe en el fichero
                if(file.exists()){
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
            }
        
        return res;
    } 
    
    //Metodo que devuelve un map que relaciona key = nombrefichero con value= ruta absoluta, devuelve dicho map
    //Consigue los ficheros a analizar.
    //Recibe el properties que se obtiene con cargarconfiguracion
    private static Map<String,String> getRutasAbsolutas(Properties p){
		
		Map<String, String> map = new HashMap<String, String>();
		//obtenemos del valor filelist= una lista de ficheros, por tanto , debemos seleccionar cada valor de la lista
        //String res1[] =  p.getProperty("filelist").split(",");
        String res1[];
        //Comprobamos
        //if(getOpSystem().equals("windows")){
            res1 = p.getProperty("filelist").split(",");

            for(int i=0;i<res1.length;i++) {
                    //En el caso de windows habria que introducir rutas absolutas, en este caso metemos ficheros en la ruta del proyecto
                    //aqui se generaria el map nombre,ruta
                    File aux = new File(System.getProperty("user.dir")+File.separator+res1[i]);
                    //Comprobamos si el fichero que estamos buscando Existe o no antes de añadir la ruta absoluta
                    if(aux.exists()){
                        String ruta = System.getProperty("user.dir")+File.separator+res1[i];
                       map.put(res1[i],ruta);
                    }
                   
               }
        /*}else{
            res1 = p.getProperty("filelist").split(",");
        
		
		    for(int i=0;i<res1.length;i++) {
             //Obtenemos la ruta de cada uno de los ficheros que tienen el nombre que aparece en el archivo de configuracion
                String ruta = getPathFichero(new File("/"), res1[i]);
            
			    if(!ruta.equals("")) {

                //si el fichero tiene ruta "" es que no existe, por tanto, aquí, solo entra en caso de que existe 
                //y lo introduce en el map
				    map.put(res1[i],getPathFichero(new File("/"), res1[i]));
			    }
            }
        }*/
		return map;
	}
   
    /*test para mis metodos subidos, habria que cambiar la ruta del config.properties
	System.out.println("------------------------pruebas path de todos los ficheros------------------");
	    Map<String, String> test = getRutasAbsolutas();
        System.out.println(test.values());
        System.out.println(test.keySet());
    */

    //Este método lo vamos a usar para cifrar el archivo que contiene la lista de Hash 
    private static String cifrarArchivoHash(String data, String algorithm_simetric, Key keyGenerated){
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
        return Base64.getEncoder().encodeToString(cipherText);
        //return cipherText;
    }
    //Este método lo vamos a usar para cifrar el archivo que contiene la lista de Hash 
    private static String descifrarArchivoHash(String data_crypt, String algorithm_simetric, Key keyGenerated){
        //Creamos las variables necesarias:
        String decryptTextRes = "";
        try{
            byte[] data_crypt_byte = Base64.getDecoder().decode(data_crypt);
            Cipher cipherObj = Cipher.getInstance(algorithm_simetric);
            //Inicializamos el cifrador para descifrar pasándole la clave generada:
            cipherObj.init(Cipher.DECRYPT_MODE, keyGenerated);
            byte[] decryptText = cipherObj.doFinal(data_crypt_byte);
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
            if(file.exists()){
                fileReader = new FileReader(file);
                bufferedReader = new BufferedReader(fileReader);

                //Leemos el fichero completamente:
                String var_control_string = "";
                while((var_control_string = bufferedReader.readLine()) != null){
                    System.out.println("Línea --> "+var_control_string);
                    //TODO: Pasarle la propiedad "keyword.crypt.fich.hash" del archivo config en vez de "asignaturaSSII"
                    if(salt){
                        ret_data = ret_data + "asignaturaSSII" + var_control_string;
                    }else{
                        ret_data = ret_data + var_control_string;
                    }
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

    private static Key generadorClavesSimetricas(String alg, Integer longitud, String passwordSimetrica){
        Key key = null;
        try{
            // Generamos una clave de 128 bits adecuada para AES
            KeyGenerator keyGenerator = KeyGenerator.getInstance(alg);
            keyGenerator.init(longitud);
            key = keyGenerator.generateKey();
            
            // Alternativamente, una clave que queramos que tenga al menos 16 bytes
            // y nos quedamos con los bytes 0 a 15
            key = new SecretKeySpec(passwordSimetrica.getBytes(),  0, 16, alg);
            
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

    private static Connection conexionBBDD(String usernameParam, String passwordParam){
        //Conexion con la base de datos 
        String driver = "com.mysql.jdbc.Driver";

        String database = "hids_database";
        String hostname = "localhost";
        String port = "3307";
        String url = "jdbc:mysql://" + hostname + ":" + port + "/" + database ;
        String username = "user";
        String password = "password";

        Connection conn = null;

        try {
            //Class.forName(driver);
            conn = DriverManager.getConnection(url, "root", "");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return conn;
        
        //return null;
    }

    private static void cerrarConexionBBDD(){
        //Cerramos la conexión con la base de datos
    }

    private static void guardarPasswordAndCryptFile(Key password, String archivo_cifrado){
        //En principio escribimos en un fichero:
        FileWriter fichero = null;
        FileWriter fichero_crypt = null;
        try{
            fichero = new FileWriter("../fichero_password.txt");
            fichero.write(Base64.getEncoder().encodeToString(password.getEncoded()) +"\n");
            
            fichero_crypt = new FileWriter("../fichero_cifrado.txt");
            fichero_crypt.write(archivo_cifrado);

            fichero.close();
            fichero_crypt.close();
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
private static Map<String,String> getNombreHash(Properties p){
	
    //Obtenemos del archivo de configuración el algoritmo que vamos a usar para generar los hash
    MessageDigest sha256Digest = null;
    String hash = "";
    String algoritmo = p.getProperty("algorithm");
    try {
        sha256Digest = MessageDigest.getInstance(algoritmo);
    }
    catch(NoSuchAlgorithmException e) {
        System.out.println("El algoritmo para generar el hash no ha sido seleccionado correctamente.");
    }
    Map<String, String> map = getRutasAbsolutas(p);
    Map<String, String> mapRes = new HashMap<String, String>(); // Relaciona nombres de fichero con hash
    
    for(String n:map.keySet()){
        
        File f = new File(map.get(n));
        if(f.exists()){
            hash = getHashFichero(sha256Digest,f);
            mapRes.put(map.get(n), hash);
        }
    }
    return mapRes;
}
	
	



//Metodo que genera un fichero que almacena nombreFichero:hashdefichero
private static void generarFicheroHash(Properties p){
		
    BufferedWriter output = null;
    File file = new File("hashes.txt");//Hay que seleccionar una ruta segura
    Map<String, String> map = getNombreHash(p);
    String s = "";
    Boolean esPrimero = true;
    
    for(String n:map.keySet()) {
        if(esPrimero) {
            //Usamos el doble :: para separar para que el formato en TODOS los sistemas sea el mismo
            s=(n+"::"+map.get(n)+"-");
            esPrimero = false;
        }else {
            s+=(n+"::"+map.get(n)+"-");
        }
    }
    try {
        if(file.exists()){
            output = new BufferedWriter(new FileWriter(file));
            output.write(s);
            output.close();
        }
    }
    catch(IOException e) {
        System.out.println("El fichero de hash no se ha podido generar correctamente.");
        
    }
    
}

    //Metodo comparar y leer
	//Metodo de generacion de fichero hashCifrado
	private static void generaFicheroHashCifrado(byte[] hashCifrado) {
		
		try {
			//Esto funciona en linux en windows habria que modificar el path
			FileOutputStream stream = new FileOutputStream("./hashCifrado.txt");
		    stream.write(hashCifrado);
		    stream.close();
		}catch(	IOException e) {
			System.out.println("El archivo hash Cifrado no se ha podido generar");
		}
		
    }
	
	//Metodo que lee el fichero de los hash(RAW) y saca nombreFichero:hash
	private static Map<String,String> leerFichero(String hashes){
		//Obtenemos el valor del archivo que almacena los hashes
		String hashesLeido = lecturaFicheros("hashes.txt", false);
		String[] parts = hashesLeido.split("-");
		Map<String, String> map = new HashMap<String, String>();
		
		for(String s:parts) {
			String[] aux = s.split("::");
			map.put(aux[0], aux[1]);
		}
		return map;
	}
    
    //metodo comparar hashes
		//Metodo para comparar 
        private static void comparaHashes(Map<String,String>nuevosHash,Properties prop,String rutaHash){
		
            Map<String, String> originalHash = leerFichero(rutaHash);
            List<String>ListaNoCoincidencias = new ArrayList<String>();
            Integer total = originalHash.keySet().size();
            String res = ""; 
            for(String s:originalHash.keySet()){
                if(nuevosHash.get(s)==null){
                    res = res + "El archivo "+s+" ha sido eliminado"+"\n";
                    ListaNoCoincidencias.add(s);
                }else{
                     if(nuevosHash.get(s).equals(originalHash.get(s))) {
                   
                         res = res + "El archivo "+s+" coincide"+"\n";
                    }else {
                        ListaNoCoincidencias.add(s);
                   
                         res = res + "El archivo "+s+" no coincide"+"\n";
                    }
                }
            }
            BufferedWriter output = null;
            File file = new File("Integridad.txt");//Hay que seleccionar una ruta segura
            if(file.exists()){
                float dif = (float)(total - ListaNoCoincidencias.size());
                float div = dif/total;
                res = res + " La integridad de los archivos es del "+ (div*100 + "%.");
                res = res + "Los ficheros que no coinciden son: "+ListaNoCoincidencias.toString();
                try {
                    output = new BufferedWriter(new FileWriter(file));
                    output.write(res);
                    output.close();
                    }
                    catch(IOException e) {
                        System.out.println("El fichero de hash no se ha podido generar correctamente.");
                        
                    }
                System.out.println(res);
                }
        }
        private static void comparaHashesString(Map<String,String>nuevosHash,Properties prop,String stringHashesConSalt){

            Map<String, String> originalHash = leerHashConSalt(stringHashesConSalt,prop);
            List<String>ListaNoCoincidencias = new ArrayList<String>();
            Integer total = originalHash.keySet().size();
            String res = ""; 
            for(String s:originalHash.keySet()){
                if(nuevosHash.get(s)==null){
                    res = res + "El archivo "+s+" ha sido eliminado"+"\n";
                    ListaNoCoincidencias.add(s);
                }else{
                     if(nuevosHash.get(s).equals(originalHash.get(s))) {
                   
                         res = res + "El archivo "+s+" coincide"+"\n";
                    }else {
                        ListaNoCoincidencias.add(s);
                   
                         res = res + "El archivo "+s+" no coincide"+"\n";
                    }
                }
            }
            BufferedWriter output = null;
            File file = new File("Intregidad.txt");//Hay que seleccionar una ruta segura
            if(file.exists()){
                float dif = (float)(total - ListaNoCoincidencias.size());
                float div = dif/total;
                res = res + " La integridad de los archivos es del "+ (div*100 + "%.");
                res = res + "Los ficheros que no coinciden son: "+ListaNoCoincidencias.toString();
                try {
                    output = new BufferedWriter(new FileWriter(file));
                    output.write(res);
                    output.close();
                    }
                    catch(IOException e) {
                        System.out.println("El fichero de hash no se ha podido generar correctamente.");
                        
                    }
                System.out.println(res);
                }
        }
    


    private static String pedirPasswordSimetrica(){		
        String res_ret = new String();		
        System.out.println("Introduzca una clave de 16 bits para el cifrado simétrico: ");		
        Scanner inputText = new Scanner(System.in);	
        res_ret = inputText.next();		 		
        if(res_ret.length() != 16){	
            System.out.println("[ERROR] La clave introducida no es de 16 bits.");		    
            System.out.println("Introduzca una clave de 16 bits: ");		   
            res_ret = inputText.next();		  
            if(res_ret.length() != 16){		    
                System.out.println("[ERROR] La clave introducida no es de 16 bits.");		     
                System.out.println("Ha excedido el número de intentos.");		     
                System.exit(0);		 
            }		       
        }
        return res_ret;		
    }

    private static String partHashingCode(Properties p, Key clave){
        //Map<String, String> ficheros = getRutasAbsolutas(p);
        //función de obtención de hash
        //Map<String, String> nombreHash = getNombreHash(p);
        
        String res = "";
        ////
        String salt = p.getProperty("keyword.crypt.fich.hash");
        Map<String, String> map = getNombreHash(p);
            Boolean esPrimero = true;
            
            for(String n:map.keySet()) {
                if(esPrimero) {
                    //Usamos el doble :: para separar para que el formato en TODOS los sistemas sea el mismo
                    res=(n+"::"+map.get(n)+"-"+salt);
                    esPrimero = false;
                }else {
                    res+=(n+"::"+map.get(n)+"-"+salt);
                }
            }
        //System.out.println("El string de hashes con salt :---------------------------");
        //System.out.println(res);
        return res;

        /* File file = new File("../fichero_cifrado.txt");
        if(file.exists()){
            System.out.println("Desciframos el archivo...");
            String data_fichero_hash_decrypt = descifrarArchivoHashdescifrarArchivoHash(lecturaFicheros("../fichero_cifrado.txt", false), p.getProperty("algorithm.simetric"),clave);
            System.out.println("Datos del fichero de hash descifrado: "+data_fichero_hash_decrypt); 
            
        }

        //De momento obtenemos los hash desde aquí:
        String data_fichero_hash = lecturaFicheros("../fichero_hashes.txt",true);
        return data_fichero_hash; */
    }

    private static Key obtencionClave(Properties p){
        Key res_ret;
        File file = new File("../fichero_password.txt");
        if(file.exists()){
            //Conseguimos la clave desde el fichero:
            Key keyPassword = getPasswordSimetrica(p.getProperty("algorithm.simetric"));
            System.out.println("Clave de Cifrado: " + keyPassword);
            res_ret = keyPassword;
        }else{
            String claveSimetrica = pedirPasswordSimetrica();
            Key keyGenerated = generadorClavesSimetricas(p.getProperty("algorithm.simetric"),Integer.parseInt(p.getProperty("algorithm.simetric.tam")),claveSimetrica);
            System.out.println("Clave de cifrado: " + keyGenerated);
            res_ret = keyGenerated;
            guardarPasswordAndCryptFile(keyGenerated, "../fichero_password.txt");
        }
        return res_ret; 
    }

    private static String partCryptSimetric(Properties p, String hash, Key clave){
        
        String data_fichero_hash_crypt = cifrarArchivoHash(hash,p.getProperty("algorithm.simetric"),clave);
        System.out.println("Datos del fichero de hash cifrado: "+data_fichero_hash_crypt);
        return data_fichero_hash_crypt;
    }

    private static void modificarFichero(String s,File f){
        // este es el archivo que insertaras caracteres
        try {
       FileWriter escribir = new FileWriter(f);
       String texto = s;
       for(int i=0; i<texto.length();i++){
       escribir.write(texto.charAt(i));
       
       System.out.println("El archivo "+ f.getPath()+ " ha sido modificado.");
       }
       escribir.close();
    }catch(IOException e){
    }
   }
   //Metodo que introduce en un map a partir de un string de los hashes con salt
   private static Map<String,String> leerHashConSalt(String hashesStringConSalt,Properties p){
    //Obtenemos el valor del archivo que almacena los hashes
    String salt = p.getProperty("keyword.crypt.fich.hash");
    String[] parts = hashesStringConSalt.split(salt);
    Map<String, String> map = new HashMap<String, String>();
    
    for(String s:parts) {
        System.out.println("Muestra cada array");
        System.out.println(s);
        String[] aux = s.split("::");
        map.put(aux[0], aux[1].split("-")[0]);
    }
    return map;
}



} //Cierre de la clase