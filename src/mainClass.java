import java.io.*;
import java.util.*;

public class mainClass {
    public static void main (String [ ] args) {
 
        System.out.println ("HIDS v1.0");
        Properties prop = cargaConfiguracion("config.properties");
        System.out.println("***** Configuración del sistema: ");
        System.out.println("Periodo: "+prop.getProperty("task.hours") + " Horas");
        configuracionTiempo(2, tareaParaRealizar());
        System.out.println("Terminamos...");
 
    } //Cierre del main

    private static void configuracionTiempo(Integer periodoHoras, TimerTask task){
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

} //Cierre de la clase